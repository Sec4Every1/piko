[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$pikoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$pikoEvidence = Join-Path $pikoRoot '.build/dependencies'
New-Item -ItemType Directory -Path $pikoEvidence -Force | Out-Null
# This directory is generated check evidence. Do not leave a previous run's
# SBOM beside current failed checks. Remove only direct SBOM output files.
Get-ChildItem -LiteralPath $pikoEvidence -Filter '*.cdx.json' -File | ForEach-Object {
    Remove-Item -LiteralPath $_.FullName
}

function Invoke-PikoDependencyCheck {
    param([string]$Program, [string[]]$Arguments, [string]$LogName)
    & $Program @Arguments 2>&1 | Tee-Object -FilePath (Join-Path $pikoEvidence $LogName) -Append
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}

function Get-PikoSbomPackages {
    param([string]$Root, [string[]]$Manifests = @('Cargo.toml', 'apps/desktop-ui/src-tauri/Cargo.toml'))
    foreach ($pikoManifest in $Manifests) {
        $pikoMetadataJson = & cargo metadata --locked --no-deps --format-version 1 --manifest-path (Join-Path $Root $pikoManifest)
        if ($LASTEXITCODE -ne 0) { throw "Cargo metadata failed: $pikoManifest" }
        $pikoMetadata = $pikoMetadataJson | ConvertFrom-Json
        foreach ($pikoPackage in $pikoMetadata.packages) {
            if ($pikoPackage.id -notin $pikoMetadata.workspace_members) { continue }
            $pikoRootPath = [IO.Path]::GetFullPath($Root).TrimEnd([char[]]'\/')
            $pikoPackagePath = [IO.Path]::GetFullPath((Split-Path -Parent $pikoPackage.manifest_path))
            $pikoPrefix = $pikoRootPath + [IO.Path]::DirectorySeparatorChar
            if ($pikoPackagePath.Equals($pikoRootPath, [StringComparison]::OrdinalIgnoreCase)) {
                $pikoDirectory = '.'
            } elseif ($pikoPackagePath.StartsWith($pikoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                $pikoDirectory = $pikoPackagePath.Substring($pikoPrefix.Length).Replace('\', '/')
            } else {
                throw "Workspace package is outside the repository: $($pikoPackage.name)"
            }
            [pscustomobject]@{Directory=$pikoDirectory; Name=$pikoPackage.name}
        }
    }
}

# Independent gates must still produce evidence when an earlier audit fails.
# Catch only at phase boundaries; prerequisites within a phase remain fail-fast.
function Invoke-PikoDependencyPhase {
    param([string]$Name, [scriptblock]$Action, [Collections.Generic.List[string]]$Failures)
    try { & $Action } catch {
        $Failures.Add($Name + ': ' + $_.Exception.Message)
        Write-Warning ($Name + ' failed; continuing independent dependency checks.')
    }
}

function Export-PikoRustSbom {
    param([string]$Manifest)
    $pikoArguments = @('cyclonedx', '--manifest-path', $Manifest, '--format', 'json', '--all', '--spec-version', '1.5', '--target', 'x86_64-pc-windows-msvc')
    Invoke-PikoDependencyCheck cargo $pikoArguments 'rust-sbom.txt'
    # Never copy pre-existing SBOMs when generation failed.
    $pikoPackages = @(Get-PikoSbomPackages -Root $pikoRoot -Manifests @($Manifest) | Sort-Object Directory -Unique)
    foreach ($pikoPackage in $pikoPackages) {
        $pikoName = $pikoPackage.Name + '.cdx.json'
        $pikoBom = Join-Path $pikoRoot ($pikoPackage.Directory + '/' + $pikoName)
        if (-not (Test-Path -LiteralPath $pikoBom)) { throw "Expected SBOM is missing: $($pikoPackage.Directory)/$pikoName" }
        Copy-Item -LiteralPath $pikoBom -Destination (Join-Path $pikoEvidence $pikoName)
    }
}

$pikoFailures = New-Object 'Collections.Generic.List[string]'
Push-Location $pikoRoot
try {
    Invoke-PikoDependencyCheck cargo @('deny', '--version') 'tools.txt'
    Invoke-PikoDependencyCheck cargo @('cyclonedx', '--version') 'tools.txt'
    Invoke-PikoDependencyPhase 'Rust core audit' {
        Invoke-PikoDependencyCheck cargo @('deny', '--locked', '--target', 'x86_64-pc-windows-msvc', 'check') 'rust-core-audit.txt'
    } $pikoFailures
    Invoke-PikoDependencyPhase 'Rust desktop audit' {
        # cargo-deny common options must precede the check subcommand.
        Invoke-PikoDependencyCheck cargo @('deny', '--locked', '--manifest-path', 'apps/desktop-ui/src-tauri/Cargo.toml', '--target', 'x86_64-pc-windows-msvc', '--config', 'deny.toml', 'check') 'rust-desktop-audit.txt'
    } $pikoFailures
    Invoke-PikoDependencyPhase 'Rust core SBOM' { Export-PikoRustSbom 'Cargo.toml' } $pikoFailures
    Invoke-PikoDependencyPhase 'Rust desktop SBOM' { Export-PikoRustSbom 'apps/desktop-ui/src-tauri/Cargo.toml' } $pikoFailures
    Invoke-PikoDependencyPhase 'Frontend dependencies' {
        Push-Location (Join-Path $pikoRoot 'apps/desktop-ui')
        try {
            Invoke-PikoDependencyCheck npm.cmd @('ci', '--ignore-scripts', '--no-audit', '--no-fund') 'npm-install.txt'
            Invoke-PikoDependencyPhase 'Frontend SBOM' {
                $pikoSbom = & npm.cmd sbom --sbom-format cyclonedx --package-lock-only
                if ($LASTEXITCODE -ne 0) { throw 'npm SBOM generation failed.' }
                [IO.File]::WriteAllText((Join-Path $pikoEvidence 'frontend.cdx.json'), ($pikoSbom -join [Environment]::NewLine), (New-Object Text.UTF8Encoding($false)))
            } $pikoFailures
            Invoke-PikoDependencyPhase 'Frontend audit' {
                Invoke-PikoDependencyCheck npm.cmd @('audit', '--audit-level=moderate') 'npm-audit.txt'
            } $pikoFailures
        } finally { Pop-Location }
    } $pikoFailures
    Invoke-PikoDependencyPhase 'Lockfile integrity' {
        Invoke-PikoDependencyCheck git @('diff', '--exit-code', '--', 'Cargo.lock', 'apps/desktop-ui/src-tauri/Cargo.lock', 'apps/desktop-ui/package-lock.json') 'lockfiles.txt'
    } $pikoFailures
    if ($pikoFailures.Count -gt 0) {
        throw ('Dependency checks failed: ' + ($pikoFailures -join '; '))
    }
} finally { Pop-Location }
