[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$pikoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$pikoEvidence = Join-Path $pikoRoot '.build/dependencies'
New-Item -ItemType Directory -Path $pikoEvidence -Force | Out-Null

function Invoke-PikoDependencyCheck {
    param([string]$Program, [string[]]$Arguments, [string]$LogName)
    & $Program @Arguments 2>&1 | Tee-Object -FilePath (Join-Path $pikoEvidence $LogName) -Append
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}

Push-Location $pikoRoot
try {
    Invoke-PikoDependencyCheck cargo @('deny', '--version') 'tools.txt'
    Invoke-PikoDependencyCheck cargo @('cyclonedx', '--version') 'tools.txt'
    Invoke-PikoDependencyCheck cargo @('deny', '--locked', '--target', 'x86_64-pc-windows-msvc', 'check') 'rust-core-audit.txt'
    Invoke-PikoDependencyCheck cargo @('deny', '--locked', '--manifest-path', 'apps/desktop-ui/src-tauri/Cargo.toml', '--target', 'x86_64-pc-windows-msvc', 'check', '--config', 'deny.toml') 'rust-desktop-audit.txt'
    Invoke-PikoDependencyCheck cargo @('cyclonedx', '--format', 'json', '--all', '--spec-version', '1.5', '--target', 'x86_64-pc-windows-msvc') 'rust-sbom.txt'
    Invoke-PikoDependencyCheck cargo @('cyclonedx', '--manifest-path', 'apps/desktop-ui/src-tauri/Cargo.toml', '--format', 'json', '--all', '--spec-version', '1.5', '--target', 'x86_64-pc-windows-msvc') 'rust-sbom.txt'

    $pikoManifests = @('crates/common-model', 'crates/event-schema', 'crates/event-fabric', 'crates/event-storage', 'crates/win-platform', 'crates/ipc', 'apps/security-service', 'apps/cli', 'apps/desktop-ui/src-tauri')
    foreach ($pikoDirectory in $pikoManifests) {
        $pikoBom = Join-Path $pikoRoot "$pikoDirectory/bom.json"
        if (-not (Test-Path -LiteralPath $pikoBom)) { throw "Expected SBOM is missing: $pikoDirectory/bom.json" }
        $pikoName = $pikoDirectory.Replace('/', '-') + '.cdx.json'
        Copy-Item -LiteralPath $pikoBom -Destination (Join-Path $pikoEvidence $pikoName)
    }

    Push-Location (Join-Path $pikoRoot 'apps/desktop-ui')
    try {
        Invoke-PikoDependencyCheck npm.cmd @('ci', '--ignore-scripts', '--no-audit', '--no-fund') 'npm-install.txt'
        $pikoSbom = & npm.cmd sbom --sbom-format cyclonedx --package-lock-only
        if ($LASTEXITCODE -ne 0) { throw 'npm SBOM generation failed.' }
        $pikoSbom | Set-Content -LiteralPath (Join-Path $pikoEvidence 'frontend.cdx.json') -Encoding utf8NoBOM
        Invoke-PikoDependencyCheck npm.cmd @('audit', '--audit-level=moderate') 'npm-audit.txt'
    } finally { Pop-Location }

    Invoke-PikoDependencyCheck git @('diff', '--exit-code', '--', 'Cargo.lock', 'apps/desktop-ui/src-tauri/Cargo.lock', 'apps/desktop-ui/package-lock.json') 'lockfiles.txt'
} finally { Pop-Location }
