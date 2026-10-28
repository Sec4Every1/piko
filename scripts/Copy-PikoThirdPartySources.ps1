[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Destination)
$ErrorActionPreference = 'Stop'
$pikoRoot = Split-Path -Parent $PSScriptRoot
$pikoReviewed = @{
    'cssparser'='0.37.0'; 'cssparser-macros'='0.7.1'; 'dtoa-short'='0.3.5'
    'option-ext'='0.2.0'; 'selectors'='0.38.0'
}
$pikoMetadataJson = & cargo metadata --offline --locked --format-version 1 --filter-platform x86_64-pc-windows-msvc --manifest-path (Join-Path $pikoRoot 'apps/desktop-ui/src-tauri/Cargo.toml')
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve locked desktop sources for distribution.' }
$pikoMetadata = $pikoMetadataJson | ConvertFrom-Json
$pikoLock = Get-Content -LiteralPath (Join-Path $pikoRoot 'apps/desktop-ui/src-tauri/Cargo.lock') -Raw
$pikoSourceDestination = Join-Path $Destination 'third-party-sources'
New-Item -ItemType Directory -Path $pikoSourceDestination -Force | Out-Null
foreach ($pikoName in $pikoReviewed.Keys) {
    $pikoVersion = $pikoReviewed[$pikoName]
    $pikoPackages = @($pikoMetadata.packages | Where-Object { $_.name -ceq $pikoName -and $_.version -ceq $pikoVersion -and $_.source -like 'registry+*' })
    if ($pikoPackages.Count -ne 1) { throw "Reviewed source version missing: $pikoName $pikoVersion" }
    $pikoStanzas = @([regex]::Split($pikoLock, '(?m)^\[\[package\]\]\s*$') | Where-Object {
        $_ -match ('(?m)^name = "' + [regex]::Escape($pikoName) + '"\s*$') -and
        $_ -match ('(?m)^version = "' + [regex]::Escape($pikoVersion) + '"\s*$')
    })
    if ($pikoStanzas.Count -ne 1 -or $pikoStanzas[0] -notmatch '(?m)^checksum = "([a-f0-9]{64})"\s*$') { throw "Locked source checksum missing: $pikoName" }
    $pikoChecksum = $Matches[1]
    $pikoCrateDirectory = Split-Path -Parent $pikoPackages[0].manifest_path
    $pikoIndexDirectory = Split-Path -Parent $pikoCrateDirectory
    $pikoRegistryRoot = Split-Path -Parent (Split-Path -Parent $pikoIndexDirectory)
    $pikoArchiveName = "$pikoName-$pikoVersion.crate"
    $pikoArchive = Join-Path $pikoRegistryRoot ('cache/' + (Split-Path -Leaf $pikoIndexDirectory) + '/' + $pikoArchiveName)
    if (!(Test-Path -LiteralPath $pikoArchive) -or (Get-FileHash -LiteralPath $pikoArchive -Algorithm SHA256).Hash -ine $pikoChecksum) { throw "Source archive absent or modified: $pikoArchiveName" }
    $pikoTarget = Join-Path $pikoSourceDestination $pikoArchiveName
    Copy-Item -LiteralPath $pikoArchive -Destination $pikoTarget -Force
    if ((Get-FileHash -LiteralPath $pikoTarget -Algorithm SHA256).Hash -ine $pikoChecksum) { throw "Packaged source checksum mismatch: $pikoArchiveName" }
}
Copy-Item -LiteralPath (Join-Path $pikoRoot 'docs/THIRD_PARTY_MPL.md') -Destination (Join-Path $Destination 'THIRD_PARTY_MPL.md') -Force
Copy-Item -LiteralPath (Join-Path $pikoRoot 'docs/licenses/MPL-2.0.txt') -Destination (Join-Path $Destination 'MPL-2.0.txt') -Force

# Include the reviewed build-time parser backport and its retained MIT notice.
# Resolve the service workspace: this build dependency is absent from the desktop graph.
$pikoCoreJson = & cargo metadata --offline --locked --format-version 1 --filter-platform x86_64-pc-windows-msvc --manifest-path (Join-Path $pikoRoot 'Cargo.toml')
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve patched build-time sources for distribution.' }
$pikoCore = $pikoCoreJson | ConvertFrom-Json
$pikoParserRoot = [IO.Path]::GetFullPath((Join-Path $pikoRoot 'vendor/i18n-config'))
$pikoParser = @($pikoCore.packages | Where-Object { $_.name -ceq 'i18n-config' -and $_.version -ceq '0.4.8' })
if ($pikoParser.Count -ne 1 -or $null -ne $pikoParser[0].source -or
    [IO.Path]::GetFullPath($pikoParser[0].manifest_path) -ine (Join-Path $pikoParserRoot 'Cargo.toml')) {
    throw 'Expected local i18n-config parser backport is missing from the locked graph.'
}
$pikoParserDestination = Join-Path $pikoSourceDestination 'i18n-config-0.4.8-piko'
# Explicit inventory excludes standalone Cargo.lock, target output and machine paths.
foreach ($pikoRelative in @('Cargo.toml', 'LICENSE.txt', 'README.md', 'CHANGELOG.md', 'PIKO_PATCH.md',
    'src/lib.rs', 'src/fluent.rs', 'src/gettext.rs', 'tests/piko_parser.rs', 'tests/fixtures/age-i18n.toml')) {
    $pikoOriginal = Join-Path $pikoParserRoot $pikoRelative
    $pikoCopied = Join-Path $pikoParserDestination $pikoRelative
    New-Item -ItemType Directory -Path (Split-Path -Parent $pikoCopied) -Force | Out-Null
    Copy-Item -LiteralPath $pikoOriginal -Destination $pikoCopied -Force
    if ((Get-FileHash -LiteralPath $pikoOriginal -Algorithm SHA256).Hash -cne
        (Get-FileHash -LiteralPath $pikoCopied -Algorithm SHA256).Hash) {
        throw "Patched source copy mismatch: $pikoRelative"
    }
}
