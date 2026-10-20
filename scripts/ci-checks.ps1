# Windows development checks. Does not install a service, driver or product.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$pikoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$pikoEvidence = Join-Path $pikoRoot '.build/ci'
New-Item -ItemType Directory -Path $pikoEvidence -Force | Out-Null

function Invoke-PikoCheck {
    param([string]$Program, [string[]]$Arguments, [string]$LogName)
    & $Program @Arguments 2>&1 | Tee-Object -FilePath (Join-Path $pikoEvidence $LogName) -Append
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}

Push-Location $pikoRoot
try {
    Invoke-PikoCheck rustc @('--version', '--verbose') 'toolchain.txt'
    Invoke-PikoCheck cargo @('--version') 'toolchain.txt'
    Invoke-PikoCheck node @('--version') 'toolchain.txt'
    Invoke-PikoCheck npm.cmd @('--version') 'toolchain.txt'
    Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $pikoEvidence 'windows.json')
    Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $pikoEvidence 'cpu.json')

    Invoke-PikoCheck cargo @('fmt', '--all', '--', '--check') 'format.txt'
    Invoke-PikoCheck cargo @('fmt', '--manifest-path', 'apps/desktop-ui/src-tauri/Cargo.toml', '--', '--check') 'format.txt'
    Invoke-PikoCheck powershell.exe @('-NoProfile', '-File', 'scripts/tests/Test-PikoService.Tests.ps1') 'service-preflight-tests.txt'
    Invoke-PikoCheck pwsh @('-NoProfile', '-File', 'scripts/tests/Test-PikoService.Tests.ps1') 'service-preflight-tests.txt'
    Invoke-PikoCheck powershell.exe @('-NoProfile', '-File', 'scripts/tests/Update-Piko.Tests.ps1') 'service-update-tests.txt'
    Invoke-PikoCheck pwsh @('-NoProfile', '-File', 'scripts/tests/Update-Piko.Tests.ps1') 'service-update-tests.txt'
    Invoke-PikoCheck powershell.exe @('-NoProfile', '-File', 'scripts/tests/Backup-PikoInstallation.Tests.ps1') 'recovery-backup-tests.txt'
    Invoke-PikoCheck pwsh @('-NoProfile', '-File', 'scripts/tests/Backup-PikoInstallation.Tests.ps1') 'recovery-backup-tests.txt'
    Invoke-PikoCheck cargo @('clippy', '--workspace', '--all-targets', '--locked', '--', '-D', 'warnings') 'clippy.txt'
    Invoke-PikoCheck cargo @('test', '--workspace', '--locked', '--', '--show-output') 'rust-tests.txt'
    Invoke-PikoCheck cargo @('build', '--workspace', '--release', '--locked') 'rust-build.txt'
    Invoke-PikoCheck cargo @('run', '--release', '--locked', '-p', 'piko-event-storage', '--example', 'storage_bench') 'storage-benchmark.txt'

    & (Join-Path $PSScriptRoot 'smoke-runtime.ps1') -BinaryDirectory (Join-Path $pikoRoot 'target/release') -EvidenceDirectory $pikoEvidence
    Invoke-PikoCheck cargo @('build', '--release', '--locked', '-p', 'piko-win-platform', '--example', 'event_log_probe') 'sensor-build.txt'
    & (Join-Path $PSScriptRoot 'event-log-smoke.ps1') -BuildProfile release

    Push-Location (Join-Path $pikoRoot 'apps/desktop-ui')
    try {
        Invoke-PikoCheck npm.cmd @('ci', '--no-audit', '--no-fund') 'npm-install.txt'
        Invoke-PikoCheck npm.cmd @('run', 'check') 'frontend-check.txt'
        Invoke-PikoCheck npm.cmd @('test') 'frontend-tests.txt'
        Invoke-PikoCheck npm.cmd @('run', 'test:ui:install') 'browser-install.txt'
        Invoke-PikoCheck npm.cmd @('run', 'test:ui') 'browser-tests.txt'
        Invoke-PikoCheck npm.cmd @('run', 'build') 'frontend-build.txt'
        Invoke-PikoCheck cargo @('clippy', '--manifest-path', 'src-tauri/Cargo.toml', '--all-targets', '--locked', '--', '-D', 'warnings') 'desktop-clippy.txt'
        Invoke-PikoCheck npm.cmd @('run', 'tauri', '--', 'build', '--no-bundle', '--ci', '--', '--locked') 'desktop-build.txt'
    } finally { Pop-Location }

    $pikoBinaries = @(
        'target/release/piko.exe',
        'target/release/piko-service.exe',
        'apps/desktop-ui/src-tauri/target/release/piko-desktop.exe'
    )
    $pikoHashes = foreach ($pikoBinary in $pikoBinaries) {
        $pikoHash = Get-FileHash -LiteralPath (Join-Path $pikoRoot $pikoBinary) -Algorithm SHA256
        [pscustomobject]@{ path = $pikoBinary; sha256 = $pikoHash.Hash.ToLowerInvariant() }
    }
    $pikoHashes | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $pikoEvidence 'binary-sha256.json')
    Invoke-PikoCheck git @('diff', '--exit-code', '--', 'Cargo.lock', 'apps/desktop-ui/src-tauri/Cargo.lock', 'apps/desktop-ui/package-lock.json') 'lockfiles.txt'
} finally { Pop-Location }
