# Lifecycle checks require elevation and restart piko. -ReadOnly never changes service state.
[CmdletBinding()]
param(
    [switch]$RequireEtw,
    [switch]$ReadOnly,
    [string]$ExpectedPackagePath
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$program = Join-Path $env:ProgramFiles 'piko'
$files = @('piko-service.exe', 'piko.exe', 'piko-desktop.exe', 'piko-network-helper.exe')

function Assert-PackageFiles([string]$Directory) {
    $manifest = Get-Content -LiteralPath (Join-Path $Directory 'manifest.json') -Raw | ConvertFrom-Json
    if ($manifest.product -cne 'piko' -or $manifest.architecture -cne 'x64' -or
        [string]::IsNullOrWhiteSpace($manifest.version) -or @($manifest.files).Count -ne $files.Count) {
        throw 'Invalid piko installation/package manifest.'
    }
    foreach ($name in $files) {
        $entry = @($manifest.files | Where-Object { $_.name -ceq $name })
        if ($entry.Count -ne 1 -or $entry[0].sha256 -cnotmatch '^[A-Fa-f0-9]{64}$' -or
            (Get-FileHash -LiteralPath (Join-Path $Directory $name) -Algorithm SHA256).Hash -ine $entry[0].sha256) {
            throw "Installation/package hash mismatch: $name. No service lifecycle changes were made."
        }
    }
    return $manifest
}

# A version alone cannot distinguish different development builds of the same release.
# Check every installed executable, including UI, before stopping a running service.
$installedManifest = Assert-PackageFiles $program
if ($ExpectedPackagePath) {
    $packageManifest = Assert-PackageFiles ((Resolve-Path -LiteralPath $ExpectedPackagePath).Path)
    if ($installedManifest.version -cne $packageManifest.version) { throw 'Installed version differs from the expected package.' }
    foreach ($name in $files) {
        $installedEntry = @($installedManifest.files | Where-Object { $_.name -ceq $name })
        $packageEntry = @($packageManifest.files | Where-Object { $_.name -ceq $name })
        if ($installedEntry[0].sha256 -ine $packageEntry[0].sha256) { throw "Installed binary differs from the expected package: $name" }
    }
}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$ReadOnly -and !$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Service lifecycle validation requires an elevated PowerShell.' }
$cli = Join-Path $program 'piko.exe'
$expected = '"' + (Join-Path $program 'piko-service.exe') + '" --service --config "' + (Join-Path $program 'service.json') + '"'
$service = Get-CimInstance Win32_Service -Filter "Name='piko'"
if (!$service -or $service.PathName -cne $expected -or $service.StartName -ine 'NT SERVICE\piko') { throw 'Installed service does not match piko virtual-account configuration.' }
if ((Get-Service piko).Status -ne 'Running') {
    if ($ReadOnly) { throw 'Installed piko service is not running; read-only validation does not start it.' }
    Start-Service piko
}
(Get-Service piko).WaitForStatus('Running', [TimeSpan]::FromSeconds(35))
$first = & $cli health | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $first.runtime_mode -ne 'windows_service') { throw 'Authenticated SCM endpoint unavailable.' }
if ($first.version -cne $installedManifest.version) { throw 'Running service version differs from the installed package.' }
if ($ReadOnly) {
    $storage = @($first.sensors | Where-Object { $_.id -ceq 'piko.storage' })
    if ($storage.Count -ne 1 -or $storage[0].state -cne 'active' -or $first.dropped_events -ne 0) {
        throw 'Storage is unavailable or runtime has lost events.'
    }
    if ($RequireEtw) {
        $trace = @($first.sensors | Where-Object { $_.id -ceq 'windows.etw.process_image' })
        if ($trace.Count -ne 1 -or $trace[0].state -cne 'active') { throw 'ETW has not confirmed reception of process/image events.' }
    }
    [ordered]@{result='PASS'; scope='read_only_files_and_health'; version=$first.version; expected_package_checked=[bool]$ExpectedPackagePath; lifecycle_tested=$false; tests=@('installed executable hashes','virtual service account','SCM-authenticated IPC','runtime version','storage health'); etw_required=[bool]$RequireEtw} | ConvertTo-Json -Depth 6
    return
}
try {
    Stop-Service piko
    (Get-Service piko).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15))
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $unavailable = & $cli health 2>&1
        $offlineExitCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previousPreference }
    if ($offlineExitCode -eq 0) { throw 'Stopped installed service silently fell back to another endpoint.' }
} finally {
    Start-Service piko
    (Get-Service piko).WaitForStatus('Running', [TimeSpan]::FromSeconds(35))
}
$second = & $cli health | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Cannot read service health after restart.' }
$durableDeadline = [DateTime]::UtcNow.AddSeconds(10)
while ($second.stored_events -le $first.stored_events -and [DateTime]::UtcNow -lt $durableDeadline) {
    Start-Sleep -Milliseconds 300
    $second = & $cli health | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Cannot read durable evidence after restart.' }
}
if ($LASTEXITCODE -ne 0 -or $second.runtime_mode -ne 'windows_service' -or $second.version -cne $installedManifest.version -or $second.stored_events -le $first.stored_events) { throw 'Restart did not preserve and extend durable evidence with the installed version.' }
if ($RequireEtw) {
    $traceDeadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        $trace = @($second.sensors | Where-Object { $_.id -ceq 'windows.etw.process_image' })
        if ($trace.Count -eq 1 -and $trace[0].state -ceq 'active') { break }
        if ($trace.Count -eq 1 -and $trace[0].state -ceq 'degraded') { throw "ETW unavailable: $($trace[0].detail)" }
        Start-Sleep -Milliseconds 300
        $second = & $cli health | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0) { throw 'Cannot read ETW service health.' }
    } while ([DateTime]::UtcNow -lt $traceDeadline)
    if ($trace.Count -ne 1 -or $trace[0].state -cne 'active') { throw 'ETW has not confirmed reception of process/image events.' }
}
$integrity = & $cli verify | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $integrity.externally_anchored) { throw 'Post-restart integrity verification failed.' }
$storage = @($second.sensors | Where-Object { $_.id -ceq 'piko.storage' })
if ($storage.Count -ne 1 -or $storage[0].state -cne 'active' -or $second.dropped_events -ne 0) {
    throw 'Storage is unavailable or runtime has lost events; lifecycle alone cannot qualify ingestion.'
}
$testNames = @('installed executable hashes','runtime version','virtual service account','SCM-authenticated IPC','stop and no fallback','restart and durable evidence','integrity')
if ($RequireEtw) { $testNames += 'live ETW reception after service restart' }
[ordered]@{result='PASS'; scope='service_lifecycle'; version=$second.version; expected_package_checked=[bool]$ExpectedPackagePath; lifecycle_tested=$true; tests=$testNames; etw_required=[bool]$RequireEtw; stored_events=$second.stored_events; sensors=$second.sensors} | ConvertTo-Json -Depth 6
