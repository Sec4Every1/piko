# Run after installation, from an elevated PowerShell. Tests only the piko service.
[CmdletBinding()]
param([switch]$RequireEtw)
$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Service lifecycle validation requires an elevated PowerShell.' }
$program = Join-Path $env:ProgramFiles 'piko'
$cli = Join-Path $program 'piko.exe'
$expected = '"' + (Join-Path $program 'piko-service.exe') + '" --service --config "' + (Join-Path $program 'service.json') + '"'
$service = Get-CimInstance Win32_Service -Filter "Name='piko'"
if (!$service -or $service.PathName -cne $expected -or $service.StartName -ine 'NT SERVICE\piko') { throw 'Installed service does not match piko virtual-account configuration.' }
if ((Get-Service piko).Status -ne 'Running') { Start-Service piko }
(Get-Service piko).WaitForStatus('Running', [TimeSpan]::FromSeconds(35))
$first = & $cli health | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $first.runtime_mode -ne 'windows_service') { throw 'Authenticated SCM endpoint unavailable.' }
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
if ($LASTEXITCODE -ne 0 -or $second.runtime_mode -ne 'windows_service' -or $second.stored_events -le $first.stored_events) { throw 'Restart did not preserve and extend durable evidence.' }
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
$testNames = @('virtual service account','SCM-authenticated IPC','stop and no fallback','restart and durable evidence','integrity')
if ($RequireEtw) { $testNames += 'live ETW reception after service restart' }
[ordered]@{result='PASS'; tests=$testNames; etw_required=[bool]$RequireEtw; stored_events=$second.stored_events; sensors=$second.sensors} | ConvertTo-Json -Depth 6
