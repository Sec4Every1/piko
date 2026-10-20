param([string]$BuildProfile = 'debug')
$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
$binary = Join-Path $workspace "target\$BuildProfile\piko-service.exe"
$cli = Join-Path $workspace "target\$BuildProfile\piko.exe"
$probe = Join-Path $workspace "target\$BuildProfile\examples\event_log_probe.exe"
$testToken = [guid]::NewGuid().ToString('N')
$runDir = Join-Path $workspace ('.runtime\event-log-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $runDir | Out-Null
$config = Join-Path $runDir 'config.json'
$json = @{data_dir=$runDir; heartbeat_seconds=1; flush_seconds=1; max_disk_mib=64; queue_capacity=64} | ConvertTo-Json
[IO.File]::WriteAllText($config, $json, (New-Object Text.UTF8Encoding($false)))
function Collect([int]$Run) {
    $process = Start-Process -FilePath $binary -ArgumentList @('--config', ('"' + $config + '"'), '--run-for-seconds', '8') -PassThru -WindowStyle Hidden -RedirectStandardError (Join-Path $runDir "run-$Run.log")
    $null = $process.Handle # Retain ExitCode on Windows PowerShell 5.
    try {
        Start-Sleep -Seconds 1
        if ($Run -eq 1) {
            & $probe $testToken
            if ($LASTEXITCODE -ne 0) { throw 'Cannot emit benign local Event Log probe' }
        }
        Start-Sleep -Seconds 4
        if ($process.HasExited) { throw "Runtime exited: $(Get-Content -LiteralPath (Join-Path $runDir "run-$Run.log") -Raw)" }
        $health = & $cli health | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0) { throw 'Health unavailable' }
        # PS5 emits the entire JSON array as one pipeline object; do not wrap
        # that pipeline in @(), which would create a nested event array.
        $events = & $cli events windows.event_log | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0) { throw 'Event query unavailable' }
        $verify = & $cli verify | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0 -or $verify.externally_anchored) { throw 'Integrity failed' }
        foreach ($channel in @('System','Application')) {
            if (@($health.sensors | Where-Object { $_.id -eq "windows.event_log.$channel" -and $_.state -eq 'active' }).Count -ne 1) { throw "Live $channel subscription unavailable" }
        }
        $live = @($events | Where-Object { $_.target.identifier -like 'Application:piko:*' })
        $foundToken = $false
        foreach ($record in $live) {
            $raw = & $cli evidence $record.raw_evidence_reference | ConvertFrom-Json
            if ($LASTEXITCODE -ne 0) { throw 'Raw evidence API failed' }
            if ([Text.Encoding]::UTF8.GetString([byte[]]$raw.bytes).Contains($testToken)) { $foundToken = $true }
        }
        if (!$foundToken) { throw 'Live Event Log probe or its original XML is missing' }
        if (!$process.WaitForExit(12000) -or $process.ExitCode -ne 0) { throw 'Runtime failed bounded stop' }
        return @{health=$health; events=$events; verified=$verify.verified_events}
    } finally { if (!$process.HasExited) { Stop-Process -Id $process.Id } }
}
$first = Collect 1
$second = Collect 2
$observed = @($first.events | Where-Object { $_.event_category -eq 'windows_event_log' })
if ($observed.Count -eq 0) { throw "No actual Windows records captured. Sensor state: $($first.health.sensors | ConvertTo-Json -Compress)" }
if (@($observed | Where-Object { !$_.raw_evidence_reference -or !$_.integrity_metadata.source_integrity -or $_.process -or $_.actor_identity }).Count -ne 0) { throw 'Missing evidence/bookmark or fabricated process attribution' }
$all = @($second.events | Where-Object { $_.event_category -eq 'windows_event_log' })
if (@($all | Group-Object { $_.sensor_id + '/' + $_.target.identifier } | Where-Object Count -gt 1).Count -gt 0) { throw 'Duplicate Windows records after restart' }
$ids = @($all | ForEach-Object event_id)
if (@($observed | Where-Object { $_.event_id -notin $ids }).Count -gt 0) { throw 'Previously persisted Windows record missing after restart' }
$summary = [ordered]@{result='PASS'; tests=@('real Windows records','new live diagnostic received','original XML read through API','active subscriptions','raw evidence references','durable bookmarks','no fabricated actor','restart without replay duplicates','hash verification'); first_windows_records=$observed.Count; second_windows_records=$all.Count; channels=@($second.health.sensors | Where-Object id -Like 'windows.event_log.*' | Select-Object id,state,detail); evidence_directory=$runDir} | ConvertTo-Json -Depth 6
[IO.File]::WriteAllText((Join-Path $runDir 'result.json'), $summary, (New-Object Text.UTF8Encoding($false)))
$summary

