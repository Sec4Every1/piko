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
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
$pipeName = "piko.dev.v1.$sid.$sessionId"

function Read-Exact([IO.Stream]$Stream, [int]$Length) {
    $buffer = New-Object byte[] $Length
    $offset = 0
    while ($offset -lt $Length) {
        $read = $Stream.Read($buffer, $offset, $Length - $offset)
        if ($read -eq 0) { throw 'Unexpected IPC EOF' }
        $offset += $read
    }
    return ,$buffer
}
function Invoke-DevPiko([hashtable]$Command) {
    $client = New-Object IO.Pipes.NamedPipeClientStream('.', $pipeName, [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::None, [Security.Principal.TokenImpersonationLevel]::Identification)
    $stage = 'connect'
    try {
        $client.Connect(2500)
        $stage = 'write'
        $payload = [Text.Encoding]::UTF8.GetBytes((@{protocol_version=1; request_id=71; command=$Command} | ConvertTo-Json -Depth 10 -Compress))
        $header = [BitConverter]::GetBytes([uint32]$payload.Length)
        $client.Write($header,0,4)
        $client.Write($payload,0,$payload.Length)
        $client.Flush()
        $stage = 'response header'
        $size = [BitConverter]::ToUInt32((Read-Exact $client 4),0)
        if ($size -eq 0 -or $size -gt 4MB) { throw 'Invalid response size' }
        $stage = 'response body'
        $response = [Text.Encoding]::UTF8.GetString((Read-Exact $client $size)) | ConvertFrom-Json
        if ($response.result.Err) { throw "$($response.result.Err.code): $($response.result.Err.message)" }
        return $response
    } catch {
        throw "IPC action '$($Command.action)' failed during $stage for '$($Command.evidence_id)': $($_.Exception.Message)"
    } finally { $client.Dispose() }
}
function Read-PersistedEvent([string]$Id) {
    if ($Id -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        throw 'First-run event ID is malformed'
    }
    $expression = 'event.id = "{0}"' -f $Id
    $specific = @(Invoke-DevPiko @{action='list_events';filter=@{limit=2;expression=$expression}}).result.Ok.data
    $matching = @($specific | Where-Object { $_ -and $_.event_id -eq $Id })
    if ($matching.Count -ne 1 -or @($specific).Count -ne 1) {
        throw "Previously persisted Windows record missing or ambiguous after restart: $Id"
    }
    return $matching[0]
}
function Read-UniqueWindowsRecord([object]$Record) {
    $id = [string]$Record.event_id
    $sensor = [string]$Record.sensor_id
    $identifier = [string]$Record.target.identifier
    if ($id -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' -or
        $sensor -notmatch '^windows\.event_log\.[a-zA-Z0-9_.-]{1,96}$' -or
        [string]::IsNullOrWhiteSpace($identifier) -or $identifier.Length -gt 512) {
        throw 'Invalid Windows record identity for restart verification'
    }
    # JSON string encoding is also the query language's quoted-string encoding.
    $expression = 'sensor.id = {0} AND target.identifier = {1}' -f ($sensor | ConvertTo-Json -Compress), ($identifier | ConvertTo-Json -Compress)
    $rows = @(Invoke-DevPiko @{action='list_events';filter=@{limit=2;expression=$expression}}).result.Ok.data
    $matching = @($rows | Where-Object { $_ -and $_.event_id -eq $id -and $_.sensor_id -eq $sensor -and $_.target.identifier -eq $identifier })
    if (@($rows).Count -ne 1 -or $matching.Count -ne 1) {
        throw "Windows source record missing, replaced or replayed after restart: $id"
    }
    return $matching[0]
}
function Read-EventLogProbeCandidates {
    # Separate bounded provider query: a busy general Windows page can exclude
    # the diagnostic before the first run has recorded its UUID.
    $rows = @(Invoke-DevPiko @{action='list_events';filter=@{limit=128;expression='sensor.id = "windows.event_log.Application" AND target.identifier CONTAINS "Application:piko:"'}}).result.Ok.data
    if (@($rows).Count -ge 128) { throw 'Event Log probe candidate bound reached; result is inconclusive' }
    return $rows
}
function Collect([int]$Run, [string[]]$ExpectedIds = @(), [string]$ExpectedProbeId = '', [object[]]$ExpectedRecords = @()) {
    $runSeconds = if ($ExpectedIds.Count -gt 0) { 60 } else { 30 }
    $process = Start-Process -FilePath $binary -ArgumentList @('--config', ('"' + $config + '"'), '--run-for-seconds', $runSeconds) -PassThru -WindowStyle Hidden -RedirectStandardError (Join-Path $runDir "run-$Run.log")
    $null = $process.Handle # Retain ExitCode on Windows PowerShell 5.
    try {
        Start-Sleep -Seconds 1
        if ($Run -eq 1) {
            & $probe $testToken
            if ($LASTEXITCODE -ne 0) { throw 'Cannot emit benign local Event Log probe' }
        }
        Start-Sleep -Seconds 4
        if ($process.HasExited) { throw "Runtime exited: $(Get-Content -LiteralPath (Join-Path $runDir "run-$Run.log") -Raw)" }
        $health = (Invoke-DevPiko @{action='get_health'}).result.Ok.data
        # PS5 emits the entire JSON array as one pipeline object; do not wrap
        # that pipeline in @(), which would create a nested event array.
        $events = @(Invoke-DevPiko @{action='list_events';filter=@{limit=100;search='windows_event_log'}}).result.Ok.data
        $pageIds = @($events | ForEach-Object { [string]$_.event_id })
        $rechecked = 0
        foreach ($record in $ExpectedRecords) {
            # Presence by UUID alone misses replay rows with a new UUID outside
            # the newest page. Query each original source key with limit two.
            $null = Read-UniqueWindowsRecord $record
            if ([string]$record.event_id -notin $pageIds) { $rechecked++ }
        }
        $verify = (Invoke-DevPiko @{action='verify_store'}).result.Ok.data
        if ($verify.externally_anchored) { throw 'Integrity failed' }
        foreach ($channel in @('System','Application')) {
            if (@($health.sensors | Where-Object { $_.id -eq "windows.event_log.$channel" -and $_.state -eq 'active' }).Count -ne 1) { throw "Live $channel subscription unavailable" }
        }
        $live = @(Read-EventLogProbeCandidates)
        if ($ExpectedProbeId -and $ExpectedProbeId -notin @($live | ForEach-Object { [string]$_.event_id })) {
            $live += @(Read-PersistedEvent $ExpectedProbeId)
        }
        $foundToken = $false
        $probeEventId = ''
        $probeRecord = $null
        foreach ($record in $live) {
            $raw = (Invoke-DevPiko @{action='get_evidence';filter=@{evidence_id=$record.raw_evidence_reference}}).result.Ok.data
            if ([Text.Encoding]::UTF8.GetString([byte[]]$raw.bytes).Contains($testToken)) {
                $foundToken = $true
                $probeEventId = [string]$record.event_id
                $probeRecord = $record
            }
        }
        if (!$foundToken) { throw 'Live Event Log probe or its original XML is missing' }
        if (!$process.WaitForExit(($runSeconds + 5) * 1000) -or $process.ExitCode -ne 0) { throw 'Runtime failed bounded stop' }
        return @{health=$health; events=$events; verified=$verify.verified_events; targeted_rechecks=$rechecked; probe_event_id=$probeEventId; probe_record=$probeRecord}
    } finally { if (!$process.HasExited) { Stop-Process -Id $process.Id } }
}
$first = Collect 1
$expectedIds = @($first.events | Where-Object { $_.event_category -eq 'windows_event_log' } | ForEach-Object { [string]$_.event_id })
$expectedRecords = @($first.events | Where-Object event_category -eq 'windows_event_log')
if ($first.probe_event_id -notin $expectedIds) { $expectedRecords += $first.probe_record }
$second = Collect -Run 2 -ExpectedIds $expectedIds -ExpectedProbeId $first.probe_event_id -ExpectedRecords $expectedRecords
$observed = @($first.events | Where-Object { $_.event_category -eq 'windows_event_log' })
if ($observed.Count -eq 0) { throw "No actual Windows records captured. Sensor state: $($first.health.sensors | ConvertTo-Json -Compress)" }
if (@($observed | Where-Object { !$_.raw_evidence_reference -or !$_.integrity_metadata.source_integrity -or $_.process -or $_.actor_identity }).Count -ne 0) { throw 'Missing evidence/bookmark or fabricated process attribution' }
$all = @($second.events | Where-Object { $_.event_category -eq 'windows_event_log' })
if (@($all | Group-Object { $_.sensor_id + '/' + $_.target.identifier } | Where-Object Count -gt 1).Count -gt 0) { throw 'Duplicate Windows records after restart' }
$summary = [ordered]@{result='PASS'; tests=@('real Windows records','new live diagnostic received','original XML read through API','active subscriptions','raw evidence references','durable bookmarks','no fabricated actor','sampled Windows source keys unique across restart','hash verification'); first_windows_records=$observed.Count; second_windows_records=$all.Count; targeted_rechecks=$second.targeted_rechecks; channels=@($second.health.sensors | Where-Object id -Like 'windows.event_log.*' | Select-Object id,state,detail); evidence_directory=$runDir} | ConvertTo-Json -Depth 6
[IO.File]::WriteAllText((Join-Path $runDir 'result.json'), $summary, (New-Object Text.UTF8Encoding($false)))
$summary

