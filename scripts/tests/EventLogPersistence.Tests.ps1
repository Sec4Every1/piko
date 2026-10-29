$ErrorActionPreference = 'Stop'
# Import the production query guard without executing collection or the probe.
$source = Join-Path $PSScriptRoot '../event-log-smoke.ps1'
$tokens = $null; $parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
$definition = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Read-PersistedEvent', 'Read-UniqueWindowsRecord', 'Read-EventLogProbeCandidates', 'Collect')
}, $true))
if ($definition.Count -ne 4) { throw 'Expected production persistence queries and collection function' }
foreach ($function in $definition) { . ([scriptblock]::Create($function.Extent.Text)) }
$script:calls = 0
$script:rows = @()
$id = '11111111-2222-3333-4444-555555555555'
function Invoke-DevPiko([hashtable]$Command) {
    $script:calls++
    if ($Command.action -ne 'list_events' -or $Command.filter.limit -ne 2 -or
        $Command.filter.expression -ne ('event.id = "{0}"' -f $id)) { throw 'Unexpected bounded exact query' }
    return @{result=@{Ok=@{data=$script:rows}}}
}
function Assert-Refused([scriptblock]$Action) {
    $refused = $false
    try { & $Action } catch { $refused = $true }
    if (!$refused) { throw 'Expected refusal' }
}
foreach ($bad in @('', 'not-an-id', ($id + '" or true'))) {
    Assert-Refused { Read-PersistedEvent $bad }
}
if ($script:calls -ne 0) { throw 'Malformed ID reached IPC' }
Write-Output 'PASS malformed identifiers refused before IPC'
$script:rows = @(@{event_id=$id; raw_evidence_reference='fixture-raw'})
$row = Read-PersistedEvent $id
if ($row.raw_evidence_reference -ne 'fixture-raw' -or $script:calls -ne 1) { throw 'Exact persisted row not returned' }
Write-Output 'PASS older event retrieved by bounded exact query'
foreach ($rows in @(
    @{data=@()},
    @{data=@(@{event_id='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'})},
    @{data=@(@{event_id=$id}, @{event_id=$id})},
    @{data=@(@{event_id=$id}, @{event_id='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'})}
)) {
    $script:rows = $rows.data
    Assert-Refused { Read-PersistedEvent $id }
}
Write-Output 'PASS missing, mismatched and ambiguous rows refused'
Write-Output 'PASS production script parses without running its top level'

$record=@{event_id=$id;sensor_id='windows.event_log.Application';target=@{identifier='Application:piko:42'}}
$script:expression='sensor.id = "windows.event_log.Application" AND target.identifier = "Application:piko:42"'
function Invoke-DevPiko([hashtable]$Command) {
    $script:calls++
    if ($Command.action -ne 'list_events' -or $Command.filter.limit -ne 2 -or
        $Command.filter.expression -cne $script:expression) { throw 'Unexpected bounded source-key query' }
    return @{result=@{Ok=@{data=$script:rows}}}
}
$script:rows=@($record)
$actual=Read-UniqueWindowsRecord $record
if ($actual.event_id -ne $id) { throw 'Original source key not returned' }
Write-Output 'PASS exact source identity retrieved independently of newest page'
$other=@{event_id='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';sensor_id=$record.sensor_id;target=$record.target}
foreach ($rows in @(
    @{data=@()}, @{data=@($other)}, @{data=@($record,$other)},
    @{data=@(@{event_id=$id;sensor_id='windows.event_log.System';target=$record.target})},
    @{data=@(@{event_id=$id;sensor_id=$record.sensor_id;target=@{identifier='other'}})}
)) {
    $script:rows=$rows.data
    Assert-Refused { Read-UniqueWindowsRecord $record }
}
Write-Output 'PASS missing, replaced and replayed source records refused across pages'
$before=$script:calls
foreach ($bad in @(
    @{event_id='bad';sensor_id=$record.sensor_id;target=$record.target},
    @{event_id=$id;sensor_id='other';target=$record.target},
    @{event_id=$id;sensor_id=$record.sensor_id;target=@{identifier=''}},
    @{event_id=$id;sensor_id=$record.sensor_id;target=@{identifier=('x'*513)}}
)) { Assert-Refused { Read-UniqueWindowsRecord $bad } }
if ($script:calls -ne $before) { throw 'Malformed source key reached IPC' }
Write-Output 'PASS malformed source identities refused before IPC'
$escaped=@{event_id=$id;sensor_id=$record.sensor_id;target=@{identifier='Application:provider"quoted\name:42'}}
$script:expression='sensor.id = "windows.event_log.Application" AND target.identifier = ' + ($escaped.target.identifier | ConvertTo-Json -Compress)
$script:rows=@($escaped)
$null=Read-UniqueWindowsRecord $escaped
Write-Output 'PASS source identity query quotes special characters'
$defender=@{event_id=$id;sensor_id='windows.event_log.Microsoft-Windows-Windows Defender/Operational';target=@{identifier='Microsoft-Windows-Windows Defender/Operational:provider:42'}}
$script:expression='sensor.id = ' + ($defender.sensor_id | ConvertTo-Json -Compress) + ' AND target.identifier = ' + ($defender.target.identifier | ConvertTo-Json -Compress)
$script:rows=@($defender)
$null=Read-UniqueWindowsRecord $defender
Write-Output 'PASS supported Defender channel with spaces and slash'

function Invoke-DevPiko([hashtable]$Command) {
    if ($Command.action -ne 'list_events' -or $Command.filter.limit -ne 128 -or
        $Command.filter.expression -cne 'sensor.id = "windows.event_log.Application" AND target.identifier CONTAINS "Application:piko:"') { throw 'Unexpected bounded probe query' }
    return @{result=@{Ok=@{data=$script:rows}}}
}
$script:rows=@($record)
$candidates=@(Read-EventLogProbeCandidates)
if ($candidates.Count -ne 1 -or $candidates[0].event_id -ne $id) { throw 'Probe outside general page was not retrieved' }
$script:rows=@()
if (@(Read-EventLogProbeCandidates).Count -ne 0) { throw 'Empty probe query returned data' }
$script:rows=@(1..128 | ForEach-Object { $record })
Assert-Refused { Read-EventLogProbeCandidates }
Write-Output 'PASS provider-specific probe query works outside general page and refuses saturation'

# Exercise production collection orchestration with no process, sleep or OS probe.
$binary='fixture-service'; $config='fixture-config'; $runDir=$PSScriptRoot
$testToken='fixture-fresh-token'
$record.raw_evidence_reference='fixture-raw'
$script:collection=@{Page=@($record);Duplicate=$false;SourceQueries=0;Stops=0;Duration=0}
function Start-Sleep { param([int]$Seconds) }
function Start-Process {
    param($FilePath,$ArgumentList,[switch]$PassThru,$WindowStyle,$RedirectStandardError)
    if ($FilePath -ne 'fixture-service' -or $WindowStyle -ne 'Hidden') { throw 'Unexpected collection process request' }
    $script:collection.Duration=[int]$ArgumentList[-1]
    $process=[pscustomobject]@{Handle=0;HasExited=$false;ExitCode=0;Id=12345}
    $process | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { param($Timeout) $this.HasExited=$true; return $true }
    return $process
}
function Stop-Process { param($Id) $script:collection.Stops++ }
function Invoke-DevPiko([hashtable]$Command) {
    $data=$null
    switch ($Command.action) {
        'get_health' { $data=@{sensors=@(@{id='windows.event_log.System';state='active'},@{id='windows.event_log.Application';state='active'})} }
        'verify_store' { $data=@{externally_anchored=$false;verified_events=152} }
        'get_evidence' {
            if ($Command.filter.evidence_id -ne 'fixture-raw') { throw 'Unexpected raw reference' }
            $data=@{bytes=[Text.Encoding]::UTF8.GetBytes($testToken)}
        }
        'list_events' {
            if ($Command.filter.limit -eq 100) { $data=$script:collection.Page }
            elseif ($Command.filter.limit -eq 128) { $data=@($record) }
            elseif ($Command.filter.limit -eq 2) {
                $script:collection.SourceQueries++
                $data=if ($script:collection.Duplicate) { @($record,$other) } else { @($record) }
            } else { throw 'Unexpected collection query bound' }
        }
        default { throw 'Unexpected collection command' }
    }
    return @{result=@{Ok=@{data=$data}}}
}
$collected=Collect -Run 2 -ExpectedIds @($id) -ExpectedProbeId $id -ExpectedRecords @($record)
if ($script:collection.SourceQueries -ne 1 -or $collected.targeted_rechecks -ne 0 -or
    $collected.probe_record.event_id -ne $id -or $script:collection.Duration -ne 60 -or $script:collection.Stops -ne 0) { throw 'Collection skipped a source key on the newest page or failed bounded stop' }
Write-Output 'PASS production collection verifies source keys even when UUID is on newest page'
$script:collection.Page=@($other)
$collected=Collect -Run 2 -ExpectedIds @($id) -ExpectedProbeId $id -ExpectedRecords @($record)
if ($collected.targeted_rechecks -ne 1 -or $collected.probe_event_id -ne $id) { throw 'Collection failed outside-page source/probe verification' }
Write-Output 'PASS production collection retrieves probe and source key outside general page'
$script:collection.Duplicate=$true
Assert-Refused { Collect -Run 2 -ExpectedIds @($id) -ExpectedProbeId $id -ExpectedRecords @($record) }
if ($script:collection.Stops -ne 1) { throw 'Failed collection did not clean up its own test process' }
Write-Output 'PASS production collection rejects replay and cleans up its process'

$script:collection.Duplicate=$false
$script:collection.Probes=0
$probe='Invoke-FixtureProbe'
function Invoke-FixtureProbe([string]$Token) {
    if ($Token -ne $testToken) { throw 'Unexpected diagnostic token' }
    $script:collection.Probes++
    $global:LASTEXITCODE=0
}
$collected=Collect -Run 1
if ($script:collection.Duration -ne 30 -or $script:collection.Probes -ne 1 -or
    $collected.probe_record.event_id -ne $id) { throw 'First collection lost outside-page probe identity' }
Write-Output 'PASS first collection preserves probe identity outside general page'
