$ErrorActionPreference = 'Stop'
# Import the production query guard without executing collection or the probe.
$source = Join-Path $PSScriptRoot '../event-log-smoke.ps1'
$tokens = $null; $parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
$definition = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Read-PersistedEvent', 'Read-UniqueWindowsRecord', 'Read-EventLogProbeCandidates')
}, $true))
if ($definition.Count -ne 3) { throw 'Expected three production persistence query functions' }
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
