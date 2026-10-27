$ErrorActionPreference = 'Stop'
# Import the production query guard without executing collection or the probe.
$source = Join-Path $PSScriptRoot '../event-log-smoke.ps1'
$tokens = $null; $parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
$definition = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Read-PersistedEvent'
}, $true))
if ($definition.Count -ne 1) { throw 'Expected one production persistence query function' }
. ([scriptblock]::Create($definition[0].Extent.Text))
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
