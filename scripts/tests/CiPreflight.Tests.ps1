# Invoke the real CI entrypoint with command discovery replaced. Never run checks.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$pikoCiScript = Join-Path (Split-Path -Parent $PSScriptRoot) 'ci-checks.ps1'
foreach ($source in @($pikoCiScript, $PSCommandPath,
    (Join-Path $PSScriptRoot 'Enable-PikoEvidenceProtection.Tests.ps1'),
    (Join-Path $PSScriptRoot 'RecoveryMetadata.Tests.ps1'),
    (Join-Path $PSScriptRoot 'Start-Piko.Tests.ps1'),
    (Join-Path $PSScriptRoot 'EventLogPersistence.Tests.ps1'))) {
    $tokens=$null; $parseErrors=$null
    $null=[System.Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$parseErrors)
    if ($parseErrors.Count -ne 0) { throw "PowerShell syntax errors in $source" }
}
Write-Output 'PASS CI entrypoint and isolated fixture scripts parse without errors'

$pikoCiState=@{Missing=@();Lookups=@();Actions=@()}
function Get-Command {
    param([string]$Name,[string]$CommandType,[string]$ErrorAction)
    if ($CommandType -cne 'Application') { throw 'Preflight must resolve executable applications.' }
    $pikoCiState.Lookups += $Name
    if ($pikoCiState.Missing -contains $Name) { return }
    return [pscustomobject]@{Name=$Name;CommandType='Application'}
}
function New-Item {
    $pikoCiState.Actions += 'filesystem'
    throw 'Unexpected filesystem action after failed tool preflight.'
}
function Push-Location {
    $pikoCiState.Actions += 'working-directory'
    throw 'Unexpected working-directory action after failed tool preflight.'
}
function Get-CimInstance {
    $pikoCiState.Actions += 'OS-probe'
    throw 'Unexpected OS probe after failed tool preflight.'
}
function Stop-PikoCiAction([string]$Name) {
    $pikoCiState.Actions += $Name
    throw "Unexpected check action after failed tool preflight: $Name"
}
function rustc { Stop-PikoCiAction 'rustc' }
function cargo { Stop-PikoCiAction 'cargo' }
function node { Stop-PikoCiAction 'node' }
function npm.cmd { Stop-PikoCiAction 'npm.cmd' }
function powershell.exe { Stop-PikoCiAction 'powershell.exe' }
function pwsh { Stop-PikoCiAction 'pwsh' }
function git { Stop-PikoCiAction 'git' }
$pikoExpectedTools=@('rustc','cargo','node','npm.cmd','powershell.exe','pwsh','git')
foreach ($missing in @(
    @{Names=$pikoExpectedTools},
    @{Names=@('pwsh')},
    @{Names=@('cargo','npm.cmd')}
)) {
    $pikoCiState.Missing=$missing.Names
    $pikoCiState.Lookups=@(); $pikoCiState.Actions=@()
    $failure=$null
    try { & $pikoCiScript } catch { $failure=$_.Exception.Message }
    $expected='Required check tools missing: ' + ($missing.Names -join ', ') + '. No checks or dependency installation started.'
    if ($failure -cne $expected) { throw "Unexpected preflight failure: $failure" }
    if (@($pikoCiState.Actions).Count -ne 0 -or
        ($pikoCiState.Lookups -join ',') -cne ($pikoExpectedTools -join ',')) {
        throw 'Preflight started work or failed to report all missing tools.'
    }
    Write-Output ('PASS missing tools refuse before any work: ' + ($missing.Names -join ', '))
}
Write-Output "CI preflight fixtures passed on PowerShell $($PSVersionTable.PSVersion); no checks, dependencies, services or processes started."
