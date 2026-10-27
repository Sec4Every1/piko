# Actual launcher with synthetic service/principal/process boundaries only.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$pikoSource = Join-Path (Split-Path -Parent $PSScriptRoot) 'Start-Piko.ps1'
$pikoSavedProgramFiles = $env:ProgramFiles
$pikoSavedLocal = $env:LOCALAPPDATA
$pikoTempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$pikoName = 'piko-start-fixture-' + [guid]::NewGuid().ToString('N')
$pikoFixture = [IO.Path]::GetFullPath((Join-Path $pikoTempRoot $pikoName))
$pikoState = @{Elevated=$false;Installed=$true;Status='Stopped';Calls=@();ServiceReads=0;HealthReads=0}
function New-Object {
    param([string]$TypeName, [object[]]$ArgumentList)
    if ($TypeName -eq 'Security.Principal.WindowsPrincipal') {
        $principal = [pscustomobject]@{FixtureState=$pikoState}
        $principal | Add-Member -MemberType ScriptMethod -Name IsInRole -Value { param($role) return $this.FixtureState.Elevated }
        return $principal
    }
    Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName -ArgumentList $ArgumentList
}
function Get-Service {
    param([string]$Name,[string]$ErrorAction)
    if ($Name -cne 'piko') { throw 'Unexpected fixture service lookup.' }
    $pikoState.ServiceReads++
    if (!$pikoState.Installed) { return }
    return [pscustomobject]@{Status=$pikoState.Status}
}
function Start-Process {
    param([string]$FilePath,[string[]]$ArgumentList,[switch]$PassThru,[string]$WindowStyle)
    if ($args.Count) { throw 'Unexpected process arguments; no process was started.' }
    if ($pikoState.Installed) {
        if ($FilePath -cne $pikoExpectedDesktop -or $ArgumentList -or $PassThru -or $WindowStyle) { throw 'Unexpected installed process launch.' }
        $pikoState.Calls += $FilePath
        return
    }
    if ($FilePath -ceq $pikoPackagedRuntime) {
        if (!$PassThru -or $WindowStyle -cne 'Hidden' -or $ArgumentList.Count -ne 2 -or
            $ArgumentList[0] -cne '--config' -or $ArgumentList[1] -cne ('"' + $pikoConsoleConfig + '"')) { throw 'Unexpected console runtime arguments.' }
        $pikoState.Calls += $FilePath
        return [pscustomobject]@{HasExited=$true;Id=42}
    }
    if ($FilePath -cne $pikoPackagedDesktop -or $ArgumentList -or $PassThru -or $WindowStyle) { throw 'Unexpected per-user UI launch.' }
    $pikoState.Calls += $FilePath
}
function Start-Service { throw 'Real service mutations are forbidden in launcher fixtures.' }
function Stop-Service { throw 'Real service mutations are forbidden in launcher fixtures.' }
function Restart-Service { throw 'Real service mutations are forbidden in launcher fixtures.' }
function Set-Service { throw 'Real service mutations are forbidden in launcher fixtures.' }
try {
    $env:ProgramFiles = Join-Path $pikoFixture 'program-files'
    $env:LOCALAPPDATA = Join-Path $pikoFixture 'local-appdata'
    $pikoInstalled = Join-Path $env:ProgramFiles 'piko'
    New-Item -ItemType Directory -Path $pikoInstalled,$env:LOCALAPPDATA -Force | Out-Null
    $pikoExpectedDesktop = Join-Path $pikoInstalled 'piko-desktop.exe'
    [IO.File]::WriteAllText($pikoExpectedDesktop,'synthetic UI placeholder, never executed')
    foreach ($status in @('Stopped','Running')) {
        $pikoState.Status=$status
        $pikoState.Calls=@()
        $pikoState.ServiceReads=0
        & $pikoSource
        if ($pikoState.ServiceReads -ne 1 -or @($pikoState.Calls).Count -ne 1 -or
            $pikoState.Calls[0] -cne $pikoExpectedDesktop -or
            (Test-Path -LiteralPath (Join-Path $env:LOCALAPPDATA 'piko-monitor'))) { throw 'Installed launcher used a console fallback or lost the UI.' }
        Write-Output "PASS installed $status service opens only the installed non-elevated UI"
    }
    Remove-Item -LiteralPath $pikoExpectedDesktop
    $pikoState.Calls=@()
    $refused=$false
    try { & $pikoSource } catch { $refused=$true }
    if (!$refused -or @($pikoState.Calls).Count -ne 0) { throw 'Missing installed UI did not refuse without fallback.' }
    Write-Output 'PASS missing installed UI refuses without starting a collector'
    $pikoState.Elevated=$true
    $pikoState.ServiceReads=0
    $refused=$false
    try { & $pikoSource } catch { $refused=$true }
    if (!$refused -or $pikoState.ServiceReads -ne 0 -or @($pikoState.Calls).Count -ne 0) { throw 'Elevated UI launch was not refused before dispatch.' }
    Write-Output 'PASS elevated UI launch refuses before service/process dispatch'
    $pikoState.Elevated=$false
    $pikoState.Installed=$false
    $pikoPackagedRuntime=Join-Path (Split-Path -Parent $PSScriptRoot) 'piko-service.exe'
    $pikoPackagedDesktop=Join-Path (Split-Path -Parent $PSScriptRoot) 'piko-desktop.exe'
    $pikoPackagedCli=Join-Path (Split-Path -Parent $PSScriptRoot) 'piko.exe'
    $pikoConsoleConfig=Join-Path $env:LOCALAPPDATA 'piko-monitor\console.json'
    Set-Item -LiteralPath ('Function:' + $pikoPackagedCli) -Value {
        param([string]$Action)
        if ($Action -cne 'health' -or $args.Count) { throw 'Unexpected CLI fixture action.' }
        $pikoState.HealthReads++
        $global:LASTEXITCODE=1
        return '{"product":"unavailable"}'
    }
    $pikoState.Calls=@(); $pikoState.ServiceReads=0; $pikoState.HealthReads=0
    & $pikoSource
    $fresh=Get-Content -LiteralPath $pikoConsoleConfig -Raw | ConvertFrom-Json
    if ($fresh.max_disk_mib -ne 2048 -or $fresh.retention_months -ne 12 -or
        $fresh.data_dir -cne (Join-Path $env:LOCALAPPDATA 'piko-monitor') -or
        $pikoState.ServiceReads -ne 1 -or $pikoState.HealthReads -ne 1 -or
        @($pikoState.Calls).Count -ne 2 -or $pikoState.Calls[0] -cne $pikoPackagedRuntime -or
        $pikoState.Calls[1] -cne $pikoPackagedDesktop) { throw 'Fresh console defaults or disconnected UI route changed.' }
    Write-Output 'PASS fresh per-user defaults are 2048 MiB and 12 months; UI remains reachable after runtime exit'

    $custom=[Text.Encoding]::UTF8.GetBytes('{ "data_dir": "synthetic-custom", "max_disk_mib": 512, "retention_months": 0, "queue_capacity": 128 }' + "`r`n")
    [IO.File]::WriteAllBytes($pikoConsoleConfig,$custom)
    $pikoState.Calls=@(); $pikoState.HealthReads=0
    & $pikoSource
    $after=[IO.File]::ReadAllBytes($pikoConsoleConfig)
    if ([Convert]::ToBase64String($after) -cne [Convert]::ToBase64String($custom) -or
        $pikoState.HealthReads -ne 1 -or @($pikoState.Calls).Count -ne 2 -or
        $pikoState.Calls[0] -cne $pikoPackagedRuntime -or $pikoState.Calls[1] -cne $pikoPackagedDesktop) { throw 'Existing console configuration was rewritten or disconnected UI lost.' }
    Write-Output 'PASS existing custom console configuration remains byte-exact after runtime exit'

    # Evaluate only the production parameter block, never installer statements.
    $pikoInstaller=Join-Path (Split-Path -Parent $PSScriptRoot) 'Install-Piko.ps1'
    $parseTokens=$null; $parseErrors=$null
    $installerAst=[System.Management.Automation.Language.Parser]::ParseFile($pikoInstaller,[ref]$parseTokens,[ref]$parseErrors)
    if ($parseErrors.Count -ne 0 -or $null -eq $installerAst.ParamBlock) { throw 'Installer parameter block unavailable.' }
    $parameterProbe=[scriptblock]::Create($installerAst.ParamBlock.Extent.Text + "`n" + '[pscustomobject]@{MaxDiskMiB=$MaxDiskMiB;RetentionMonths=$RetentionMonths}')
    $defaults=& $parameterProbe -ViewerSid 'S-1-5-18'
    if ($defaults.MaxDiskMiB -ne 2048 -or $defaults.RetentionMonths -ne 12) { throw 'Installer frozen fresh defaults changed.' }
    Write-Output 'PASS actual installer parameter block defaults to 2048 MiB and 12 months without installation'
    Write-Output "Launcher and fresh-default fixtures passed on PowerShell $($PSVersionTable.PSVersion); no real service or process was changed."
} finally {
    $env:ProgramFiles=$pikoSavedProgramFiles
    $env:LOCALAPPDATA=$pikoSavedLocal
    $resolved=[IO.Path]::GetFullPath($pikoFixture)
    if ([IO.Path]::GetDirectoryName($resolved).TrimEnd('\') -ine $pikoTempRoot.TrimEnd('\') -or
        [IO.Path]::GetFileName($resolved) -cne $pikoName -or
        ((Get-Item -LiteralPath $resolved).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unsafe fixture cleanup target.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
