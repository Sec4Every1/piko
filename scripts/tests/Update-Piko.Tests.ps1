# Standalone fixture tests; SCM, process queries, ACL writes and CLI are doubles.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Update-Piko.ps1'
$fixtureName = 'piko-upgrade-test-' + [guid]::NewGuid().ToString('N')
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$fixture = Join-Path $tempRoot $fixtureName
$programFiles = Join-Path $fixture 'program-files'
$program = Join-Path $programFiles 'piko'
$programData = Join-Path $fixture 'program-data'
$data = Join-Path $programData 'piko'
$package = Join-Path $fixture 'package'
$savedProgramFiles = $env:ProgramFiles
$savedProgramData = $env:ProgramData
$files = @('piko-service.exe', 'piko.exe', 'piko-desktop.exe', 'piko-network-helper.exe')
$pikoUpgradeTestState = @{Status='Running'; Mutations=0; AclWrites=0; HealthCalls=0; ActiveClient=$false; FailStart=$false; TamperStage=$false; FailHealth=$false; ServiceExists=$true}
$testAcl = Microsoft.PowerShell.Utility\New-Object Security.AccessControl.DirectorySecurity
$testAcl.SetOwner((Microsoft.PowerShell.Utility\New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
$fixtureIdentity = Microsoft.PowerShell.Utility\New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
$fixtureRule = Microsoft.PowerShell.Utility\New-Object Security.AccessControl.FileSystemAccessRule($fixtureIdentity, 'FullControl', 'Allow')
$testAcl.AddAccessRule($fixtureRule)
if (!$testAcl.PSObject.Properties['Sddl']) {
    $testAcl | Add-Member -NotePropertyName Sddl -NotePropertyValue ($testAcl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All))
}

function New-Object {
    param([string]$TypeName, [object[]]$ArgumentList)
    if ($TypeName -eq 'Security.Principal.WindowsPrincipal') {
        $principalDouble = [pscustomobject]@{}
        $principalDouble | Add-Member -MemberType ScriptMethod -Name IsInRole -Value { param($role) return $true }
        return $principalDouble
    }
    Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName -ArgumentList $ArgumentList
}
function Get-Acl { param([string]$LiteralPath) return $testAcl }
function Set-Acl {
    param([string]$LiteralPath, $AclObject)
    $pikoUpgradeTestState.AclWrites++
    if ([IO.Path]::GetDirectoryName($LiteralPath) -ieq $program -and [IO.Path]::GetFileName($LiteralPath) -in (@($files) + @('manifest.json')) -and
        ![object]::ReferenceEquals($AclObject, $testAcl)) { throw 'Installed file did not receive its preserved ACL.' }
}
function Get-CimInstance {
    param([string]$ClassName, [string]$Filter)
    if ($ClassName -eq 'Win32_Service') {
        return [pscustomobject]@{PathName=('"' + (Join-Path $program 'piko-service.exe') + '" --service --config "' + (Join-Path $program 'service.json') + '"'); StartName='NT SERVICE\piko'; StartMode='Auto'}
    }
    if ($ClassName -eq 'Win32_Process') {
        if ($pikoUpgradeTestState.ActiveClient) { return [pscustomobject]@{ExecutablePath=(Join-Path $program 'piko-desktop.exe')} }
        return
    }
    throw 'Unexpected OS query.'
}
function Get-Service {
    param([string]$Name)
    if (!$pikoUpgradeTestState.ServiceExists) { return }
    $controller = [pscustomobject]@{Status=$pikoUpgradeTestState.Status}
    $controller | Add-Member -MemberType ScriptMethod -Name Refresh -Value { $this.Status = $pikoUpgradeTestState.Status }
    $controller | Add-Member -MemberType ScriptMethod -Name Stop -Value {
        $pikoUpgradeTestState.Mutations++; $pikoUpgradeTestState.Status='Stopped'; $this.Status='Stopped'
    }
    $controller | Add-Member -MemberType ScriptMethod -Name Start -Value {
        $pikoUpgradeTestState.Mutations++
        if ($pikoUpgradeTestState.FailStart) { $pikoUpgradeTestState.FailStart=$false; throw 'Injected new-service start failure' }
        $pikoUpgradeTestState.Status='Running'; $this.Status='Running'
    }
    $controller | Add-Member -MemberType ScriptMethod -Name WaitForStatus -Value {
        param($state,$timeout)
        if ($pikoUpgradeTestState.Status -ne $state.ToString()) { throw 'Unexpected fixture transition.' }
    }
    return $controller
}
function Copy-Item {
    param([string]$LiteralPath, [string]$Destination, [switch]$Force)
    Microsoft.PowerShell.Management\Copy-Item -LiteralPath $LiteralPath -Destination $Destination -Force:$Force
    if ($pikoUpgradeTestState.TamperStage -and [IO.Path]::GetFileName($Destination) -eq 'piko-service.exe' -and
        [IO.Path]::GetFileName([IO.Path]::GetDirectoryName($Destination)) -eq 'next') {
        [IO.File]::AppendAllText($Destination, 'changed during package copy')
    }
}
function Write-FixtureManifest([string]$Directory) {
    $entries = @($files | ForEach-Object { @{name=$_; sha256=(Get-FileHash -LiteralPath (Join-Path $Directory $_) -Algorithm SHA256).Hash} })
    @{product='piko'; architecture='x64'; version='0.2.0'; files=$entries} | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath (Join-Path $Directory 'manifest.json')
}
function Reset-Fixture {
    foreach ($name in $files) {
        [IO.File]::WriteAllText((Join-Path $program $name), 'old fixture: ' + $name)
        [IO.File]::WriteAllText((Join-Path $package $name), 'new fixture: ' + $name)
    }
    Write-FixtureManifest $program
    Write-FixtureManifest $package
    @{data_dir=$data; viewer_sid='fixture-only'} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $program 'service.json')
    [IO.File]::WriteAllText((Join-Path $data 'evidence.txt'), 'retained evidence fixture')
    $pikoUpgradeTestState.Status='Running'
    $pikoUpgradeTestState.Mutations=0
    $pikoUpgradeTestState.AclWrites=0
    $pikoUpgradeTestState.HealthCalls=0
    $pikoUpgradeTestState.ActiveClient=$false
    $pikoUpgradeTestState.FailStart=$false
    $pikoUpgradeTestState.TamperStage=$false
    $pikoUpgradeTestState.FailHealth=$false
    $pikoUpgradeTestState.ServiceExists=$true
}
function Assert-PreservedData {
    if ([IO.File]::ReadAllText((Join-Path $data 'evidence.txt')) -cne 'retained evidence fixture' -or
        (Get-FileHash -LiteralPath (Join-Path $program 'service.json') -Algorithm SHA256).Hash -cne $configHash) {
        throw 'Configuration/evidence changed.'
    }
}
function Assert-Refused([string]$Name, [string]$ExpectedMessage) {
    $message = $null
    try { $null = & $scriptPath -PackagePath $package -Confirm:$false } catch { $message=$_.Exception.Message }
    if (!$message -or $message -notlike $ExpectedMessage) { throw "Unexpected result for '$Name': $message" }
    Assert-PreservedData
    Write-Output "PASS $Name"
}
try {
    New-Item -ItemType Directory -Path $program, $data, $package -Force | Out-Null
    $env:ProgramFiles=$programFiles
    $env:ProgramData=$programData
    Set-Item -LiteralPath ('Function:' + (Join-Path $program 'piko.exe')) -Value {
        param($action)
        if ($action -cne 'health') { throw 'Unexpected CLI action.' }
        $pikoUpgradeTestState.HealthCalls++
        $global:LASTEXITCODE=0
        $version='0.2.0'
        if ($pikoUpgradeTestState.FailHealth) { $version='0.1.0'; $pikoUpgradeTestState.FailHealth=$false }
        @{runtime_mode='windows_service'; version=$version; dropped_events=0; sensors=@(@{id='piko.storage';state='active'})} | ConvertTo-Json -Depth 5
    }
    Reset-Fixture
    $configHash=(Get-FileHash -LiteralPath (Join-Path $program 'service.json') -Algorithm SHA256).Hash
    $before = @(Get-ChildItem -LiteralPath $program -Force).Count
    $preflight = & $scriptPath -PackagePath $package -PreflightOnly | ConvertFrom-Json
    $null = & $scriptPath -PackagePath $package -WhatIf
    if ($preflight.result -cne 'preflight_passed' -or $pikoUpgradeTestState.Mutations -ne 0 -or
        $pikoUpgradeTestState.AclWrites -ne 0 -or $pikoUpgradeTestState.HealthCalls -ne 0 -or
        @(Get-ChildItem -LiteralPath $program -Force).Count -ne $before) { throw 'Read-only preflight/WhatIf mutated the installation.' }
    Assert-PreservedData
    Write-Output 'PASS preflight and WhatIf make no lifecycle/ACL/file changes'

    [IO.File]::AppendAllText((Join-Path $program 'piko-service.exe'), 'manifest mismatch')
    Assert-Refused 'installed manifest mismatch is never repaired' '*Manifest hash mismatch*'
    if ($pikoUpgradeTestState.Mutations -ne 0 -or $pikoUpgradeTestState.AclWrites -ne 0) { throw 'Mismatch refusal changed service/ACLs.' }
    Reset-Fixture
    $pikoUpgradeTestState.ActiveClient=$true
    Assert-Refused 'running dashboard is refused without killing it' '*Close the installed piko*'
    if ($pikoUpgradeTestState.Mutations -ne 0) { throw 'Active-client refusal changed service state.' }
    Reset-Fixture
    $pikoUpgradeTestState.TamperStage=$true
    Assert-Refused 'staged writable-package race fails before service stop' '*Manifest hash mismatch*'
    if ($pikoUpgradeTestState.Mutations -ne 0) { throw 'Staging failure stopped the service.' }

    Reset-Fixture
    $result = & $scriptPath -PackagePath $package -Confirm:$false | ConvertFrom-Json
    if ($result.result -cne 'updated' -or $pikoUpgradeTestState.Status -cne 'Running' -or $pikoUpgradeTestState.HealthCalls -ne 1) { throw 'Update did not restore/qualify the running service.' }
    foreach ($name in $files) {
        if ([IO.File]::ReadAllText((Join-Path $program $name)) -cne ('new fixture: ' + $name) -or
            [IO.File]::ReadAllText((Join-Path $result.backup_directory $name)) -cne ('old fixture: ' + $name)) { throw 'New/backup binary identity differs.' }
    }
    Assert-PreservedData
    Write-Output 'PASS same-version different-build refresh retains old binaries and data'

    Reset-Fixture
    $pikoUpgradeTestState.Status='Stopped'
    $result = & $scriptPath -PackagePath $package -Confirm:$false | ConvertFrom-Json
    if ($result.result -cne 'updated' -or $pikoUpgradeTestState.Status -cne 'Stopped' -or $pikoUpgradeTestState.HealthCalls -ne 1) { throw 'Initially stopped service state not restored.' }
    Assert-PreservedData
    Write-Output 'PASS initially stopped service is qualified then restored stopped'

    Reset-Fixture
    $oldManifest=[IO.File]::ReadAllText((Join-Path $program 'manifest.json'))
    $pikoUpgradeTestState.FailStart=$true
    Assert-Refused 'failed new-service start restores old files and prior state' '*previous_binaries_and_service_state_restored*'
    if ($pikoUpgradeTestState.Status -cne 'Running' -or [IO.File]::ReadAllText((Join-Path $program 'manifest.json')) -cne $oldManifest) { throw 'Rollback failed to restore manifest/service state.' }
    foreach ($name in $files) {
        if ([IO.File]::ReadAllText((Join-Path $program $name)) -cne ('old fixture: ' + $name)) { throw 'Rollback failed to restore an executable.' }
    }
    Reset-Fixture
    $pikoUpgradeTestState.FailHealth=$true
    Assert-Refused 'failed IPC version check restores and verifies previous runtime' '*previous_binaries_and_service_state_restored*'
    if ($pikoUpgradeTestState.HealthCalls -ne 2 -or $pikoUpgradeTestState.Status -cne 'Running') { throw 'Previous runtime was not checked after rollback.' }
    foreach ($name in $files) {
        if ([IO.File]::ReadAllText((Join-Path $program $name)) -cne ('old fixture: ' + $name)) { throw 'IPC failure rollback did not restore all binaries.' }
    }
    # Test the elevated interactive dispatch without UAC or real installation.
    $pikoUpgradeTestState.Route=''
    Set-Item -LiteralPath ('Function:' + $scriptPath) -Value {
        param([string]$PackagePath)
        if ($args.Count -ne 0) { throw 'Update dispatch unexpectedly changed install options.' }
        $pikoUpgradeTestState.Route='update'
    }
    $interactive = Join-Path (Split-Path -Parent $PSScriptRoot) 'Install-Piko-Interactive.ps1'
    & $interactive -Elevated -ViewerSid 'S-1-5-18'
    if ($pikoUpgradeTestState.Route -cne 'update') { throw 'Existing installation did not dispatch to updater.' }
    Write-Output 'PASS interactive existing-service route preserves installer options'
    $pikoUpgradeTestState.ServiceExists=$false
    $installer = Join-Path (Split-Path -Parent $PSScriptRoot) 'Install-Piko.ps1'
    Set-Item -LiteralPath ('Function:' + $installer) -Value {
        param([string]$ViewerSid, [switch]$EnableEtw)
        if ($ViewerSid -cne 'S-1-5-18' -or !$EnableEtw -or $args.Count -ne 0) { throw 'Fresh-install options changed.' }
        $pikoUpgradeTestState.Route='install'
    }
    & $interactive -Elevated -ViewerSid 'S-1-5-18'
    if ($pikoUpgradeTestState.Route -cne 'install') { throw 'Fresh installation did not retain its route.' }
    Write-Output 'PASS interactive fresh-install route retains viewer and ETW options'
    Write-Output "All ten upgrade fixture checks passed on PowerShell $($PSVersionTable.PSVersion); no real installation or SCM state was changed."
} finally {
    $env:ProgramFiles=$savedProgramFiles
    $env:ProgramData=$savedProgramData
    $resolved=[IO.Path]::GetFullPath($fixture)
    if ([IO.Path]::GetDirectoryName($resolved).TrimEnd([char]92) -ine $tempRoot.TrimEnd([char]92) -or [IO.Path]::GetFileName($resolved) -cne $fixtureName) { throw 'Unsafe fixture cleanup target.' }
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
}
