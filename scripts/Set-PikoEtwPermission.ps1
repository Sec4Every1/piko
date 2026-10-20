[CmdletBinding(SupportsShouldProcess)]
param([switch]$Restore)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$program = Join-Path $env:ProgramFiles 'piko'
$provider = '22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716'
$registryPath = 'SYSTEM\CurrentControlSet\Control\WMI\Security'
$statePath = Join-Path $program 'etw-provider-permission.json'
$service = Get-CimInstance Win32_Service -Filter "Name='piko'"
$expected = '"' + (Join-Path $program 'piko-service.exe') + '" --service --config "' + (Join-Path $program 'service.json') + '"'
if (!$service -or $service.StartName -ine 'NT SERVICE\piko' -or $service.PathName -cne $expected) { throw 'Unexpected piko service identity.' }
$sid = (New-Object Security.Principal.NTAccount('NT SERVICE\piko')).Translate([Security.Principal.SecurityIdentifier])
if (!$PSCmdlet.ShouldProcess("ETW provider $provider", 'Grant/restore only piko provider-enable permission, preserve original descriptor')) { return }
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Requires elevated PowerShell.' }
$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($registryPath, $true)
if (!$key) { throw 'ETW security registry key unavailable.' }
try {
    $current = $key.GetValue($provider, $null)
    $currentText = if ($null -eq $current) { $null } else { [Convert]::ToBase64String([byte[]]$current) }
    if ($Restore) {
        $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        if ($state.provider -cne $provider -or $state.sid -cne $sid.Value -or $state.status -cne 'applied' -or $currentText -cne $state.after) { throw 'ETW permissions changed externally or backup incomplete; refusing overwrite.' }
        if ($state.before_exists) { $key.SetValue($provider, [Convert]::FromBase64String($state.before), [Microsoft.Win32.RegistryValueKind]::Binary) }
        else { $key.DeleteValue($provider, $false) }
        $state.status = 'restored'
        $state | ConvertTo-Json | Set-Content -LiteralPath $statePath
        Write-Output 'Original ETW provider permissions restored.'
        return
    }
    if (Test-Path -LiteralPath $statePath) {
        $previous = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        if ($previous.status -ceq 'applied' -and $previous.provider -ceq $provider -and $previous.sid -ceq $sid.Value -and $previous.after -ceq $currentText) { Write-Output 'Permission already applied.'; return }
        throw 'Existing permission journal requires inspection; refusing overwrite.'
    }
    $definition = @'
using System;
using System.Runtime.InteropServices;
public static class PikoEtwPermission {
 [DllImport("advapi32.dll")] public static extern uint EventAccessControl(ref Guid guid,uint operation,byte[] sid,uint rights,[MarshalAs(UnmanagedType.U1)] bool allow);
}
'@
    Add-Type -TypeDefinition $definition
    $state = [ordered]@{provider=$provider; sid=$sid.Value; status='prepared'; before_exists=($null -ne $current); before=$currentText; after=$null; rights=128}
    $state | ConvertTo-Json | Set-Content -LiteralPath $statePath
    $sidBytes = New-Object byte[] $sid.BinaryLength
    $sid.GetBinaryForm($sidBytes,0)
    $guid = [Guid]$provider
    # EventSecurityAddDACL, TRACELOG_GUID_ENABLE: retain all existing ACEs.
    $result = [PikoEtwPermission]::EventAccessControl([ref]$guid,2,$sidBytes,128,$true)
    if ($result -ne 0) { throw "EventAccessControl failed: $result" }
    $after = $key.GetValue($provider, $null)
    if ($null -eq $after) { throw 'Native permission update has no persisted descriptor.' }
    $state.after = [Convert]::ToBase64String([byte[]]$after)
    $state.status = 'applied'
    $state | ConvertTo-Json | Set-Content -LiteralPath $statePath
    Write-Output 'Provider-enable permission granted only to NT SERVICE\piko; original descriptor preserved.'
} finally { $key.Dispose() }
