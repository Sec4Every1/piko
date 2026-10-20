[CmdletBinding(SupportsShouldProcess)]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$program = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'piko'))
$data = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'piko'))
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this script from an elevated PowerShell.' }
$manifest = Get-Content -LiteralPath (Join-Path $program 'manifest.json') -Raw | ConvertFrom-Json
if ($manifest.product -ne 'piko') { throw 'Refusing removal: missing piko package identity.' }
$service = Get-CimInstance Win32_Service -Filter "Name='piko'"
if ($service -and !$service.PathName.StartsWith(('"' + (Join-Path $program 'piko-service.exe') + '" --service --config "' + (Join-Path $program 'service.json') + '"'), [StringComparison]::OrdinalIgnoreCase)) { throw 'Service binary does not match this installation.' }
# Validate every existing ancestor and every child before recursive removal.
$cursor = $program
while ($cursor) {
    if ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse path refused: $cursor" }
    $cursor = [IO.Path]::GetDirectoryName($cursor)
}
if (@(Get-ChildItem -LiteralPath $program -Recurse -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count -gt 0) { throw 'Installation contains a reparse point; removal refused.' }
if (!$PSCmdlet.ShouldProcess($program, 'Stop/remove piko service and binaries; preserve ALL recorded data')) { return }
if ($service) {
    $serviceSid = (New-Object Security.Principal.NTAccount('NT SERVICE\piko')).Translate([Security.Principal.SecurityIdentifier]).Value
    Stop-Service -Name piko -ErrorAction Stop
    (Get-Service -Name piko).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15))
    if (Test-Path -LiteralPath (Join-Path $program 'etw-provider-permission.json')) {
        & (Join-Path $program 'Set-PikoEtwPermission.ps1') -Restore
    }
    foreach ($groupSid in @('S-1-5-32-573','S-1-5-32-559')) {
        $ownedGroup = (New-Object Security.Principal.SecurityIdentifier($groupSid)).Translate([Security.Principal.NTAccount]).Value.Split([char]92)[-1]
        $member = Get-LocalGroupMember -Group $ownedGroup | Where-Object { $_.SID.Value -eq $serviceSid }
        if ($member) { Remove-LocalGroupMember -Group $ownedGroup -Member $member }
    }
    & "$env:SystemRoot\System32\sc.exe" delete piko
    if ($LASTEXITCODE -ne 0) { throw 'SCM did not remove piko.' }
}
Remove-Item -LiteralPath $program -Recurse -Force
Write-Output "piko removed. Evidence is preserved in $data. No evidence was deleted."
