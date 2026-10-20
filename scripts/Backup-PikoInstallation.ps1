# Preserve an inconsistent installation for recovery; never execute its binaries.
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Destination,
    [string]$InstallationPath = (Join-Path $env:ProgramFiles 'piko')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$names = @('piko-service.exe', 'piko.exe', 'piko-desktop.exe', 'piko-network-helper.exe', 'manifest.json', 'service.json')
function Assert-OrdinaryPath([string]$Path) {
    for ($cursor = [IO.Path]::GetFullPath($Path); $cursor; $cursor = [IO.Path]::GetDirectoryName($cursor)) {
        if ((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Reparse paths are refused for recovery backups.'
        }
    }
}
if (![IO.Path]::IsPathRooted($Destination)) { throw 'Use an absolute recovery destination.' }
$destinationPath = [IO.Path]::GetFullPath($Destination)
$sourcePath = (Resolve-Path -LiteralPath $InstallationPath).Path
Assert-OrdinaryPath $sourcePath
Assert-OrdinaryPath $destinationPath
if (Test-Path -LiteralPath $destinationPath) { throw 'Recovery destination must not already exist.' }
$parent = [IO.Path]::GetDirectoryName($destinationPath)
if (!(Test-Path -LiteralPath $parent -PathType Container)) { throw 'Recovery destination parent must exist.' }
$trustedInstaller = (New-Object Security.Principal.NTAccount('NT SERVICE', 'TrustedInstaller')).Translate([Security.Principal.SecurityIdentifier]).Value
$callerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$trusted = @('S-1-5-18', 'S-1-5-32-544', $trustedInstaller, $callerSid)
for ($cursor = $parent; $cursor; $cursor = [IO.Path]::GetDirectoryName($cursor)) {
    $parentAcl = Get-Acl -LiteralPath $cursor
    if ($parentAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) { throw 'Recovery destination requires protected caller/admin-owned ancestors.' }
    $rights = [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    if ($cursor -ieq $parent) { $rights = $rights -bor [Security.AccessControl.FileSystemRights]::Write }
    $raw = New-Object Security.AccessControl.RawSecurityDescriptor($parentAcl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access))
    if ($null -eq $raw.DiscretionaryAcl) { throw 'Unrestricted destination ACL refused.' }
    foreach ($rule in $parentAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and !($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
            ($rule.FileSystemRights -band $rights) -and $rule.IdentityReference.Value -notin $trusted) { throw 'Recovery destination can be changed by an untrusted account.' }
    }
}
$handles = @{}
try {
    foreach ($name in $names) {
        $path = Join-Path $sourcePath $name
        Assert-OrdinaryPath $path
        # Keep every original stable until all copies and checks are complete.
        $handles[$name] = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    }
    if (!$PSCmdlet.ShouldProcess($destinationPath, 'Preserve original Piko binaries, manifest, configuration and ACL metadata; no event archive copy')) { return }
    # An explicit ACL is applied at creation, before copying private configuration.
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier($callerSid)))
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544', $callerSid) | Select-Object -Unique) {
        $identity = New-Object Security.Principal.SecurityIdentifier($sid)
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    # PowerShell 5.1/.NET Framework and PowerShell 7 expose different ACL creation APIs.
    $directory = New-Object IO.DirectoryInfo($destinationPath)
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        [IO.FileSystemAclExtensions]::Create($directory, $acl)
    } else { $directory.Create($acl) }
    Assert-OrdinaryPath $destinationPath
    $records = @()
    foreach ($name in $names) {
        $source = $handles[$name]
        $hasher = [Security.Cryptography.SHA256]::Create()
        try { $hash = [BitConverter]::ToString($hasher.ComputeHash($source)).Replace('-', '') } finally { $hasher.Dispose() }
        $source.Position = 0
        $target = Join-Path $destinationPath $name
        $output = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $source.CopyTo($output); $output.Flush($true) } finally { $output.Dispose() }
        if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ine $hash) { throw 'Recovery copy checksum mismatch; incomplete backup retained.' }
        $records += [ordered]@{name=$name; sha256=$hash; bytes=$source.Length; original_acl=(Get-Acl -LiteralPath (Join-Path $sourcePath $name)).Sddl}
    }
    $manifest = Get-Content -LiteralPath (Join-Path $destinationPath 'manifest.json') -Raw | ConvertFrom-Json
    $consistent = $manifest.product -ceq 'piko' -and @($manifest.files).Count -eq 4
    foreach ($name in $names[0..3]) {
        $declared = @($manifest.files | Where-Object { $_.name -ceq $name })
        $observed = @($records | Where-Object { $_.name -ceq $name })
        if ($declared.Count -ne 1 -or $declared[0].sha256 -ine $observed[0].sha256) { $consistent = $false }
    }
    $report = [ordered]@{format='piko-recovery-copy-v1'; completed=$true; installed_manifest_consistent=$consistent;
        source_trust_verified=$false; event_archive_included=$false; files=$records}
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $destinationPath 'recovery-copy.json') -Encoding utf8
    [ordered]@{result='originals_preserved'; directory=$destinationPath; files=$records.Count; installed_manifest_consistent=$consistent; service_changed=$false} | ConvertTo-Json
} finally {
    foreach ($handle in $handles.Values) { $handle.Dispose() }
}
