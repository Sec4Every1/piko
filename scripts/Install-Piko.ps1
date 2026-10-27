[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^S-1-[0-9-]+$')][string]$ViewerSid,
    [string]$PackagePath = $PSScriptRoot,
    [string[]]$ResponseRoots = @(),
    [switch]$EnableEtw,
    [switch]$EnableEtwProviderAccess,
    [switch]$ResumeIncomplete,
    [ValidateRange(8,4096)][int]$MaxDiskMiB = 2048,
    [ValidateRange(0,120)][int]$RetentionMonths = 12
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$package = (Resolve-Path -LiteralPath $PackagePath).Path
$program = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'piko'))
$data = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'piko'))
$files = @('piko-service.exe', 'piko.exe', 'piko-desktop.exe', 'piko-network-helper.exe')
$manifest = Get-Content -LiteralPath (Join-Path $package 'manifest.json') -Raw | ConvertFrom-Json
if ($manifest.product -ne 'piko' -or $manifest.files.Count -ne $files.Count) { throw 'Invalid piko package manifest.' }
foreach ($name in $files) {
    $entry = @($manifest.files | Where-Object { $_.name -ceq $name })
    if ($entry.Count -ne 1 -or (Get-FileHash -LiteralPath (Join-Path $package $name) -Algorithm SHA256).Hash -cne $entry[0].sha256) { throw "Package hash mismatch: $name" }
}
# Resolve the requested viewer before making changes; never interpolate unvalidated SDDL.
$viewer = New-Object Security.Principal.SecurityIdentifier($ViewerSid)
$null = $viewer.Translate([Security.Principal.NTAccount])

function Assert-NoReparse([string]$Path) {
    $cursor = [IO.Path]::GetFullPath($Path)
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            if ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse path refused: $cursor" }
        }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
}
Assert-NoReparse $program
Assert-NoReparse $data
if ($ResponseRoots.Count -gt 16) { throw 'At most 16 response roots are permitted.' }
foreach ($root in $ResponseRoots) {
    if ($root -notmatch '^[A-Za-z]:\\' -or !(Test-Path -LiteralPath $root -PathType Container)) { throw "Response root must be an existing local absolute directory: $root" }
    Assert-NoReparse $root
}
if (Get-Service -Name piko -ErrorAction SilentlyContinue) { throw 'piko is already installed. This package does not perform an in-place upgrade.' }
$resumeProgram = Test-Path -LiteralPath $program
if ($resumeProgram) {
    if (!$ResumeIncomplete) { throw "Installation directory already exists: $program" }
    $existing = @(Get-ChildItem -LiteralPath $program -Force)
    $expectedNames = @($files) + @('manifest.json')
    if ($existing.Count -ne $expectedNames.Count -or @($existing | Where-Object { $_.PSIsContainer -or $_.Name -cnotin $expectedNames -or ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) }).Count) { throw 'Partial installation contains unexpected entries; preserving it.' }
    foreach ($name in $expectedNames) { if ((Get-FileHash -LiteralPath (Join-Path $program $name) -Algorithm SHA256).Hash -cne (Get-FileHash -LiteralPath (Join-Path $package $name) -Algorithm SHA256).Hash) { throw "Partial installation mismatch: $name" } }
}
if (Test-Path -LiteralPath $data) { throw "Data directory already exists: $data. Preserve it; migration/import requires explicit review." }
$membershipDescription = 'Event Log Readers'
if ($EnableEtw -or $EnableEtwProviderAccess) { $membershipDescription += ' and Performance Log Users for cross-process ETW' }
if ($EnableEtwProviderAccess) { $membershipDescription += '; grant piko provider-enable access to the process ETW provider, with reversible backup' }
if (!$PSCmdlet.ShouldProcess("$program; $data; Windows service piko", "Install local monitoring service, enroll viewer SID and grant ONLY NT SERVICE\piko $membershipDescription membership")) { return }
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Installation requires an elevated PowerShell. No automatic elevation is performed.' }

function Invoke-Sc([string[]]$Arguments) {
    # Explicit Windows argv quoting for Windows PowerShell 5.1.
    $encoded = @($Arguments | ForEach-Object { '"' + [regex]::Replace([regex]::Replace($_, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1') + '"' }) -join ' '
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = "$env:SystemRoot\System32\sc.exe"
    $info.Arguments = $encoded
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $child = New-Object Diagnostics.Process
    $child.StartInfo = $info
    try {
        [void]$child.Start()
        $output = $child.StandardOutput.ReadToEnd()
        $errors = $child.StandardError.ReadToEnd()
        $child.WaitForExit()
        if ($child.ExitCode -ne 0) { throw "SCM operation failed: $output $errors" }
    } finally { $child.Dispose() }
}

function Protect-Directory([string]$Path, [string]$ServiceSid, [bool]$Writable, [bool]$PublicRead) {
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    $entries = @(@('S-1-5-18','FullControl'), @('S-1-5-32-544','FullControl'))
    if ($ServiceSid) { $entries += ,@($ServiceSid, $(if ($Writable) {'Modify'} else {'ReadAndExecute'})) }
    if ($PublicRead) { $entries += ,@('S-1-5-32-545','ReadAndExecute') }
    foreach ($entry in $entries) {
        $sid = New-Object Security.Principal.SecurityIdentifier($entry[0])
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, $entry[1], 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
if (!$resumeProgram) { New-Item -ItemType Directory -Path $program | Out-Null }
Protect-Directory $program '' $false $true
$created = $false
try {
    foreach ($name in $files) { Copy-Item -LiteralPath (Join-Path $package $name) -Destination (Join-Path $program $name) }
    Copy-Item -LiteralPath (Join-Path $package 'manifest.json') -Destination (Join-Path $program 'manifest.json')
    $binary = '"' + (Join-Path $program 'piko-service.exe') + '" --service --config "' + (Join-Path $program 'service.json') + '"'
    Invoke-Sc @('create', 'piko', 'binPath=', $binary, 'start=', 'demand', 'obj=', 'NT SERVICE\piko', 'DisplayName=', 'piko local security monitor')
    $created = $true
    $serviceSid = (New-Object Security.Principal.NTAccount('NT SERVICE\piko')).Translate([Security.Principal.SecurityIdentifier]).Value
    Invoke-Sc @('sidtype', 'piko', 'unrestricted')
    Protect-Directory $program $serviceSid $false $true
    New-Item -ItemType Directory -Path $data | Out-Null
    Protect-Directory $data $serviceSid $true $false
    $configuration = @{data_dir=$data; viewer_sid=$ViewerSid; response_roots=@($ResponseRoots); heartbeat_seconds=5; flush_seconds=5; max_disk_mib=$MaxDiskMiB; queue_capacity=256;retention_months=$(if($RetentionMonths -eq 0){$null}else{$RetentionMonths})} | ConvertTo-Json
    [IO.File]::WriteAllText((Join-Path $program 'service.json'), $configuration, (New-Object Text.UTF8Encoding($false)))
    # Built-in group SID avoids dependence on the Windows display language.
    $readerGroup = (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-573')).Translate([Security.Principal.NTAccount]).Value.Split([char]92)[-1]
    Add-LocalGroupMember -Group $readerGroup -Member $serviceSid
    # Opt-in membership for the virtual service account only; no viewer/admin group change.
    if ($EnableEtw -or $EnableEtwProviderAccess) {
        $traceGroup = (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-559')).Translate([Security.Principal.NTAccount]).Value.Split([char]92)[-1]
        Add-LocalGroupMember -Group $traceGroup -Member $serviceSid
    }
    Copy-Item -LiteralPath (Join-Path $package 'Set-PikoEtwPermission.ps1') -Destination (Join-Path $program 'Set-PikoEtwPermission.ps1')
    # Activation procedure is embedded in the manifest-owned network helper.
    if ($EnableEtwProviderAccess) { & (Join-Path $program 'Set-PikoEtwPermission.ps1') }
    Invoke-Sc @('description', 'piko', 'Local Windows telemetry and evidence. No antivirus or preventive enforcement is enabled by this version.')
    & (Join-Path $program 'piko-service.exe') --configure-recovery
    if ($LASTEXITCODE -ne 0) { throw 'Cannot configure bounded SCM recovery policy.' }
    Start-Service -Name piko
    (Get-Service -Name piko).WaitForStatus('Running', [TimeSpan]::FromSeconds(35))
    Invoke-Sc @('config', 'piko', 'start=', 'delayed-auto')
    [ordered]@{result='installed'; program_directory=$program; data_directory=$data; viewer_sid=$ViewerSid; service_account='NT SERVICE\piko'; response_roots=@($ResponseRoots); etw_membership_requested=[bool]($EnableEtw -or $EnableEtwProviderAccess); etw_provider_permission_requested=[bool]$EnableEtwProviderAccess; signed_release=$false} | ConvertTo-Json
} catch {
    if ($created) { Stop-Service -Name piko -ErrorAction SilentlyContinue }
    throw "Installation incomplete: $($_.Exception.Message). Files and data are preserved. Inspect the service before retrying; no automatic deletion occurred."
}
