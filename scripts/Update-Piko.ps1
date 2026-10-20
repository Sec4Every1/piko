# Same-version binary refresh only. Does not migrate, delete or inspect evidence.
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$PackagePath = $PSScriptRoot,
    [switch]$PreflightOnly
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$files = @('piko-service.exe', 'piko.exe', 'piko-desktop.exe', 'piko-network-helper.exe')
$ownedNames = @($files) + @('manifest.json')
$program = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'piko'))
$data = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'piko'))
$configuration = Join-Path $program 'service.json'

function Assert-NoReparse([string]$Path) {
    $cursor = [IO.Path]::GetFullPath($Path)
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            if ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Reparse path refused: $cursor"
            }
        }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
}
function Assert-AdminProtected([string]$Path) {
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $trusted = @('S-1-5-18', 'S-1-5-32-544')
    if ($owner -notin $trusted) { throw "Administrator/SYSTEM ownership required: $Path" }
    $raw = New-Object Security.AccessControl.RawSecurityDescriptor($acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access))
    if ($null -eq $raw.DiscretionaryAcl) { throw "Unrestricted null DACL refused: $Path" }
    $writeRights = [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $writeRights) -and
            $rule.IdentityReference.Value -notin $trusted) { throw "Untrusted write access refused: $Path" }
    }
    return $acl
}
function Protect-Transaction([string]$Path) {
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $identity = New-Object Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
    $null = Assert-AdminProtected $Path
}
function Assert-Snapshot([string]$Directory, $Snapshot) {
    foreach ($name in $ownedNames) { Assert-NoReparse (Join-Path $Directory $name) }
    if ((Get-FileHash -LiteralPath (Join-Path $Directory 'manifest.json') -Algorithm SHA256).Hash -ine $Snapshot.ManifestHash) {
        throw 'Manifest changed after it was read; refresh refused.'
    }
    foreach ($entry in $Snapshot.Manifest.files) {
        if ((Get-FileHash -LiteralPath (Join-Path $Directory $entry.name) -Algorithm SHA256).Hash -ine $entry.sha256) {
            throw "Manifest hash mismatch: $($entry.name). No repair/bypass is supported."
        }
    }
}
function Read-Snapshot([string]$Directory) {
    Assert-NoReparse $Directory
    foreach ($name in $ownedNames) { Assert-NoReparse (Join-Path $Directory $name) }
    $bytes = [IO.File]::ReadAllBytes((Join-Path $Directory 'manifest.json'))
    $manifest = [Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF) | ConvertFrom-Json
    if ($manifest.product -cne 'piko' -or $manifest.architecture -cne 'x64' -or
        [string]::IsNullOrWhiteSpace($manifest.version) -or @($manifest.files).Count -ne $files.Count) { throw 'Invalid piko package manifest.' }
    foreach ($name in $files) {
        $entry = @($manifest.files | Where-Object { $_.name -ceq $name })
        if ($entry.Count -ne 1 -or $entry[0].sha256 -cnotmatch '^[A-Fa-f0-9]{64}$') { throw 'Invalid executable name/checksum in manifest.' }
    }
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { $hash = [BitConverter]::ToString($hasher.ComputeHash($bytes)).Replace('-', '') } finally { $hasher.Dispose() }
    $snapshot = [pscustomobject]@{Manifest=$manifest; Bytes=$bytes; ManifestHash=$hash}
    Assert-Snapshot $Directory $snapshot
    return $snapshot
}
function Assert-ServiceIdentity {
    $service = Get-CimInstance Win32_Service -Filter "Name='piko'"
    $expected = '"' + (Join-Path $program 'piko-service.exe') + '" --service --config "' + $configuration + '"'
    if (!$service -or $service.PathName -cne $expected -or $service.StartName -ine 'NT SERVICE\piko' -or $service.StartMode -eq 'Disabled') {
        throw 'Expected enabled piko virtual-account service configuration is required.'
    }
}
function Assert-NoRunningClients {
    $clients = @(Get-CimInstance Win32_Process -Filter "Name='piko.exe' OR Name='piko-desktop.exe' OR Name='piko-network-helper.exe'")
    foreach ($client in $clients) {
        if (!$client.ExecutablePath) { throw 'Cannot resolve a running piko client path; close piko applications before updating.' }
        $path = [IO.Path]::GetFullPath($client.ExecutablePath)
        if ([IO.Path]::GetDirectoryName($path) -ieq $program) { throw 'Close the installed piko dashboard, CLI and network helper before updating. No process was killed.' }
    }
}
function Set-ServiceState([ValidateSet('Running','Stopped')][string]$State) {
    $controller = Get-Service -Name piko
    $controller.Refresh()
    if ($controller.Status.ToString() -eq $State) { return }
    if ($State -eq 'Stopped') {
        if ($controller.Status -eq 'Running') { $controller.Stop() }
        elseif ($controller.Status -ne 'StopPending') { throw 'Cannot safely stop piko in its current transitional state.' }
    } else {
        if ($controller.Status -eq 'Stopped') { $controller.Start() }
        elseif ($controller.Status -ne 'StartPending') { throw 'Cannot safely start piko in its current transitional state.' }
    }
    $controller.WaitForStatus($State, [TimeSpan]::FromSeconds(35))
}
function Assert-PreservedConfiguration {
    Assert-NoReparse $configuration
    if ((Get-FileHash -LiteralPath $configuration -Algorithm SHA256).Hash -ine $configurationHash -or
        (Get-Acl -LiteralPath $configuration).Sddl -cne $configurationAcl -or
        (Get-Acl -LiteralPath $data).Sddl -cne $dataAcl -or
        (Get-Acl -LiteralPath $program).Sddl -cne $programAcl.Sddl) { throw 'Configuration or directory ACL changed during the refresh.' }
}
function Copy-OwnedSnapshot([string]$Source, [string]$Destination, $Snapshot, [bool]$RestoreAcls) {
    Assert-Snapshot $Source $Snapshot
    foreach ($name in $ownedNames) {
        $target = Join-Path $Destination $name
        Assert-NoReparse $target
        Copy-Item -LiteralPath (Join-Path $Source $name) -Destination $target -Force
        if ($RestoreAcls) {
            Set-Acl -LiteralPath $target -AclObject $installedAcls[$name]
            if ((Get-Acl -LiteralPath $target).Sddl -cne $installedAcls[$name].Sddl) { throw 'Installed executable ACL was not preserved.' }
        }
    }
    Assert-Snapshot $Destination $Snapshot
}
function Wait-ServiceHealth([string]$Version) {
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        $health = $null
        try {
            # Piko health has a three-second IPC timeout; readiness retries are bounded.
            $health = & (Join-Path $program 'piko.exe') health | ConvertFrom-Json
            if ($LASTEXITCODE -ne 0) { $health = $null }
        } catch { $health = $null }
        if ($health) {
            if ($health.runtime_mode -cne 'windows_service' -or $health.version -cne $Version) { throw 'Service failed authenticated IPC/version validation.' }
            if ($health.dropped_events -ne 0) { throw 'Service has lost events; refresh qualification failed.' }
            $storage = @($health.sensors | Where-Object { $_.id -ceq 'piko.storage' })
            if ($storage.Count -eq 1 -and $storage[0].state -ceq 'active') { return }
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Service did not establish authenticated IPC and active storage within the readiness deadline.'
}

$package = (Resolve-Path -LiteralPath $PackagePath).Path
$source = Read-Snapshot $package
$installed = Read-Snapshot $program
if ($source.Manifest.version -cne $installed.Manifest.version) { throw 'Only same-version build refreshes are supported; cross-version data migration is not qualified.' }
Assert-NoReparse $configuration
Assert-NoReparse $data
if (!(Test-Path -LiteralPath $data -PathType Container)) { throw 'Installed evidence directory is missing; refresh refused.' }
$config = Get-Content -LiteralPath $configuration -Raw | ConvertFrom-Json
if ([IO.Path]::GetFullPath($config.data_dir) -ine $data) { throw 'Custom evidence directories are not qualified for refresh.' }
$programAcl = Assert-AdminProtected $program
$installedAcls = @{}
foreach ($name in $ownedNames) { $installedAcls[$name] = Assert-AdminProtected (Join-Path $program $name) }
$configurationHash = (Get-FileHash -LiteralPath $configuration -Algorithm SHA256).Hash
$configurationAcl = (Get-Acl -LiteralPath $configuration).Sddl
$dataAcl = (Get-Acl -LiteralPath $data).Sddl
Assert-ServiceIdentity
Assert-NoRunningClients
$previousState = (Get-Service -Name piko).Status.ToString()
if ($previousState -notin @('Running','Stopped')) { throw 'Wait for a stable piko service state before refreshing.' }
if ($PreflightOnly) {
    [ordered]@{result='preflight_passed'; scope='same_version_binary_refresh'; version=$source.Manifest.version; previous_service_state=$previousState; service_changed=$false; signed_release_verified=$false} | ConvertTo-Json
    return
}
if (!$PSCmdlet.ShouldProcess($program, 'Refresh piko binaries with protected backup and rollback; preserve evidence, configuration and OS policy')) { return }
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Updating requires an elevated PowerShell.' }

$lock = $null
$transaction = Join-Path $program ('.upgrade-' + [guid]::NewGuid().ToString('N'))
$backup = Join-Path $transaction 'previous'
$staged = Join-Path $transaction 'next'
$serviceTouched = $false
$replacementStarted = $false
try {
    # CreateNew + exclusive sharing serializes refreshes. The OS removes only this
    # lock file on close/crash; interrupted transaction directories are retained.
    $lock = New-Object IO.FileStream((Join-Path $program '.upgrade.lock'), [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None, 1, [IO.FileOptions]::DeleteOnClose)
    Assert-Snapshot $program $installed
    Assert-ServiceIdentity
    Assert-NoRunningClients
    if ((Get-Service -Name piko).Status.ToString() -cne $previousState) { throw 'Service state changed since preflight.' }
    Assert-PreservedConfiguration
    New-Item -ItemType Directory -Path $transaction | Out-Null
    Protect-Transaction $transaction
    New-Item -ItemType Directory -Path $backup, $staged | Out-Null
    foreach ($name in $files) { Copy-Item -LiteralPath (Join-Path $package $name) -Destination (Join-Path $staged $name) }
    # Use the already-read manifest bytes, never a second writable-package read.
    [IO.File]::WriteAllBytes((Join-Path $staged 'manifest.json'), $source.Bytes)
    Assert-Snapshot $staged $source
    Copy-OwnedSnapshot $program $backup $installed $false
    [IO.File]::WriteAllText((Join-Path $transaction 'recovery.json'), (@{previous_service_state=$previousState; version=$installed.Manifest.version; note='Previous contains verified pre-refresh executables and manifest. Evidence/configuration were not backed up or migrated.'} | ConvertTo-Json))
    Assert-NoRunningClients
    Assert-Snapshot $program $installed
    Assert-PreservedConfiguration
    $serviceTouched = $true
    Set-ServiceState 'Stopped'
    Assert-NoRunningClients
    $replacementStarted = $true
    Copy-OwnedSnapshot $staged $program $source $true
    Assert-PreservedConfiguration
    Set-ServiceState 'Running'
    Wait-ServiceHealth $source.Manifest.version
    Assert-Snapshot $program $source
    Assert-PreservedConfiguration
    Set-ServiceState $previousState
    [ordered]@{result='updated'; scope='same_version_binary_refresh'; version=$source.Manifest.version; restored_service_state=$previousState; backup_directory=$backup; signed_release_verified=$false; evidence_migrated=$false} | ConvertTo-Json
} catch {
    $failure = $_.Exception.Message
    $rollback = 'not_needed_service_unchanged'
    if ($serviceTouched) {
        try {
            Set-ServiceState 'Stopped'
            if ($replacementStarted) { Copy-OwnedSnapshot $backup $program $installed $true }
            Assert-PreservedConfiguration
            Set-ServiceState $previousState
            if ($previousState -ceq 'Running') { Wait-ServiceHealth $installed.Manifest.version }
            $rollback = 'previous_binaries_and_service_state_restored'
        } catch { $rollback = 'FAILED: ' + $_.Exception.Message }
    }
    $retained = if (Test-Path -LiteralPath $transaction) { $transaction } else { 'not created' }
    throw "Refresh failed: $failure. Rollback: $rollback. Protected transaction: $retained; no evidence was deleted or migrated."
} finally {
    if ($lock) { $lock.Dispose() }
}
