# Same-version refresh; explicit recovery preserves and verifies existing evidence.
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$PackagePath = $PSScriptRoot,
    [switch]$PreflightOnly,
    [switch]$RecoverInconsistentInstallation
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
    foreach ($entry in $Snapshot.ObservedFiles) {
        if ((Get-FileHash -LiteralPath (Join-Path $Directory $entry.name) -Algorithm SHA256).Hash -ine $entry.sha256) {
            throw "Manifest hash mismatch: $($entry.name). No repair/bypass is supported."
        }
    }
}
function Read-Snapshot([string]$Directory, [bool]$PreserveInconsistentOriginals = $false) {
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
    $observed = @($manifest.files | ForEach-Object {
        [pscustomobject]@{name=$_.name; sha256=(Get-FileHash -LiteralPath (Join-Path $Directory $_.name) -Algorithm SHA256).Hash}
    })
    $consistent = $true
    foreach ($entry in $manifest.files) {
        if (($observed | Where-Object name -ceq $entry.name).sha256 -ine $entry.sha256) { $consistent = $false }
    }
    if (!$consistent -and !$PreserveInconsistentOriginals) { throw 'Manifest hash mismatch. Normal refresh refuses inconsistent installations.' }
    # Actual hashes preserve originals; never rewrite their declared manifest.
    $snapshot = [pscustomobject]@{Manifest=$manifest; Bytes=$bytes; ManifestHash=$hash; ObservedFiles=$observed; Consistent=$consistent}
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
function Test-KnownCapacityFailure($Health) {
    $storage = @($Health.sensors | Where-Object { $_.id -ceq 'piko.storage' })
    return $storage.Count -eq 1 -and $storage[0].state -ceq 'degraded' -and $storage[0].detail -cin @('SQLite error: database or disk is full','storage budget exhausted; batch was not accepted')
}
function Wait-ServiceHealth([string]$Version) {
    # Recovery may verify an archive up to 2 GiB again during runtime startup.
    $deadline = [DateTime]::UtcNow.AddSeconds($(if ($RecoverInconsistentInstallation) { 120 } else { 15 }))
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
            if ($storage.Count -eq 1 -and $storage[0].state -ceq 'active') { return 'active' }
            if ($RecoverInconsistentInstallation -and (Test-KnownCapacityFailure $health)) {
                if ($knownCapacityFailureBefore) { return 'capacity_exhausted' }
                throw 'New storage capacity failure was not observed before recovery.'
            }
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Service did not establish authenticated IPC and active storage within the readiness deadline.'
}

function Backup-RecoveryEvidence {
    $destination = Join-Path $transaction 'evidence-before'
    if (!(Test-Path -LiteralPath (Join-Path $data 'events.db') -PathType Leaf)) { throw 'Recovery requires an existing event archive.' }
    $paths = @('events.db','events.db-wal','events.db-shm') | ForEach-Object { Join-Path $data $_ } | Where-Object { Test-Path -LiteralPath $_ }
    $bytes = ($paths | ForEach-Object { (Get-Item -LiteralPath $_).Length } | Measure-Object -Sum).Sum
    $drive = (Split-Path -Qualifier $data).TrimEnd(':')
    if ((Get-PSDrive -Name $drive).Free -lt ($bytes + 64MB)) { throw 'Insufficient free space for protected recovery archive backup.' }
    New-Item -ItemType Directory -Path $destination | Out-Null
    $records = @()
    foreach ($path in $paths) {
        Assert-NoReparse $path
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        $target = Join-Path $destination ([IO.Path]::GetFileName($path))
        Copy-Item -LiteralPath $path -Destination $target
        if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ine $hash -or
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ine $hash) { throw 'Recovery archive copy could not be verified.' }
        $records += @{name=[IO.Path]::GetFileName($path);sha256=$hash;bytes=(Get-Item -LiteralPath $target).Length}
    }
    $records | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $destination 'backup-files.json') -Encoding utf8
    # Execute only the strictly verified staged replacement, never the unknown original.
    if ((Get-Service -Name piko).Status.ToString() -cne 'Stopped') { throw 'Service must remain fully stopped for offline verification.' }
    $report = & (Join-Path $staged 'piko-service.exe') --verify-evidence --config $configuration | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or !$report -or $report.result -cne 'PASS' -or $report.read_only -ne $true) { throw 'Replacement cannot verify the existing archive read-only; recovery refused.' }
    $report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $destination 'compatibility-check.json') -Encoding utf8
}

$package = (Resolve-Path -LiteralPath $PackagePath).Path
$source = Read-Snapshot $package
$installed = Read-Snapshot $program ([bool]$RecoverInconsistentInstallation)
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
    [ordered]@{result='preflight_passed'; scope='same_version_binary_refresh'; version=$source.Manifest.version; previous_service_state=$previousState; service_changed=$false; signed_release_verified=$false; recovery_requested=[bool]$RecoverInconsistentInstallation; original_manifest_consistent=$installed.Consistent} | ConvertTo-Json
    return
}
$operation = if ($RecoverInconsistentInstallation) { 'Recover using a strictly validated package; preserve inconsistent original binaries/manifest and observed hashes in a protected backup' } else { 'Refresh piko binaries with protected backup and rollback; preserve evidence, configuration and OS policy' }
if (!$PSCmdlet.ShouldProcess($program, $operation)) { return }
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Updating requires an elevated PowerShell.' }

$lock = $null
$transaction = Join-Path $program ('.upgrade-' + [guid]::NewGuid().ToString('N'))
$backup = Join-Path $transaction 'previous'
$staged = Join-Path $transaction 'next'
$serviceTouched = $false
$replacementStarted = $false
$knownCapacityFailureBefore = $false
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
    if ($RecoverInconsistentInstallation -and $previousState -ceq 'Running') {
        try {
            $before = & (Join-Path $staged 'piko.exe') health | ConvertFrom-Json
            if ($LASTEXITCODE -eq 0 -and $before.runtime_mode -ceq 'windows_service' -and $before.dropped_events -eq 0) {
                $knownCapacityFailureBefore = Test-KnownCapacityFailure $before
                $before | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $transaction 'before-health.json') -Encoding utf8
            }
        } catch { $knownCapacityFailureBefore = $false }
    }
    Copy-Item -LiteralPath $configuration -Destination (Join-Path $transaction 'service-original.json')
    if ((Get-FileHash -LiteralPath (Join-Path $transaction 'service-original.json') -Algorithm SHA256).Hash -ine $configurationHash) { throw 'Configuration changed while preparing recovery material.' }
    $originalAcls = @{}
    foreach ($name in $ownedNames) { $originalAcls[$name] = $installedAcls[$name].Sddl }
    [IO.File]::WriteAllText((Join-Path $transaction 'recovery.json'), (@{previous_service_state=$previousState; version=$installed.Manifest.version;
        original_manifest_consistent=$installed.Consistent; original_observed_files=$installed.ObservedFiles; original_manifest_sha256=$installed.ManifestHash;
        original_file_acls=$originalAcls; configuration_sha256=$configurationHash; configuration_acl=$configurationAcl;
        original_source_trust_verified=$false; recovery_requested=[bool]$RecoverInconsistentInstallation;
        known_capacity_failure_before=$knownCapacityFailureBefore;
        note='Previous preserves exact original bytes, including inconsistent manifest. Hashes are not publisher authenticity. Configuration is diagnostic only. Recovery copies evidence to evidence-before; backup-files.json records completed copy verification. Normal refresh does not copy evidence. No automatic archive restoration; runtime startup may write new records.'} | ConvertTo-Json -Depth 5))
    Assert-NoRunningClients
    Assert-Snapshot $program $installed
    Assert-PreservedConfiguration
    $serviceTouched = $true
    Set-ServiceState 'Stopped'
    Assert-NoRunningClients
    if ($RecoverInconsistentInstallation) {
        Backup-RecoveryEvidence
        Assert-Snapshot $program $installed
        Assert-Snapshot $staged $source
        Assert-PreservedConfiguration
    }
    $replacementStarted = $true
    Copy-OwnedSnapshot $staged $program $source $true
    Assert-PreservedConfiguration
    Set-ServiceState 'Running'
    $storageState = Wait-ServiceHealth $source.Manifest.version
    Assert-Snapshot $program $source
    Assert-PreservedConfiguration
    Set-ServiceState $previousState
    $warnings = @()
    if ($storageState -ceq 'capacity_exhausted') { $warnings = @('Existing archive capacity failure remains: collection is not qualified active; retained events and configured budget were preserved.') }
    [ordered]@{result='updated'; scope='same_version_binary_refresh'; version=$source.Manifest.version; restored_service_state=$previousState; backup_directory=$backup; signed_release_verified=$false; evidence_migrated=$false; recovery_requested=[bool]$RecoverInconsistentInstallation; original_manifest_consistent=$installed.Consistent; storage_state=$storageState; warnings=@($warnings)} | ConvertTo-Json
} catch {
    $failure = $_.Exception.Message
    $rollback = 'not_needed_service_unchanged'
    if ($serviceTouched) {
        try {
            Set-ServiceState 'Stopped'
            if ($replacementStarted) { Copy-OwnedSnapshot $backup $program $installed $true }
            Assert-PreservedConfiguration
            Set-ServiceState $previousState
            if ($previousState -ceq 'Running' -and $installed.Consistent) { $null = Wait-ServiceHealth $installed.Manifest.version }
            $rollback = if ($installed.Consistent) { 'previous_binaries_and_service_state_restored' } else { 'previous_exact_bytes_and_service_state_restored_health_unqualified' }
        } catch { $rollback = 'FAILED: ' + $_.Exception.Message }
    }
    $retained = if (Test-Path -LiteralPath $transaction) { $transaction } else { 'not created' }
    throw "Refresh failed: $failure. Rollback: $rollback. Protected transaction: $retained; no evidence was deleted or migrated."
} finally {
    if ($lock) { $lock.Dispose() }
}
