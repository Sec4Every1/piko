# Same-version refresh; every refresh preserves evidence and verifies it under
# the existing SCM service identity. Development source; not yet qualified.
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$PackagePath = $PSScriptRoot,
    [switch]$PreflightOnly,
    [switch]$RecoverInconsistentInstallation,
    [switch]$ResumeInterruptedUpdate
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$files = @('piko-service.exe', 'piko.exe', 'piko-desktop.exe', 'piko-network-helper.exe')
$ownedNames = @($files) + @('manifest.json')
$program = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'piko'))
$data = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'piko'))
$configuration = Join-Path $program 'service.json'
$pendingMarker = Join-Path $data 'archive-verification.pending'

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
function Assert-AdminProtected([string]$Path, [string[]]$AdditionalWriters = @(), [string[]]$AdditionalOwners = @()) {
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $trusted = @('S-1-5-18', 'S-1-5-32-544')
    if ($owner -notin (@($trusted) + @($AdditionalOwners))) { throw "Trusted ownership required: $Path" }
    $trustedWriters = @($trusted) + @($AdditionalWriters)
    $raw = New-Object Security.AccessControl.RawSecurityDescriptor($acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access))
    if ($null -eq $raw.DiscretionaryAcl) { throw "Unrestricted null DACL refused: $Path" }
    $writeRights = [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $writeRights) -and
            $rule.IdentityReference.Value -notin $trustedWriters) { throw "Untrusted write access refused: $Path" }
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
function Assert-JsonFields($Value, [string[]]$Names) {
    if ($Value -isnot [pscustomobject]) { throw 'Invalid archive protocol object.' }
    $actual = @($Value.PSObject.Properties.Name)
    if ($actual.Count -ne $Names.Count) { throw 'Unexpected archive protocol fields.' }
    foreach ($name in $Names) {
        if ($actual -cnotcontains $name) { throw 'Missing archive protocol field.' }
    }
}
function Test-UnsignedJsonInteger($Value) {
    return ($Value -is [int] -or $Value -is [long] -or $Value -is [uint32] -or $Value -is [uint64]) -and $Value -ge 0
}
function Assert-ArchiveCapabilities([string]$Directory, $Snapshot) {
    Assert-Snapshot $Directory $Snapshot
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = Join-Path $Directory 'piko-service.exe'
    $start.Arguments = '--archive-capabilities'
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $child = New-Object Diagnostics.Process
    $child.StartInfo = $start
    $childStarted = $false
    try {
        if (!$child.Start()) { throw 'Candidate capability probe did not start.' }
        $childStarted = $true
        # Fixed buffers bound output memory as well as process lifetime. Drain
        # concurrently; no SCM service or installed runtime is started here.
        $outputChars = New-Object char[] 16385
        $errorChars = New-Object char[] 1
        $outputLength = 0
        $outputClosed = $false
        $errorClosed = $false
        $outputRead = $child.StandardOutput.ReadAsync($outputChars, 0, $outputChars.Length)
        $errorRead = $child.StandardError.ReadAsync($errorChars, 0, 1)
        $deadline = [DateTime]::UtcNow.AddSeconds(15)
        do {
            if (!$outputClosed -and $outputRead.IsCompleted) {
                $read = $outputRead.GetAwaiter().GetResult()
                if ($read -eq 0) { $outputClosed = $true } else {
                    $outputLength += $read
                    if ($outputLength -gt 16384) { throw 'Candidate capability output exceeded 16 KiB.' }
                    $outputRead = $child.StandardOutput.ReadAsync($outputChars, $outputLength, ($outputChars.Length - $outputLength))
                }
            }
            if (!$errorClosed -and $errorRead.IsCompleted) {
                if ($errorRead.GetAwaiter().GetResult() -ne 0) { throw 'Candidate capability probe emitted unexpected stderr.' }
                $errorClosed = $true
            }
            if ($child.HasExited -and $outputClosed -and $errorClosed) { break }
            if ([DateTime]::UtcNow -ge $deadline) { throw 'Candidate archive capability probe exceeded 15 seconds.' }
            Start-Sleep -Milliseconds 25
        } while ($true)
        if ($child.ExitCode -ne 0 -or $outputLength -eq 0) {
            throw 'Candidate archive capability probe failed.'
        }
        $capabilities = (-join $outputChars[0..($outputLength - 1)]) | ConvertFrom-Json
        Assert-JsonFields $capabilities @('protocol','service_read_only_verification','report_version','key_recovery_portable','normal_start_guard')
        if (!(Test-UnsignedJsonInteger $capabilities.protocol) -or $capabilities.protocol -ne 1 -or
            !(Test-UnsignedJsonInteger $capabilities.report_version) -or $capabilities.report_version -ne 1 -or
            $capabilities.service_read_only_verification -isnot [bool] -or !$capabilities.service_read_only_verification -or
            $capabilities.normal_start_guard -isnot [bool] -or !$capabilities.normal_start_guard -or
            $capabilities.key_recovery_portable -isnot [bool] -or $capabilities.key_recovery_portable) {
            throw 'Candidate does not support the required service-identity archive verification protocol.'
        }
    } finally {
        try {
            if ($childStarted -and !$child.HasExited) {
                $child.Kill()
                $null = $child.WaitForExit(5000)
            }
        } finally { $child.Dispose() }
    }
    Assert-Snapshot $Directory $Snapshot
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
    if (Test-Path -LiteralPath (Join-Path $data 'evidence-key.recovery.pending')) { throw 'Complete guarded key recovery before changing the installation.' }
    Assert-ServiceIdentity
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
    # Normal startup may verify an archive up to 2 GiB again after the isolated
    # service-identity verification has succeeded.
    $deadline = [DateTime]::UtcNow.AddSeconds(120)
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

function Backup-ArchiveEvidence {
    $destination = Join-Path $transaction 'evidence-before'
    if ((Get-Service -Name piko).Status.ToString() -cne 'Stopped') { throw 'Archive backup requires a fully stopped service.' }
    if (!(Test-Path -LiteralPath (Join-Path $data 'events.db') -PathType Leaf)) { throw 'Refresh requires an existing event archive.' }
    $paths = @('events.db','events.db-wal','events.db-shm') | ForEach-Object { Join-Path $data $_ } | Where-Object { Test-Path -LiteralPath $_ }
    $bytes = ($paths | ForEach-Object { (Get-Item -LiteralPath $_).Length } | Measure-Object -Sum).Sum
    $drive = (Split-Path -Qualifier $data).TrimEnd(':')
    if ((Get-PSDrive -Name $drive).Free -lt ($bytes + 64MB)) { throw 'Insufficient free space for protected archive backup.' }
    New-Item -ItemType Directory -Path $destination | Out-Null
    $records = @()
    foreach ($path in $paths) {
        Assert-NoReparse $path
        $null = Assert-AdminProtected -Path $path -AdditionalWriters @($serviceAccountSid) -AdditionalOwners @($serviceAccountSid)
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        $target = Join-Path $destination ([IO.Path]::GetFileName($path))
        Copy-Item -LiteralPath $path -Destination $target
        if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ine $hash -or
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ine $hash) { throw 'Archive copy could not be verified.' }
        $records += @{name=[IO.Path]::GetFileName($path);sha256=$hash;bytes=(Get-Item -LiteralPath $target).Length}
    }
    $records | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $destination 'backup-files.json') -Encoding utf8
    return [pscustomobject]@{Records=@($records); Directory=$destination}
}
function Assert-ArchiveUnchanged($Snapshot) {
    # SQLite's shared-memory sidecar may be transient. Database and WAL bytes,
    # including sidecar presence, must be exactly preserved by this gate.
    foreach ($name in @('events.db','events.db-wal')) {
        $path = Join-Path $data $name
        Assert-NoReparse $path
        $record = @($Snapshot.Records | Where-Object { $_.name -ceq $name })
        if ($record.Count -eq 0) {
            if (Test-Path -LiteralPath $path) { throw 'Read-only archive verification created a database/WAL file.' }
        } elseif (!(Test-Path -LiteralPath $path -PathType Leaf) -or
            (Get-Item -LiteralPath $path).Length -ne $record[0].bytes -or
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ine $record[0].sha256 -or
            (Get-FileHash -LiteralPath (Join-Path $Snapshot.Directory $name) -Algorithm SHA256).Hash -ine $record[0].sha256) {
            throw 'Read-only archive verification changed database/WAL bytes, or the protected backup changed.'
        }
    }
}
function Assert-OwnedVerificationMarker {
    Assert-NoReparse $pendingMarker
    if (!$pendingMarkerOwned -or !(Test-Path -LiteralPath $pendingMarker -PathType Leaf) -or
        (Get-Item -LiteralPath $pendingMarker).Length -gt 1024) { throw 'Owned archive verification guard is missing or invalid.' }
    $guard = Get-Content -LiteralPath $pendingMarker -Raw | ConvertFrom-Json
    Assert-JsonFields $guard @('protocol','nonce')
    if (!(Test-UnsignedJsonInteger $guard.protocol) -or $guard.protocol -ne 1 -or
        $guard.nonce -isnot [string] -or $guard.nonce -cne $verificationNonce) { throw 'Archive verification guard ownership changed.' }
}
function New-VerificationMarker {
    Assert-NoReparse $pendingMarker
    if ((Get-Service -Name piko).Status.ToString() -cne 'Stopped') { throw 'Archive verification guard requires a fully stopped service.' }
    $stream = New-Object IO.FileStream($pendingMarker, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $script:pendingMarkerOwned = $true
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes((@{protocol=1;nonce=$verificationNonce} | ConvertTo-Json -Compress))
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
    Assert-OwnedVerificationMarker
}
function Remove-OwnedVerificationMarker {
    if (!$pendingMarkerOwned) { return }
    if ((Get-Service -Name piko).Status.ToString() -cne 'Stopped') { throw 'Cannot remove archive verification guard while service is not fully stopped.' }
    Assert-OwnedVerificationMarker
    Remove-Item -LiteralPath $pendingMarker
    $script:pendingMarkerOwned = $false
}
function Confirm-CleanVerificationStop {
    $script:verificationCleanStop = $false
    if (!$verificationStartAccepted -or $verificationUnsafeExitObserved) {
        throw 'Clean candidate verification completion could not be established.'
    }
    try {
        $service = Get-CimInstance Win32_Service -Filter "Name='piko'"
        # Win32_Service exposes SCM's Win32ExitCode as ExitCode. Missing exit
        # status is unknown, never a successful diagnostic completion.
        if (!$service -or $service.State -cne 'Stopped' -or
            $null -eq $service.PSObject.Properties['ExitCode'] -or
            $null -eq $service.PSObject.Properties['ServiceSpecificExitCode'] -or
            !(Test-UnsignedJsonInteger $service.ExitCode) -or $service.ExitCode -ne 0 -or
            !(Test-UnsignedJsonInteger $service.ServiceSpecificExitCode) -or $service.ServiceSpecificExitCode -ne 0) {
            throw 'Candidate verification did not establish an available clean SCM stop.'
        }
    } catch {
        $script:verificationUnsafeExitObserved = $true
        throw
    }
    $script:verificationCleanStop = $true
}
function Invoke-ServiceArchiveVerification($Snapshot) {
    Assert-ServiceIdentity
    Assert-PreservedConfiguration
    $controller = Get-Service -Name piko
    $controller.Refresh()
    if ($controller.Status.ToString() -cne 'Stopped') { throw 'Archive verification requires a fully stopped service.' }
    Assert-OwnedVerificationMarker
    $nonce = $verificationNonce
    $reportPath = Join-Path $data ('archive-verification-' + $nonce + '.json')
    Assert-NoReparse $reportPath
    if (Test-Path -LiteralPath $reportPath) { throw 'Archive verification report already exists.' }
    # SCM start arguments are ephemeral. Keep binPath, account and permanent
    # configuration unchanged; DPAPI decryption runs as the existing owner.
    $script:verificationAttempted = $true
    $controller.Start([string[]]@('--verify-archive', $nonce))
    $script:verificationStartAccepted = $true
    $deadline = [DateTime]::UtcNow.AddSeconds(120)
    do {
        $controller.Refresh()
        if ($controller.Status.ToString() -ceq 'Stopped') { break }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($controller.Status.ToString() -cne 'Stopped') { throw 'Service archive verification exceeded 120 seconds.' }
    Assert-NoReparse $reportPath
    $reportBytes = $null
    if ((Test-Path -LiteralPath $reportPath -PathType Leaf) -and (Get-Item -LiteralPath $reportPath).Length -le 65536) {
        $reportBytes = [IO.File]::ReadAllBytes($reportPath)
        # Retain exact private diagnostic bytes even when later checks fail.
        [IO.File]::WriteAllBytes((Join-Path $transaction 'archive-verification.json'), $reportBytes)
    }
    Confirm-CleanVerificationStop
    Assert-PreservedConfiguration
    Assert-OwnedVerificationMarker
    Assert-ArchiveUnchanged $Snapshot
    if ($null -eq $reportBytes) { throw 'Service archive verification report is missing or too large.' }
    $report = [Text.Encoding]::UTF8.GetString($reportBytes).TrimStart([char]0xFEFF) | ConvertFrom-Json
    Assert-JsonFields $report @('protocol','nonce','result','read_only','scope','integrity','error_code')
    if (!(Test-UnsignedJsonInteger $report.protocol) -or $report.protocol -ne 1 -or
        $report.nonce -isnot [string] -or $report.nonce -cne $nonce -or
        $report.result -isnot [string] -or $report.result -cnotin @('PASS','FAIL') -or
        $report.read_only -isnot [bool] -or !$report.read_only -or
        $report.scope -isnot [string] -or $report.scope -cne 'service_identity_archive_verification') {
        throw 'Service archive verification report protocol/nonce/scope mismatch.'
    }
    if ($null -ne $report.integrity) {
        Assert-JsonFields $report.integrity @('verified_events','head_hash','expired_events','externally_anchored')
        if (!(Test-UnsignedJsonInteger $report.integrity.verified_events) -or
            !(Test-UnsignedJsonInteger $report.integrity.expired_events) -or
            $report.integrity.externally_anchored -isnot [bool] -or
            ($null -ne $report.integrity.head_hash -and
                ($report.integrity.head_hash -isnot [string] -or $report.integrity.head_hash -cnotmatch '^[a-f0-9]{64}$'))) {
            throw 'Service archive verification integrity fields are invalid.'
        }
    }
    if ($report.result -ceq 'FAIL') {
        if ($report.error_code -isnot [string] -or $report.error_code -cne 'archive_verification_failed') { throw 'Invalid archive failure report.' }
        throw 'Candidate could not verify the archive under the existing service identity; normal startup refused.'
    }
    if ($null -eq $report.integrity -or $null -ne $report.error_code) { throw 'Invalid archive success report.' }
    return $report
}

if (Test-Path -LiteralPath (Join-Path $data 'evidence-key.recovery.pending')) { throw 'Complete guarded key recovery before updating piko.' }
if (Test-Path -LiteralPath (Join-Path $data 'evidence-protection-activation.pending')) { throw 'Complete guarded evidence-protection activation before updating piko.' }
if ($ResumeInterruptedUpdate) {
    if ($RecoverInconsistentInstallation) { throw 'Resume and inconsistent-installation recovery are separate operations.' }
    . (Join-Path $PSScriptRoot 'Resume-PikoUpdate.ps1')
    return
}
$package = (Resolve-Path -LiteralPath $PackagePath).Path
$source = Read-Snapshot $package
Assert-ArchiveCapabilities $package $source
$installed = Read-Snapshot $program ([bool]$RecoverInconsistentInstallation)
if ($source.Manifest.version -cne $installed.Manifest.version) { throw 'Only same-version build refreshes are supported; cross-version data migration is not qualified.' }
Assert-NoReparse $configuration
Assert-NoReparse $data
Assert-NoReparse $pendingMarker
if (Test-Path -LiteralPath $pendingMarker) { throw 'An existing archive verification guard requires explicit investigation; refresh refused without changing the service.' }
if (!(Test-Path -LiteralPath $data -PathType Container)) { throw 'Installed evidence directory is missing; refresh refused.' }
$config = Get-Content -LiteralPath $configuration -Raw | ConvertFrom-Json
if ([IO.Path]::GetFullPath($config.data_dir) -ine $data) { throw 'Custom evidence directories are not qualified for refresh.' }
$programAcl = Assert-AdminProtected $program
$installedAcls = @{}
foreach ($name in $ownedNames) { $installedAcls[$name] = Assert-AdminProtected (Join-Path $program $name) }
$configurationHash = (Get-FileHash -LiteralPath $configuration -Algorithm SHA256).Hash
$configurationAcl = (Get-Acl -LiteralPath $configuration).Sddl
$serviceAccountSid = (New-Object Security.Principal.NTAccount('NT SERVICE\piko')).Translate([Security.Principal.SecurityIdentifier]).Value
# Guard/report nonce validation assumes only administrators, SYSTEM and this
# service can write the data directory; preserving a weak ACL is insufficient.
$dataAcl = (Assert-AdminProtected -Path $data -AdditionalWriters @($serviceAccountSid)).Sddl
Assert-ServiceIdentity
Assert-NoRunningClients
$previousState = (Get-Service -Name piko).Status.ToString()
if ($previousState -notin @('Running','Stopped')) { throw 'Wait for a stable piko service state before refreshing.' }
if ($PreflightOnly) {
    [ordered]@{result='static_preflight_passed'; scope='same_version_binary_refresh'; version=$source.Manifest.version; previous_service_state=$previousState; service_changed=$false; candidate_archive_capabilities_verified=$true; archive_verified=$false; key_recovery_portable=$false; signed_release_verified=$false; recovery_requested=[bool]$RecoverInconsistentInstallation; original_manifest_consistent=$installed.Consistent} | ConvertTo-Json
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
$verificationNonce = [guid]::NewGuid().ToString('D')
$pendingMarkerOwned = $false
$verificationAttempted = $false
$verificationStartAccepted = $false
$verificationCleanStop = $false
$verificationUnsafeExitObserved = $false
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
    $recoveryRecord = @{resume_protocol=1; candidate_manifest_sha256=$source.ManifestHash; program_acl=$programAcl.Sddl; data_acl=$dataAcl;
        previous_service_state=$previousState; version=$installed.Manifest.version;
        original_manifest_consistent=$installed.Consistent; original_observed_files=$installed.ObservedFiles; original_manifest_sha256=$installed.ManifestHash;
        original_file_acls=$originalAcls; configuration_sha256=$configurationHash; configuration_acl=$configurationAcl;
        original_source_trust_verified=$false; recovery_requested=[bool]$RecoverInconsistentInstallation;
        known_capacity_failure_before=$knownCapacityFailureBefore;
        archive_verification_nonce=$verificationNonce;
        note='Exact originals and archive copies are preserved; no publisher authenticity or portable key recovery. Guarded resume uses the checked staged candidate, never an unknown old executable. No automatic archive restoration.'}
    $journal = New-Object IO.FileStream((Join-Path $transaction 'recovery.json'), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $journalBytes = [Text.Encoding]::UTF8.GetBytes(($recoveryRecord | ConvertTo-Json -Depth 5))
        $journal.Write($journalBytes, 0, $journalBytes.Length)
        $journal.Flush($true)
    } finally { $journal.Dispose() }
    Assert-NoRunningClients
    Assert-NoReparse $pendingMarker
    if (Test-Path -LiteralPath $pendingMarker) { throw 'Archive verification guard appeared after preflight; refresh refused.' }
    Assert-Snapshot $program $installed
    Assert-PreservedConfiguration
    $serviceTouched = $true
    Set-ServiceState 'Stopped'
    Assert-NoRunningClients
    $archiveSnapshot = Backup-ArchiveEvidence
    New-VerificationMarker
    Assert-Snapshot $program $installed
    Assert-Snapshot $staged $source
    Assert-PreservedConfiguration
    $replacementStarted = $true
    Copy-OwnedSnapshot $staged $program $source $true
    Assert-PreservedConfiguration
    $archiveVerification = Invoke-ServiceArchiveVerification $archiveSnapshot
    Assert-Snapshot $program $source
    Remove-OwnedVerificationMarker
    Set-ServiceState 'Running'
    $storageState = Wait-ServiceHealth $source.Manifest.version
    Assert-Snapshot $program $source
    Assert-PreservedConfiguration
    Set-ServiceState $previousState
    $warnings = @()
    if ($storageState -ceq 'capacity_exhausted') { $warnings = @('Existing archive capacity failure remains: collection is not qualified active; retained events and configured budget were preserved.') }
    [ordered]@{result='updated'; scope='same_version_binary_refresh'; version=$source.Manifest.version; restored_service_state=$previousState; backup_directory=$backup; evidence_backup_directory=$archiveSnapshot.Directory; archive_verified=$true; archive_verification_scope=$archiveVerification.scope; archive_verification_report=(Join-Path $transaction 'archive-verification.json'); key_recovery_portable=$false; signed_release_verified=$false; evidence_migrated=$false; recovery_requested=[bool]$RecoverInconsistentInstallation; original_manifest_consistent=$installed.Consistent; storage_state=$storageState; warnings=@($warnings)} | ConvertTo-Json
} catch {
    $failure = $_.Exception.Message
    $rollback = 'not_needed_service_unchanged'
    if ($serviceTouched) {
        if ($verificationAttempted) { $verificationCleanStop = $false }
        try {
            Set-ServiceState 'Stopped'
            if ($verificationAttempted) {
                # A queued SCM failure restart cannot be cancelled by Stop.
                # Keep the guarded candidate in place unless a clean completion
                # is known; an old binary may not honor the pending guard.
                # A later health failure may follow removal of the original
                # marker, so recreate our guard before deciding rollback safety.
                if (!$pendingMarkerOwned) { New-VerificationMarker }
                Assert-OwnedVerificationMarker
                Confirm-CleanVerificationStop
            }
            if ($replacementStarted) { Copy-OwnedSnapshot $backup $program $installed $true }
            Assert-PreservedConfiguration
            Remove-OwnedVerificationMarker
            Set-ServiceState $previousState
            if ($previousState -ceq 'Running' -and $installed.Consistent) { $null = Wait-ServiceHealth $installed.Manifest.version }
            $rollback = if ($installed.Consistent) { 'previous_binaries_and_service_state_restored' } else { 'previous_exact_bytes_and_service_state_restored_health_unqualified' }
        } catch {
            $rollback = if ($verificationAttempted -and !$verificationCleanStop) {
                'BLOCKED_RECOVERY_RACE: ' + $_.Exception.Message + '; guarded candidate and available backups retained. Explicit resume/investigation required; no automatic archive restoration.'
            } else { 'FAILED: ' + $_.Exception.Message }
        }
    }
    $retained = if (Test-Path -LiteralPath $transaction) { $transaction } else { 'not created' }
    throw "Refresh failed: $failure. Rollback: $rollback. Protected transaction: $retained; archive backup retained when created. No automatic archive restoration or migration was performed."
} finally {
    if ($lock) { $lock.Dispose() }
}
