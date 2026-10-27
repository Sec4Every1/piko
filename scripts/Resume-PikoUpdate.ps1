# Internal dot-sourced continuation of Update-Piko.ps1; no standalone execution.
# Development source only. No archive restore, key export or SCM policy changes.
if (!$ResumeInterruptedUpdate) { throw 'Use Update-Piko.ps1 -ResumeInterruptedUpdate.' }
function Read-ResumeJson([string]$Path, [long]$Limit) {
    Assert-NoReparse $Path
    $null = Assert-AdminProtected $Path
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($stream.Length -gt $Limit) { throw 'Recovery metadata exceeds its bound.' }
        $reader = New-Object IO.StreamReader($stream, [Text.Encoding]::UTF8, $true)
        try { return ($reader.ReadToEnd() | ConvertFrom-Json) } finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
}
Assert-NoReparse $data
$programAcl = Assert-AdminProtected $program
$serviceAccountSid = (New-Object Security.Principal.NTAccount('NT SERVICE\piko')).Translate([Security.Principal.SecurityIdentifier]).Value
$dataAcl = (Assert-AdminProtected -Path $data -AdditionalWriters @($serviceAccountSid)).Sddl
Assert-ServiceIdentity
Assert-NoRunningClients
Assert-NoReparse $pendingMarker
if (!(Test-Path -LiteralPath $pendingMarker -PathType Leaf) -or (Get-Item -LiteralPath $pendingMarker).Length -gt 1024) { throw 'No bounded pending update guard found.' }
$guard = Get-Content -LiteralPath $pendingMarker -Raw | ConvertFrom-Json
Assert-JsonFields $guard @('protocol','nonce')
if (!(Test-UnsignedJsonInteger $guard.protocol) -or $guard.protocol -ne 1 -or
    $guard.nonce -isnot [string] -or $guard.nonce -cnotmatch '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$' -or
    $guard.nonce -ceq '00000000-0000-0000-0000-000000000000') { throw 'Unknown pending update guard.' }
$verificationNonce = $guard.nonce
# Bound discovery; never choose merely the newest transaction or a supplied path.
$directories = @(Get-ChildItem -LiteralPath $program -Directory -Filter '.upgrade-*' | Select-Object -First 65)
if ($directories.Count -gt 64) { throw 'Too many retained transactions for automatic discovery; none was removed.' }
$resumeMatches = @()
foreach ($directory in $directories) {
    if ($directory.Name -cnotmatch '^\.upgrade-[a-f0-9]{32}$') { continue }
    Assert-NoReparse $directory.FullName
    $null = Assert-AdminProtected $directory.FullName
    $path = Join-Path $directory.FullName 'recovery.json'
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) { continue }
    $record = Read-ResumeJson $path 262144
    if ($null -ne $record.PSObject.Properties['archive_verification_nonce'] -and $record.archive_verification_nonce -ceq $verificationNonce) { $resumeMatches += [pscustomobject]@{Path=$directory.FullName; Record=$record} }
}
if ($resumeMatches.Count -ne 1) { throw 'Pending guard has no unique matching protected transaction.' }
$transaction = $resumeMatches[0].Path
$record = $resumeMatches[0].Record
if ($null -eq $record.PSObject.Properties['resume_protocol'] -or !(Test-UnsignedJsonInteger $record.resume_protocol) -or $record.resume_protocol -ne 1 -or
    $record.previous_service_state -cnotin @('Running','Stopped') -or
    $record.candidate_manifest_sha256 -cnotmatch '^[A-Fa-f0-9]{64}$') { throw 'Transaction lacks the durable resume contract.' }
$staged = Join-Path $transaction 'next'
$backup = Join-Path $transaction 'previous'
$source = Read-Snapshot $staged
if ($source.ManifestHash -ine $record.candidate_manifest_sha256 -or $source.Manifest.version -cne $record.version) { throw 'Staged candidate differs from the recovery journal.' }
Assert-ArchiveCapabilities $staged $source
$original = Read-Snapshot $backup $true
if ($original.ManifestHash -ine $record.original_manifest_sha256) { throw 'Original manifest backup changed.' }
if (@($record.original_observed_files).Count -ne $files.Count) { throw 'Invalid original file journal.' }
foreach ($entry in $original.ObservedFiles) {
    $expected = @($record.original_observed_files | Where-Object { $_.name -ceq $entry.name })
    if ($expected.Count -ne 1 -or $entry.sha256 -ine $expected[0].sha256) { throw 'Original binary backup changed.' }
}
$configurationHash = $record.configuration_sha256
$configurationAcl = $record.configuration_acl
if ($record.program_acl -cne $programAcl.Sddl -or $record.data_acl -cne $dataAcl) { throw 'Directory ACL differs from the interrupted transaction.' }
Assert-PreservedConfiguration
$config = Get-Content -LiteralPath $configuration -Raw | ConvertFrom-Json
if ([IO.Path]::GetFullPath($config.data_dir) -ine $data) { throw 'Custom evidence paths cannot be resumed.' }
$installedAcls = @{}
function Assert-ResumeInstalledFiles {
foreach ($name in $ownedNames) {
    $path = Join-Path $program $name
    Assert-NoReparse $path
    $acl = Assert-AdminProtected $path
    if ($acl.Sddl -cne $record.original_file_acls.$name) { throw 'Installed file ACL changed.' }
    $installedAcls[$name] = $acl
    $observed = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    $newHash = if ($name -ceq 'manifest.json') { $source.ManifestHash } else { ($source.ObservedFiles | Where-Object name -ceq $name).sha256 }
    $oldHash = if ($name -ceq 'manifest.json') { $original.ManifestHash } else { ($original.ObservedFiles | Where-Object name -ceq $name).sha256 }
    if ($observed -ine $newHash -and $observed -ine $oldHash) { throw 'Unrecognized or partially written installed file; automatic resume refused.' }
    if ($name -ceq 'piko-service.exe' -and $observed -ine $newHash) { throw 'Resume requires the guarded candidate service already installed.' }
}
}
Assert-ResumeInstalledFiles
$archiveDirectory = Join-Path $transaction 'evidence-before'
Assert-NoReparse $archiveDirectory
$null = Assert-AdminProtected $archiveDirectory
$records = @(Read-ResumeJson (Join-Path $archiveDirectory 'backup-files.json') 4096)
if ($records.Count -lt 1 -or $records.Count -gt 3 -or @($records | Where-Object name -ceq 'events.db').Count -ne 1) { throw 'Invalid archive backup inventory.' }
$names = @()
foreach ($entry in $records) {
    Assert-JsonFields $entry @('name','sha256','bytes')
    if ($entry.name -cnotin @('events.db','events.db-wal','events.db-shm') -or $names -ccontains $entry.name -or
        $entry.sha256 -cnotmatch '^[A-Fa-f0-9]{64}$' -or !(Test-UnsignedJsonInteger $entry.bytes)) { throw 'Invalid archive backup record.' }
    $names += $entry.name
    $path = Join-Path $archiveDirectory $entry.name
    Assert-NoReparse $path
    $null = Assert-AdminProtected $path
    if ((Get-Item -LiteralPath $path).Length -ne $entry.bytes -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ine $entry.sha256) { throw 'Archive backup changed.' }
}
$archiveSnapshot = [pscustomobject]@{Directory=$archiveDirectory; Records=$records}
$previousState = $record.previous_service_state
$RecoverInconsistentInstallation = [bool]$record.recovery_requested
$knownCapacityFailureBefore = [bool]$record.known_capacity_failure_before
$pendingMarkerOwned = $true
$verificationAttempted = $false
$verificationStartAccepted = $false
$verificationCleanStop = $false
$verificationUnsafeExitObserved = $false
if ($PreflightOnly) {
    [ordered]@{result='resume_static_preflight_passed'; transaction=$transaction; archive_verified=$false; service_changed=$false} | ConvertTo-Json
    return
}
if (!$PSCmdlet.ShouldProcess($program, 'Resume the uniquely matched guarded update; reverify existing evidence without restoring any archive')) { return }
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Resume requires an elevated PowerShell.' }
$lock = $null
try {
    $lock = New-Object IO.FileStream((Join-Path $program '.upgrade.lock'), [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None, 1, [IO.FileOptions]::DeleteOnClose)
    Assert-OwnedVerificationMarker
    Assert-ServiceIdentity
    Assert-NoRunningClients
    Set-ServiceState 'Stopped'
    Assert-PreservedConfiguration
    Assert-ResumeInstalledFiles
    Assert-ArchiveUnchanged $archiveSnapshot
    Assert-Snapshot $staged $source
    # Preserve a previous diagnostic, including an incomplete one, before retry.
    $reportPath = Join-Path $data ('archive-verification-' + $verificationNonce + '.json')
    Assert-NoReparse $reportPath
    if (Test-Path -LiteralPath $reportPath) {
        $null = Assert-AdminProtected -Path $reportPath -AdditionalWriters @($serviceAccountSid) -AdditionalOwners @($serviceAccountSid)
        if ((Get-Item -LiteralPath $reportPath).Length -gt 65536) { throw 'Prior verification report exceeds its bound.' }
        $target = Join-Path $transaction ('prior-verification-' + [guid]::NewGuid().ToString('N') + '.json')
        Move-Item -LiteralPath $reportPath -Destination $target
        # Move may retain the service ACL; make the diagnostic private again.
        $privateAcl = Get-Acl -LiteralPath (Join-Path $transaction 'recovery.json')
        Set-Acl -LiteralPath $target -AclObject $privateAcl
    }
    Copy-OwnedSnapshot $staged $program $source $true
    $report = Invoke-ServiceArchiveVerification $archiveSnapshot
    Assert-Snapshot $program $source
    Remove-OwnedVerificationMarker
    Set-ServiceState 'Running'
    $storageState = Wait-ServiceHealth $source.Manifest.version
    Assert-PreservedConfiguration
    Set-ServiceState $previousState
    [ordered]@{result='resumed'; archive_verified=$true; transaction=$transaction; restored_service_state=$previousState; storage_state=$storageState; key_recovery_portable=$false; archive_restored=$false} | ConvertTo-Json
} catch {
    $failure = $_.Exception.Message
    if ($lock) { try {
        Set-ServiceState 'Stopped'
        if (!$pendingMarkerOwned) { New-VerificationMarker }
        Assert-OwnedVerificationMarker
    } catch { $failure += '; retaining guard could not be confirmed: ' + $_.Exception.Message } }
    throw "Resume failed: $failure. Candidate and backups retained; no automatic archive restoration or old-binary rollback."
} finally { if ($lock) { $lock.Dispose() } }
