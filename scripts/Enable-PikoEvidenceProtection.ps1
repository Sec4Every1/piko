# Source embedded in the manifest-owned elevated helper. Fresh activation uses
# a dedicated IPC ticket; explicit resume requires a recognized durable journal.
[CmdletBinding()]
param([switch]$ResumeInterruptedActivation)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$program = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'piko'))
$data = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'piko'))
$configPath = Join-Path $program 'service.json'
$pending = Join-Path $data 'evidence-protection-activation.pending'

function Assert-NoReparse([string]$Path) {
    $cursor = [IO.Path]::GetFullPath($Path)
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            if ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse path refused.' }
        }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
}
function Assert-Protected([string]$Path, [string[]]$Writers) {
    Assert-NoReparse $Path
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin @('S-1-5-18','S-1-5-32-544')) { throw 'Trusted owner required.' }
    $raw = New-Object Security.AccessControl.RawSecurityDescriptor($acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access))
    if ($null -eq $raw.DiscretionaryAcl) { throw 'Null DACL refused.' }
    $rights = [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $rights) -and $rule.IdentityReference.Value -notin $Writers) {
            throw 'Untrusted write permission refused.'
        }
    }
}
function Set-ServiceState([ValidateSet('Running','Stopped')][string]$State) {
    $controller = Get-Service piko
    $controller.Refresh()
    if ($controller.Status.ToString() -eq $State) { return }
    if ($State -eq 'Stopped' -and $controller.Status -eq 'Running') { $controller.Stop() }
    elseif ($State -eq 'Running' -and $controller.Status -eq 'Stopped') { $controller.Start() }
    else { throw 'Piko service is in a transitional state.' }
    $controller.WaitForStatus($State,[TimeSpan]::FromSeconds(35))
}
function Write-NewSynced([string]$Path,[byte[]]$Bytes) {
    $stream = [IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try { $stream.Write($Bytes,0,$Bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
}
function Assert-ActivationBaseline($Record) {
    foreach ($pair in @(
        @((Join-Path $program 'manifest.json'), $Record.manifest_sha256),
        @((Join-Path $data 'evidence-key.json'), $Record.key_sha256),
        @((Join-Path $data 'evidence-key.confirmed.json'), $Record.receipt_sha256)
    )) {
        Assert-NoReparse $pair[0]
        if ($pair[1] -cnotmatch '^[A-Fa-f0-9]{64}$' -or
            (Get-FileHash -LiteralPath $pair[0] -Algorithm SHA256).Hash -ine $pair[1]) {
            throw 'Installation or confirmed key changed; automatic activation resume refused.'
        }
    }
}
function Confirm-ProtectedRuntime {
    Set-ServiceState Running
    $deadline = [DateTime]::UtcNow.AddSeconds(35)
    do {
        $output = & (Join-Path $program 'piko.exe') evidence-key-status 2>$null
        if ($LASTEXITCODE -eq 0) {
            $status = $output | ConvertFrom-Json
            if ($status.state -ceq 'ready' -and $status.backup_confirmed -eq $true -and
                $status.new_raw_enabled -eq $true -and $status.recoverable_mode -eq $true -and
                $status.activation_pending -eq $true) { return }
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Protected runtime IPC confirmation unavailable; journal retained.'
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator authorization required.' }
$serviceSid = (New-Object Security.Principal.NTAccount('NT SERVICE\piko')).Translate([Security.Principal.SecurityIdentifier]).Value
$trustedProgramWriters = @('S-1-5-18','S-1-5-32-544')
$trustedDataWriters = @('S-1-5-18','S-1-5-32-544',$serviceSid)
Assert-Protected $program $trustedProgramWriters
Assert-Protected $data $trustedDataWriters
Assert-Protected $configPath $trustedProgramWriters
$service = Get-CimInstance Win32_Service -Filter "Name='piko'"
$expected = '"' + (Join-Path $program 'piko-service.exe') + '" --service --config "' + $configPath + '"'
if (!$service -or $service.PathName -cne $expected -or $service.StartName -ine 'NT SERVICE\piko' -or $service.State -notin @('Running','Stopped')) { throw 'Expected installed piko service required.' }
if ($ResumeInterruptedActivation -and !(Test-Path -LiteralPath $pending -PathType Leaf)) { throw 'No interrupted activation to resume.' }
if (!$ResumeInterruptedActivation -and $service.State -ne 'Running') { throw 'Begin activation from the running desktop flow.' }
foreach ($marker in @('archive-verification.pending','evidence-key.recovery.pending')) {
    if (Test-Path -LiteralPath (Join-Path $data $marker)) { throw 'Complete the pending protected operation first.' }
}
foreach ($name in @('evidence-key.json','evidence-key.confirmed.json')) {
    $path = Join-Path $data $name
    if (!(Test-Path -LiteralPath $path -PathType Leaf) -or (Get-Item -LiteralPath $path).Length -gt 65536) { throw 'Confirmed evidence key required.' }
    Assert-Protected $path $trustedDataWriters
}
if ((Get-Item -LiteralPath $configPath).Length -gt 16384) { throw 'Configuration exceeds bound.' }
$configBytes = [IO.File]::ReadAllBytes($configPath)
if ($configBytes.Length -gt 16384) { throw 'Configuration exceeds bound.' }
$config = [Text.Encoding]::UTF8.GetString($configBytes).TrimStart([char]0xFEFF) | ConvertFrom-Json
$actualFields = @($config.PSObject.Properties.Name)
$allowed = @('data_dir','heartbeat_seconds','flush_seconds','max_disk_mib','queue_capacity','viewer_sid','response_roots','retention_months','protect_raw_evidence','recoverable_raw_evidence','archive_maintenance')
if (@($actualFields | Where-Object { $_ -notin $allowed }).Count -or [IO.Path]::GetFullPath($config.data_dir) -ine $data -or
    $config.viewer_sid -notmatch '^S-1-[0-9-]+$') { throw 'Installed configuration is not eligible.' }
if (($null -ne $config.PSObject.Properties['protect_raw_evidence'] -and $config.protect_raw_evidence -isnot [bool]) -or
    ($null -ne $config.PSObject.Properties['recoverable_raw_evidence'] -and $config.recoverable_raw_evidence -isnot [bool])) { throw 'Invalid protection settings.' }
$protectEnabled = $null -ne $config.PSObject.Properties['protect_raw_evidence'] -and [bool]$config.protect_raw_evidence
$recoverableEnabled = $null -ne $config.PSObject.Properties['recoverable_raw_evidence'] -and [bool]$config.recoverable_raw_evidence
if ($protectEnabled -ne $recoverableEnabled) { throw 'Protection configuration is inconsistent.' }

$upgradeLock = $null
try {
    $upgradeLock = New-Object IO.FileStream((Join-Path $program '.upgrade.lock'),[IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite,[IO.FileShare]::None,1,[IO.FileOptions]::DeleteOnClose)
    $manifestPath = Join-Path $program 'manifest.json'
    Assert-Protected $manifestPath $trustedProgramWriters
    if ((Get-Item -LiteralPath $manifestPath).Length -gt 65536) { throw 'Manifest exceeds bound.' }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $executables = @('piko-service.exe','piko.exe','piko-desktop.exe','piko-network-helper.exe')
    if ($manifest.product -cne 'piko' -or $manifest.architecture -cne 'x64' -or @($manifest.files).Count -ne $executables.Count) { throw 'Invalid installed manifest.' }
    foreach ($name in $executables) {
        $entry = @($manifest.files | Where-Object { $_.name -ceq $name })
        $binary = Join-Path $program $name
        Assert-Protected $binary $trustedProgramWriters
        if ($entry.Count -ne 1 -or $entry[0].sha256 -cnotmatch '^[A-Fa-f0-9]{64}$' -or
            (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash -ine $entry[0].sha256) { throw 'Installed executable mismatch; activation refused.' }
    }

# Resume only exact original or deterministically enabled configuration bytes.
# Never roll back disabled flags after the service could have written v2 data.
$resumeOriginal = $false
if (Test-Path -LiteralPath $pending) {
    Assert-Protected $pending $trustedDataWriters
    if ((Get-Item -LiteralPath $pending).Length -gt 4096) { throw 'Pending activation state exceeds bound.' }
    $prior = Get-Content -LiteralPath $pending -Raw | ConvertFrom-Json
    $priorFields = @($prior.PSObject.Properties.Name)
    if ($priorFields.Count -ne 8 -or @(@('protocol','nonce','original_sha256','backup','state','manifest_sha256','key_sha256','receipt_sha256') | Where-Object { $_ -notin $priorFields }).Count) { throw 'Unknown pending activation state; preserve it for explicit recovery.' }
    $expectedBackup = Join-Path $data ('evidence-protection-config-' + [guid]::ParseExact($prior.nonce,'D').ToString('D') + '.json')
    if ($prior.protocol -ne 2 -or $prior.state -cne 'prepared' -or $prior.original_sha256 -cnotmatch '^[A-Fa-f0-9]{64}$' -or
        [IO.Path]::GetFullPath($prior.backup) -ine $expectedBackup -or !(Test-Path -LiteralPath $expectedBackup -PathType Leaf)) { throw 'Unknown pending activation state.' }
    Assert-Protected $expectedBackup $trustedDataWriters
    if ((Get-Item -LiteralPath $expectedBackup).Length -gt 16384) { throw 'Backup exceeds bound.' }
    if ((Get-FileHash -LiteralPath $expectedBackup -Algorithm SHA256).Hash -ine $prior.original_sha256) { throw 'Interrupted activation requires installation recovery.' }
    Assert-ActivationBaseline $prior
    if (!$protectEnabled) {
        if ((Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash -ine $prior.original_sha256) { throw 'Interrupted activation requires installation recovery.' }
        $resumeOriginal = $true
    } else {
        $original = Get-Content -LiteralPath $expectedBackup -Raw | ConvertFrom-Json
        $original | Add-Member -NotePropertyName recoverable_raw_evidence -NotePropertyValue $true -Force
        $original | Add-Member -NotePropertyName protect_raw_evidence -NotePropertyValue $true -Force
        $expectedEnabled = [Text.Encoding]::UTF8.GetBytes(($original | ConvertTo-Json -Depth 8))
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $expectedEnabledHash = ([BitConverter]::ToString($sha.ComputeHash($expectedEnabled))).Replace('-','') }
        finally { $sha.Dispose(); [Array]::Clear($expectedEnabled,0,$expectedEnabled.Length) }
        if ((Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash -ine $expectedEnabledHash) { throw 'Interrupted activation requires installation recovery.' }
        Confirm-ProtectedRuntime
        Assert-ActivationBaseline $prior
        Remove-Item -LiteralPath $pending
        return
    }
}
if ($protectEnabled) { throw 'Protection is already enabled.' }

if ($resumeOriginal) {
    $nonce = $prior.nonce
    $backupPath = $expectedBackup
    $journal = $prior
    $journalBytes = [byte[]]@()
} else {
# Retained configuration copies and incomplete attempts are private diagnostics,
# not an unbounded retry sink. Nothing is deleted to satisfy this bound.
if (@(Get-ChildItem -LiteralPath $data -Filter 'evidence-protection-config-*' -Force | Select-Object -First 17).Count -ge 16) { throw 'Retained activation attempts reached the bound; preserve and review them.' }
$nonce = [guid]::NewGuid().ToString('D')
$backupPath = Join-Path $data ('evidence-protection-config-' + $nonce + '.json')
$journal = [ordered]@{protocol=2;nonce=$nonce;original_sha256=(Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash;backup=$backupPath;state='prepared';
    manifest_sha256=(Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash;
    key_sha256=(Get-FileHash -LiteralPath (Join-Path $data 'evidence-key.json') -Algorithm SHA256).Hash;
    receipt_sha256=(Get-FileHash -LiteralPath (Join-Path $data 'evidence-key.confirmed.json') -Algorithm SHA256).Hash}
$journalBytes = [Text.Encoding]::UTF8.GetBytes(($journal | ConvertTo-Json -Compress))
Write-NewSynced $backupPath $configBytes
if ((Get-FileHash -LiteralPath $backupPath -Algorithm SHA256).Hash -ine $journal.original_sha256) { throw 'Configuration changed while preparing activation.' }
$journalStage = Join-Path $data ('evidence-protection-config-' + $nonce + '.journal')
Write-NewSynced $journalStage $journalBytes
Assert-Protected $journalStage $trustedDataWriters
# Publish only a fully flushed journal, before changing configuration or service.
[IO.File]::Move($journalStage,$pending)
Assert-Protected $backupPath $trustedDataWriters
Assert-Protected $pending $trustedDataWriters
}

$config | Add-Member -NotePropertyName recoverable_raw_evidence -NotePropertyValue $true -Force
$config | Add-Member -NotePropertyName protect_raw_evidence -NotePropertyValue $true -Force
$replacement = [Text.Encoding]::UTF8.GetBytes(($config | ConvertTo-Json -Depth 8))
if ($replacement.Length -gt 16384) { throw 'Updated configuration exceeds bound.' }
$temporary = Join-Path $program ('service-protection-' + $nonce + '.tmp')
try {
    Set-ServiceState Stopped
    Assert-ActivationBaseline $journal
    if ((Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash -ine $journal.original_sha256) { throw 'Configuration changed during activation.' }
    if (Test-Path -LiteralPath $temporary) {
        Assert-Protected $temporary $trustedProgramWriters
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $replacementHash = ([BitConverter]::ToString($sha.ComputeHash($replacement))).Replace('-','') }
        finally { $sha.Dispose() }
        if ((Get-Item -LiteralPath $temporary).Length -gt 16384) { throw 'Stage exceeds bound; retained for explicit recovery.' }
        if ((Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash -ine $replacementHash) {
            if (!$ResumeInterruptedActivation) { throw 'Partial stage retained; use explicit activation resume.' }
            # The exact original configuration and key/installation baseline
            # were proven above. Preserve one partial stage before rebuilding.
            $retainedStage = Join-Path $data ('evidence-protection-stage-' + $nonce + '.partial')
            Assert-NoReparse $retainedStage
            if (Test-Path -LiteralPath $retainedStage) { throw 'A prior partial stage is already retained; review required.' }
            Set-Acl -LiteralPath $temporary -AclObject (Get-Acl -LiteralPath $backupPath)
            Assert-Protected $temporary $trustedDataWriters
            [IO.File]::Move($temporary,$retainedStage)
            Assert-Protected $retainedStage $trustedDataWriters
            Write-NewSynced $temporary $replacement
        }
        $stream = [IO.File]::Open($temporary,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        try { $stream.Flush($true) } finally { $stream.Dispose() }
    } else { Write-NewSynced $temporary $replacement }
    Assert-Protected $temporary $trustedProgramWriters
    [IO.File]::Replace($temporary,$configPath,$null)
    Confirm-ProtectedRuntime
    Assert-ActivationBaseline $journal
    Remove-Item -LiteralPath $pending
} catch {
    try { Set-ServiceState Stopped } catch { }
    throw 'Activation interrupted; settings, stage and private journal retained. Use Resume-PikoEvidenceProtection.cmd. Never restore disabled flags after a possible protected write.'
} finally {
    [Array]::Clear($configBytes,0,$configBytes.Length)
    [Array]::Clear($replacement,0,$replacement.Length)
    [Array]::Clear($journalBytes,0,$journalBytes.Length)
}
} finally {
    if ($null -ne $upgradeLock) { $upgradeLock.Dispose() }
}
