# Guarded profile-loss recovery. Source unverified; no secret arguments or output.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$files = @('piko-service.exe','piko.exe','piko-desktop.exe','piko-network-helper.exe')
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
function Assert-KeyRecoveryCapabilities([string]$Directory, $Snapshot) {
    Assert-Snapshot $Directory $Snapshot
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = Join-Path $Directory 'piko-service.exe'
    $start.Arguments = '--key-recovery-capabilities'
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
        Assert-JsonFields $capabilities @('protocol','service_key_recovery','report_version','normal_start_guard')
        if (!(Test-UnsignedJsonInteger $capabilities.protocol) -or $capabilities.protocol -ne 1 -or
            !(Test-UnsignedJsonInteger $capabilities.report_version) -or $capabilities.report_version -ne 1 -or
            $capabilities.service_key_recovery -isnot [bool] -or !$capabilities.service_key_recovery -or
            $capabilities.normal_start_guard -isnot [bool] -or !$capabilities.normal_start_guard) {

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

# These helpers operate only after the installed private-directory boundary has
# been checked. Recovery files never contain user-selected destination paths.
function Assert-Private([string]$Path) {
    Assert-NoReparse $Path
    $acl = Assert-AdminProtected $Path @($serviceAccountSid) @($serviceAccountSid)
    $trusted = @('S-1-5-18','S-1-5-32-544',$serviceAccountSid)
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $trusted) {
            throw 'Recovery requires private service data permissions.'
        }
    }
}
function Read-Bounded([string]$Path, [int]$Limit, [bool]$Private = $true) {
    Assert-NoReparse $Path
    if ($Private) { Assert-Private $Path }
    $buffer = $null
    $stream = [IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if ($stream.Length -gt $Limit) { throw 'Recovery input exceeds its size limit.' }
        $buffer = New-Object byte[] ($Limit + 1)
        $length = 0
        do {
            $read = $stream.Read($buffer,$length,$buffer.Length - $length)
            $length += $read
            if ($length -gt $Limit) { throw 'Recovery input exceeds its size limit.' }
        } while ($read -gt 0)
        return [Text.Encoding]::UTF8.GetString($buffer,0,$length).TrimStart([char]0xFEFF)
    } finally {
        if ($null -ne $buffer) { [Array]::Clear($buffer,0,$buffer.Length) }
        $stream.Dispose()
    }
}
function Write-NewPrivate([string]$Path, [string]$Text) {
    Assert-Private $data
    Assert-NoReparse $Path
    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    if ($bytes.Length -gt 16384) { throw 'Recovery state exceeds its size limit.' }
    $stream = $null
    try {
        $stream = [IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        Assert-Private $Path
        $stream.Write($bytes,0,$bytes.Length)
        $stream.Flush($true)
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        [Array]::Clear($bytes,0,$bytes.Length)
    }
    if ((Read-Bounded $Path 16384) -cne $Text) { throw 'Recovery state readback failed.' }
}
function Read-ArchiveFingerprint {
    if ((Get-Service piko).Status.ToString() -cne 'Stopped') { throw 'Stop piko before reading its archive.' }
    $records = @()
    foreach ($name in @('events.db','events.db-wal')) {
        $path = Join-Path $data $name
        Assert-NoReparse $path
        if (Test-Path -LiteralPath $path) {
            Assert-Private $path
            $item = Get-Item -LiteralPath $path
            if ($item.PSIsContainer) { throw 'Invalid archive object.' }
            $records += [ordered]@{name=$name;length=$item.Length;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash}
        } elseif ($name -ceq 'events.db') { throw 'Existing archive required.' }
    }
    return ConvertTo-Json -InputObject @($records) -Compress
}
function Assert-OwnedRequest {
    $current = Read-Bounded $pending 16384
    if ($current -cne $requestText) { throw 'Recovery request changed; guard retained.' }
}
function Flush-Private([string]$Path) {
    Assert-Private $Path
    $stream = [IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try { $stream.Flush($true) } finally { $stream.Dispose() }
}
function Assert-RecoveryInstallation {
    Assert-ServiceIdentity
    Assert-Snapshot $program $installed
    Assert-Private $data
    if ((Get-FileHash -LiteralPath $configuration -Algorithm SHA256).Hash -ine $configurationHash -or
        (Get-Acl -LiteralPath $configuration).Sddl -cne $configurationAcl -or
        (Get-Acl -LiteralPath $data).Sddl -cne $dataAcl -or
        (Get-Acl -LiteralPath $program).Sddl -cne $programAcl) { throw 'Installation changed during recovery.' }
    if (Test-Path -LiteralPath (Join-Path $data 'archive-verification.pending')) { throw 'Complete the interrupted update first.' }
    if (Test-Path -LiteralPath (Join-Path $data 'evidence-protection-activation.pending')) { throw 'Complete evidence-protection activation first.' }
}

$lock = $null
$ownsOperation = $false
$requestText = $null
$pending = Join-Path $data 'evidence-key.recovery.pending'
$buffer = $null
try {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Open Restore-PikoEvidenceKey.cmd and approve Windows elevation.' }
    $serviceAccountSid = (New-Object Security.Principal.NTAccount('NT SERVICE\piko')).Translate([Security.Principal.SecurityIdentifier]).Value
    Assert-ServiceIdentity
    Assert-NoReparse $program
    $programAcl = (Assert-AdminProtected $program).Sddl
    Assert-Private $data
    $dataAcl = (Get-Acl -LiteralPath $data).Sddl
    foreach ($name in (@($ownedNames) + @('service.json'))) {
        $path = Join-Path $program $name
        Assert-NoReparse $path
        $null = Assert-AdminProtected $path
    }
    if ((Get-Item -LiteralPath (Join-Path $program 'manifest.json')).Length -gt 65536) { throw 'Manifest exceeds bound.' }
    $installed = Read-Snapshot $program
    $configurationHash = (Get-FileHash -LiteralPath $configuration -Algorithm SHA256).Hash
    $configurationAcl = (Get-Acl -LiteralPath $configuration).Sddl
    $configText = Read-Bounded $configuration 65536 $false
    $config = $configText | ConvertFrom-Json
    if ([IO.Path]::GetFullPath($config.data_dir) -ine $data -or $config.viewer_sid -notmatch '^S-1-[0-9-]+$') { throw 'Unexpected installed configuration.' }
    Assert-RecoveryInstallation
    Assert-KeyRecoveryCapabilities $program $installed

    Add-Type -AssemblyName System.Windows.Forms
    $picker = New-Object Windows.Forms.OpenFileDialog
    $picker.Title = 'Seleziona il backup della chiave di piko'
    $picker.Filter = 'Backup piko (*.txt)|*.txt'
    $picker.CheckFileExists = $true
    $picker.Multiselect = $false
    try {
        if ($picker.ShowDialog() -ne [Windows.Forms.DialogResult]::OK) { throw 'Recovery cancelled before any service change.' }
        $backupText = Read-Bounded $picker.FileName 2048 $false
    } finally { $picker.Dispose() }
    $archiveLines = [regex]::Matches($backupText,'(?m)^Archive: ([0-9a-f-]{36})\r?$')
    $recipientLines = [regex]::Matches($backupText,'(?m)^Recipient: (age1[0-9a-z]{1,124})\r?$')
    $codeLines = [regex]::Matches($backupText,'(?m)^Recovery code: (AGE-SECRET-KEY-1[0-9A-Z]{1,110})\r?$')
    if ($archiveLines.Count -ne 1 -or $recipientLines.Count -ne 1 -or $codeLines.Count -ne 1) { throw 'Invalid piko key backup.' }
    $archiveId = [guid]::ParseExact($archiveLines[0].Groups[1].Value,'D').ToString('D')
    if ($archiveId -eq [guid]::Empty.ToString()) { throw 'Invalid archive identifier.' }
    $recipient = $recipientLines[0].Groups[1].Value
    $code = $codeLines[0].Groups[1].Value

    # Failure to acquire this lock must never stop another operation's service.
    $lock = New-Object IO.FileStream((Join-Path $program '.upgrade.lock'),[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None,1,[IO.FileOptions]::DeleteOnClose)
    Assert-RecoveryInstallation
    Set-ServiceState Stopped
    $ownsOperation = $true
    $archiveFingerprint = Read-ArchiveFingerprint
    if (Test-Path -LiteralPath $pending) {
        $requestText = Read-Bounded $pending 16384
        $request = $requestText | ConvertFrom-Json
        Assert-JsonFields $request @('protocol','nonce','archive_id','recipient','code')
        if (!(Test-UnsignedJsonInteger $request.protocol) -or $request.protocol -ne 1 -or $request.archive_id -cne $archiveId -or
            $request.recipient -cne $recipient -or $request.code -cne $code) { throw 'Pending recovery does not match the selected backup.' }
        $nonce = [guid]::ParseExact($request.nonce,'D').ToString('D')
        if ($nonce -cne $request.nonce -or $nonce -eq [guid]::Empty.ToString()) { throw 'Invalid pending nonce.' }
        $statePath = Join-Path $data ('evidence-key.recovery-state-' + $nonce + '.json')
        $baseline = (Read-Bounded $statePath 16384) | ConvertFrom-Json
        Assert-JsonFields $baseline @('protocol','nonce','archive','configuration_hash','manifest_hash')
        if (!(Test-UnsignedJsonInteger $baseline.protocol) -or $baseline.protocol -ne 1 -or $baseline.nonce -cne $nonce -or
            $baseline.archive -cne $archiveFingerprint -or $baseline.configuration_hash -ine $configurationHash -or
            $baseline.manifest_hash -ine $installed.ManifestHash) { throw 'Recovery baseline changed; automatic resume refused.' }
    } else {
        $nonce = [guid]::NewGuid().ToString('D')
        $statePath = Join-Path $data ('evidence-key.recovery-state-' + $nonce + '.json')
        $baseline = [ordered]@{protocol=1;nonce=$nonce;archive=$archiveFingerprint;configuration_hash=$configurationHash;manifest_hash=$installed.ManifestHash}
        Write-NewPrivate $statePath ($baseline | ConvertTo-Json -Compress)
        $requestText = [ordered]@{protocol=1;nonce=$nonce;archive_id=$archiveId;recipient=$recipient;code=$code} | ConvertTo-Json -Compress
        Write-NewPrivate $pending $requestText
    }
    Assert-OwnedRequest
    Flush-Private $statePath
    Flush-Private $pending
    $reportPath = Join-Path $data ('evidence-key.recovery-report-' + $nonce + '.json')
    Assert-NoReparse $reportPath
    if (Test-Path -LiteralPath $reportPath) {
        # Bound attempts; retain exact failure diagnostics before the next try.
        $oldReport = Read-Bounded $reportPath 4096
        $saved = $false
        for ($attempt = 1; $attempt -le 64; $attempt++) {
            $older = Join-Path $data ('evidence-key.recovery-report-' + $nonce + '.attempt-' + $attempt + '.json')
            if (!(Test-Path -LiteralPath $older)) {
                $rootPrefix = $data.TrimEnd('\') + '\'
                if (![IO.Path]::GetFullPath($reportPath).StartsWith($rootPrefix,[StringComparison]::OrdinalIgnoreCase) -or
                    ![IO.Path]::GetFullPath($older).StartsWith($rootPrefix,[StringComparison]::OrdinalIgnoreCase)) { throw 'Recovery diagnostic path escaped its directory.' }
                Assert-NoReparse $older
                Move-Item -LiteralPath $reportPath -Destination $older
                $saved = $true
                break
            }
        }
        if (!$saved) { throw 'Recovery retry limit reached; diagnostics retained.' }
    }
    Assert-RecoveryInstallation
    $controller = Get-Service piko
    $controller.Start([string[]]@('--recover-evidence-key',$nonce))
    $deadline = [DateTime]::UtcNow.AddSeconds(240)
    do {
        $controller.Refresh()
        if ($controller.Status.ToString() -ceq 'Stopped') { break }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($controller.Status.ToString() -cne 'Stopped') { throw 'Key recovery exceeded its deadline.' }
    $service = Get-CimInstance Win32_Service -Filter "Name='piko'"
    if (!$service -or $service.State -cne 'Stopped' -or !(Test-UnsignedJsonInteger $service.ExitCode) -or $service.ExitCode -ne 0 -or
        !(Test-UnsignedJsonInteger $service.ServiceSpecificExitCode) -or $service.ServiceSpecificExitCode -ne 0) { throw 'Recovery did not exit cleanly.' }
    Assert-RecoveryInstallation
    Assert-OwnedRequest
    if ((Read-ArchiveFingerprint) -cne $archiveFingerprint) { throw 'Archive bytes changed during recovery.' }
    $report = (Read-Bounded $reportPath 4096) | ConvertFrom-Json
    Assert-JsonFields $report @('protocol','nonce','result','read_only_archive','key_changes','integrity','error_code')
    # A wrong code/archive must not trap the user behind a request that only
    # accepts that same wrong backup. Release only a clean, nonce-bound refusal
    # which proves that key replacement never began and archive bytes match.
    if ((Test-UnsignedJsonInteger $report.protocol) -and $report.protocol -eq 1 -and $report.nonce -ceq $nonce -and
        $report.result -ceq 'FAIL' -and $report.read_only_archive -is [bool] -and $report.read_only_archive -and
        $report.key_changes -ceq 'none' -and $null -eq $report.integrity -and $report.error_code -ceq 'evidence_key_recovery_failed') {
        Assert-OwnedRequest
        Remove-Item -LiteralPath $pending
        $requestText = $null
        throw 'Backup rejected without key changes; select the matching backup on retry.'
    }
    if (!(Test-UnsignedJsonInteger $report.protocol) -or $report.protocol -ne 1 -or $report.nonce -cne $nonce -or
        $report.result -cne 'PASS' -or $report.read_only_archive -isnot [bool] -or !$report.read_only_archive -or
        $report.key_changes -cne 'complete' -or $null -ne $report.error_code) { throw 'Key recovery was not confirmed.' }
    Assert-JsonFields $report.integrity @('verified_events','head_hash','expired_events','externally_anchored')
    if (!(Test-UnsignedJsonInteger $report.integrity.verified_events) -or !(Test-UnsignedJsonInteger $report.integrity.expired_events) -or
        $report.integrity.externally_anchored -isnot [bool] -or
        ($null -ne $report.integrity.head_hash -and ($report.integrity.head_hash -isnot [string] -or $report.integrity.head_hash -cnotmatch '^[a-fA-F0-9]{64}$'))) { throw 'Invalid integrity result.' }
    Assert-OwnedRequest
    Remove-Item -LiteralPath $pending
    # The archive has passed verification under the newly wrapped local key.
    Set-ServiceState Running
    Write-Output 'Chiave ripristinata e servizio avviato. Originali e rapporto conservati nella cartella privata di piko.'
} catch {
    if ($ownsOperation) {
        try { Set-ServiceState Stopped } catch { }
        # If normal restart failed after releasing the guard, restore the exact
        # owned request. Changed evidence will refuse an automatic later resume.
        if ($requestText -and !(Test-Path -LiteralPath $pending)) {
            try { Write-NewPrivate $pending $requestText } catch { }
        }
    }
    # Never echo parser/OS exception data: it could contain the supplied code.
    Write-Error "Recupero non completato. File e copie conservati. Se era gia iniziato, piko resta sospeso: ripeti Restore-PikoEvidenceKey.cmd con lo stesso backup. Installazioni incoerenti o archivi modificati richiedono prima il recupero dell'installazione."
    exit 1
} finally {
    if ($null -ne $lock) { $lock.Dispose() }
    # Managed strings cannot be securely erased; do not persist them elsewhere.
    $code = $null; $backupText = $null; $requestText = $null; $request = $null
    $codeLines = $null; $recipientLines = $null; $archiveLines = $null
}
