$ErrorActionPreference = 'Stop'
$backupScript = Join-Path (Split-Path -Parent $PSScriptRoot) 'Backup-PikoInstallation.ps1'
$fixture = Join-Path $env:ProgramData ('piko-recovery-fixture-' + [guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $fixture | Out-Null
    $fixtureAcl = New-Object Security.AccessControl.DirectorySecurity
    $fixtureAcl.SetAccessRuleProtection($true, $false)
    $fixtureSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $fixtureAcl.SetOwner($fixtureSid)
    foreach ($sid in @($fixtureSid.Value,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique) {
        $identity = New-Object Security.Principal.SecurityIdentifier($sid)
        $fixtureAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
    }
    Set-Acl -LiteralPath $fixture -AclObject $fixtureAcl
    $names = @('piko-service.exe','piko.exe','piko-desktop.exe','piko-network-helper.exe')
    foreach ($name in $names) { [IO.File]::WriteAllText((Join-Path $fixture $name), 'benign fixture ' + $name) }
    $entries = @($names | ForEach-Object { @{name=$_; sha256=(Get-FileHash (Join-Path $fixture $_)).Hash} })
    @{product='piko';files=$entries} | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $fixture 'manifest.json')
    '{}' | Set-Content (Join-Path $fixture 'service.json')
    $destination = Join-Path $fixture 'backup'
    & $backupScript -InstallationPath $fixture -Destination $destination -WhatIf
    if (Test-Path $destination) { throw 'WhatIf wrote files.' }
    [IO.File]::AppendAllText((Join-Path $fixture 'piko-service.exe'), ' inconsistent')
    $result = & $backupScript -InstallationPath $fixture -Destination $destination -Confirm:$false | ConvertFrom-Json
    if ($result.files -ne 6 -or $result.installed_manifest_consistent -ne $false) { throw 'Mismatch was hidden.' }
    foreach ($name in @($names) + @('manifest.json','service.json')) {
        if ((Get-FileHash (Join-Path $fixture $name)).Hash -ne (Get-FileHash (Join-Path $destination $name)).Hash) { throw 'Copy mismatch.' }
    }
    $caller = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $acl = Get-Acl -LiteralPath $destination
    if (!$acl.AreAccessRulesProtected) { throw 'Private backup inherited unrelated access.' }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin @($caller,'S-1-5-18','S-1-5-32-544')) { throw 'Unexpected backup reader.' }
    }
    $refused = $false
    try { & $backupScript -InstallationPath $fixture -Destination $destination -Confirm:$false } catch { $refused = $_.Exception.Message -like '*must not already exist*' }
    if (!$refused) { throw 'Existing backup was not refused.' }
    Write-Output "PASS WhatIf, six exact copies preserving mismatch, private ACL and no overwrite on PowerShell $($PSVersionTable.PSVersion)"
} finally {
    if ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($fixture)) -ine $env:ProgramData -or [IO.Path]::GetFileName($fixture) -notlike 'piko-recovery-fixture-*') { throw 'Unsafe cleanup.' }
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force }
}
