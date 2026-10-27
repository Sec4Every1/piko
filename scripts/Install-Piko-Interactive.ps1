[CmdletBinding()]
param([switch]$Elevated, [string]$ViewerSid, [switch]$RecoverInconsistentInstallation, [switch]$ResumeInterruptedUpdate, [switch]$RestoreEvidenceKey, [switch]$ResumeEvidenceProtection)
$ErrorActionPreference = 'Stop'
if ($ResumeEvidenceProtection -and ($RestoreEvidenceKey -or $ResumeInterruptedUpdate -or $RecoverInconsistentInstallation)) { throw 'Resume protection separately from installation and key recovery.' }
if ($ResumeInterruptedUpdate -and $RecoverInconsistentInstallation) { throw 'Scegli ripresa aggiornamento oppure recupero installazione, non entrambi.' }
if ($RestoreEvidenceKey -and ($ResumeInterruptedUpdate -or $RecoverInconsistentInstallation)) { throw 'Esegui il recupero della chiave separatamente dagli aggiornamenti.' }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$ViewerSid) { $ViewerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value }
if ($ViewerSid -notmatch '^S-1-[0-9-]+$') { throw 'Windows could not determine the account that will use piko.' }

if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    try {
        $scriptPath = (Resolve-Path -LiteralPath $PSCommandPath).Path
        $arguments = '-NoProfile -STA -ExecutionPolicy Bypass -File "' + $scriptPath + '" -Elevated -ViewerSid "' + $ViewerSid + '"'
        if ($RecoverInconsistentInstallation) { $arguments += ' -RecoverInconsistentInstallation' }
        if ($ResumeInterruptedUpdate) { $arguments += ' -ResumeInterruptedUpdate' }
        if ($RestoreEvidenceKey) { $arguments += ' -RestoreEvidenceKey' }
        if ($ResumeEvidenceProtection) { $arguments += ' -ResumeEvidenceProtection' }
        $child = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList $arguments -Verb RunAs -Wait -PassThru
        if ($child.ExitCode -ne 0) { throw "Installer exited with code $($child.ExitCode)." }
        $desktop = Join-Path $env:ProgramFiles 'piko\piko-desktop.exe'
        if (Test-Path -LiteralPath $desktop) { Start-Process -FilePath $desktop }
        exit 0
    } catch {
        Write-Error "Installazione annullata o non riuscita. Se hai annullato la richiesta Windows, nessuna installazione è stata completata. $($_.Exception.Message)"
        exit 1
    }
}

if (!$Elevated) {
    Write-Error 'Apri Install-Piko.cmd da una sessione utente normale; non avviare la dashboard come amministratore.'
    exit 1
}

$existingService = Get-Service -Name piko -ErrorAction SilentlyContinue
if ($ResumeEvidenceProtection) {
    if (!$existingService) { throw 'No installed piko service to resume.' }
    # Resume the procedure embedded in the installed, manifest-owned helper.
    # Do not run a potentially mismatched script from the downloaded package.
    $helper = Join-Path $env:ProgramFiles 'piko\piko-network-helper.exe'
    $resume = Start-Process -FilePath $helper -ArgumentList '--resume-evidence-protection' -WindowStyle Hidden -Wait -PassThru
    if ($resume.ExitCode -ne 0) { throw 'Activation resume refused; retained files were not removed.' }
    exit 0
}
if ($RestoreEvidenceKey) {
    if (!$existingService) { throw 'Installa piko prima di recuperare una chiave.' }
    & (Join-Path $PSScriptRoot 'Restore-PikoEvidenceKey.ps1')
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    exit 0
}
if ($existingService) {
    $updater = Join-Path $PSScriptRoot 'Update-Piko.ps1'
    if (!(Test-Path -LiteralPath $updater)) { throw 'Update-Piko.ps1 is missing from this package.' }
    # An existing installation keeps its enrolled viewer, policy and evidence.
    # The updater independently validates the installation and may refuse it.
    if ($ResumeInterruptedUpdate) { & $updater -ResumeInterruptedUpdate }
    elseif ($RecoverInconsistentInstallation) { & $updater -PackagePath $PSScriptRoot -RecoverInconsistentInstallation }
    elseif (Test-Path -LiteralPath (Join-Path $env:ProgramData 'piko\archive-verification.pending')) { & $updater -ResumeInterruptedUpdate }
    else { & $updater -PackagePath $PSScriptRoot }
} else {
    if ($RecoverInconsistentInstallation -or $ResumeInterruptedUpdate) { throw 'Nessuna installazione piko da recuperare. Usa Install-Piko.cmd per una nuova installazione.' }
    $installer = Join-Path $PSScriptRoot 'Install-Piko.ps1'
    if (!(Test-Path -LiteralPath $installer)) { throw 'Install-Piko.ps1 is missing from this package.' }
    & $installer -ViewerSid $ViewerSid -EnableEtw
}
if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
