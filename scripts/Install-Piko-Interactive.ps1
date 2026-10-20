[CmdletBinding()]
param([switch]$Elevated, [string]$ViewerSid)
$ErrorActionPreference = 'Stop'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$ViewerSid) { $ViewerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value }
if ($ViewerSid -notmatch '^S-1-[0-9-]+$') { throw 'Windows could not determine the account that will use piko.' }

if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    try {
        $scriptPath = (Resolve-Path -LiteralPath $PSCommandPath).Path
        $arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $scriptPath + '" -Elevated -ViewerSid "' + $ViewerSid + '"'
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
if ($existingService) {
    $updater = Join-Path $PSScriptRoot 'Update-Piko.ps1'
    if (!(Test-Path -LiteralPath $updater)) { throw 'Update-Piko.ps1 is missing from this package.' }
    # An existing installation keeps its enrolled viewer, policy and evidence.
    # The updater independently validates the installation and may refuse it.
    & $updater -PackagePath $PSScriptRoot
} else {
    $installer = Join-Path $PSScriptRoot 'Install-Piko.ps1'
    if (!(Test-Path -LiteralPath $installer)) { throw 'Install-Piko.ps1 is missing from this package.' }
    & $installer -ViewerSid $ViewerSid -EnableEtw
}
if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
