param([ValidateSet('debug','release')][string]$Profile = 'release')
$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
$destination = Join-Path $workspace "artifacts\piko-0.2.0-windows-x64-$Profile"
New-Item -ItemType Directory -Path $destination -Force | Out-Null
$binaries = @(
    @{source="target\$Profile\piko-service.exe"; name='piko-service.exe'},
    @{source="target\$Profile\piko.exe"; name='piko.exe'},
    @{source="target\$Profile\piko-network-helper.exe"; name='piko-network-helper.exe'},
    @{source="apps\desktop-ui\src-tauri\target\$Profile\piko-desktop.exe"; name='piko-desktop.exe'}
)
$hashes = foreach ($binary in $binaries) {
    $source = Join-Path $workspace $binary.source
    if (!(Test-Path -LiteralPath $source)) { throw "Missing binary: $source. Build this profile before packaging." }
    $hash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    $targetBinary = Join-Path $destination $binary.name
    # Do not rewrite an identical running executable while refreshing documentation.
    if (!(Test-Path -LiteralPath $targetBinary) -or (Get-FileHash -LiteralPath $targetBinary -Algorithm SHA256).Hash -cne $hash) {
        Copy-Item -LiteralPath $source -Destination $targetBinary -Force
    }
    @{name=$binary.name; sha256=$hash}
}
$manifest = @{product='piko'; version='0.2.0'; architecture='x64'; profile=$Profile; signed=$false; files=@($hashes)} | ConvertTo-Json -Depth 5
[IO.File]::WriteAllText((Join-Path $destination 'manifest.json'), $manifest, (New-Object Text.UTF8Encoding($false)))
foreach ($script in @('Install-Piko.ps1','Install-Piko-Interactive.ps1','Install-Piko.cmd','Recover-Piko.cmd','Update-Piko.ps1','Backup-PikoInstallation.ps1','Uninstall-Piko.ps1','Set-PikoEtwPermission.ps1','Compress-PikoArchive.ps1','Remove-PikoNoise.ps1','Set-PikoRetention.ps1','Test-PikoService.ps1','Start-Piko.ps1','Open-Piko.cmd')) { Copy-Item -LiteralPath (Join-Path $PSScriptRoot $script) -Destination (Join-Path $destination $script) -Force }
Copy-Item -LiteralPath (Join-Path $workspace 'LICENSE') -Destination (Join-Path $destination 'LICENSE') -Force
Copy-Item -LiteralPath (Join-Path $workspace 'README.md') -Destination (Join-Path $destination 'README.md') -Force
Copy-Item -LiteralPath (Join-Path $workspace 'docs\INSTALLATION.md') -Destination (Join-Path $destination 'LEGGIMI.md') -Force
Copy-Item -LiteralPath (Join-Path $workspace 'docs\RESPONSE.md') -Destination (Join-Path $destination 'RESPONSE.md') -Force
Copy-Item -LiteralPath (Join-Path $workspace 'docs\MANUALE_UTENTE.md') -Destination (Join-Path $destination 'MANUALE_UTENTE.md') -Force
[IO.File]::WriteAllText((Join-Path $destination 'INSTALL-COMMAND.txt'), "Fare doppio clic su Install-Piko.cmd in questa cartella e confermare la richiesta Windows.`r`nL'installer rileva automaticamente l'utente sul PC di destinazione.`r`n", (New-Object Text.UTF8Encoding($false)))
Write-Output $destination

& (Join-Path $PSScriptRoot 'Copy-PikoThirdPartySources.ps1') -Destination $destination


Copy-Item -LiteralPath (Join-Path $workspace 'docs\REQUIREMENT_MATRIX.md') -Destination (Join-Path $destination 'STATO_REQUISITI.md') -Force

Copy-Item -LiteralPath (Join-Path $workspace 'docs\IMPLEMENTATION_STATUS.md') -Destination (Join-Path $destination 'STATO_IMPLEMENTAZIONE.md') -Force

Copy-Item -LiteralPath (Join-Path $workspace 'docs\ADVISORY_FEED.md') -Destination (Join-Path $destination 'ADVISORY_FEED.md') -Force

Copy-Item -LiteralPath (Join-Path $workspace 'docs\VALIDATION.md') -Destination (Join-Path $destination 'VALIDAZIONE.md') -Force
