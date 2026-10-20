[CmdletBinding(SupportsShouldProcess)]
param()
$ErrorActionPreference='Stop'
$program=Join-Path $env:ProgramFiles 'piko'
$configPath=Join-Path $program 'service.json'
$service=Get-CimInstance Win32_Service -Filter "Name='piko'"
$expected='"'+(Join-Path $program 'piko-service.exe')+'" --service --config "'+$configPath+'"'
if(!$service -or $service.PathName -cne $expected -or $service.StartName -ine 'NT SERVICE\piko'){throw 'Unexpected service identity'}
$config=Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
$data=[IO.Path]::GetFullPath($config.data_dir)
if($data -cne (Join-Path $env:ProgramData 'piko')){throw 'Unexpected archive location'}
if((Get-Item -LiteralPath $data).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse archive refused'}
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Requires elevated PowerShell'}
if(!$PSCmdlet.ShouldProcess($data,'Back up archive; remove informational DLL unloads and heartbeats; verify and replace archive with explicit new hash chain')){return}
Stop-Service piko
(Get-Service piko).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
$backup=$null
$installed=$false
try {
 $destination=Join-Path $data 'events.without-noise.db'
 foreach($name in @('events.without-noise.db','events.without-noise.db-wal','events.without-noise.db-shm')) {
  if(Test-Path -LiteralPath (Join-Path $data $name)){throw 'Previous maintenance output exists; refusing overwrite'}
 }
 $files=@('events.db','events.db-wal','events.db-shm') | ForEach-Object {Join-Path $data $_} | Where-Object {Test-Path -LiteralPath $_}
 foreach($file in $files){if((Get-Item -LiteralPath $file).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse database refused'}}
 $bytes=($files | ForEach-Object {(Get-Item -LiteralPath $_).Length} | Measure-Object -Sum).Sum
 $drive=(Split-Path -Qualifier $data).TrimEnd(':')
 if((Get-PSDrive $drive).Free -lt ($bytes+2GB)){throw 'Insufficient free space for backup and replacement archive'}
 $backup=Join-Path $data ('before-noise-cleanup-'+[Guid]::NewGuid().ToString())
 New-Item -ItemType Directory -Path $backup | Out-Null
 foreach($file in $files){Copy-Item -LiteralPath $file -Destination (Join-Path $backup ([IO.Path]::GetFileName($file)))}
 $hashes=@($files | ForEach-Object {Get-FileHash -LiteralPath (Join-Path $backup ([IO.Path]::GetFileName($_))) -Algorithm SHA256 | Select-Object Path,Hash})
 $hashes|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $backup 'backup-digests.json')
 $output=& (Join-Path $program 'piko-service.exe') --remove-noise --config $configPath
 if($LASTEXITCODE -ne 0){throw 'Noise cleanup failed; original and protected backup preserved'}
 $report=$output|ConvertFrom-Json
 if(!$report.chain_rebuilt -or $report.policy -cne 'piko.security-noise.v1'){throw 'Unexpected cleanup report'}
 foreach($suffix in @('-wal','-shm')) {
  if(Test-Path -LiteralPath ($destination+$suffix)){throw 'Replacement archive still has SQLite sidecars'}
 }
 $report|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $backup 'cleanup-report.json')
 # Preserve old sidecars rather than deleting them; File.Replace swaps the main
 # database on the same volume. The protected initial backup is always complete.
 foreach($suffix in @('-wal','-shm')) {
  $side=Join-Path $data ('events.db'+$suffix)
  if(Test-Path -LiteralPath $side){Move-Item -LiteralPath $side -Destination (Join-Path $backup ('retired-events.db'+$suffix))}
 }
 [IO.File]::Replace($destination,(Join-Path $data 'events.db'),(Join-Path $backup 'retired-events.db'))
 $installed=$true
 [ordered]@{backup=$backup;cleanup=$report;before_bytes=$bytes;after_bytes=(Get-Item -LiteralPath (Join-Path $data 'events.db')).Length}|ConvertTo-Json -Depth 8
} catch {
 if(!$installed -and $backup) {
  foreach($suffix in @('-wal','-shm')) {
   $side=Join-Path $backup ('retired-events.db'+$suffix)
   if(Test-Path -LiteralPath $side){Move-Item -LiteralPath $side -Destination (Join-Path $data ('events.db'+$suffix))}
  }
 }
 throw
} finally {
 Start-Service piko
 (Get-Service piko).WaitForStatus('Running',[TimeSpan]::FromSeconds(35))
}
