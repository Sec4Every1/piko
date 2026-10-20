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
if(!$PSCmdlet.ShouldProcess($data,'Stop piko, back up SQLite files, losslessly compress existing evidence and restart')){return}
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Requires elevated PowerShell'}
Stop-Service piko
(Get-Service piko).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
try {
 $files=@('events.db','events.db-wal','events.db-shm') | ForEach-Object {Join-Path $data $_} | Where-Object {Test-Path -LiteralPath $_}
 $bytes=($files | ForEach-Object {(Get-Item -LiteralPath $_).Length} | Measure-Object -Sum).Sum
 $drive=(Split-Path -Qualifier $data).TrimEnd(':')
 if((Get-PSDrive $drive).Free -lt ($bytes+2GB)){throw 'Insufficient free space for protected backup and WAL margin'}
 $backup=Join-Path $data ('before-compression-'+[Guid]::NewGuid().ToString())
 New-Item -ItemType Directory -Path $backup | Out-Null
 foreach($file in $files){Copy-Item -LiteralPath $file -Destination (Join-Path $backup ([IO.Path]::GetFileName($file)))}
 $output=& (Join-Path $program 'piko-service.exe') --compact-evidence --config $configPath
 if($LASTEXITCODE -ne 0){throw 'Evidence compression failed; protected backup preserved'}
 $report=$output|ConvertFrom-Json
 $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $backup 'compaction-report.json')
 [ordered]@{backup=$backup;compaction=$report} | ConvertTo-Json -Depth 6
} finally {
 Start-Service piko
 (Get-Service piko).WaitForStatus('Running',[TimeSpan]::FromSeconds(35))
}
