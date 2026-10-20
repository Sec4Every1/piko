[CmdletBinding(SupportsShouldProcess)]
param([ValidateRange(0,120)][int]$Months=12)
$ErrorActionPreference='Stop'
$program=Join-Path $env:ProgramFiles 'piko'
$configPath=Join-Path $program 'service.json'
$service=Get-CimInstance Win32_Service -Filter "Name='piko'"
$expected='"'+(Join-Path $program 'piko-service.exe')+'" --service --config "'+$configPath+'"'
if(!$service -or $service.StartName -ine 'NT SERVICE\piko' -or $service.PathName -cne $expected){throw 'Unexpected piko service identity'}
$config=Get-Content -LiteralPath $configPath -Raw|ConvertFrom-Json
$data=[IO.Path]::GetFullPath($config.data_dir)
if($data -cne (Join-Path $env:ProgramData 'piko') -or ((Get-Item -LiteralPath $data).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected/reparse archive location'}
if(!$PSCmdlet.ShouldProcess($data,"Back up current SQLite/config and set $Months calendar months retention (0 disables); space limits never shorten retention")){return}
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Requires elevated PowerShell'}
Stop-Service piko
(Get-Service piko).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
try {
 $files=@('events.db','events.db-wal','events.db-shm')|ForEach-Object {Join-Path $data $_}|Where-Object {Test-Path -LiteralPath $_}
 $bytes=($files|ForEach-Object {(Get-Item -LiteralPath $_).Length}|Measure-Object -Sum).Sum
 if((Get-PSDrive (Split-Path -Qualifier $data).TrimEnd(':')).Free -lt ($bytes+2GB)){throw 'Insufficient space for protected backup'}
 $backup=Join-Path $data ('before-retention-'+[Guid]::NewGuid().ToString())
 New-Item -ItemType Directory -Path $backup|Out-Null
 foreach($file in $files){Copy-Item -LiteralPath $file -Destination (Join-Path $backup ([IO.Path]::GetFileName($file)))}
 Copy-Item -LiteralPath $configPath -Destination (Join-Path $backup 'service.json')
 $config|Add-Member -NotePropertyName retention_months -NotePropertyValue $(if($Months -eq 0){$null}else{$Months}) -Force
 $temporary=Join-Path $program ('service-retention-'+[Guid]::NewGuid().ToString()+'.tmp')
 [IO.File]::WriteAllText($temporary,($config|ConvertTo-Json -Depth 6),(New-Object Text.UTF8Encoding($false)))
 [IO.File]::Replace($temporary,$configPath,$null)
 [ordered]@{result='configured';months=$Months;budget_mib=$config.max_disk_mib;backup=$backup;early_deletion_for_space=$false}|ConvertTo-Json
} finally {
 Start-Service piko
 (Get-Service piko).WaitForStatus('Running',[TimeSpan]::FromSeconds(35))
}
