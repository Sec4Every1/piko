# Optional per-user run without installing SCM. Closing the UI leaves monitoring on.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$cli = Join-Path $PSScriptRoot 'piko.exe'
$desktop = Join-Path $PSScriptRoot 'piko-desktop.exe'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Launch piko from a normal user session; the UI must not run elevated.' }
$installed = Get-Service -Name piko -ErrorAction SilentlyContinue
if ($installed -and $installed.Status -ne 'Running') { throw 'The installed piko service is stopped. Start it through the Windows service manager.' }
$connected = $false
try {
    $snapshot = & $cli health 2>$null | ConvertFrom-Json
    $connected = $LASTEXITCODE -eq 0 -and $snapshot.product -eq 'piko'
} catch { $connected = $false }
if (!$connected -and $installed) { throw 'The installed service is inaccessible. Verify that your SID was enrolled at installation.' }
if ($connected -and $snapshot.version -ne '0.2.0') { throw 'An older piko runtime is running. Stop that runtime before starting version 0.2.0; its existing data will be preserved.' }
if (!$connected) {
    $data = Join-Path $env:LOCALAPPDATA 'piko-monitor'
    New-Item -ItemType Directory -Path $data -Force | Out-Null
    $config = Join-Path $data 'console.json'
    if (!(Test-Path -LiteralPath $config)) {
        $json = @{data_dir=$data; heartbeat_seconds=5; flush_seconds=5; max_disk_mib=256; queue_capacity=256} | ConvertTo-Json
        [IO.File]::WriteAllText($config, $json, (New-Object Text.UTF8Encoding($false)))
    }
    $runtime = Start-Process -FilePath (Join-Path $PSScriptRoot 'piko-service.exe') -ArgumentList @('--config', ('"' + $config + '"')) -PassThru -WindowStyle Hidden
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        if ($runtime.HasExited) { throw 'The local runtime could not start. Run piko-service.exe in a terminal to read its diagnostics.' }
        try {
            $snapshot = & $cli health 2>$null | ConvertFrom-Json
            if ($LASTEXITCODE -eq 0 -and $snapshot.product -eq 'piko') { $connected = $true; break }
        } catch { }
        Start-Sleep -Milliseconds 100
    }
    if (!$connected) { throw 'Runtime initialization is still pending. Retry after checking its status.' }
    Write-Output "Per-user monitoring started (PID $($runtime.Id)). It stops at logoff or when this process is stopped; it is not installed as a Windows service."
}
Start-Process -FilePath $desktop
