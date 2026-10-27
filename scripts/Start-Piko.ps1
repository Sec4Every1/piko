# Optional per-user run without installing SCM. Closing the UI leaves monitoring on.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$cli = Join-Path $PSScriptRoot 'piko.exe'
$desktop = Join-Path $PSScriptRoot 'piko-desktop.exe'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Launch piko from a normal user session; the UI must not run elevated.' }
$installed = Get-Service -Name piko -ErrorAction SilentlyContinue
if ($installed) {
    # The installed UI must remain reachable when collection is stopped, so a
    # user can see the real disconnected state and resume a guarded activation.
    # Never create a second console runtime for an installed service.
    $installedDesktop = Join-Path $env:ProgramFiles 'piko\piko-desktop.exe'
    if (!(Test-Path -LiteralPath $installedDesktop -PathType Leaf)) {
        throw 'Interfaccia installata mancante. Conserva i dati e usa Recover-Piko.cmd dal pacchetto.'
    }
    Start-Process -FilePath $installedDesktop
    return
}
$connected = $false
try {
    $snapshot = & $cli health 2>$null | ConvertFrom-Json
    $connected = $LASTEXITCODE -eq 0 -and $snapshot.product -eq 'piko'
} catch { $connected = $false }
if ($connected -and $snapshot.version -ne '0.2.0') { throw 'An older piko runtime is running. Stop that runtime before starting version 0.2.0; its existing data will be preserved.' }
if (!$connected) {
    $data = Join-Path $env:LOCALAPPDATA 'piko-monitor'
    New-Item -ItemType Directory -Path $data -Force | Out-Null
    $config = Join-Path $data 'console.json'
    if (!(Test-Path -LiteralPath $config)) {
        # Fresh profiles only. Never rewrite an existing archive's policy.
        $json = @{data_dir=$data; heartbeat_seconds=5; flush_seconds=5; max_disk_mib=2048; retention_months=12; queue_capacity=256} | ConvertTo-Json
        [IO.File]::WriteAllText($config, $json, (New-Object Text.UTF8Encoding($false)))
    }
    $runtime = Start-Process -FilePath (Join-Path $PSScriptRoot 'piko-service.exe') -ArgumentList @('--config', ('"' + $config + '"')) -PassThru -WindowStyle Hidden
    # The dashboard can report unavailability and retry while a large archive
    # opens. Do not turn a short readiness window into a terminal-only workflow.
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        if ($runtime.HasExited) {
            Start-Process -FilePath $desktop
            Write-Warning 'Monitor locale non avviato: la dashboard mostra la disconnessione. La raccolta non risulta attiva; dati e configurazione sono conservati.'
            return
        }
        try {
            $snapshot = & $cli health 2>$null | ConvertFrom-Json
            if ($LASTEXITCODE -eq 0 -and $snapshot.product -eq 'piko') { $connected = $true; break }
        } catch { }
        Start-Sleep -Milliseconds 100
    }
    if (!$connected) {
        Start-Process -FilePath $desktop
        Write-Output 'Piko sta ancora aprendo il proprio archivio. La dashboard mostra lo stato e tenta la riconnessione.'
        return
    }
    Write-Output "Per-user monitoring started (PID $($runtime.Id)). It stops at logoff or when this process is stopped; it is not installed as a Windows service."
}
Start-Process -FilePath $desktop
