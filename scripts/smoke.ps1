param([string]$BuildProfile = 'debug', [string]$BinaryDirectory = '', [string]$EvidenceDirectory = '')
$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
if (!$BinaryDirectory) { $BinaryDirectory = Join-Path $workspace "target\$BuildProfile" }
$servicePath = [IO.Path]::GetFullPath((Join-Path $BinaryDirectory 'piko-service.exe'))
$cliPath = [IO.Path]::GetFullPath((Join-Path $BinaryDirectory 'piko.exe'))
if (!(Test-Path -LiteralPath $servicePath) -or !(Test-Path -LiteralPath $cliPath)) {
    throw 'Build the binaries first: cargo build --workspace --locked'
}
$runId = [guid]::NewGuid().ToString('N')
$runDir = Join-Path $workspace ".runtime\smoke-$runId"
New-Item -ItemType Directory -Path $runDir -Force | Out-Null
$configPath = Join-Path $runDir 'config.json'
@{data_dir=$runDir; heartbeat_seconds=1; flush_seconds=2; max_disk_mib=16; queue_capacity=16} |
    ConvertTo-Json | Set-Content -LiteralPath $configPath -Encoding UTF8
# Windows PowerShell UTF8 writes a BOM; Rust JSON expects plain UTF8.
$configText = Get-Content -LiteralPath $configPath -Raw
[IO.File]::WriteAllText($configPath, $configText, (New-Object Text.UTF8Encoding($false)))
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
$pipeName = "piko.dev.v1.$sid.$sessionId"

function Read-Exact([IO.Stream]$Stream, [int]$Length) {
    $buffer = New-Object byte[] $Length
    $offset = 0
    while ($offset -lt $Length) {
        $read = $Stream.Read($buffer, $offset, $Length - $offset)
        if ($read -eq 0) { throw 'Unexpected IPC EOF' }
        $offset += $read
    }
    return ,$buffer
}
function Invoke-Piko([hashtable]$Command, [int]$Version = 1) {
    $client = New-Object IO.Pipes.NamedPipeClientStream('.', $pipeName, [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::None, [Security.Principal.TokenImpersonationLevel]::Identification)
    try {
        $client.Connect(2500)
        $payload = [Text.Encoding]::UTF8.GetBytes((@{protocol_version=$Version; request_id=71; command=$Command} | ConvertTo-Json -Depth 10 -Compress))
        $header = [BitConverter]::GetBytes([uint32]$payload.Length)
        $client.Write($header,0,4)
        $client.Write($payload,0,$payload.Length)
        $client.Flush()
        $size = [BitConverter]::ToUInt32((Read-Exact $client 4),0)
        if ($size -eq 0 -or $size -gt 4MB) { throw 'Invalid response size' }
        return ([Text.Encoding]::UTF8.GetString((Read-Exact $client $size)) | ConvertFrom-Json)
    } finally { $client.Dispose() }
}

$service = Start-Process -FilePath $servicePath -ArgumentList @('--config', ('"' + $configPath + '"'), '--run-for-seconds', '12') -WorkingDirectory $workspace -PassThru -WindowStyle Hidden -RedirectStandardError (Join-Path $runDir 'service.log')
$null = $service.Handle # Keep the process handle so Windows PowerShell 5 retains ExitCode.
try {
    $health = $null
    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        try { $health = Invoke-Piko @{action='get_health'}; if ($health.result.Ok.data.stored_events -ge 2) { break }; Start-Sleep -Milliseconds 100 }
        catch { if ($service.HasExited) { throw }; Start-Sleep -Milliseconds 100 }
    }
    if ($null -eq $health -or $health.result.Ok.data.protection_state -notin @('limited', 'degraded')) { throw 'Health failed or falsely claims full protection' }
    if ($health.result.Ok.data.runtime_mode -ne 'development_console') { throw 'Unexpected runtime mode' }
    $events = Invoke-Piko @{action='list_events';filter=@{limit=100}}
    if ($events.result.Ok.data.Count -lt 2) { throw 'No persisted runtime events' }
    if (@($events.result.Ok.data | Where-Object { $_.process.pid -eq $service.Id }).Count -eq 0) { throw 'Events do not belong to the process created by this test' }
    if ($events.result.Ok.data[0].boot_id) { throw 'Fabricated boot identity' }
    if ($events.result.Ok.data[0].logon_session) { throw 'Fabricated authentication identity' }
    $invalidVersion = Invoke-Piko @{action='get_health'} 99
    if ($invalidVersion.result.Err.code -ne 'protocol_version') { throw 'Invalid protocol version was accepted' }
    $invalidQuery = Invoke-Piko @{action='list_events';filter=@{limit=1001}}
    if (!$invalidQuery.result.Err) { throw 'Unbounded query accepted' }
    $verify = Invoke-Piko @{action='verify_store'}
    if ($verify.result.Ok.data.verified_events -lt 2 -or $verify.result.Ok.data.externally_anchored) { throw 'Invalid integrity report' }
    $cli = & $cliPath health | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $cli.product -ne 'piko') { throw 'CLI roundtrip failed' }
    # Closing clients must not close the independent backend.
    Start-Sleep -Milliseconds 2100
    $later = Invoke-Piko @{action='get_health'}
    if ($later.result.Ok.data.uptime_seconds -lt 2) { throw 'Runtime failed to continue without a client' }
    if (!$service.WaitForExit(15000)) { throw 'Runtime did not honor its bounded shutdown' }
    if ($service.ExitCode -ne 0) { throw "Runtime exit code: $($service.ExitCode)" }
    $summary = [ordered]@{result='PASS'; tests=10; events_verified=$verify.result.Ok.data.verified_events; evidence_directory=$runDir} | ConvertTo-Json
    if ($EvidenceDirectory) {
        New-Item -ItemType Directory -Path $EvidenceDirectory -Force | Out-Null
        $summary | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'ipc-smoke.json')
        Copy-Item -LiteralPath (Join-Path $runDir 'service.log') -Destination (Join-Path $EvidenceDirectory 'runtime-smoke.log')
    }
    $summary
} finally {
    if (!$service.HasExited) { Stop-Process -Id $service.Id -ErrorAction SilentlyContinue }
}
