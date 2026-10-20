# Run in a separate PowerShell process. All service/CLI calls are fixture doubles;
# no administrator privileges, installed binaries or real evidence are required.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Test-PikoService.ps1'
$tokens = $null
$parseErrors = $null
$null = [Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'Service qualification script does not parse.' }
$fixtureName = 'piko-service-test-' + [guid]::NewGuid().ToString('N')
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$fixture = Join-Path $tempRoot $fixtureName
$fakeProgramFiles = Join-Path $fixture 'program-files'
$fakeProgram = Join-Path $fakeProgramFiles 'piko'
$package = Join-Path $fixture 'package'
$savedProgramFiles = $env:ProgramFiles
$pikoTestState = @{RuntimeVersion='0.2.0'; ServiceStatus='Running'; Mutations=0; HealthCalls=0}
$files = @('piko-service.exe', 'piko.exe', 'piko-desktop.exe', 'piko-network-helper.exe')

function Write-FixtureManifest([string]$Directory) {
    $entries = @($files | ForEach-Object { @{name=$_; sha256=(Get-FileHash -LiteralPath (Join-Path $Directory $_) -Algorithm SHA256).Hash} })
    @{product='piko'; version='0.2.0'; architecture='x64'; files=$entries} |
        ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $Directory 'manifest.json')
}
function Reset-Fixture {
    foreach ($directory in @($fakeProgram, $package)) {
        foreach ($name in $files) { [IO.File]::WriteAllText((Join-Path $directory $name), 'benign fixture: ' + $name) }
        Write-FixtureManifest $directory
    }
    $pikoTestState.RuntimeVersion = '0.2.0'
    $pikoTestState.ServiceStatus = 'Running'
}
function Assert-Refused([string]$Name, [string]$ExpectedMessage) {
    $message = $null
    try { $null = & $scriptPath -ReadOnly -ExpectedPackagePath $package } catch { $message = $_.Exception.Message }
    if (!$message -or $message -notlike $ExpectedMessage) { throw "Unexpected result for '$Name': $message" }
    if ($pikoTestState.Mutations -ne 0) { throw 'Read-only test attempted a service mutation.' }
    Write-Output "PASS $Name"
}

# These functions shadow Windows commands for the invoked script. The mocked CLI
# is bound to the temporary full path, so fixture bytes are never executed.
function Get-CimInstance {
    [pscustomobject]@{PathName=('"' + (Join-Path $fakeProgram 'piko-service.exe') + '" --service --config "' + (Join-Path $fakeProgram 'service.json') + '"'); StartName='NT SERVICE\piko'}
}
function Get-Service {
    $serviceDouble = [pscustomobject]@{Status=$pikoTestState.ServiceStatus}
    $serviceDouble | Add-Member -MemberType ScriptMethod -Name WaitForStatus -Value { param($state, $timeout) }
    return $serviceDouble
}
function Start-Service { $pikoTestState.Mutations++; throw 'Unexpected service start.' }
function Stop-Service { $pikoTestState.Mutations++; throw 'Unexpected service stop.' }

try {
    New-Item -ItemType Directory -Path $fakeProgram, $package -Force | Out-Null
    $env:ProgramFiles = $fakeProgramFiles
    Set-Item -LiteralPath ('Function:' + (Join-Path $fakeProgram 'piko.exe')) -Value {
        param($action)
        if ($action -cne 'health') { throw 'Unexpected fixture CLI command.' }
        $pikoTestState.HealthCalls++
        $global:LASTEXITCODE = 0
        @{runtime_mode='windows_service'; version=$pikoTestState.RuntimeVersion; dropped_events=0; sensors=@(@{id='piko.storage'; state='active'}, @{id='windows.etw.process_image'; state='active'})} | ConvertTo-Json -Depth 5
    }
    Reset-Fixture
    $report = & $scriptPath -ReadOnly -RequireEtw -ExpectedPackagePath $package | ConvertFrom-Json
    if ($report.result -cne 'PASS' -or $report.lifecycle_tested -or !$report.expected_package_checked -or
        $report.scope -cne 'read_only_files_and_health' -or $pikoTestState.HealthCalls -ne 1 -or $pikoTestState.Mutations -ne 0) {
        throw 'Matching read-only fixture was not qualified without lifecycle changes.'
    }
    Write-Output 'PASS matching installation and authenticated-health fixture'

    [IO.File]::AppendAllText((Join-Path $fakeProgram 'piko-desktop.exe'), 'tampered')
    Assert-Refused 'tampered installed UI binary' '*hash mismatch: piko-desktop.exe*'
    Reset-Fixture
    $manifestPath = Join-Path $fakeProgram 'manifest.json'
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $manifest.files[1] = $manifest.files[0]
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath
    Assert-Refused 'duplicate executable and missing CLI' '*hash mismatch*'
    Reset-Fixture
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $manifest.architecture = 'arm64'
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath
    Assert-Refused 'unexpected architecture' '*Invalid piko*manifest*'
    Reset-Fixture
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $manifest.files[0].sha256 = 'invalid'
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath
    Assert-Refused 'malformed checksum' '*hash mismatch*'
    Reset-Fixture
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $manifest.files[0].name = '../escape.exe'
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath
    Assert-Refused 'unexpected filename' '*hash mismatch*'
    Reset-Fixture
    $pikoTestState.ServiceStatus = 'Stopped'
    Assert-Refused 'stopped service refused without starting' '*does not start it*'
    Reset-Fixture
    $pikoTestState.RuntimeVersion = '0.1.0'
    Assert-Refused 'stale running service version' '*version differs*'
    Reset-Fixture
    [IO.File]::AppendAllText((Join-Path $package 'piko-service.exe'), 'another build with same version')
    Write-FixtureManifest $package
    Assert-Refused 'same version with different expected binary' '*differs from the expected package*'
    Write-Output "All nine fixture checks passed on PowerShell $($PSVersionTable.PSVersion). No real service was contacted or changed."
} finally {
    $env:ProgramFiles = $savedProgramFiles
    # Delete only this test's GUID-named directory after checking its absolute parent.
    $resolvedFixture = [IO.Path]::GetFullPath($fixture)
    if ([IO.Path]::GetDirectoryName($resolvedFixture).TrimEnd([char]92) -ine $tempRoot.TrimEnd([char]92) -or
        [IO.Path]::GetFileName($resolvedFixture) -cne $fixtureName) { throw 'Unsafe fixture cleanup target.' }
    if (Test-Path -LiteralPath $resolvedFixture) { Remove-Item -LiteralPath $resolvedFixture -Recurse -Force }
}
