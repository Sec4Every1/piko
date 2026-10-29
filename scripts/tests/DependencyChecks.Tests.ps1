# Exercise the real dependency entrypoint with synthetic commands and files only.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$source = Join-Path $PSScriptRoot '../ci-sbom.ps1'
$fixtureRoot = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) ('.build/dependency-gate-fixture-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path (Join-Path $fixtureRoot 'scripts'), (Join-Path $fixtureRoot 'apps/desktop-ui/src-tauri') -Force | Out-Null
Copy-Item -LiteralPath $source -Destination (Join-Path $fixtureRoot 'scripts/ci-sbom.ps1')
$pikoFixtureState = @{Calls=@(); Fail=@(); Root=$fixtureRoot}
function Record-Command([string]$Name) {
    $pikoFixtureState.Calls += $Name
    $global:LASTEXITCODE = if ($Name -in $pikoFixtureState.Fail) { 1 } else { 0 }
}
function cargo {
    if ($args[0] -eq 'metadata') {
        $manifest = $args[([array]::IndexOf($args, '--manifest-path') + 1)]
        if ($manifest -notlike '*src-tauri*' -and 'metadata-core-outside' -in $pikoFixtureState.Fail) {
            $manifest = Join-Path ($pikoFixtureState.Root + '-sibling') 'Cargo.toml'
        }
        $directory = Split-Path -Parent $manifest
        $name = if ($directory -like '*src-tauri') { 'fixture-desktop' } else { 'fixture-core' }
        return (@{packages=@(@{id=$name;name=$name;manifest_path=$manifest});workspace_members=@($name)} | ConvertTo-Json -Depth 6 -Compress)
    }
    $desktop = $args -contains 'apps/desktop-ui/src-tauri/Cargo.toml'
    $scope = if ($desktop) { 'desktop' } else { 'core' }
    $kind = if ($args -contains '--version') { $args[0] + '-version' } else { $args[0] + '-' + $scope }
    Record-Command $kind
    if ($args[0] -eq 'cyclonedx' -and $args -notcontains '--version' -and $global:LASTEXITCODE -eq 0) {
        $directory = if ($desktop) { Join-Path $pikoFixtureState.Root 'apps/desktop-ui/src-tauri' } else { $pikoFixtureState.Root }
        $name = 'fixture-' + $scope + '.cdx.json'
        '{}' | Set-Content -LiteralPath (Join-Path $directory $name)
    }
}
function npm.cmd {
    Record-Command ('npm-' + $args[0])
    if ($args[0] -eq 'sbom' -and $global:LASTEXITCODE -eq 0) { '{"bomFormat":"CycloneDX"}' }
}
function git { Record-Command 'lockfiles' }
$expected = @('deny-version','cyclonedx-version','deny-core','deny-desktop','cyclonedx-core','cyclonedx-desktop','npm-ci','npm-sbom','npm-audit','lockfiles')
foreach ($case in @(
    @{Name='all green'; Fail=@(); Skip=@()},
    @{Name='core audit failure still collects every independent result'; Fail=@('deny-core'); Skip=@()},
    @{Name='both audits fail'; Fail=@('deny-core','deny-desktop'); Skip=@()},
    @{Name='core SBOM failure never copies stale output'; Fail=@('cyclonedx-core'); Skip=@()},
    @{Name='metadata outside repository is refused'; Fail=@('metadata-core-outside'); Skip=@()},
    @{Name='npm install failure prevents stale frontend checks'; Fail=@('npm-ci'); Skip=@('npm-sbom','npm-audit')},
    @{Name='npm SBOM failure still runs npm audit'; Fail=@('npm-sbom'); Skip=@()},
    @{Name='npm audit and lock integrity failures stay fatal'; Fail=@('npm-audit','lockfiles'); Skip=@()},
    @{Name='missing audit tool refuses before gates'; Fail=@('deny-version'); Skip=$expected[1..9]}
)) {
    $pikoFixtureState.Calls=@(); $pikoFixtureState.Fail=$case.Fail
    # Retain prior outputs between cases, including success -> generation failure.
    $evidence=Join-Path $fixtureRoot '.build/dependencies'
    New-Item -ItemType Directory -Path $evidence -Force | Out-Null
    '{}' | Set-Content -LiteralPath (Join-Path $evidence 'previous-run.cdx.json')
    $failure=$null
    try { & (Join-Path $fixtureRoot 'scripts/ci-sbom.ps1') } catch { $failure=$_.Exception.Message }
    if (Test-Path -LiteralPath (Join-Path $evidence 'previous-run.cdx.json')) { throw 'Prior-run SBOM remained in current evidence' }
    $wanted=@($expected | Where-Object { $_ -notin $case.Skip })
    if (($pikoFixtureState.Calls -join ',') -cne ($wanted -join ',')) { throw ('Unexpected commands: ' + ($pikoFixtureState.Calls -join ',') + '; error=' + $failure) }
    if (($case.Fail.Count -eq 0) -ne ($null -eq $failure)) { throw ('Incorrect gate result: ' + $failure) }
    if ($case.Fail -contains 'cyclonedx-core' -and (Test-Path -LiteralPath (Join-Path $evidence 'fixture-core.cdx.json'))) { throw 'Stale core SBOM copied after failed generation' }
    if ($case.Fail.Count -eq 0) {
        foreach ($name in @('fixture-core.cdx.json','fixture-desktop.cdx.json','frontend.cdx.json')) {
            if (!(Test-Path -LiteralPath (Join-Path $evidence $name))) { throw ('Missing evidence: ' + $name) }
        }
    }
    if ($case.Fail -contains 'deny-core' -and $failure -notlike '*Rust core audit*') { throw 'Core audit failure lost from final summary' }
    if ($case.Fail -contains 'deny-desktop' -and $failure -notlike '*Rust desktop audit*') { throw 'Desktop audit failure lost from final summary' }
    if ($case.Fail -contains 'metadata-core-outside' -and $failure -notlike '*outside the repository*') { throw 'Outside-root metadata was not refused' }
    Write-Output ('PASS ' + $case.Name)
}
Write-Output ('Dependency gate fixtures passed on PowerShell ' + $PSVersionTable.PSVersion + '; no real tools, dependencies or runtime used.')
