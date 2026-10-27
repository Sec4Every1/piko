# Real production metadata functions; ACL boundary is doubled, not qualified.
# Neither recovery script's top level, SCM, keys nor installed paths execute.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$pikoScripts = Split-Path -Parent $PSScriptRoot
function Import-ProductionFunctions([string]$Path, [string[]]$Names) {
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors.Count) {
        $details = ($errors | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Message)" }) -join '; '
        throw "Production recovery source has parser errors: $details"
    }
    $functions = @($ast.FindAll({param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in $Names
    }, $true))
    foreach ($name in $Names) {
        if (@($functions | Where-Object Name -eq $name).Count -ne 1) { throw 'Expected one production function.' }
    }
    return ($functions | ForEach-Object { $_.Extent.Text }) -join "`n"
}
. ([scriptblock]::Create((Import-ProductionFunctions (Join-Path $pikoScripts 'Restore-PikoEvidenceKey.ps1') @('Assert-NoReparse','Assert-JsonFields','Test-UnsignedJsonInteger'))))
. ([scriptblock]::Create((Import-ProductionFunctions (Join-Path $pikoScripts 'Resume-PikoUpdate.ps1') @('Read-ResumeJson'))))
function Assert-Refused([scriptblock]$Action) {
    $refused = $false
    try { & $Action } catch { $refused = $true }
    if (!$refused) { throw 'Expected recovery metadata refusal.' }
}
$pikoTempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$pikoFixtureName = 'piko-recovery-metadata-' + [guid]::NewGuid().ToString('N')
$pikoFixture = [IO.Path]::GetFullPath((Join-Path $pikoTempRoot $pikoFixtureName))
New-Item -ItemType Directory -Path $pikoFixture | Out-Null
function Assert-AdminProtected([string]$Path) {
    if ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Path)) -ine $pikoFixture) {
        throw 'Fixture ACL double received an external path.'
    }
    return [pscustomobject]@{Sddl='fixture ACL boundary only'}
}
try {
    Assert-JsonFields ([pscustomobject]@{protocol=1;nonce='synthetic'}) @('protocol','nonce')
    foreach ($value in @($null, @{}, [pscustomobject]@{protocol=1},
        [pscustomobject]@{protocol=1;nonce='synthetic';activate=$true},
        [pscustomobject]@{Protocol=1;nonce='synthetic'})) {
        Assert-Refused { Assert-JsonFields $value @('protocol','nonce') }
    }
    Write-Output 'PASS metadata objects reject missing, injected and mis-cased fields'
    foreach ($value in @($null,$true,-1,1.5,'1')) {
        if (Test-UnsignedJsonInteger $value) { throw 'Non-integer recovery protocol value accepted.' }
    }
    if (!(Test-UnsignedJsonInteger 0) -or !(Test-UnsignedJsonInteger 1)) { throw 'Unsigned integer rejected.' }
    Write-Output 'PASS numeric protocol values never coerce booleans or strings'

    $path = Join-Path $pikoFixture 'recovery.json'
    $bytes = [Text.Encoding]::UTF8.GetBytes('{"protocol":1}')
    [IO.File]::WriteAllBytes($path,$bytes)
    $record = Read-ResumeJson $path $bytes.Length
    if ($record.protocol -ne 1) { throw 'Bounded metadata was not decoded.' }
    Assert-Refused { Read-ResumeJson $path ($bytes.Length-1) }
    if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) -cne [Convert]::ToBase64String($bytes)) { throw 'Refused metadata was modified.' }
    $handle = [IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    $handle.Dispose()
    Write-Output 'PASS oversized metadata refuses without mutation or retained handles'

    [IO.File]::WriteAllBytes($path,[Text.Encoding]::UTF8.GetBytes('{invalid'))
    Assert-Refused { Read-ResumeJson $path 1024 }
    $handle = [IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    $handle.Dispose()
    if ([IO.File]::ReadAllText($path) -cne '{invalid') { throw 'Invalid metadata was modified.' }
    Write-Output 'PASS malformed JSON remains preserved and releases its read handle'
    Write-Output "Recovery metadata fixtures passed on PowerShell $($PSVersionTable.PSVersion); ACL/SCM/key behavior is not qualified."
} finally {
    $resolved = [IO.Path]::GetFullPath($pikoFixture)
    if ([IO.Path]::GetDirectoryName($resolved).TrimEnd('\') -ine $pikoTempRoot.TrimEnd('\') -or
        [IO.Path]::GetFileName($resolved) -cne $pikoFixtureName -or
        ((Get-Item -LiteralPath $resolved).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unsafe fixture cleanup target.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
