# Executes selected production function ASTs, never top-level activation code.
# No service, account, ACL, UAC, installed path or real evidence operations.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$pikoSource = Join-Path (Split-Path -Parent $PSScriptRoot) 'Enable-PikoEvidenceProtection.ps1'
$pikoTokens = $null
$pikoErrors = $null
$pikoAst = [Management.Automation.Language.Parser]::ParseFile($pikoSource, [ref]$pikoTokens, [ref]$pikoErrors)
if ($pikoErrors.Count) { throw 'Production activation source has parser errors.' }
$pikoNames = @('Assert-NoReparse', 'Write-NewSynced', 'Assert-ActivationBaseline')
$pikoFunctions = @($pikoAst.FindAll({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in $pikoNames
}, $true))
foreach ($pikoName in $pikoNames) {
    if (@($pikoFunctions | Where-Object Name -eq $pikoName).Count -ne 1) {
        throw 'Expected one production definition per tested function.'
    }
}
. ([scriptblock]::Create(($pikoFunctions | ForEach-Object { $_.Extent.Text }) -join "`n"))

function Assert-Refused([scriptblock]$Action) {
    $refused = $false
    try { & $Action } catch { $refused = $true }
    if (!$refused) { throw 'Expected a fail-closed refusal.' }
}

$pikoTempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$pikoFixtureName = 'piko-activation-functions-' + [guid]::NewGuid().ToString('N')
$pikoFixture = [IO.Path]::GetFullPath((Join-Path $pikoTempRoot $pikoFixtureName))
New-Item -ItemType Directory -Path $pikoFixture | Out-Null
try {
    # These scoped names are used by the actual Assert-ActivationBaseline.
    $program = Join-Path $pikoFixture 'program'
    $data = Join-Path $pikoFixture 'data'
    New-Item -ItemType Directory -Path $program, $data | Out-Null
    $pikoManifest = Join-Path $program 'manifest.json'
    $pikoKey = Join-Path $data 'evidence-key.json'
    $pikoReceipt = Join-Path $data 'evidence-key.confirmed.json'
    Write-NewSynced $pikoManifest ([Text.Encoding]::UTF8.GetBytes('synthetic manifest'))
    Write-NewSynced $pikoKey ([Text.Encoding]::UTF8.GetBytes('synthetic wrapped key'))
    Write-NewSynced $pikoReceipt ([Text.Encoding]::UTF8.GetBytes('synthetic receipt'))
    $record = [pscustomobject]@{
        manifest_sha256 = (Get-FileHash -LiteralPath $pikoManifest -Algorithm SHA256).Hash
        key_sha256 = (Get-FileHash -LiteralPath $pikoKey -Algorithm SHA256).Hash
        receipt_sha256 = (Get-FileHash -LiteralPath $pikoReceipt -Algorithm SHA256).Hash
    }
    Assert-ActivationBaseline $record
    Write-Output 'PASS exact installation/key/receipt hash baseline is accepted'

    Assert-Refused { Write-NewSynced $pikoKey ([Text.Encoding]::UTF8.GetBytes('replacement')) }
    if ([IO.File]::ReadAllText($pikoKey) -cne 'synthetic wrapped key') { throw 'Existing key fixture was overwritten.' }
    Write-Output 'PASS durable CreateNew never overwrites an existing artifact'

    $pikoOriginalDigest = $record.key_sha256
    $record.key_sha256 = 'not-a-digest'
    Assert-Refused { Assert-ActivationBaseline $record }
    $record.key_sha256 = $pikoOriginalDigest
    Write-Output 'PASS malformed commitment is refused'

    [IO.File]::WriteAllText($pikoReceipt, 'changed synthetic receipt')
    Assert-Refused { Assert-ActivationBaseline $record }
    if ([IO.File]::ReadAllText($pikoReceipt) -cne 'changed synthetic receipt') { throw 'Changed receipt fixture was modified.' }
    if (!(Test-Path -LiteralPath $pikoManifest) -or !(Test-Path -LiteralPath $pikoKey)) { throw 'Baseline artifacts were removed.' }
    Write-Output 'PASS changed receipt refuses activation baseline and preserves artifacts'
    Write-Output "Activation function fixtures passed on PowerShell $($PSVersionTable.PSVersion); top-level activation was never executed."
} finally {
    $pikoResolved = [IO.Path]::GetFullPath($pikoFixture)
    if ([IO.Path]::GetDirectoryName($pikoResolved).TrimEnd('\') -ine $pikoTempRoot.TrimEnd('\') -or
        [IO.Path]::GetFileName($pikoResolved) -cne $pikoFixtureName -or
        ((Get-Item -LiteralPath $pikoResolved).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Fixture cleanup target validation failed.'
    }
    Remove-Item -LiteralPath $pikoResolved -Recurse -Force
}
