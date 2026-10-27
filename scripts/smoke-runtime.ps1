# Compatibility entry point for CI. All assertions live in smoke.ps1.
[CmdletBinding()]
param(
    [string]$BinaryDirectory = '',
    [string]$EvidenceDirectory = ''
)
$ErrorActionPreference = 'Stop'
# Resolve defaults after parameter binding; Windows PowerShell 5.1 can evaluate
# parameter expressions before PSScriptRoot is available.
if ([string]::IsNullOrWhiteSpace($BinaryDirectory)) {
    $BinaryDirectory = Join-Path $PSScriptRoot '../target/release'
}
if ([string]::IsNullOrWhiteSpace($EvidenceDirectory)) {
    $EvidenceDirectory = Join-Path $PSScriptRoot '../.build/ci'
}
& (Join-Path $PSScriptRoot 'smoke.ps1') -BinaryDirectory $BinaryDirectory -EvidenceDirectory $EvidenceDirectory
