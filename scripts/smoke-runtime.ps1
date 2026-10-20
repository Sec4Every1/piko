# Compatibility entry point for CI. All assertions live in smoke.ps1.
[CmdletBinding()]
param(
    [string]$BinaryDirectory = (Join-Path $PSScriptRoot '../target/release'),
    [string]$EvidenceDirectory = (Join-Path $PSScriptRoot '../.build/ci')
)
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'smoke.ps1') -BinaryDirectory $BinaryDirectory -EvidenceDirectory $EvidenceDirectory
