<#
.SYNOPSIS
    RASD-Red cleanup · lsass_memory_access. Exit code 0 only when verified clean.
#>
[CmdletBinding()]
param([Parameter(Mandatory)] [ValidatePattern('^rasd_[0-9a-f]{8}$')] [string] $Marker)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # the runner's 'Stop' is inherited; native stderr must not throw (Windows PowerShell 5.1)

$dump = Join-Path "$env:SystemRoot\Temp" "$Marker.dmp"
if (Test-Path -LiteralPath $dump) { Remove-Item -LiteralPath $dump -Force -ErrorAction SilentlyContinue }
if (-not (Test-Path -LiteralPath $dump)) { Write-Host "[cleanup] verified: dump $Marker.dmp deleted"; exit 0 }
Write-Warning "[cleanup] dump $dump still exists"
exit 1
