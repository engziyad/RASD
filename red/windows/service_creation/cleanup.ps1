<#
.SYNOPSIS
    RASD-Red cleanup · service_creation. Exit code 0 only when verified clean.
#>
[CmdletBinding()]
param([Parameter(Mandatory)] [ValidatePattern('^rasd_[0-9a-f]{8}$')] [string] $Marker)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # the runner's 'Stop' is inherited; native stderr must not throw (Windows PowerShell 5.1)

& sc.exe delete $Marker 2>$null | Out-Null
& sc.exe query $Marker 2>$null | Out-Null
if ($LASTEXITCODE -eq 1060) { Write-Host "[cleanup] verified: service $Marker does not exist"; exit 0 }
Write-Warning "[cleanup] service $Marker still exists (sc.exe query exit $LASTEXITCODE)"
exit 1
