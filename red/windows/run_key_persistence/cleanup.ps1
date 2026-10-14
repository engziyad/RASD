<#
.SYNOPSIS
    RASD-Red cleanup · run_key_persistence. Exit code 0 only when verified clean.
#>
[CmdletBinding()]
param([Parameter(Mandatory)] [ValidatePattern('^rasd_[0-9a-f]{8}$')] [string] $Marker)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # the runner's 'Stop' is inherited; native stderr must not throw (Windows PowerShell 5.1)

$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
Remove-ItemProperty -Path $runKey -Name $Marker -ErrorAction SilentlyContinue
$still = Get-ItemProperty -Path $runKey -Name $Marker -ErrorAction SilentlyContinue
if (-not $still) { Write-Host "[cleanup] verified: Run value $Marker removed"; exit 0 }
Write-Warning "[cleanup] Run value $Marker still present"
exit 1
