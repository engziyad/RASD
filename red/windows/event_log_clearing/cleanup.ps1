<#
.SYNOPSIS
    RASD-Red cleanup · event_log_clearing. Exit code 0 only when verified clean.
.DESCRIPTION
    Removes the test log created by step 1. The Security backup written by the opt-in step
    is kept on purpose: it is the evidence of that step.
#>
[CmdletBinding()]
param([Parameter(Mandatory)] [ValidatePattern('^purplelab_[0-9a-f]{8}$')] [string] $Marker)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # the runner's 'Stop' is inherited; native stderr must not throw (Windows PowerShell 5.1)

$LogName = 'R' + $Marker.Substring(10)
if ([System.Diagnostics.EventLog]::Exists($LogName)) {
    Remove-EventLog -LogName $LogName -ErrorAction SilentlyContinue
}
if (-not [System.Diagnostics.EventLog]::Exists($LogName)) { Write-Host "[cleanup] verified: test log $LogName removed"; exit 0 }
Write-Warning "[cleanup] test log $LogName still exists"
exit 1
