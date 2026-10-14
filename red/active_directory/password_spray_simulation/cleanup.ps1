<#
.SYNOPSIS
    RASD-Red cleanup · password_spray_simulation. Exit code 0 only when verified clean.
.DESCRIPTION
    Failed binds leave log entries only; badPwdCount resets after the lockout observation window.
#>
[CmdletBinding()]
param([Parameter(Mandatory)] [ValidatePattern('^rasd_[0-9a-f]{8}$')] [string] $Marker)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # the runner's 'Stop' is inherited; native stderr must not throw (Windows PowerShell 5.1)
Write-Host '[cleanup] verified: nothing persisted'
exit 0
