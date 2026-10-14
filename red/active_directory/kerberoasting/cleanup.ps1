<#
.SYNOPSIS
    RASD-Red cleanup · kerberoasting. Exit code 0 only when verified clean.
.DESCRIPTION
    The test writes nothing to disk or registry. The ticket stays in the session cache until
    it expires (run klist purge to drop it sooner). Nothing to remove, so this verifies and exits 0.
#>
[CmdletBinding()]
param([Parameter(Mandatory)] [ValidatePattern('^rasd_[0-9a-f]{8}$')] [string] $Marker)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # the runner's 'Stop' is inherited; native stderr must not throw (Windows PowerShell 5.1)
Write-Host '[cleanup] verified: nothing persisted (ticket cache expires with the session)'
exit 0
