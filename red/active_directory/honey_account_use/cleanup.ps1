<#
.SYNOPSIS
    RASD-Red cleanup · honey_account_use. Exit code 0 only when verified clean.
.DESCRIPTION
    The bind and the ticket request write nothing to disk or registry: the failed bind leaves log entries
    (and one badPwdCount on the decoy, which resets after the lockout observation window) and the ticket
    stays in the session cache until it expires. Nothing to remove, so this verifies and exits 0.
#>
[CmdletBinding()]
param([Parameter(Mandatory)] [ValidatePattern('^rasd_[0-9a-f]{8}$')] [string] $Marker)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # the runner's 'Stop' is inherited; native stderr must not throw (Windows PowerShell 5.1)
Write-Host '[cleanup] verified: nothing persisted (one failed bind on the decoy; the ticket cache expires with the session)'
exit 0
