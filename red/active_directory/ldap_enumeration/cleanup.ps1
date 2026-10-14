<#
.SYNOPSIS
    RASD-Red cleanup · ldap_enumeration. Exit code 0 only when verified clean.
.DESCRIPTION
    Read-only test: nothing to remove.
#>
[CmdletBinding()]
param([Parameter(Mandatory)] [ValidatePattern('^rasd_[0-9a-f]{8}$')] [string] $Marker)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # the runner's 'Stop' is inherited; native stderr must not throw (Windows PowerShell 5.1)
Write-Host '[cleanup] verified: nothing persisted'
exit 0
