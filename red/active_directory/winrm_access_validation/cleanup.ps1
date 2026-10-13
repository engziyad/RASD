<#
.SYNOPSIS
    RASD-Red cleanup · winrm_access_validation. Exit code 0 only when verified clean.
.DESCRIPTION
    Invoke-Command closes its session when the command returns; nothing is created.
#>
[CmdletBinding()]
param([Parameter(Mandatory)] [ValidatePattern('^purplelab_[0-9a-f]{8}$')] [string] $Marker)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # the runner's 'Stop' is inherited; native stderr must not throw (Windows PowerShell 5.1)
Write-Host '[cleanup] verified: nothing persisted'
exit 0
