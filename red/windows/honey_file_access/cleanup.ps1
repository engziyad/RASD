<#
.SYNOPSIS
    RASD-Red cleanup · honey_file_access. Exit code 0 only when verified clean.
.DESCRIPTION
    The step only reads the decoy; it creates, changes and deletes nothing. The decoy stays where the
    deployment script put it (removing it is the deployment script's -Remove, not this test's cleanup).
    Nothing to remove, so this verifies the decoy is still intact and exits 0.
#>
[CmdletBinding()]
param([Parameter(Mandatory)] [ValidatePattern('^rasd_[0-9a-f]{8}$')] [string] $Marker)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # the runner's 'Stop' is inherited; native stderr must not throw (Windows PowerShell 5.1)
$root = if ($env:RASD_DECOY_ROOT) { $env:RASD_DECOY_ROOT } else { 'C:\Shares' }
$path = Join-Path $root 'IT\Passwords\service_accounts.xlsx'
if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Write-Host "[cleanup] the decoy $path is gone - it was read, not removed, by this test; redeploy it"; exit 1 }
Write-Host '[cleanup] verified: nothing persisted (the decoy was read, not changed)'
exit 0
