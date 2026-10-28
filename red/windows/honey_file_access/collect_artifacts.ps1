<#
.SYNOPSIS
    RASD-Red collect · honey_file_access. Prints the path of every file it writes.
.DESCRIPTION
    Saves the decoy's audit entries (its SACL) and the File System audit policy of this host, so the
    evidence shows that the conditions for 4663 were in place when the file was read.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern('^rasd_[0-9a-f]{8}$')] [string] $Marker,
    [Parameter(Mandatory)] [string] $OutDir
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # the runner's 'Stop' is inherited; native stderr must not throw (Windows PowerShell 5.1)
$root = if ($env:RASD_DECOY_ROOT) { $env:RASD_DECOY_ROOT } else { 'C:\Shares' }
$path = Join-Path $root 'IT\Passwords\service_accounts.xlsx'
$lines = @("decoy: $path")
try { $lines += (Get-Acl -LiteralPath $path -Audit).Audit | ForEach-Object { "audit: $($_.IdentityReference) $($_.FileSystemRights) $($_.AuditFlags)" } } catch { $lines += "audit: unreadable ($($_.Exception.Message))" }
$lines += @(& auditpol.exe /get /subcategory:'File System' 2>&1 | ForEach-Object { "$_" })
$out = Join-Path $OutDir 'decoy-file-audit.txt'
[System.IO.File]::WriteAllText($out, ($lines -join [Environment]::NewLine))
$out
