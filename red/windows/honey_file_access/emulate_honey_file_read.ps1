<#
.SYNOPSIS
    RASD-Red · T1552.001 · read the honey credentials spreadsheet on the host that holds it.
.DESCRIPTION
    Does what a scripted search for password files does: opens the decoy service_accounts.xlsx
    and reads it. The file's SACL (set by deceive\Deploy-RasdDecoys.ps1 -Files) makes Windows
    write Security 4663 with ReadData (%%4416) for the user running this step - the honey file
    rule's event. The decoy root is C:\Shares, or RASD_DECOY_ROOT when set. The step refuses when
    the decoy is missing or carries no audit entry (nothing would be logged), and warns when the
    File System audit subcategory is off. Lab use only.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern('^rasd_[0-9a-f]{8}$')] [string] $Marker,
    [Parameter(Mandatory)] [switch] $LabConfirmed
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $LabConfirmed) { throw 'Refusing to run without -LabConfirmed.' }
. (Join-Path $PSScriptRoot '..\..\lab\RasdLabGuard.ps1')
Assert-RasdLab

$root = if ($env:RASD_DECOY_ROOT) { $env:RASD_DECOY_ROOT } else { 'C:\Shares' }
$relative = '\IT\Passwords\service_accounts.xlsx'      # deceive/decoys.yml: honey_file_service_accounts (rasd deceive --rename keeps this in step)
$path = Join-Path $root $relative.TrimStart('\')
if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    throw "the honey file $path does not exist: deploy the decoys first (deceive\Deploy-RasdDecoys.ps1 -LabConfirmed -Files), or set RASD_DECOY_ROOT"
}

# Without an audit entry on the file, Windows writes no 4663 and the step would be a MISSED for the wrong reason.
$sacl = (Get-Acl -LiteralPath $path -Audit).Audit
if (-not $sacl -or -not ($sacl | Where-Object { $_.AuditFlags -match 'Success' -and ($_.FileSystemRights -match 'ReadData|Read\b|FullControl|Modify') })) {
    throw "$path carries no success audit entry for ReadData; deceive\Deploy-RasdDecoys.ps1 -Files sets it"
}
$policy = & auditpol.exe /get /subcategory:'File System' 2>&1
if (($policy | Out-String) -notmatch 'File System\s+Success') {
    Write-Warning 'the File System audit subcategory does not include Success on this host: 4663 will not be written (auditpol /set /subcategory:"File System" /success:enable)'
}

$content = [System.IO.File]::ReadAllBytes($path)        # one open for read: the access the SACL audits
Write-Host "read $($content.Length) bytes of $path as $env:USERDOMAIN\$env:USERNAME"
