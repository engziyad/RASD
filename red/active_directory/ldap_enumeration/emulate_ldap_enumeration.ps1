<#
.SYNOPSIS
    RASD-Red · T1087.002 · read-only LDAP enumeration (counts only).
.DESCRIPTION
    Runs three DirectorySearcher queries against the current domain - users with an SPN,
    Domain Admins members, computers - and prints how many objects each returned.
    Nothing is written. Lab use only.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern('^rasd_[0-9a-f]{8}$')] [string] $Marker,
    [Parameter(Mandatory)] [switch] $LabConfirmed
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $LabConfirmed) { throw 'Refusing to run without -LabConfirmed.' }

$root = New-Object System.DirectoryServices.DirectoryEntry
$domainDn = [string]$root.distinguishedName
$queries = [ordered]@{
    'users with an SPN'     = '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))'
    'Domain Admins members' = "(&(objectCategory=person)(memberOf=CN=Domain Admins,CN=Users,$domainDn))"
    'computers'             = '(objectCategory=computer)'
}
foreach ($label in $queries.Keys) {
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($root, $queries[$label])
    $searcher.PageSize = 500
    [void]$searcher.PropertiesToLoad.Add('distinguishedName')
    $results = $searcher.FindAll()
    try { Write-Host ("{0}: {1}" -f $label, $results.Count) } finally { $results.Dispose() }
}
