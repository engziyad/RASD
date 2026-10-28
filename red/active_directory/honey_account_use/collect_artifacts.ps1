<#
.SYNOPSIS
    RASD-Red collect · honey_account_use. Prints the path of every file it writes.
.DESCRIPTION
    Saves klist output for the current logon session (the honey SPN's ticket, if the KDC issued one, with
    its encryption type) and the decoys' AD attributes as the emulation saw them (badPwdCount, lastLogon,
    servicePrincipalName), so the evidence shows the state of the decoys at run time.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern('^rasd_[0-9a-f]{8}$')] [string] $Marker,
    [Parameter(Mandatory)] [string] $OutDir
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # the runner's 'Stop' is inherited; native stderr must not throw (Windows PowerShell 5.1)
$out = & klist.exe 2>&1
$path = Join-Path $OutDir 'klist.txt'
[System.IO.File]::WriteAllText($path, (@($out | ForEach-Object { "$_" }) -join [Environment]::NewLine))
$path

$rows = foreach ($account in 'svc_backup_adm', 'svc_sqlreport') {
    try {
        $searcher = [adsisearcher]"(&(objectCategory=person)(sAMAccountName=$account))"
        foreach ($p in 'samaccountname', 'badpwdcount', 'lastlogon', 'serviceprincipalname', 'description') { $null = $searcher.PropertiesToLoad.Add($p) }
        $r = $searcher.FindOne()
        if ($r) {
            [pscustomobject]@{
                account = $account
                badPwdCount = if ($r.Properties['badpwdcount'].Count) { [int]$r.Properties['badpwdcount'][0] } else { $null }
                servicePrincipalName = @($r.Properties['serviceprincipalname'] | ForEach-Object { "$_" })
                description = [string]($r.Properties['description'] | Select-Object -First 1)
            }
        } else { [pscustomobject]@{ account = $account; missing = $true } }
    } catch { [pscustomobject]@{ account = $account; error = $_.Exception.Message } }
}
$path = Join-Path $OutDir 'decoy-accounts.json'
[System.IO.File]::WriteAllText($path, (ConvertTo-Json -InputObject @($rows) -Depth 4))
$path
