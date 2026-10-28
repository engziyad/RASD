<#
.SYNOPSIS
    RASD-Red · T1558.003 · request one service ticket for the honey SPN account svc_sqlreport.
.DESCRIPTION
    Does what a Kerberoasting tool does for every SPN it enumerates: reads the account's
    servicePrincipalName from AD and requests a service ticket for it with
    System.IdentityModel.Tokens.KerberosRequestorSecurityToken, so the domain controller logs
    4769 with the decoy in Service Name - the honey SPN rule's event, whatever encryption type
    the KDC picks. Nothing is exported or cracked. The account is a decoy from deceive/decoys.yml;
    the step refuses when it does not exist or holds no SPN. Lab use only.
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

$account = 'svc_sqlreport'             # deceive/decoys.yml: honey_spn_sqlreport (rasd deceive --rename keeps this in step)
$searcher = [adsisearcher]"(&(objectCategory=person)(sAMAccountName=$account))"
foreach ($p in 'samaccountname', 'serviceprincipalname', 'description') { $null = $searcher.PropertiesToLoad.Add($p) }
$found = $null
try { $found = $searcher.FindOne() } catch { throw "could not look up $account in AD ($($_.Exception.Message.Trim()))" }
if (-not $found) { throw "the honey SPN account $account does not exist in this domain: deploy the decoys first (deceive\Deploy-RasdDecoys.ps1 -LabConfirmed -Accounts)" }
$spns = @($found.Properties['serviceprincipalname'] | ForEach-Object { [string]$_ })
if ($spns.Count -eq 0) { throw "$account holds no servicePrincipalName; the deployment script registers one" }
$spn = $spns[0]

# A ticket already in this logon session's cache would be reused and the DC would log nothing (lab VM).
& klist.exe purge | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Warning "klist purge exited with $LASTEXITCODE; a cached ticket may be reused (no new 4769)" }

Add-Type -AssemblyName System.IdentityModel
try {
    $null = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn
    Write-Host "requested a service ticket for $spn ($account)"
} catch {
    # the KDC refused (the decoy may be disabled, or RC4 disabled domain-wide and the account RC4-only):
    # the request itself is what the DC logs, so a refusal is still the rule's event
    Write-Host "service ticket request for $spn ($account) was refused by the KDC: $($_.Exception.Message.Trim()) - the request was logged all the same"
}
