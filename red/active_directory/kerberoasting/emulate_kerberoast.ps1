<#
.SYNOPSIS
    RASD-Red · T1558.003 · request one service ticket for a lab SPN.
.DESCRIPTION
    Uses System.IdentityModel.Tokens.KerberosRequestorSecurityToken to request a TGS for
    -Spn, which makes the domain controller log 4769. Nothing is exported or cracked.
    Lab use only.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern('^rasd_[0-9a-f]{8}$')] [string] $Marker,
    [Parameter(Mandatory)] [switch] $LabConfirmed,
    [Parameter(Mandatory)] [ValidatePattern('^[A-Za-z0-9\-]+/[^\s]+$')] [string] $Spn
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $LabConfirmed) { throw 'Refusing to run without -LabConfirmed.' }

# The rule detects RC4 (0x17) tickets. The KDC picks the strongest type the service account
# supports, so the lab account must be RC4-only (msDS-SupportedEncryptionTypes = 0x4): unset,
# or with AES bits, current DCs issue an AES ticket, the rule correctly stays silent and the
# evidence step reports MISSED. Check before requesting rather than after.
$escaped = $Spn -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29'
$account = $null
try {
    $searcher = [adsisearcher]"(servicePrincipalName=$escaped)"
    foreach ($p in 'samaccountname', 'msds-supportedencryptiontypes') { $null = $searcher.PropertiesToLoad.Add($p) }
    $account = $searcher.FindOne()
} catch {
    Write-Warning "could not read the SPN's account from AD ($($_.Exception.Message)); make sure it is RC4-only (0x4)"
}
if ($account) {
    $name = [string]$account.Properties['samaccountname'][0]
    $types = $account.Properties['msds-supportedencryptiontypes']
    $value = if ($types.Count) { [int]$types[0] } else { $null }
    if ($null -eq $value -or -not ($value -band 0x4) -or ($value -band 0x18)) {
        $shown = if ($null -eq $value) { 'unset' } else { '0x{0:x}' -f $value }
        throw ("lab account $name has msDS-SupportedEncryptionTypes $shown; the test needs RC4 only. On the lab DC: " +
               "Set-ADUser $name -Replace @{'msDS-SupportedEncryptionTypes'=4} (restore it after the lab)")
    }
}

# A service ticket already in this logon session's cache would be reused for ~10 hours and the
# DC would log nothing, so a rerun would be MISSED: drop the session's tickets first (lab VM).
& klist.exe purge | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Warning "klist purge exited with $LASTEXITCODE; a cached ticket may be reused (no new 4769)" }

Add-Type -AssemblyName System.IdentityModel
$null = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $Spn
Write-Host "requested a service ticket for $Spn"
