<#
.SYNOPSIS
    RASD-Red · T1078.002 · one LDAP bind as the honey account svc_backup_adm, with a wrong password.
.DESCRIPTION
    Does what an attacker who read the decoy's lure does: tries the credential. The bind uses a
    random 40-character password that is never the real one, so the attempt fails and the domain
    controller logs 4771 (Kerberos pre-authentication failed) or, on NTLM fallback, 4776 and 4625
    for the decoy account - the honey account rule's events. The account is a decoy from
    deceive/decoys.yml; the step refuses when it does not exist, is not marked as a decoy by its
    description, or is one failure away from lockout. Lab use only.
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

$account = 'svc_backup_adm'            # deceive/decoys.yml: honey_account_backup_admin (rasd deceive --rename keeps this in step)
$domain = New-Object System.DirectoryServices.DirectoryEntry
$searcher = [adsisearcher]"(&(objectCategory=person)(sAMAccountName=$account))"
foreach ($p in 'samaccountname', 'description', 'badpwdcount', 'lastlogon') { $null = $searcher.PropertiesToLoad.Add($p) }
$found = $null
try { $found = $searcher.FindOne() } catch { throw "could not look up $account in AD ($($_.Exception.Message.Trim()))" }
if (-not $found) { throw "the honey account $account does not exist in this domain: deploy the decoys first (deceive\Deploy-RasdDecoys.ps1 -LabConfirmed -Accounts)" }

# Never touch a real account by mistake: the decoy is recognised by the lure the deployment script writes.
$description = [string]($found.Properties['description'] | Select-Object -First 1)
if ($description -notmatch 'service_accounts\.xlsx') {
    throw "$account does not carry the decoy's description from deceive/decoys.yml; refusing to try a password against an account that may be real"
}

# One failure must not lock the decoy: a locked decoy stops recording the attackers who come after.
$threshold = [int]($domain.lockoutThreshold.Value)
$bad = if ($found.Properties['badpwdcount'].Count) { [int]$found.Properties['badpwdcount'][0] } else { 0 }
if ($threshold -gt 0 -and $bad + 1 -ge $threshold) {
    throw "$account has $bad recent failure(s) and the domain locks at $threshold; refusing (wait for the observation window to pass)"
}

$bytes = New-Object byte[] 30
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$password = [Convert]::ToBase64String($bytes)                     # 40 characters, never the lure's password
$entry = New-Object System.DirectoryServices.DirectoryEntry($domain.Path, $account, $password)
try {
    $null = $entry.NativeObject
    throw "the bind as $account SUCCEEDED with a random password - this is not a decoy as deployed; stop and check the account"
} catch [System.Runtime.InteropServices.COMException] {
    $ex = $_.Exception
    while ($ex.InnerException) { $ex = $ex.InnerException }
    # 0x8007052E: the user name or password is incorrect - the failure this step exists to log
    if ($ex -is [System.Runtime.InteropServices.COMException] -and $ex.ErrorCode -eq -2147023570) {
        Write-Host "bind as $account rejected as a wrong password (the domain controller logged the attempt)"
    } else {
        throw "the bind did not reach the DC as a password check ($($ex.Message.Trim())); nothing was logged"
    }
} finally { $entry.Dispose() }
