<#
.SYNOPSIS
    RASD-Red · T1110.003 · password spray simulation that cannot succeed.
.DESCRIPTION
    Reads lab test accounts from -UserList (at most 10) and attempts one LDAP bind per
    account with a random 40-character password generated for this run. Before that it
    checks, per account, the lockout threshold that really applies (the domain policy or a
    fine-grained password policy) and the account's current badPwdCount, and skips any
    account that one more failure could lock. Refuses to run when the domain threshold is
    1 or 2. Lab use only.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern('^rasd_[0-9a-f]{8}$')] [string] $Marker,
    [Parameter(Mandatory)] [switch] $LabConfirmed,
    [Parameter(Mandatory)] [string] $UserList
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $LabConfirmed) { throw 'Refusing to run without -LabConfirmed.' }
. (Join-Path $PSScriptRoot '..\..\lab\RasdLabGuard.ps1')
Assert-RasdLab

$users = @(Get-Content -LiteralPath $UserList | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^[A-Za-z0-9._\-]{1,64}$' })
if ($users.Count -eq 0) { throw "no valid account names in $UserList" }
if ($users.Count -gt 10) { throw 'at most 10 lab accounts per run' }

$domain = New-Object System.DirectoryServices.DirectoryEntry
$threshold = [int]($domain.lockoutThreshold.Value)
if ($threshold -eq 1 -or $threshold -eq 2) { throw "domain lockout threshold is $threshold - refusing (one attempt could lock accounts)" }
Write-Host "domain lockout threshold: $threshold"

# Per account: a fine-grained password policy can set a lower threshold than the domain, and
# earlier failures inside the observation window count too. msDS-ResultantPSO is computed by
# AD and returned only when asked for on the object itself (RefreshCache), and policy objects
# are hidden from ordinary users - so the check is complete only when the account running
# the test may read them (a lab admin). badPwdCount is kept per DC (the PDC is consulted on
# failures), so it is a close estimate; accounts within one failure of their limit are skipped.
$psoVisible = $false
$targets = @(foreach ($u in $users) {
    $searcher = [adsisearcher]"(&(objectCategory=person)(sAMAccountName=$u))"
    $found = $null
    try { $found = $searcher.FindOne() } catch { Write-Warning "${u}: lookup failed ($($_.Exception.Message.Trim())) - skipped"; continue }
    if (-not $found) { Write-Warning "${u}: no such account - skipped"; continue }
    $user = $found.GetDirectoryEntry()
    try { $user.RefreshCache(@('msDS-ResultantPSO', 'badPwdCount')) }
    catch { Write-Warning "${u}: cannot read badPwdCount / msDS-ResultantPSO - skipped"; $user.Dispose(); continue }
    $limit = $threshold
    $psoDn = $user.Properties['msDS-ResultantPSO'].Value
    if ($psoDn) {
        $psoVisible = $true
        $value = $null
        try { $value = ([adsi]("LDAP://$psoDn")).Properties['msDS-LockoutThreshold'].Value } catch { }
        if ($null -eq $value) { Write-Warning "${u}: a fine-grained policy applies but its threshold is unreadable - skipped"; $user.Dispose(); continue }
        $limit = [int]$value
    }
    $bad = if ($null -ne $user.Properties['badPwdCount'].Value) { [int]$user.Properties['badPwdCount'].Value } else { 0 }
    $user.Dispose()
    if ($limit -gt 0 -and ($limit -le 2 -or $bad + 1 -ge $limit)) {
        Write-Warning "${u}: $bad recent failure(s), lockout at $limit - skipped"
        continue
    }
    $u
})
if (-not $psoVisible) {
    Write-Warning 'no fine-grained password policy was visible for these accounts: the domain threshold is assumed (run as a lab admin to check policies hidden from this account)'
}
if ($targets.Count -eq 0) { throw 'no account can take one more failed attempt safely' }

$bytes = New-Object byte[] 30
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$password = [Convert]::ToBase64String($bytes)                     # 40 characters, never a real password
$path = $domain.Path
$ok = 0; $wrong = 0; $other = @()
foreach ($u in $targets) {
    $entry = New-Object System.DirectoryServices.DirectoryEntry($path, $u, $password)
    try { $null = $entry.NativeObject; $ok++ }
    catch {
        $ex = $_.Exception
        while ($ex.InnerException) { $ex = $ex.InnerException }
        # 0x8007052E: the user name or password is incorrect - the failure this test exists to log
        if ($ex -is [System.Runtime.InteropServices.COMException] -and $ex.ErrorCode -eq -2147023570) { $wrong++ }
        else { $other += "${u}: $($ex.Message.Trim())" }
    }
    finally { $entry.Dispose() }
}
Write-Host "attempted $($targets.Count) account(s): $wrong rejected as wrong password, $ok succeeded (expected: 0)"
if ($other.Count) {
    Write-Warning "these attempts did not reach the DC as a password check, so they logged no 4771/4776:"
    $other | ForEach-Object { Write-Warning "  $_" }
}
