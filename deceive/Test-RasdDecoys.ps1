<#
.SYNOPSIS
    RASD-Deceive · is every decoy of deceive/decoys.yml still in place, with its lure and its audit entry?
.DESCRIPTION
    A decoy that drifted stops alerting silently: an account someone deleted, a description an
    administrator "fixed", a pre-authentication flag re-enabled, a file moved, an audit entry lost
    with a permissions change, a decoy host that is down. This check compares the lab with the
    inventory and prints one line per decoy:

      accounts   exists, description, pre-authentication flag, service principal name, enabled,
                 not a member of any group, badPwdCount (a recent failure is a touch to look at)
      files      exists, audit entry (Everyone, success, the data accesses the rule reads),
                 File System audit subcategory enabled on this host
      host       the decoy's address answers on the ports of the enabled modules

    Exit code 0 when every decoy is in place, 1 otherwise. Read-only: it changes nothing.
    -Json prints the result as JSON for a scheduled check.
.EXAMPLE
    .\Test-RasdDecoys.ps1
    .\Test-RasdDecoys.ps1 -DecoyRoot D:\Shares -SkipHost
#>
[CmdletBinding()]
param(
    [string] $DecoyRoot = 'C:\Shares',
    [string] $DecoyHost = '10.0.0.40',
    [switch] $SkipAccounts,
    [switch] $SkipFiles,
    [switch] $SkipHost,
    [switch] $Json
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# deceive/decoys.yml is the source; rasd deceive --rename rewrites these literals with it.
$HoneyAccounts = @(
    [pscustomobject]@{ Name = 'svc_backup_adm';     Description = 'Backup service account - pw reset 2024-03, temp pw in \\LAB-FS01\IT\Passwords\service_accounts.xlsx'; PreAuth = $true;  Spn = $null }
    [pscustomobject]@{ Name = 'adm_helpdesk_tier2'; Description = 'Helpdesk tier 2 - legacy admin, do not remove (ticket 48112)';                                          PreAuth = $false; Spn = $null }
    [pscustomobject]@{ Name = 'svc_sqlreport';      Description = 'SQL Server Reporting (SQLRPT01) service account';                                                      PreAuth = $true;  Spn = 'MSSQLSvc/sqlrpt01.lab.local:1433' }
)
$HoneyFiles = @('\IT\Passwords\service_accounts.xlsx', '\IT\Tools\credentials_backup.kdbx', '\Public\Onboarding\vpn_and_wifi_codes.txt')
$DecoyPorts = @(21, 22, 23, 80, 445, 1433, 3389, 5900)     # ftp, ssh, telnet, http, smb, mssql, rdp, vnc of deceive/opencanary/settings.json

$results = [System.Collections.Generic.List[object]]::new()
function Add-Result([string] $Kind, [string] $Decoy, [bool] $Ok, [string] $Detail) {
    $results.Add([pscustomobject]@{ kind = $Kind; decoy = $Decoy; ok = $Ok; detail = $Detail })
}

if (-not $SkipAccounts) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        foreach ($a in $HoneyAccounts) {
            $u = Get-ADUser -Filter "sAMAccountName -eq '$($a.Name)'" -Properties Description, DoesNotRequirePreAuth, ServicePrincipalNames, Enabled, MemberOf, badPwdCount, LastLogonDate -ErrorAction SilentlyContinue
            if (-not $u) { Add-Result 'account' $a.Name $false 'missing: deploy with Deploy-RasdDecoys.ps1 -Accounts'; continue }
            $problems = @()
            if ($u.Description -ne $a.Description) { $problems += 'description changed (the lure is gone)' }
            if ([bool]$u.DoesNotRequirePreAuth -eq [bool]$a.PreAuth) { $problems += $(if ($a.PreAuth) { 'pre-authentication is disabled but should be required' } else { 'pre-authentication is required: the AS-REP lure is gone' }) }
            if ($a.Spn -and ($u.ServicePrincipalNames -notcontains $a.Spn)) { $problems += "service principal name $($a.Spn) missing" }
            if (-not $u.Enabled) { $problems += 'disabled (a disabled decoy is skipped by most tools)' }
            if ($u.MemberOf.Count -gt 0) { $problems += 'member of a group: a decoy must hold no rights' }
            $touch = if ($u.badPwdCount -gt 0) { " · badPwdCount $($u.badPwdCount): someone tried it" } else { '' }
            Add-Result 'account' $a.Name ($problems.Count -eq 0) $(if ($problems.Count) { ($problems -join '; ') + $touch } else { 'in place' + $touch })
        }
    } catch {
        Add-Result 'account' '*' $false "cannot read Active Directory ($($_.Exception.Message.Trim())); run on a domain-joined lab host with RSAT, or -SkipAccounts"
    }
}

if (-not $SkipFiles) {
    $policy = & auditpol.exe /get /subcategory:'File System' 2>&1 | Out-String
    Add-Result 'audit policy' 'File System' ($policy -match 'File System\s+Success') $(if ($policy -match 'File System\s+Success') { 'Success enabled' } else { 'Success not enabled on this host: 4663 is never written (auditpol /set /subcategory:"File System" /success:enable)' })
    foreach ($rel in $HoneyFiles) {
        $path = Join-Path $DecoyRoot $rel.TrimStart('\')
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Add-Result 'file' $rel $false "missing at ${path}: deploy with Deploy-RasdDecoys.ps1 -Files"; continue }
        $audit = (Get-Acl -LiteralPath $path -Audit).Audit
        $ok = [bool]($audit | Where-Object { $_.AuditFlags -match 'Success' -and $_.IdentityReference -match 'Everyone' -and ($_.FileSystemRights -match 'ReadData|Read\b|FullControl|Modify') })
        Add-Result 'file' $rel $ok $(if ($ok) { "in place at $path, audit entry present" } else { "audit entry missing or not for Everyone/Success at ${path}: nothing would be logged" })
    }
}

if (-not $SkipHost) {
    foreach ($port in $DecoyPorts) {
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $async = $client.BeginConnect($DecoyHost, $port, $null, $null)
            $ok = $async.AsyncWaitHandle.WaitOne(2000) -and $client.Connected
            Add-Result 'host' "${DecoyHost}:$port" $ok $(if ($ok) { 'answers' } else { 'no answer: the decoy is down, the module is off, or a firewall is in the way' })
        } catch { Add-Result 'host' "${DecoyHost}:$port" $false "no answer ($($_.Exception.Message.Trim()))" }
        finally { $client.Dispose() }
    }
    Write-Host 'note: this check itself is a touch of the decoy; the detection filters only the authorised scanner, so expect an alert from this host unless its address is tuned' -ForegroundColor DarkGray
}

if ($Json) { $results | ConvertTo-Json -Depth 3 }
else {
    foreach ($r in $results) {
        $mark = if ($r.ok) { '[ OK ]' } else { '[MISS]' }
        Write-Host ('{0} {1,-13} {2,-44} {3}' -f $mark, $r.kind, $r.decoy, $r.detail) -ForegroundColor $(if ($r.ok) { 'Green' } else { 'Red' })
    }
    $missing = @($results | Where-Object { -not $_.ok }).Count
    Write-Host ("`n{0} of {1} checks in place" -f ($results.Count - $missing), $results.Count)
}
exit $(if (@($results | Where-Object { -not $_.ok }).Count) { 1 } else { 0 })
