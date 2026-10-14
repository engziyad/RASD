<#
.SYNOPSIS
    RASD lab run: readiness, the offensive tests, SIEM wait, telemetry export - one workstation zip.
.DESCRIPTION
    The whole evidence run on the Windows lab VM in one command:
      1. Test-LabReadiness.ps1 - stops on a FAIL unless -Force
      2. Invoke-RasdEmulation.ps1 -Technique All with the options you pass
      3. waits -SiemWaitMinutes so Splunk's scheduled alerts (every 5 minutes over the
         last 10) see the events
      4. Export-LabTelemetry.ps1 for the run window
      5. zips the workstation side: results, collected artifacts, telemetry export, readiness report
    and prints what is left: the DC export (when Kerberoasting ran), the Splunk alert
    export, and the rasd evidence --run command that turns the zip and those exports into
    evidence.md.
    Safe by default: credential access and the Security-log clear run only with
    -IncludeCredentialAccess / -IncludeSecurityLogClear (a full validation run).
    Lab use only: an elevated Windows PowerShell 5.1 on a disposable VM, never a
    production or work machine. Take a VM snapshot first and revert it afterwards.
.PARAMETER SiemWaitMinutes
    Minutes to wait after the tests before exporting (default 15; 0 without a SIEM).
.PARAMETER Force
    Run even when the readiness check reports a FAIL (the evidence step will say what is missing).
.PARAMETER FixReadiness
    Pass -Fix to Test-LabReadiness.ps1 before the run (audit policy and logging fixes only; no software install).
.PARAMETER DryRun
    Print the plan and which tests would run or be skipped, without running anything.
.EXAMPLE
    .\red\lab\Invoke-RasdLabRun.ps1 -LabConfirmed -DryRun
.EXAMPLE
    .\red\lab\Invoke-RasdLabRun.ps1 -LabConfirmed -Spn MSSQLSvc/sql01.lab.local:1433 -UserList .\lab-users.txt
.EXAMPLE
    .\red\lab\Invoke-RasdLabRun.ps1 -LabConfirmed -IncludeCredentialAccess -IncludeSecurityLogClear
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [switch] $LabConfirmed,
    [string] $Spn,
    [string] $UserList,
    [string] $Target,
    [switch] $IncludeCredentialAccess,
    [switch] $IncludeSecurityLogClear,
    [ValidateRange(0, 120)] [int] $SiemWaitMinutes = 15,
    [string] $OutDir,
    [switch] $Force,
    [switch] $FixReadiness,
    [switch] $DryRun
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $LabConfirmed) { throw 'Refusing to run without -LabConfirmed.' }

$red = Split-Path -Parent $PSScriptRoot
$runner = Join-Path $red 'Invoke-RasdEmulation.ps1'
$exporter = Join-Path $red 'Export-LabTelemetry.ps1'
$readinessScript = Join-Path $PSScriptRoot 'Test-LabReadiness.ps1'

$emulation = @{ Technique = 'All'; LabConfirmed = $true }
if ($Spn) { $emulation.Spn = $Spn }
if ($UserList) { $emulation.UserList = $UserList }
if ($Target) { $emulation.Target = $Target }
if ($IncludeCredentialAccess) { $emulation.IncludeCredentialAccess = $true }
if ($IncludeSecurityLogClear) { $emulation.IncludeSecurityLogClear = $true }

if ($DryRun) {
    Write-Host 'RASD lab run - plan (nothing runs)' -ForegroundColor Cyan
    $readinessPlan = '  1. readiness check (red\lab\Test-LabReadiness.ps1' + $(if ($FixReadiness) { ' -Fix' } else { '' }) + ')'
    Write-Host $readinessPlan
    Write-Host '  2. offensive tests:'
    & $runner @emulation -DryRun
    Write-Host "  3. wait $SiemWaitMinutes minute(s) for Splunk's scheduled alerts"
    Write-Host '  4. export the Sysmon, Security and System events of the run window'
    Write-Host '  5. zip results, artifacts, telemetry export and readiness report'
    return
}

# 1 · readiness
$readinessArgs = @{ PassThru = $true }
if ($FixReadiness) { $readinessArgs.Fix = $true }
$readiness = @(& $readinessScript @readinessArgs)
$readiness | Format-Table -Property check, result, detail -AutoSize -Wrap | Out-Host
$failed = @($readiness | Where-Object { $_.result -eq 'FAIL' })
if ($failed.Count -and -not $Force) {
    $failed | ForEach-Object { Write-Host "  [FAIL] $($_.check): $($_.fix)" -ForegroundColor Red }
    throw "$($failed.Count) readiness check(s) failed - fix them, or rerun with -Force"
}

if (-not $OutDir) { $OutDir = Join-Path $red ('results\lab-' + (Get-Date -Format 'yyyyMMdd-HHmmss')) }
$OutDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutDir)
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
[System.IO.File]::WriteAllText((Join-Path $OutDir 'lab-readiness.json'), (ConvertTo-Json -InputObject @($readiness) -Depth 3))

# 2 · offensive tests (the runner records every step's UTC window, marker, host and cleanup)
$start = (Get-Date).AddMinutes(-1)
& $runner @emulation -OutDir $OutDir

# 3 · give the SIEM time to alert
if ($SiemWaitMinutes -gt 0) {
    Write-Host "waiting $SiemWaitMinutes minute(s) so Splunk's scheduled alerts can run ..." -ForegroundColor DarkGray
    Start-Sleep -Seconds ($SiemWaitMinutes * 60)
}

# 4 · telemetry of the run window
$exportFile = Join-Path $OutDir 'lab-export.jsonl'
& $exporter -Since $start -OutFile $exportFile

# 5 · manifest and one file to keep or send
$resultsFile = Join-Path $OutDir 'emulation-results.json'
$manifest = [pscustomobject][ordered]@{
    tool = 'RASD lab run'
    host = [System.Net.Dns]::GetHostName()
    user = "$env:USERDOMAIN\$env:USERNAME"
    run_start_local = $start.ToString('o')
    run_end_local = (Get-Date).ToString('o')
    siem_wait_minutes = $SiemWaitMinutes
    include_credential_access = [bool]$IncludeCredentialAccess
    include_security_log_clear = [bool]$IncludeSecurityLogClear
    fix_readiness = [bool]$FixReadiness
    files = @(Get-ChildItem -LiteralPath $OutDir -File -Recurse | ForEach-Object {
        [pscustomobject]@{ path = $_.FullName.Substring($OutDir.Length).TrimStart('\'); sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLower(); bytes = $_.Length }
    })
}
[System.IO.File]::WriteAllText((Join-Path $OutDir 'lab-run-manifest.json'), (ConvertTo-Json -InputObject $manifest -Depth 6))
$zip = "$OutDir.zip"
Compress-Archive -Path (Join-Path $OutDir '*') -DestinationPath $zip -Force
$zipHash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLower()
# sha256sum format beside the zip (a zip cannot hold its own hash): sha256sum -c <zip>.sha256
[System.IO.File]::WriteAllText("$zip.sha256", "$zipHash  $(Split-Path -Leaf $zip)`n")

# Kerberos tickets (4769) and pre-authentication failures (4771) are logged on the DC, not here
$needsDc = $false
foreach ($r in (Get-Content -LiteralPath $resultsFile -Raw | ConvertFrom-Json)) {
    if ($r.test -in @('kerberoasting', 'password_spray_simulation') -and $r.status -eq 'executed') { $needsDc = $true }
}
$since = $start.ToString('yyyy-MM-dd HH:mm:ss')
Write-Host ''
Write-Host "[+] lab run packed: $zip" -ForegroundColor Green
Write-Host "    sha256: $zipHash (also in $(Split-Path -Leaf $zip).sha256)" -ForegroundColor DarkGray
Write-Host 'Left to do:'
$n = 1
if ($needsDc) {
    Write-Host "  $n. On the lab DC: .\Export-LabTelemetry.ps1 -LogName Security -EventId 4768,4769,4771,4776,4625 -Since '$since' -OutFile .\dc-export.jsonl"
    $n++
}
Write-Host "  $n. In Splunk: run the report 'RASD - alert export' from $since to now and export it as siem-alerts.csv"
$n++
Write-Host "  $n. rasd evidence --run `"$zip`"$(if ($needsDc) { ' dc-export.jsonl' }) siem-alerts.csv"
Write-Host '     (raw files stay out of the repository; evidence.md records their SHA-256)'
Write-Host '  Then revert the VM snapshot.'
