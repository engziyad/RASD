<#
.SYNOPSIS
    RASD-Red runner: safe, self-cleaning adversary emulation for the Windows and Active
    Directory tests in red\windows and red\active_directory.

.DESCRIPTION
    Every test is described by its test.json (generated from test.yml by tools/red.py).
    The runner:
      1. discovers the tests and selects them by -Technique and/or -Test
      2. runs each step with one random run marker (rasd_xxxxxxxx), honouring the
         step's administrator requirement, opt-in switch and parameters
      3. runs the test's collect script before cleanup and records the SHA-256 of every
         artifact it saved
      4. runs the cleanup script and records it as verified (exit 0), manual (exit 3) or failed
      5. writes emulation-results.json: technique, test, step, expected detections and correlations, host,
         user, UTC window, marker, cleanup status and artifacts

    Then turn the run into evidence:
        .\Export-LabTelemetry.ps1 -Since <start time printed at the end>
        rasd evidence --results <out>\emulation-results.json --logs lab-export.jsonl

    *** LAB USE ONLY. Run on an isolated, disposable VM that you own. ***

.PARAMETER Technique
    ATT&CK IDs to run (for example T1059.001), or All.

.PARAMETER Test
    Test ids (folder names, for example scheduled_task_creation). Combines with -Technique.

.PARAMETER LabConfirmed
    Mandatory acknowledgement that this host is an isolated lab machine. On its own it is not
    enough: the lab guard (lab\RasdLabGuard.ps1) also requires the machine variable
    RASD_LAB_HOST to name this computer and, on a domain-joined host, the domain to be listed
    in RASD_LAB_DOMAINS. See lab\README.md.

.PARAMETER IncludeCredentialAccess
    Opt-in for lsass_memory_access (dumps LSASS memory; the dump is hashed and deleted).

.PARAMETER IncludeSecurityLogClear
    Opt-in for the event_log_clearing step that clears the Security log (backed up first).

.PARAMETER Spn
    Service principal name for kerberoasting (for example MSSQLSvc/sql01.lab.local:1433).

.PARAMETER Target
    Lab host for winrm_access_validation.

.PARAMETER UserList
    File of lab test accounts (one per line) for password_spray_simulation.

.PARAMETER OutDir
    Folder for emulation-results.json and collected artifacts. Default: red\results\<timestamp>.

.PARAMETER DryRun
    Show which steps would run or be skipped, and why, without running anything.

.PARAMETER List
    List the available tests and exit.

.EXAMPLE
    .\Invoke-RasdEmulation.ps1 -List

.EXAMPLE
    .\Invoke-RasdEmulation.ps1 -Technique T1059.001,T1547.001 -LabConfirmed

.EXAMPLE
    .\Invoke-RasdEmulation.ps1 -Technique All -LabConfirmed -IncludeCredentialAccess -Spn MSSQLSvc/sql01.lab.local:1433
#>
[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
    [Parameter(ParameterSetName = 'Run')] [string[]] $Technique = @(),
    [Parameter(ParameterSetName = 'Run')] [string[]] $Test = @(),
    [Parameter(ParameterSetName = 'Run', Mandatory)] [switch] $LabConfirmed,
    [Parameter(ParameterSetName = 'Run')] [switch] $IncludeCredentialAccess,
    [Parameter(ParameterSetName = 'Run')] [switch] $IncludeSecurityLogClear,
    [Parameter(ParameterSetName = 'Run')] [string] $Spn,
    [Parameter(ParameterSetName = 'Run')] [string] $Target,
    [Parameter(ParameterSetName = 'Run')] [string] $UserList,
    [Parameter(ParameterSetName = 'Run')] [string] $OutDir,
    [Parameter(ParameterSetName = 'Run')] [switch] $DryRun,
    [Parameter(ParameterSetName = 'List', Mandatory)] [switch] $List
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ExitManual = 3

# ------------------------------------------------------------------ catalogue
$roots = @('windows', 'active_directory') | ForEach-Object { Join-Path $PSScriptRoot $_ } | Where-Object { Test-Path -LiteralPath $_ }
$catalog = @(foreach ($file in (Get-ChildItem -Path $roots -Filter 'test.json' -Recurse | Sort-Object FullName)) {
    $t = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
    $t | Add-Member -NotePropertyName folder -NotePropertyValue $file.DirectoryName -PassThru
})

if ($List) {
    foreach ($t in $catalog) {
        '{0,-28} {1,-10} {2}' -f $t.id, $t.technique, (($t.steps | ForEach-Object { $_.name }) -join ' | ')
    }
    return
}

if (-not $LabConfirmed) { throw 'Refusing to run without -LabConfirmed.' }
# -LabConfirmed is an acknowledgement; the guard checks the machine itself (red/lab/README.md, Lab guard)
. (Join-Path $PSScriptRoot 'lab\RasdLabGuard.ps1')
Assert-RasdLab -DryRun:$DryRun
if (-not $Technique -and -not $Test) { throw 'Choose -Technique <ID|All> and/or -Test <id> (see -List).' }
$selected = @($catalog | Where-Object { ($Technique -contains 'All') -or ($Technique -contains $_.technique) -or ($Test -contains $_.id) })
if ($selected.Count -eq 0) { throw 'No test matches the selection (see -List).' }

$onWindows = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
if (-not $onWindows -and -not $DryRun) { throw 'These tests run on Windows. Use -DryRun to preview the plan on another OS.' }
$IsAdmin = $false
if ($onWindows) {
    $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

$Marker = 'rasd_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
# the full host name ($env:COMPUTERNAME is the NetBIOS name, cut at 15 characters) and every
# non-loopback address: evidence.py binds events a DC logs (4769, 4624 ...) to this host by them
$HostName = [System.Net.Dns]::GetHostName()
$HostIps = @(foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
    if ($nic.OperationalStatus -ne 'Up') { continue }
    foreach ($a in $nic.GetIPProperties().UnicastAddresses) {
        if (-not [System.Net.IPAddress]::IsLoopback($a.Address)) { ($a.Address.IPAddressToString -split '%')[0] }
    }
})
$Available = @{ Spn = $Spn; Target = $Target; UserList = $UserList }
$OptIn = @{ IncludeCredentialAccess = [bool]$IncludeCredentialAccess; IncludeSecurityLogClear = [bool]$IncludeSecurityLogClear }
$RunStart = (Get-Date)

if (-not $DryRun) {
    if (-not $OutDir) { $OutDir = Join-Path $PSScriptRoot ('results\' + (Get-Date -Format 'yyyyMMdd-HHmmss')) }
    $OutDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutDir)
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
}

function Get-Detections($step) { if ($step.detections) { @($step.detections) } else { @() } }
function Get-Correlations($step) {
    # older test.json copies have no correlations key, and StrictMode throws on a missing property
    if ($step.PSObject.Properties['correlations'] -and $step.correlations) { @($step.correlations) } else { @() }
}
function Get-Parameters($step) { if ($step.parameters) { @($step.parameters) } else { @() } }

function Get-SkipReason($step) {
    if ($step.opt_in -and -not $OptIn[$step.opt_in]) { return "opt-in: add -$($step.opt_in)" }
    if ($step.needs_admin -and -not $IsAdmin -and $onWindows) { return 'requires an elevated session' }
    $missing = @(Get-Parameters $step | Where-Object { -not $Available[$_] })
    if ($missing.Count) { return 'missing parameter: -' + ($missing -join ', -') }
    return $null
}

# ------------------------------------------------------------------ run
$Results = [System.Collections.Generic.List[object]]::new()
Write-Host "run marker: $Marker" -ForegroundColor DarkGray
foreach ($t in $selected) {
    $ran = [System.Collections.Generic.List[object]]::new()
    foreach ($s in $t.steps) {
        $reason = Get-SkipReason $s
        if ($DryRun) {
            $state = if ($reason) { "skip ($reason)" } else { 'run' }
            '{0,-28} {1,-24} {2}' -f $t.id, $s.id, $state
            continue
        }
        $rec = [pscustomobject][ordered]@{
            technique = $t.technique; test = $t.id; step = $s.id; name = $s.name; detections = @(Get-Detections $s)
            correlations = @(Get-Correlations $s)
            status = 'skipped'; reason = $reason; host = $HostName; host_netbios = $env:COMPUTERNAME; host_ips = $HostIps; user = "$env:USERDOMAIN\$env:USERNAME"
            marker = $Marker; bind = $s.bind; utc_start = $null; utc_end = $null; error = $null; cleanup = 'not-run'; artifacts = @()
            # a remote step's target: its own events count as evidence when they carry this run's token
            targets = @(if ((Get-Parameters $s) -contains 'Target' -and $Target) { $Target })
        }
        if ($reason) {
            Write-Warning "[$($t.technique)] $($s.name) - skipped ($reason)"
            $Results.Add($rec)
            continue
        }
        $splat = @{ Marker = $Marker; LabConfirmed = $true }
        foreach ($p in (Get-Parameters $s)) { $splat[$p] = $Available[$p] }
        Write-Host "[$($t.technique)] $($s.name)" -ForegroundColor Cyan
        $rec.utc_start = (Get-Date).ToUniversalTime().ToString('o')
        try {
            & (Join-Path $t.folder $s.script) @splat | Out-Host
            $rec.status = 'executed'
        } catch {
            $rec.status = 'error'
            $rec.error = $_.Exception.Message
            Write-Warning "[$($t.id)] $($rec.error)"
        }
        $rec.utc_end = (Get-Date).ToUniversalTime().ToString('o')
        $Results.Add($rec)
        $ran.Add($rec)
        Start-Sleep -Seconds 2          # spacing keeps steps apart in the SIEM timeline
    }
    if ($DryRun -or $ran.Count -eq 0) { continue }

    # collect DFIR artifacts before cleanup destroys them
    $artifacts = @()
    if ($t.scripts.collect) {
        $dir = Join-Path $OutDir $t.id
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        try {
            $paths = @(& (Join-Path $t.folder $t.scripts.collect) -Marker $Marker -OutDir $dir)
            foreach ($p in $paths) {
                if ($p -is [string] -and (Test-Path -LiteralPath $p)) {
                    $artifacts += [pscustomobject]@{ path = $p; sha256 = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower() }
                }
            }
        } catch { Write-Warning "[$($t.id)] collect: $($_.Exception.Message)" }
    }

    $cleanup = 'not-run'
    if ($t.scripts.cleanup) {
        $global:LASTEXITCODE = 0
        try {
            & (Join-Path $t.folder $t.scripts.cleanup) -Marker $Marker | Out-Host
            $cleanup = switch ($LASTEXITCODE) { 0 { 'verified' } $ExitManual { 'manual' } default { 'failed' } }
        } catch {
            $cleanup = 'failed'
            Write-Warning "[$($t.id)] cleanup: $($_.Exception.Message)"
        }
    }
    foreach ($r in $ran) { $r.cleanup = $cleanup; $r.artifacts = $artifacts }
}

if ($DryRun) { return }

# -InputObject keeps a one-step run a JSON array; WriteAllText writes UTF-8 without a BOM
$resultsPath = Join-Path $OutDir 'emulation-results.json'
[System.IO.File]::WriteAllText($resultsPath, (ConvertTo-Json -InputObject @($Results) -Depth 5))
$executed = @($Results | Where-Object { $_.status -eq 'executed' }).Count
Write-Host "`n[+] $executed/$($Results.Count) step(s) executed - results: $resultsPath" -ForegroundColor Green
Write-Host 'Next:'
Write-Host ("  .\Export-LabTelemetry.ps1 -Since '{0}'" -f $RunStart.ToString('yyyy-MM-dd HH:mm:ss'))
Write-Host "  rasd evidence --results `"$resultsPath`" --logs lab-export.jsonl"
