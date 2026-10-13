<#
.SYNOPSIS
    RASD lab readiness: can this VM produce real evidence right now?
.DESCRIPTION
    Checks what the RASD tests, detections and Splunk need before a lab run, and prints
    the fix for every gap:
      Session       elevated, Windows PowerShell 5.1 (the event-log test needs New-EventLog)
      Sysmon        installed and running; its configuration logs lsass access and Run keys
      Probe         a harmless process creation really reaches the Sysmon log (EID 1)
      Domain        joined (Active Directory tests); on a DC, the audit policy behind
                    4769, 4771, 4776 and 4625
      Logging       PowerShell script block logging (4104) for the DFIR playbooks
      Splunk        Universal Forwarder running, rasd_forwarder app present, connected to
                    an indexer on 9997
      Lab context   LSA protection and Defender real-time protection, which block parts of
                    the credential-access and proxy-execution tests
    -Fix turns on the audit policy and PowerShell logging it checks. It never installs
    software. Exit code 1 when a check FAILs. Lab use only.
.EXAMPLE
    .\red\lab\Test-LabReadiness.ps1
.EXAMPLE
    .\red\lab\Test-LabReadiness.ps1 -Fix
#>
[CmdletBinding()]
param(
    [switch] $Fix,
    [switch] $PassThru
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # native tools write to stderr; a check must never abort the others

function Resolve-ExecutablePath([string] $PathName) {
    <# The executable of a Win32_Service PathName: quoted, unquoted with spaces, or followed by arguments. #>
    if (-not $PathName) { return $null }
    $text = $PathName.Trim()
    if ($text -match '^"([^"]+)"') { return $matches[1] }
    if ($text -match '^(.+?\.exe)(\s|$)') { return $matches[1] }
    return ($text -split '\s+', 2)[0]
}

if ($MyInvocation.InvocationName -eq '.') { return }   # dot-sourced (tests): expose the helpers only

if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) { throw 'Run this on the Windows lab VM.' }

$results = [System.Collections.Generic.List[object]]::new()
function Add-Check([string] $Check, [string] $Result, [string] $Detail, [string] $Remedy = '') {
    $results.Add([pscustomobject][ordered]@{ check = $Check; result = $Result; detail = $Detail; fix = $Remedy })
}

function Test-EventLogChannel([string] $Name, [string] $Why) {
    $log = Get-WinEvent -ListLog $Name -ErrorAction SilentlyContinue
    if (-not $log) { Add-Check "Event log: $Name" 'FAIL' "missing - $Why" 'Enable/install the component that owns this channel'; return }
    if ($log.IsEnabled) { Add-Check "Event log: $Name" 'PASS' "enabled - $Why" }
    else { Add-Check "Event log: $Name" 'FAIL' "disabled - $Why" "wevtutil sl '$Name' /e:true" }
}

# ------------------------------------------------------------------ session
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if ($admin) { Add-Check 'Elevated session' 'PASS' 'running as administrator' }
else { Add-Check 'Elevated session' 'FAIL' 'the tests and most checks need an elevated session' 'Start Windows PowerShell with Run as administrator' }

if ($PSVersionTable.PSEdition -eq 'Desktop') { Add-Check 'Windows PowerShell 5.1' 'PASS' "PowerShell $($PSVersionTable.PSVersion)" }
else { Add-Check 'Windows PowerShell 5.1' 'WARN' "PowerShell $($PSVersionTable.PSVersion): the event-log test needs New-EventLog" 'Run the lab from powershell.exe (5.1), not pwsh' }

# ------------------------------------------------------------------ event channels and command line visibility
Test-EventLogChannel 'Microsoft-Windows-Sysmon/Operational' 'Sysmon process, access and registry events'
Test-EventLogChannel 'Security' 'Security 1102 and Kerberos 4769 on the DC'
Test-EventLogChannel 'System' 'System 104 and service installation 7045'
Test-EventLogChannel 'Microsoft-Windows-PowerShell/Operational' 'PowerShell 4104 context for DFIR'

$cmdLineKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
$cmdLine = Get-ItemProperty -Path $cmdLineKey -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue
if ($cmdLine -and $cmdLine.ProcessCreationIncludeCmdLine_Enabled -eq 1) {
    Add-Check 'Command line audit policy' 'PASS' 'Security 4688 can include command lines if collected later'
} elseif ($Fix -and $admin) {
    New-Item -Path $cmdLineKey -Force | Out-Null
    Set-ItemProperty -Path $cmdLineKey -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord
    Add-Check 'Command line audit policy' 'FIXED' 'turned on for future 4688 collection'
} else {
    Add-Check 'Command line audit policy' 'WARN' 'off: Sysmon still covers current detections, but 4688 fallback context is weaker' 'Rerun with -Fix'
}

# ------------------------------------------------------------------ Sysmon
$sysmon = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -in @('Sysmon', 'Sysmon64') })
$sysmonExe = $null
if ($sysmon.Count -eq 0) {
    Add-Check 'Sysmon' 'FAIL' 'not installed: the rules read Sysmon EID 1, 10 and 13' 'Sysmon64.exe -accepteula -i red\lab\sysmon-rasd.xml (Sysinternals download)'
} elseif ($sysmon[0].State -ne 'Running') {
    Add-Check 'Sysmon' 'FAIL' "service $($sysmon[0].Name) is $($sysmon[0].State)" "Start-Service $($sysmon[0].Name)"
} else {
    $sysmonExe = Resolve-ExecutablePath $sysmon[0].PathName
    $version = try { (Get-Item -LiteralPath $sysmonExe -ErrorAction Stop).VersionInfo.FileVersion } catch { 'unknown version' }
    Add-Check 'Sysmon' 'PASS' "$($sysmon[0].Name) running ($version)"
}

if ($sysmonExe -and $admin) {
    $config = (& $sysmonExe -c 2>&1 | Out-String)
    $missing = @()
    if (-not ($config -match 'ProcessAccess' -and $config -match 'lsass')) { $missing += 'EID 10 for lsass.exe' }
    if (-not ($config -match 'Registry' -and $config -match 'CurrentVersion\\Run')) { $missing += 'EID 13 for Run keys' }
    if ($missing.Count) {
        Add-Check 'Sysmon configuration' 'WARN' ("the configuration does not seem to log " + ($missing -join ' and ')) 'Sysmon64.exe -c red\lab\sysmon-rasd.xml'
    } else {
        Add-Check 'Sysmon configuration' 'PASS' 'logs lsass access and Run-key writes'
    }
}

# A real process creation must reach the Sysmon log: the only check that proves the sensor works.
if ($sysmonExe -and $admin) {
    $probe = 'rasd-readiness-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    $t0 = (Get-Date).AddSeconds(-2)
    Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList "/c rem $probe" -WindowStyle Hidden -Wait
    $seen = $false
    foreach ($i in 1..10) {
        Start-Sleep -Seconds 1
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1; StartTime = $t0 } -ErrorAction SilentlyContinue)
        if (@($events | Where-Object { $_.Message -match $probe }).Count) { $seen = $true; break }
    }
    if ($seen) { Add-Check 'Sysmon probe' 'PASS' "a test process ($probe) was logged as EID 1" }
    else { Add-Check 'Sysmon probe' 'FAIL' 'a test process was NOT logged as EID 1 within 10 s' 'Check the ProcessCreate rules of the Sysmon configuration (red\lab\sysmon-rasd.xml logs every process)' }
}

# ------------------------------------------------------------------ domain and audit policy
$cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
$isDc = $cs -and $cs.DomainRole -ge 4
if ($cs -and $cs.PartOfDomain) { Add-Check 'Domain' 'PASS' ("member of $($cs.Domain)" + $(if ($isDc) { ' (domain controller)' } else { '' })) }
else { Add-Check 'Domain' 'WARN' 'not domain-joined: the Active Directory tests will be skipped or fail' 'Join the VM to the lab domain' }

$required = @()
if ($isDc) {
    $required = @(
        @{ Name = 'Kerberos Service Ticket Operations'; Guid = '0CCE9240-69AE-11D9-BED3-505054503030'; Bit = 1; Why = '4769 (Kerberoasting rule and volume correlation)' },
        @{ Name = 'Kerberos Authentication Service'; Guid = '0CCE9242-69AE-11D9-BED3-505054503030'; Bit = 2; Why = '4771 failures (password-spray correlation)' },
        @{ Name = 'Credential Validation'; Guid = '0CCE923F-69AE-11D9-BED3-505054503030'; Bit = 2; Why = '4776 failures (spray investigation)' },
        @{ Name = 'Logon'; Guid = '0CCE9215-69AE-11D9-BED3-505054503030'; Bit = 2; Why = '4625 failures (password-spray correlation, LDAP binds)' })
}
if ($required.Count -and $admin) {
    $backup = Join-Path $env:TEMP ('rasd-auditpol-' + [guid]::NewGuid().ToString('N') + '.csv')
    & auditpol.exe /backup /file:$backup | Out-Null
    $policy = @{}
    if (Test-Path -LiteralPath $backup) {
        foreach ($row in (Import-Csv -LiteralPath $backup)) {
            $guid = [string]$row.'Subcategory GUID'
            if ($guid) { $policy[$guid.Trim('{}').ToUpper()] = [int]("0" + $row.'Setting Value') }
        }
        Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
    }
    foreach ($r in $required) {
        $value = if ($policy.ContainsKey($r.Guid)) { $policy[$r.Guid] } else { 0 }
        $kind = if ($r.Bit -eq 1) { 'success' } else { 'failure' }
        if ($value -band $r.Bit) {
            Add-Check "Audit: $($r.Name)" 'PASS' "$kind audited - $($r.Why)"
            continue
        }
        $command = "auditpol /set /subcategory:{$($r.Guid)} /$($kind):enable"
        if ($Fix) {
            & auditpol.exe /set "/subcategory:{$($r.Guid)}" "/$($kind):enable" | Out-Null
            Add-Check "Audit: $($r.Name)" 'FIXED' "$kind auditing turned on - $($r.Why); a domain GPO may turn it off again" 'Set it in the Default Domain Controllers Policy to make it stick'
        } else {
            Add-Check "Audit: $($r.Name)" 'FAIL' "$kind not audited - no $($r.Why)" $command
        }
    }
} elseif (-not $isDc) {
    Add-Check 'Audit policy (DC)' 'INFO' 'not a domain controller: run this script on the lab DC too (Kerberos events are logged there)'
}

# ------------------------------------------------------------------ PowerShell logging (DFIR)
$sblKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
$sbl = Get-ItemProperty -Path $sblKey -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue
if ($sbl -and $sbl.EnableScriptBlockLogging -eq 1) {
    Add-Check 'Script block logging' 'PASS' '4104 records the decoded script of an encoded command'
} elseif ($Fix -and $admin) {
    New-Item -Path $sblKey -Force | Out-Null
    Set-ItemProperty -Path $sblKey -Name EnableScriptBlockLogging -Value 1 -Type DWord
    Add-Check 'Script block logging' 'FIXED' 'turned on (4104)'
} else {
    Add-Check 'Script block logging' 'WARN' 'off: the DFIR playbook cannot show the decoded script' 'Rerun with -Fix'
}

# ------------------------------------------------------------------ Splunk
$uf = Get-Service -Name SplunkForwarder -ErrorAction SilentlyContinue
if (-not $uf) {
    Add-Check 'Splunk forwarder' 'WARN' 'not installed: lab evidence still counts, but the SIEM result and latency score 0' 'Install the Splunk Universal Forwarder and point it at the lab Splunk on 9997'
} elseif ($uf.Status -ne 'Running') {
    Add-Check 'Splunk forwarder' 'FAIL' "SplunkForwarder is $($uf.Status)" 'Start-Service SplunkForwarder'
} else {
    Add-Check 'Splunk forwarder' 'PASS' 'SplunkForwarder running'
    $ufApps = Join-Path ${env:ProgramFiles} 'SplunkUniversalForwarder\etc\apps'
    $rasdInputs = Join-Path $ufApps 'rasd_forwarder\default\inputs.conf'
    if (Test-Path -LiteralPath $rasdInputs) {
        $rawInputs = Get-Content -LiteralPath $rasdInputs -Raw
        $neededInputs = @('WinEventLog://Microsoft-Windows-Sysmon/Operational', 'WinEventLog://Security', 'WinEventLog://System', 'renderXml = true')
        $missingInputs = @($neededInputs | Where-Object { $rawInputs -notmatch [regex]::Escape($_) })
        if ($missingInputs.Count) {
            Add-Check 'rasd_forwarder app' 'FAIL' ('installed but missing: ' + ($missingInputs -join ', ')) "Re-copy queries\splunk_app\rasd_forwarder to $ufApps, then Restart-Service SplunkForwarder"
        } else {
            Add-Check 'rasd_forwarder app' 'PASS' 'Sysmon, Security and System XML inputs installed'
        }
    } else {
        Add-Check 'rasd_forwarder app' 'FAIL' 'the forwarder does not have the RASD inputs' "Copy queries\splunk_app\rasd_forwarder to $ufApps, then Restart-Service SplunkForwarder"
    }
    $link = @(Get-NetTCPConnection -RemotePort 9997 -State Established -ErrorAction SilentlyContinue)
    if ($link.Count) { Add-Check 'Forwarder connection' 'PASS' "connected to $($link[0].RemoteAddress):9997" }
    else { Add-Check 'Forwarder connection' 'FAIL' 'no connection to an indexer on 9997' 'Enable receiving on 9997 in Splunk and run: splunk add forward-server <splunk-host>:9997' }
}

# ------------------------------------------------------------------ lab context
$ppl = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue
if ($ppl -and $ppl.RunAsPPL -ge 1) { Add-Check 'LSA protection' 'INFO' 'RunAsPPL is on: the LSASS dump step will be blocked (the rundll32 command line is still logged)' }
$mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($mp -and $mp.RealTimeProtectionEnabled) {
    Add-Check 'Defender real-time protection' 'INFO' 'on: it may block the LSASS and rundll32 steps; their process-creation events are still written'
}

# ------------------------------------------------------------------ report
if ($PassThru) { return $results }
$results | Format-Table -Property check, result, detail -AutoSize -Wrap | Out-Host
$todo = @($results | Where-Object { $_.fix -and $_.result -in @('FAIL', 'WARN') })
if ($todo.Count) {
    Write-Host 'To fix:' -ForegroundColor Yellow
    foreach ($t in $todo) { Write-Host "  [$($t.result)] $($t.check): $($t.fix)" }
}
$failed = @($results | Where-Object { $_.result -eq 'FAIL' }).Count
if ($failed) { Write-Host "$failed check(s) failed - fix them before the lab run." -ForegroundColor Red; exit 1 }
Write-Host 'Ready for a lab run.' -ForegroundColor Green
exit 0
