# RASD lab kit · real evidence from a lab and Splunk

Synthetic samples prove the rule logic. Only a real run proves the rest: the technique runs, Windows writes the event, the forwarder ships it, Splunk raises the alert, and the host is clean afterwards. This kit turns that run into one command and one workstation zip; with the DC export (for Kerberoasting) and the Splunk alert export, `rasd evidence` turns them into committed `evidence.md` files.

> Use a personal, isolated lab only. Never a work machine, a work SIEM or work logs: the repository holds synthetic data and lab evidence, nothing else.

## Lab layout

| Machine | Role | Needs |
|---|---|---|
| Windows 10/11 or Server VM | Runs the tests | Sysmon with [`sysmon-rasd.xml`](sysmon-rasd.xml) (lab only - see below); Splunk Universal Forwarder with the `rasd_forwarder` app; domain-joined for the Active Directory tests |
| Windows Server DC (for the AD tests) | Logs Kerberos 4768, 4769, 4771, 4776 | The audit policy `Test-LabReadiness.ps1 -Fix` sets; the forwarder with `rasd_forwarder` |
| Second Windows VM (for the WinRM test) | WinRM target: logs what the remote session starts | WinRM enabled (`Enable-PSRemoting`), Sysmon with `sysmon-rasd.xml`, the forwarder with `rasd_forwarder` |
| Linux VM (for the Linux and web tests) | Runs the cron and shell tests; hosts the lab web application | Sysmon for Linux; Splunk Universal Forwarder with the Splunk Add-on for Sysmon for Linux and the `rasd_forwarder_linux` app; a lab copy of a web application (for example OWASP Juice Shop) on localhost |
| Splunk Enterprise (60-day trial) | SIEM | Splunk Add-on for Microsoft Windows, Splunk Add-on for Sysmon, Splunk Add-on for Sysmon for Linux, the [`rasd`](../../queries/splunk_app/) app, receiving on port 9997 |

Splunk Free cannot run scheduled alerts, so it cannot produce the SIEM part of the evidence; use the Enterprise trial.

## Steps

**1 · Splunk.** Install Splunk Enterprise and the three add-ons (Microsoft Windows, Sysmon, Sysmon for Linux). Copy `queries/splunk_app/rasd` to `$SPLUNK_HOME/etc/apps/`, enable receiving on 9997 (Settings › Forwarding and receiving), restart. The app creates every index the queries read (`sysmon`, `wineventlog`, `linux`, `web`) and `rasd_alerts`, where the alerts are written and one scheduled alert per detection, named `RASD - <detection id>` - see [queries/splunk_app](../../queries/splunk_app/README.md).

**2 · Lab VM and DC.** On each machine, from an elevated Windows PowerShell:

```powershell
Sysmon64.exe -accepteula -i .\red\lab\sysmon-rasd.xml          # the test VM
# Universal Forwarder: point it at <splunk-host>:9997 during setup, then
Copy-Item .\queries\splunk_app\rasd_forwarder "$env:ProgramFiles\SplunkUniversalForwarder\etc\apps\" -Recurse
Restart-Service SplunkForwarder
```

**3 · Readiness.** Run on the VM and on the DC until nothing FAILs. `-Fix` turns on the audit policy and PowerShell logging it checks; it never installs software.

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\red\lab\Test-LabReadiness.ps1 -Fix
```

The probe starts a harmless `cmd.exe /c rem rasd-readiness-…` and confirms Sysmon logged it, so a PASS means the sensor really works, not only that it is installed.

**4 · Snapshot the VM**, so it can be reverted after the run.

**5 · Run.**

```powershell
.\red\lab\Invoke-RasdLabRun.ps1 -LabConfirmed -DryRun        # which tests run or are skipped, and why

# Safe default: skips credential access (LSASS dump) and the Security-log clear
.\red\lab\Invoke-RasdLabRun.ps1 -LabConfirmed -FixReadiness -Spn MSSQLSvc/sql01.lab.local:1433 -UserList .\lab-users.txt

# Full validation attempt for every Windows detection
.\red\lab\Invoke-RasdLabRun.ps1 -LabConfirmed -IncludeCredentialAccess -IncludeSecurityLogClear -Spn MSSQLSvc/sql01.lab.local:1433 -UserList .\lab-users.txt
```

The safe default leaves `T1003.001_lsass_memory_access` and `T1685.005_security_log_cleared` without a step, so they stay pending; the full run attempts every Windows detection. Without `-Spn` the Kerberoasting step is skipped too, and without `-Target <second VM>` the WinRM step; the WinRM event is logged on the target, so export that VM's logs as well (`Export-LabTelemetry.ps1 -Since '<start>' -OutFile target-export.jsonl`). The script checks readiness, runs every test, waits 15 minutes for Splunk's alerts, exports the run's events and packs everything into `red\results\lab-<time>.zip`. The zip holds the workstation side only; the script then prints the commands for the rest:

- on the DC, when Kerberoasting or the password spray ran: `Export-LabTelemetry.ps1 -LogName Security -EventId 4768,4769,4771,4776,4625 -Since '<start>' -OutFile dc-export.jsonl`
- in Splunk: the report **RASD - alert export** over the run window, exported as `siem-alerts.csv` - preferred, because it carries the alerting host; the `(audit)` and `(scheduler)` variants are acceptable fallbacks without a host. On the first run, confirm the host is written: `index=rasd_alerts | table _time rasd_alert alert_host alert_hosts first_event last_event`

**5b · Linux and web.** On the Linux VM, after a snapshot:

```bash
export RASD_LAB_EMAIL=<lab test account> RASD_LAB_PASSWORD=<its password>   # the IDOR and JWT tests log in; never a real account
python3 red/run_red.py --platform linux web --lab-confirmed --target http://127.0.0.1:3000 --dry-run
python3 red/run_red.py --platform linux web --lab-confirmed --target http://127.0.0.1:3000
python3 red/linux/export_sysmon_linux.py --since '<start printed by the runner>' --out linux-export.jsonl
python3 red/web/export_access_log.py --input <the application's access log> --marker <run marker> --out web-export.jsonl
```

The runner writes its own `emulation-results.json` and artifacts under `red/results/<timestamp>`; give that folder to `rasd evidence --run` with the two exports: `rasd evidence --run red/results/<timestamp> linux-export.jsonl web-export.jsonl`.

**6 · Evidence.**

```bash
rasd doctor red/results/lab-<timestamp>/lab-export.jsonl   # fields intact? anything truncated?
rasd evidence --run red/results/lab-<timestamp>.zip dc-export.jsonl siem-alerts.csv
rasd build
git add detect/detections/*/evidence.md detect/correlations/*/evidence.md
```

Each detection is reported **FIRED** (and gets `evidence.md`) or **MISSED** (and the command fails); a miss is never written down. An event counts only when it is bound to the run - right host or client address, inside the step's window, carrying the run marker where the test declares one ([details](../../docs/OPERATIONAL_VALIDATION.md)). The Operational Score, maturity levels and matrices then update from the committed evidence.

**7 · Revert the VM snapshot.**

## What goes into the repository

Only the `evidence.md` files under `detect/detections/` and `detect/correlations/`. Each records the run, host, marker, matching event, latencies, cleanup status and the SHA-256 of every raw file. The raw files - results, exports, the alert CSV, collected artifacts - stay with you (`red/results/` is ignored by git), so anyone you give them to can re-run `rasd evidence --dry-run` and get the same verdict.

## Files

| File | Purpose |
|---|---|
| [`Test-LabReadiness.ps1`](Test-LabReadiness.ps1) | Sysmon, live probe, audit policy, PowerShell logging, forwarder and connection, lab context; `-Fix` |
| [`Invoke-RasdLabRun.ps1`](Invoke-RasdLabRun.ps1) | Readiness → tests → SIEM wait → export → zip, then the remaining commands |
| [`sysmon-rasd.xml`](sysmon-rasd.xml) | Sysmon configuration covering what the rules, hunts and playbooks read. **Do not deploy sysmon-rasd.xml to production. It is intentionally verbose for validation.** |
| [`../../queries/splunk_app`](../../queries/splunk_app/) | The Splunk apps, generated from the rules on every build |
