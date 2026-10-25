# SIEM Validation Scorecard

The one page that turns a detection from *SIEM-Ready* into live-SIEM evidence. It runs each generated query in a real Splunk and in Microsoft Sentinel / Defender, drives the attack from the lab kit, and records, per detection, whether the alert fired, how long it took, how it behaves on a benign baseline, and whether the telemetry it needs was actually present.

It does not invent results. Every result cell below reads `pending` until a lab run produces the evidence; the numbers come from [`rasd evidence`](OPERATIONAL_VALIDATION.md) and are committed as each detection's `evidence.md`. This page builds on [OPERATIONAL_VALIDATION](OPERATIONAL_VALIDATION.md) (the mechanics) and [EVIDENCE_PLAN](EVIDENCE_PLAN.md) (which lab host produces which event).

## The lab

Isolated and disposable. Never a production host, never credentials that exist anywhere else, never real estate telemetry.

| Component | Purpose |
|---|---|
| Domain controller (lab domain) | Kerberos and logon events (4769, 4768, 4771, 4776, 4625, 1102) |
| Windows 10/11 or Server endpoint, Sysmon + command-line auditing | Process creation, process access to lsass, registry Run-key writes, service install (7045), System 104 |
| Linux VM, Sysmon for Linux | Process creation for the crontab and shell tests |
| Lab web application (for example OWASP Juice Shop) | Access log in combined format for the web correlations |
| Splunk (free or trial) with the RASD app installed | Each detection as a scheduled alert; alert export is the latency source |
| Microsoft Sentinel or Defender for Endpoint, test tenant | The KQL run as an analytics rule or advanced-hunting query |
| Log forwarding from the VMs to each SIEM | So the same run scores in both |

Sysmon uses [`red/lab/sysmon-rasd.xml`](../red/lab/sysmon-rasd.xml) or any config that logs the same events; [`red/lab/Test-LabReadiness.ps1`](../red/lab/README.md) proves it with a live probe.

## What each metric means

| Metric | Definition | Target |
|---|---|---|
| Alert fired | The SIEM raised the detection on an event bound to the attack step (time + host + token, per OPERATIONAL_VALIDATION) | Yes for every `fires` step |
| Detection latency | Alert time minus the triggering event's time | Report; no pass/fail without a tuned estate |
| SIEM pipeline delay | Alert time minus ingest time, i.e. scheduling and search lag, separated from true latency | Report |
| False positives (benign baseline) | Alerts raised while only the benign baseline ran, over the baseline window | 0 on the baseline below; any FP is tuned, not hidden |
| Telemetry coverage | Expected event types present in the export divided by the expected set for that detection | 100% before a miss is believed to be the rule |

Latency and false-positive rate are estate-dependent; this scorecard records them, it does not grade them. A production estate sets its own thresholds in [ENTERPRISE_ADOPTION](ENTERPRISE_ADOPTION.md).

## Run it in Splunk

1. Install the app: [`queries/splunk_app`](../queries/splunk_app/README.md) loads every detection as a scheduled alert named after its id.
2. Drive the attack and export the telemetry: steps 2 and 3 of [OPERATIONAL_VALIDATION](OPERATIONAL_VALIDATION.md).
3. Export the alerts over the run window: run **RASD - alert export** and save CSV (`siem-alerts.csv`).
4. Score it:
   ```bash
   rasd evidence --run <lab-run>.zip dc-export.jsonl siem-alerts.csv --strict
   ```
   `evidence.md` records the alert, its latency and the SIEM pipeline delay per detection.

## Run it in Microsoft Sentinel / Defender

Defender advanced hunting carries `DeviceProcessEvents` and `DeviceRegistryEvents`, so it validates the process-creation and registry detections. It has no Sysmon-style process-access record and no 4769 / 7045 / 1102 / 104 fields, so LSASS access, Kerberoasting, service install, the log-clear events and the web correlations are validated in Splunk over native Windows and Sysmon forwarding instead; `rasd doctor --profile mde-advanced-hunting` marks those BLIND with that reason, and the scorecard reads `n/a` for them under Defender.

1. Deploy the generated KQL (`queries/kql/<id>.kql`) as a scheduled analytics rule, or as a custom detection in Defender for Endpoint, for the detections the schema supports.
2. Drive the same attack from the lab kit.
3. Export the alerts, or the advanced-hunting rows, as CSV or JSON (`siem-alerts.csv`).
4. Score it with the Defender field names:
   ```bash
   rasd evidence --run <lab-run>.zip lab-export.jsonl siem-alerts.csv --profile mde-advanced-hunting --strict
   ```
   The [telemetry profile](../profiles/README.md) maps the rules onto Defender advanced-hunting columns; the profile used is written into `evidence.md`.

## Benign baseline (the false-positive number)

Run the lab for a fixed window (for example 72 hours) with only ordinary activity and no attack steps: domain logons, Group Policy refreshes, software updates, scheduled tasks, admin PowerShell, Defender scans, routine web traffic. Export the same windows and run `rasd evidence` over them with no run to bind against; any detection that alerts is a false positive and its false-positive cell carries the count over the baseline window. A clean baseline is `0`.

## Scorecard: what each detection needs

| Detection | Data source · key event | Attack step | Queries |
|---|---|---|---|
| T1003.001 LSASS memory access | Sysmon 10 (process access to lsass.exe) | `-Technique T1003.001 -IncludeCredentialAccess` | `queries/splunk`, `queries/kql` |
| T1021.006 WSMProvHost child | Sysmon 1 (child of wsmprovhost.exe) | `-Technique T1021.006` | `queries/splunk`, `queries/kql` |
| T1053.003 crontab non-interactive | Sysmon for Linux 1 | `run_red.py` crontab test | `queries/splunk`, `queries/kql` |
| T1053.005 PowerShell scheduled task | Sysmon 1 / PowerShell | `-Technique T1053.005` | `queries/splunk`, `queries/kql` |
| T1053.005 schtasks creation | Sysmon 1 (schtasks /create) | `-Technique T1053.005` | `queries/splunk`, `queries/kql` |
| T1059.001 PowerShell encoded command | Sysmon 1 (powershell -enc) | `-Technique T1059.001` | `queries/splunk`, `queries/kql` |
| T1059.004 Linux suspicious shell | Sysmon for Linux 1 | `run_red.py` shell test | `queries/splunk`, `queries/kql` |
| T1218.011 rundll32 execution | Sysmon 1 (rundll32) | `-Technique T1218.011` | `queries/splunk`, `queries/kql` |
| T1547.001 registry Run key | Sysmon 13 (Run/RunOnce value set) | `-Technique T1547.001` | `queries/splunk`, `queries/kql` |
| T1558.003 Kerberoasting RC4 TGS | Security 4769 (RC4 ticket) | `-Technique T1558.003 -Spn <spn>` | `queries/splunk`, `queries/kql` |
| T1569.002 service installation | System 7045 | `-Technique T1569.002` | `queries/splunk`, `queries/kql` |
| T1685.005 event log clearing | Sysmon 1 (wevtutil cl / Clear-EventLog) | `-Technique T1685.005` | `queries/splunk`, `queries/kql` |
| T1685.005 Security log cleared | Security 1102 | `-Technique T1685.005 -IncludeSecurityLogClear` | `queries/splunk`, `queries/kql` |
| T1685.005 System log cleared | System 104 | `-Technique T1685.005` | `queries/splunk`, `queries/kql` |
| T1110.003 password spray burst (corr) | Security 4625 / 4771 volume | `-Technique T1110.003` | `queries/splunk`, `queries/kql` |
| T1190 object-id enumeration (corr) | Web access log | `run_red.py` IDOR test | `queries/splunk`, `queries/kql` |
| T1558.003 Kerberoasting volume (corr) | Security 4769 volume | `-Technique T1558.003` | `queries/splunk`, `queries/kql` |
| T1595.003 API auth probing (corr) | Web access log | `run_red.py` API auth test | `queries/splunk`, `queries/kql` |

## Scorecard: results (filled by the lab run)

Each cell is written from the committed `evidence.md`, not by hand. `pending` means no lab run has produced it yet.

| Detection | Splunk alert | Splunk latency | Defender alert | Defender latency | FP (72h baseline) | Telemetry coverage | Evidence |
|---|---|---|---|---|---|---|---|
| T1003.001 LSASS memory access | pending | pending | n/a | n/a | pending | pending | pending |
| T1021.006 WSMProvHost child | pending | pending | pending | pending | pending | pending | pending |
| T1053.003 crontab non-interactive | pending | pending | pending | pending | pending | pending | pending |
| T1053.005 PowerShell scheduled task | pending | pending | pending | pending | pending | pending | pending |
| T1053.005 schtasks creation | pending | pending | pending | pending | pending | pending | pending |
| T1059.001 PowerShell encoded command | pending | pending | pending | pending | pending | pending | pending |
| T1059.004 Linux suspicious shell | pending | pending | pending | pending | pending | pending | pending |
| T1218.011 rundll32 execution | pending | pending | pending | pending | pending | pending | pending |
| T1547.001 registry Run key | pending | pending | pending | pending | pending | pending | pending |
| T1558.003 Kerberoasting RC4 TGS | pending | pending | n/a | n/a | pending | pending | pending |
| T1569.002 service installation | pending | pending | n/a | n/a | pending | pending | pending |
| T1685.005 event log clearing | pending | pending | pending | pending | pending | pending | pending |
| T1685.005 Security log cleared | pending | pending | n/a | n/a | pending | pending | pending |
| T1685.005 System log cleared | pending | pending | n/a | n/a | pending | pending | pending |
| T1110.003 password spray burst (corr) | pending | pending | n/a | n/a | pending | pending | pending |
| T1190 object-id enumeration (corr) | pending | pending | n/a | n/a | pending | pending | pending |
| T1558.003 Kerberoasting volume (corr) | pending | pending | n/a | n/a | pending | pending | pending |
| T1595.003 API auth probing (corr) | pending | pending | n/a | n/a | pending | pending | pending |

## Sign-off

A row is complete when both SIEM columns carry an alert bound to the run, the false-positive cell holds the baseline count, and telemetry coverage is 100% (or the gap is explained). Commit the `evidence.md` files and run `rasd build && rasd chain`: the Operational Score and the latency and evidence matrices update from the committed evidence, moving each detection from *SIEM-Ready* to *Validated*. Until then this page is the honest statement of what remains to be measured.
