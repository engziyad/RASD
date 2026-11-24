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
| Splunk Enterprise with the RASD apps installed (a trial licence schedules alerts; Splunk Free does not) | Each detection as a scheduled alert; alert export is the latency source |
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

The hosted lab does all four steps by itself when it is started with the Splunk terms accepted ([how](../red/lab/README.md#a-lab-you-do-not-have-to-build)). On a Splunk of your own:

1. Install the apps: [`queries/splunk_app`](../queries/splunk_app/README.md) loads every detection as a scheduled alert named after its id. The searches need the fields of the vendor add-ons, or `rasd_fields` in their place.
2. Drive the attack and export the telemetry: steps 2 and 3 of [OPERATIONAL_VALIDATION](OPERATIONAL_VALIDATION.md).
3. Export the alerts over the run window: run **RASD - alert export** and save CSV (`siem-alerts.csv`), or let [`red/lab/splunk_lab.py`](../red/lab/splunk_lab.py) wait for the alerts and write it.
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

One row per detection of the library, written on every build from the rule's log source, the offensive tests that name it and the queries generated for it.

<!-- rasd:scorecard-needs:start -->
| Detection | Events it reads | Attack step | Queries |
|---|---|---|---|
| [T1003.001_lsass_memory_access](../detect/detections/T1003.001_lsass_memory_access/) | Sysmon · `process_access` | [lsass_memory_access](../red/windows/lsass_memory_access/) | [SPL](../queries/spl/T1003.001_lsass_memory_access.spl) · [KQL](../queries/kql/T1003.001_lsass_memory_access.kql) |
| [T1021.006_wsmprovhost_suspicious_child](../detect/detections/T1021.006_wsmprovhost_suspicious_child/) | Sysmon · `process_creation` | [winrm_access_validation](../red/active_directory/winrm_access_validation/) | [SPL](../queries/spl/T1021.006_wsmprovhost_suspicious_child.spl) · [KQL](../queries/kql/T1021.006_wsmprovhost_suspicious_child.kql) · [Defender](../queries/mde/T1021.006_wsmprovhost_suspicious_child.kql) |
| [T1046_decoy_service_interaction](../detect/detections/T1046_decoy_service_interaction/) | Decoy records · `opencanary/honeypot` | [decoy_service_probe](../red/linux/decoy_service_probe/) | [SPL](../queries/spl/T1046_decoy_service_interaction.spl) · [KQL](../queries/kql/T1046_decoy_service_interaction.kql) |
| [T1053.003_crontab_noninteractive_install](../detect/detections/T1053.003_crontab_noninteractive_install/) | Sysmon for Linux · `linux/process_creation` | [cron_persistence](../red/linux/cron_persistence/) | [SPL](../queries/spl/T1053.003_crontab_noninteractive_install.spl) · [KQL](../queries/kql/T1053.003_crontab_noninteractive_install.kql) |
| [T1053.005_powershell_scheduled_task_creation](../detect/detections/T1053.005_powershell_scheduled_task_creation/) | Sysmon · `process_creation` | [scheduled_task_creation](../red/windows/scheduled_task_creation/) | [SPL](../queries/spl/T1053.005_powershell_scheduled_task_creation.spl) · [KQL](../queries/kql/T1053.005_powershell_scheduled_task_creation.kql) · [Defender](../queries/mde/T1053.005_powershell_scheduled_task_creation.kql) |
| [T1053.005_schtasks_suspicious_creation](../detect/detections/T1053.005_schtasks_suspicious_creation/) | Sysmon · `process_creation` | [scheduled_task_creation](../red/windows/scheduled_task_creation/) | [SPL](../queries/spl/T1053.005_schtasks_suspicious_creation.spl) · [KQL](../queries/kql/T1053.005_schtasks_suspicious_creation.kql) · [Defender](../queries/mde/T1053.005_schtasks_suspicious_creation.kql) |
| [T1059.001_powershell_encoded_command](../detect/detections/T1059.001_powershell_encoded_command/) | Sysmon · `process_creation` | [powershell_encoded_command](../red/windows/powershell_encoded_command/) | [SPL](../queries/spl/T1059.001_powershell_encoded_command.spl) · [KQL](../queries/kql/T1059.001_powershell_encoded_command.kql) · [Defender](../queries/mde/T1059.001_powershell_encoded_command.kql) |
| [T1059.004_linux_suspicious_shell_execution](../detect/detections/T1059.004_linux_suspicious_shell_execution/) | Sysmon for Linux · `linux/process_creation` | [suspicious_shell_execution](../red/linux/suspicious_shell_execution/) | [SPL](../queries/spl/T1059.004_linux_suspicious_shell_execution.spl) · [KQL](../queries/kql/T1059.004_linux_suspicious_shell_execution.kql) |
| [T1078.002_honey_account_authentication](../detect/detections/T1078.002_honey_account_authentication/) | Security log · `windows/security` 4624, 4625, 4768, 4771, 4776 | [honey_account_use](../red/active_directory/honey_account_use/) | [SPL](../queries/spl/T1078.002_honey_account_authentication.spl) · [KQL](../queries/kql/T1078.002_honey_account_authentication.kql) |
| [T1218.011_rundll32_suspicious_execution](../detect/detections/T1218.011_rundll32_suspicious_execution/) | Sysmon · `process_creation` | [lsass_memory_access](../red/windows/lsass_memory_access/), [rundll32_execution](../red/windows/rundll32_execution/) | [SPL](../queries/spl/T1218.011_rundll32_suspicious_execution.spl) · [KQL](../queries/kql/T1218.011_rundll32_suspicious_execution.kql) · [Defender](../queries/mde/T1218.011_rundll32_suspicious_execution.kql) |
| [T1547.001_registry_run_key_persistence](../detect/detections/T1547.001_registry_run_key_persistence/) | Sysmon · `registry_set` | [run_key_persistence](../red/windows/run_key_persistence/) | [SPL](../queries/spl/T1547.001_registry_run_key_persistence.spl) · [KQL](../queries/kql/T1547.001_registry_run_key_persistence.kql) · [Defender](../queries/mde/T1547.001_registry_run_key_persistence.kql) |
| [T1552.001_honey_file_access](../detect/detections/T1552.001_honey_file_access/) | Security log · `windows/security` 4663 | [honey_file_access](../red/windows/honey_file_access/) | [SPL](../queries/spl/T1552.001_honey_file_access.spl) · [KQL](../queries/kql/T1552.001_honey_file_access.kql) |
| [T1558.003_honey_spn_ticket_request](../detect/detections/T1558.003_honey_spn_ticket_request/) | Security log · `windows/security` 4769 | [honey_account_use](../red/active_directory/honey_account_use/) | [SPL](../queries/spl/T1558.003_honey_spn_ticket_request.spl) · [KQL](../queries/kql/T1558.003_honey_spn_ticket_request.kql) |
| [T1558.003_kerberoasting_rc4_tgs](../detect/detections/T1558.003_kerberoasting_rc4_tgs/) | Security log · `windows/security` 4769 | [kerberoasting](../red/active_directory/kerberoasting/) | [SPL](../queries/spl/T1558.003_kerberoasting_rc4_tgs.spl) · [KQL](../queries/kql/T1558.003_kerberoasting_rc4_tgs.kql) |
| [T1569.002_suspicious_service_installation](../detect/detections/T1569.002_suspicious_service_installation/) | System log · `windows/system` 7045 | [service_creation](../red/windows/service_creation/) | [SPL](../queries/spl/T1569.002_suspicious_service_installation.spl) · [KQL](../queries/kql/T1569.002_suspicious_service_installation.kql) |
| [T1685.005_event_log_clearing](../detect/detections/T1685.005_event_log_clearing/) | Sysmon · `process_creation` | [event_log_clearing](../red/windows/event_log_clearing/) | [SPL](../queries/spl/T1685.005_event_log_clearing.spl) · [KQL](../queries/kql/T1685.005_event_log_clearing.kql) · [Defender](../queries/mde/T1685.005_event_log_clearing.kql) |
| [T1685.005_security_log_cleared](../detect/detections/T1685.005_security_log_cleared/) | Security log · `windows/security` 1102 | [event_log_clearing](../red/windows/event_log_clearing/) | [SPL](../queries/spl/T1685.005_security_log_cleared.spl) · [KQL](../queries/kql/T1685.005_security_log_cleared.kql) |
| [T1685.005_system_log_cleared](../detect/detections/T1685.005_system_log_cleared/) | System log · `windows/system` 104 | [event_log_clearing](../red/windows/event_log_clearing/) | [SPL](../queries/spl/T1685.005_system_log_cleared.spl) · [KQL](../queries/kql/T1685.005_system_log_cleared.kql) |
| [T1110.003_password_spray_burst](../detect/correlations/T1110.003_password_spray_burst/) (correlation) | Security log · `windows/security` 4625, 4768, 4771 | [password_spray_simulation](../red/active_directory/password_spray_simulation/) | [SPL](../queries/spl/correlations/T1110.003_password_spray_burst.spl) · [KQL](../queries/kql/correlations/T1110.003_password_spray_burst.kql) |
| [T1190_object_id_enumeration](../detect/correlations/T1190_object_id_enumeration/) (correlation) | Web access log · `webserver` | [idor_testing](../red/web/idor_testing/) | [SPL](../queries/spl/correlations/T1190_object_id_enumeration.spl) · [KQL](../queries/kql/correlations/T1190_object_id_enumeration.kql) |
| [T1558.003_kerberoasting_volume](../detect/correlations/T1558.003_kerberoasting_volume/) (correlation) | Security log · `windows/security` 4769 | no step reaches it yet | [SPL](../queries/spl/correlations/T1558.003_kerberoasting_volume.spl) · [KQL](../queries/kql/correlations/T1558.003_kerberoasting_volume.kql) |
| [T1595.003_api_auth_probing](../detect/correlations/T1595.003_api_auth_probing/) (correlation) | Web access log · `webserver` | [api_auth_testing](../red/web/api_auth_testing/) | [SPL](../queries/spl/correlations/T1595.003_api_auth_probing.spl) · [KQL](../queries/kql/correlations/T1595.003_api_auth_probing.kql) |
<!-- rasd:scorecard-needs:end -->

## Scorecard: results (filled by the lab run)

Every cell is read, on every build, from the committed `evidence.md` files and from the lab runs kept beside them; none is typed. `pending` means no lab run has produced it yet.

The Splunk columns come from the live Splunk of the hosted lab: Splunk Enterprise beside each lab host, its own scheduler, the RASD apps and no vendor add-on ([what that run showed](SIEM_DEPLOYMENT_NOTES.md#what-a-live-splunk-showed)). *Alerts with no step in the lab* counts the alerts that Splunk raised for a detection on a lab host where no step of the run asked for it. That is a short window on a host made for the run, and not the 72-hour baseline, which has not been run. *Sentinel only* marks a detection whose events no Defender advanced-hunting table carries.

<!-- rasd:scorecard-results:start -->
| Detection | Splunk alert | Splunk latency | Sentinel or Defender | Alerts with no step in the lab | False positives (72 h baseline) | The rule's event | Evidence |
|---|---|---|---|---|---|---|---|
| [T1003.001_lsass_memory_access](../detect/detections/T1003.001_lsass_memory_access/) | pending | pending | pending · Sentinel only | 0 | pending | pending | pending |
| [T1021.006_wsmprovhost_suspicious_child](../detect/detections/T1021.006_wsmprovhost_suspicious_child/) | raised by Splunk Enterprise 10.4.5 | 319 s | pending | 0 | pending | in the kept run | [75/100](../detect/detections/T1021.006_wsmprovhost_suspicious_child/evidence.md) |
| [T1046_decoy_service_interaction](../detect/detections/T1046_decoy_service_interaction/) | raised by Splunk Enterprise 10.4.5 | 586 s | pending · Sentinel only | 0 | pending | in the kept run | [75/100](../detect/detections/T1046_decoy_service_interaction/evidence.md) |
| [T1053.003_crontab_noninteractive_install](../detect/detections/T1053.003_crontab_noninteractive_install/) | raised by Splunk Enterprise 10.4.5 | 588 s | pending · Sentinel only | 0 | pending | in the kept run | [90/100](../detect/detections/T1053.003_crontab_noninteractive_install/evidence.md) |
| [T1053.005_powershell_scheduled_task_creation](../detect/detections/T1053.005_powershell_scheduled_task_creation/) | raised by Splunk Enterprise 10.4.5 | 589 s | pending | 0 | pending | in the kept run | [90/100](../detect/detections/T1053.005_powershell_scheduled_task_creation/evidence.md) |
| [T1053.005_schtasks_suspicious_creation](../detect/detections/T1053.005_schtasks_suspicious_creation/) | raised by Splunk Enterprise 10.4.5 | 593 s | pending | 0 | pending | in the kept run | [90/100](../detect/detections/T1053.005_schtasks_suspicious_creation/evidence.md) |
| [T1059.001_powershell_encoded_command](../detect/detections/T1059.001_powershell_encoded_command/) | raised by Splunk Enterprise 10.4.5 | 310 s | pending | 0 | pending | in the kept run | [90/100](../detect/detections/T1059.001_powershell_encoded_command/evidence.md) |
| [T1059.004_linux_suspicious_shell_execution](../detect/detections/T1059.004_linux_suspicious_shell_execution/) | raised by Splunk Enterprise 10.4.5 | 470 s | pending · Sentinel only | 0 | pending | in the kept run | [75/100](../detect/detections/T1059.004_linux_suspicious_shell_execution/evidence.md) |
| [T1078.002_honey_account_authentication](../detect/detections/T1078.002_honey_account_authentication/) | pending | pending | pending · Sentinel only | 0 | pending | pending | pending |
| [T1218.011_rundll32_suspicious_execution](../detect/detections/T1218.011_rundll32_suspicious_execution/) | raised by Splunk Enterprise 10.4.5 | 307 s | pending | 0 | pending | in the kept run | [75/100](../detect/detections/T1218.011_rundll32_suspicious_execution/evidence.md) |
| [T1547.001_registry_run_key_persistence](../detect/detections/T1547.001_registry_run_key_persistence/) | raised by Splunk Enterprise 10.4.5 | 309 s | pending | 0 | pending | in the kept run | [90/100](../detect/detections/T1547.001_registry_run_key_persistence/evidence.md) |
| [T1552.001_honey_file_access](../detect/detections/T1552.001_honey_file_access/) | raised by Splunk Enterprise 10.4.5 | 317 s | pending · Sentinel only | 0 | pending | in the kept run | [90/100](../detect/detections/T1552.001_honey_file_access/evidence.md) |
| [T1558.003_honey_spn_ticket_request](../detect/detections/T1558.003_honey_spn_ticket_request/) | pending | pending | pending · Sentinel only | 0 | pending | pending | pending |
| [T1558.003_kerberoasting_rc4_tgs](../detect/detections/T1558.003_kerberoasting_rc4_tgs/) | pending | pending | pending · Sentinel only | 0 | pending | pending | pending |
| [T1569.002_suspicious_service_installation](../detect/detections/T1569.002_suspicious_service_installation/) | raised by Splunk Enterprise 10.4.5 | 581 s | pending · Sentinel only | 0 | pending | in the kept run | [90/100](../detect/detections/T1569.002_suspicious_service_installation/evidence.md) |
| [T1685.005_event_log_clearing](../detect/detections/T1685.005_event_log_clearing/) | raised by Splunk Enterprise 10.4.5 | 320 s | pending | 0 | pending | in the kept run | [90/100](../detect/detections/T1685.005_event_log_clearing/evidence.md) |
| [T1685.005_security_log_cleared](../detect/detections/T1685.005_security_log_cleared/) | pending | pending | pending · Sentinel only | 0 | pending | pending | pending |
| [T1685.005_system_log_cleared](../detect/detections/T1685.005_system_log_cleared/) | raised by Splunk Enterprise 10.4.5 | 317 s | pending · Sentinel only | 0 | pending | in the kept run | [90/100](../detect/detections/T1685.005_system_log_cleared/evidence.md) |
| [T1110.003_password_spray_burst](../detect/correlations/T1110.003_password_spray_burst/) (correlation) | pending | pending | pending · Sentinel only | 0 | pending | pending | pending |
| [T1190_object_id_enumeration](../detect/correlations/T1190_object_id_enumeration/) (correlation) | raised by Splunk Enterprise 10.4.5 | 194 s | pending · Sentinel only | 0 | pending | in the kept run | [95/100](../detect/correlations/T1190_object_id_enumeration/evidence.md) |
| [T1558.003_kerberoasting_volume](../detect/correlations/T1558.003_kerberoasting_volume/) (correlation) | pending | pending | pending · Sentinel only | 0 | pending | pending | pending |
| [T1595.003_api_auth_probing](../detect/correlations/T1595.003_api_auth_probing/) (correlation) | raised by Splunk Enterprise 10.4.5 | 382 s | pending · Sentinel only | 0 | pending | in the kept run | [90/100](../detect/correlations/T1595.003_api_auth_probing/evidence.md) |
<!-- rasd:scorecard-results:end -->

## Sign-off

A row is complete when both SIEM columns carry an alert bound to the run, the false-positive cell holds the baseline count, and telemetry coverage is 100% (or the gap is explained). Commit the `evidence.md` files and run `rasd build && rasd chain`: the Operational Score and the latency and evidence matrices update from the committed evidence, moving each detection from *SIEM-Ready* to *Validated*. Until then this page is the honest statement of what remains to be measured.
