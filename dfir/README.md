# RASD-DFIR: Investigation & Response

RASD-DFIR turns an alert into an investigation: what to check in the first fifteen minutes, which evidence to collect and why, when to escalate, and how to close. Every playbook is linked from the detections and offensive tests it serves, so the analyst who receives an alert lands on the right procedure.

| Folder | Contents |
|---|---|
| [`playbooks/`](playbooks/) | One playbook per behaviour, in a fixed format: Trigger, Required Data, First 15 Minutes, Deep Investigation, Evidence to Collect, Escalate If, Closure Guidance |
| [`queries/`](queries/) | Pivot queries (KQL and SPL) the playbooks call: process tree, user-host window, persistence sweep, Kerberos client activity |
| [`templates/`](templates/) | Incident summary, evidence table, timeline, containment plan, closure note |
| [`models/`](models/) | Investigation flow and the timeline model every investigation follows |

Each playbook starts with a small front matter block (`techniques`, `detections`, `red_tests`) that `tools/chain.py` reads to build the attack-to-defense matrix; CI fails when a playbook has no evidence table or points at a detection or test that does not exist.

## Playbooks

<!-- rasd:dfir-catalog:start -->
| Playbook | Techniques | Detections | Red tests |
|---|---|---|---|
| [ad_reconnaissance](playbooks/ad_reconnaissance.md) | T1087.002, T1069.002, T1018 | none yet | ldap_enumeration |
| [event_log_clearing](playbooks/event_log_clearing.md) | T1070.001 | `T1070.001_event_log_clearing`, `T1070.001_security_log_cleared`, `T1070.001_system_log_cleared` | event_log_clearing |
| [kerberoasting](playbooks/kerberoasting.md) | T1558.003, T1110.002 | `T1558.003_kerberoasting_rc4_tgs`, `T1558.003_kerberoasting_volume` | kerberoasting, ldap_enumeration |
| [lateral_movement](playbooks/lateral_movement.md) | T1021.002, T1021.006, T1569.002, T1053.005 | `T1569.002_suspicious_service_installation`, `T1053.005_schtasks_suspicious_creation`, `T1021.006_wsmprovhost_suspicious_child` | service_creation, scheduled_task_creation, winrm_access_validation |
| [linux_persistence](playbooks/linux_persistence.md) | T1053.003, T1059.004, T1083, T1548.001 | `T1053.003_crontab_noninteractive_install`, `T1059.004_linux_suspicious_shell_execution` | cron_persistence, suspicious_shell_execution, privilege_escalation_checks |
| [lsass_access](playbooks/lsass_access.md) | T1003.001 | `T1003.001_lsass_memory_access`, `T1218.011_rundll32_suspicious_execution` | lsass_memory_access |
| [password_spray](playbooks/password_spray.md) | T1110.003 | `T1110.003_password_spray_burst` | password_spray_simulation |
| [phishing_triage](playbooks/phishing_triage.md) | T1566.001, T1204.002, T1059.001 | `T1059.001_powershell_encoded_command` | powershell_encoded_command |
| [run_key_persistence](playbooks/run_key_persistence.md) | T1547.001, T1112 | `T1547.001_registry_run_key_persistence` | run_key_persistence |
| [rundll32_proxy_execution](playbooks/rundll32_proxy_execution.md) | T1218.011 | `T1218.011_rundll32_suspicious_execution` | rundll32_execution |
| [scheduled_task_persistence](playbooks/scheduled_task_persistence.md) | T1053.005 | `T1053.005_schtasks_suspicious_creation`, `T1053.005_powershell_scheduled_task_creation` | scheduled_task_creation |
| [service_installation](playbooks/service_installation.md) | T1569.002, T1543.003, T1021.002 | `T1569.002_suspicious_service_installation` | service_creation |
| [suspicious_powershell](playbooks/suspicious_powershell.md) | T1059.001, T1027 | `T1059.001_powershell_encoded_command`, `T1053.005_powershell_scheduled_task_creation` | powershell_encoded_command |
| [web_application_attack](playbooks/web_application_attack.md) | T1190, T1505.003, T1606 | `T1190_api_auth_probing`, `T1190_object_id_enumeration` | api_auth_testing, idor_testing, jwt_testing, file_upload_testing, security_headers_testing |
<!-- rasd:dfir-catalog:end -->

## From replayed logs to a case

`rasd replay <export> --assets assets.csv --case-dir reports/cases` writes one folder per attack storyline, filled only with what the logs show:

| File | Fills | Contents |
|---|---|---|
| `case_summary.md` | [Incident summary](templates/incident_summary.md) | Host, UTC window, storyline score, tactics, the alert timeline, other hosts in the same window, open risk questions, the detection cards |
| `timeline.json` | [Timeline](templates/timeline_template.md) | Every alert in order with the event fields its rule read; correlations with their window, group and counted values; the SHA-256 of each log file |
| `observables.csv` | [Evidence table](templates/evidence_table.md) | Hosts, accounts, processes, command lines, registry keys, services, addresses and hashes seen in the alerts, first and last seen |
| `analyst_closure.md` | [Closure note](templates/closure_note.md) | The escalation, benign positive and false positive notes, pre-filled with the observed facts |

The replay never sets a disposition: `timeline.json` carries `"disposition": null` and the notes leave every judgement to the analyst. A value that starts with `=`, `+`, `-` or `@` gets a leading apostrophe in `observables.csv`, so a spreadsheet cannot run a logged command line as a formula. `reports/` is ignored by git.
