# Case 01 · runnervmhh3zg

| | |
|---|---|
| Window (UTC) | 2026-11-22 17:23:19 → 17:25:30 (2 min) |
| Storyline | score 100/100 · 9 techniques · 8 tactics · 24 alerts |
| Tactics | execution → persistence → privilege-escalation → stealth → defense-impairment → credential-access → discovery → lateral-movement |
| Highest alert risk | 80 · T1552.001 at 17:24:59 |
| Disposition | not set: the replay reports what the logs show; the analyst sets it after triage |
| Built from | lab-export.jsonl (SHA-256 5fd9cf03de46…) · linux-export.jsonl (SHA-256 0d37438d1a7f…) · canary-export.jsonl (SHA-256 518122c42cf1…) · web-export.jsonl (SHA-256 a6db69df4154…) |

## What the logs show

On runnervmhh3zg, within 2 minutes: Suspicious Process Access to LSASS Memory (T1003.001) → Suspicious Child Process of a WinRM Session Host (T1021.006) → Windows Event Log Clearing via Command Line (T1685.005) → Windows Event Log Cleared (System Event 104) (T1685.005) → Deception - Honey Credentials File Opened (T1552.001) → PowerShell Execution With Encoded Command (T1059.001) → Run Key Persistence Pointing to Suspicious Location (T1547.001) → Rundll32 Proxy Execution From Suspicious Context (T1218.011) → Scheduled Task Created With Suspicious Action (T1053.005) → Scheduled Task Registered via PowerShell ScheduledTasks Cmdlets (T1053.005) → Suspicious Service Installation (PsExec-style / Command Services) (T1569.002).

## Timeline

| Time (UTC) | Technique | Detection | Host | Account | Risk | Observed |
|---|---|---|---|---|---:|---|
| 17:23:19 | T1003.001 | Suspicious Process Access to LSASS Memory | runnervmhh3zg | NT SERVICE\\Splunkd | 60 | `C:\Program Files\Splunk\bin\splunkd.exe` |
| 17:23:29 | T1003.001 | Suspicious Process Access to LSASS Memory | runnervmhh3zg | NT SERVICE\\Splunkd | 60 | `C:\Program Files\Splunk\bin\splunkd.exe` |
| 17:23:56 | T1003.001 | Suspicious Process Access to LSASS Memory | runnervmhh3zg | NT SERVICE\\Splunkd | 60 | `C:\Program Files\Splunk\bin\splunkd.exe` |
| 17:23:56 | T1003.001 | Suspicious Process Access to LSASS Memory | runnervmhh3zg | NT SERVICE\\Splunkd | 60 | `C:\Program Files\Splunk\bin\splunkd.exe` |
| 17:24:06 | T1003.001 | Suspicious Process Access to LSASS Memory | runnervmhh3zg | NT SERVICE\\Splunkd | 60 | `C:\Program Files\Splunk\bin\splunkd.exe` |
| 17:24:16 | T1003.001 | Suspicious Process Access to LSASS Memory | runnervmhh3zg | NT SERVICE\\Splunkd | 60 | `C:\Program Files\Splunk\bin\splunkd.exe` |
| 17:24:26 | T1003.001 | Suspicious Process Access to LSASS Memory | runnervmhh3zg | NT SERVICE\\Splunkd | 60 | `C:\Program Files\Splunk\bin\splunkd.exe` |
| 17:24:36 | T1003.001 | Suspicious Process Access to LSASS Memory | runnervmhh3zg | NT SERVICE\\Splunkd | 60 | `C:\Program Files\Splunk\bin\splunkd.exe` |
| 17:24:46 | T1003.001 | Suspicious Process Access to LSASS Memory | runnervmhh3zg | NT SERVICE\\Splunkd | 60 | `C:\Program Files\Splunk\bin\splunkd.exe` |
| 17:24:53 | T1021.006 | Suspicious Child Process of a WinRM Session Host | runnervmhh3zg | runnervmhh3zg\\runneradmin | 50 | `"C:\Windows\system32\cmd.exe" /c "echo runnervmhh3zg rasd_63366b09"` |
| 17:24:56 | T1003.001 | Suspicious Process Access to LSASS Memory | runnervmhh3zg | NT SERVICE\\Splunkd | 60 | `C:\Program Files\Splunk\bin\splunkd.exe` |
| 17:24:56 | T1685.005 | Windows Event Log Clearing via Command Line | runnervmhh3zg | runnervmhh3zg\\runneradmin | 60 | `"C:\Windows\system32\wevtutil.exe" cl R63366b09` |
| 17:24:56 | T1685.005 | Windows Event Log Cleared (System Event 104) | runnervmhh3zg | runneradmin | 60 |  |
| 17:24:59 | T1685.005 | Windows Event Log Cleared (System Event 104) | runnervmhh3zg | runneradmin | 60 |  |
| 17:24:59 | T1552.001 | Deception - Honey Credentials File Opened | runnervmhh3zg | runneradmin | 80 | `C:\Shares\IT\Passwords\service_accounts.xlsx` |
| 17:25:02 | T1059.001 | PowerShell Execution With Encoded Command | runnervmhh3zg | runnervmhh3zg\\runneradmin | 40 | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAHIAYQBzAGQAXwA2ADMAMwA2ADYAYgAwADkAJwA=` |
| 17:25:05 | T1547.001 | Run Key Persistence Pointing to Suspicious Location | runnervmhh3zg | runnervmhh3zg\\runneradmin | 55 | `C:\Users\runneradmin\AppData\Local\Temp\rasd_63366b09.exe` |
| 17:25:06 | T1003.001 | Suspicious Process Access to LSASS Memory | runnervmhh3zg | NT SERVICE\\Splunkd | 60 | `C:\Program Files\Splunk\bin\splunkd.exe` |
| 17:25:07 | T1218.011 | Rundll32 Proxy Execution From Suspicious Context | runnervmhh3zg | runnervmhh3zg\\runneradmin | 60 | `"C:\Windows\system32\rundll32.exe" javascript:"\..\mshtml,RunHTMLApplication ";var m='rasd_63366b09';close();` |
| 17:25:16 | T1003.001 | Suspicious Process Access to LSASS Memory | runnervmhh3zg | NT SERVICE\\Splunkd | 60 | `C:\Program Files\Splunk\bin\splunkd.exe` |
| 17:25:24 | T1053.005 | Scheduled Task Created With Suspicious Action | runnervmhh3zg | runnervmhh3zg\\runneradmin | 40 | `"C:\Windows\system32\schtasks.exe" /create /tn rasd_63366b09 /sc once /st 23:59 /f /tr "cmd /c echo rasd_63366b09 > %%TEMP%%\rasd_63366b09.txt"` |
| 17:25:26 | T1053.005 | Scheduled Task Registered via PowerShell ScheduledTasks Cmdlets | runnervmhh3zg | runnervmhh3zg\\runneradmin | 40 | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "Register-ScheduledTask -TaskName rasd_63366b09_ps -Trigger (New-ScheduledTaskT…` |
| 17:25:26 | T1003.001 | Suspicious Process Access to LSASS Memory | runnervmhh3zg | NT SERVICE\\Splunkd | 60 | `C:\Program Files\Splunk\bin\splunkd.exe` |
| 17:25:30 | T1569.002 | Suspicious Service Installation (PsExec-style / Command Services) | runnervmhh3zg | LocalSystem | 60 | `cmd.exe /c echo rasd_63366b09` |

## Open questions

The detections' risk models score these only after an analyst answers them.

| Question | Risk change if yes |
|---|---|
| Known vendor software? | T1003.001_lsass_memory_access -30 · T1059.001_powershell_encoded_command -25 · T1547.001_registry_run_key_persistence -25 · T1218.011_rundll32_suspicious_execution -25 |
| Approved admin activity? | T1003.001_lsass_memory_access -20 · T1021.006_wsmprovhost_suspicious_child -25 · T1552.001_honey_file_access -40 · T1059.001_powershell_encoded_command -20 · T1547.001_registry_run_key_persistence -20 · T1053.005_schtasks_suspicious_creation -25 · T1053.005_powershell_scheduled_task_creation -25 · T1569.002_suspicious_service_installation -25 |
| Approved change window? | T1021.006_wsmprovhost_suspicious_child -20 · T1685.005_event_log_clearing -20 · T1685.005_system_log_cleared -20 · T1053.005_schtasks_suspicious_creation -20 · T1053.005_powershell_scheduled_task_creation -20 · T1569.002_suspicious_service_installation -20 |

## Detection cards

- T1003.001_lsass_memory_access: `detect/detections/T1003.001_lsass_memory_access/` triage.md · response.md · closure.md
- T1021.006_wsmprovhost_suspicious_child: `detect/detections/T1021.006_wsmprovhost_suspicious_child/` triage.md · response.md · closure.md
- T1685.005_event_log_clearing: `detect/detections/T1685.005_event_log_clearing/` triage.md · response.md · closure.md
- T1685.005_system_log_cleared: `detect/detections/T1685.005_system_log_cleared/` triage.md · response.md · closure.md
- T1552.001_honey_file_access: `detect/detections/T1552.001_honey_file_access/` triage.md · response.md · closure.md
- T1059.001_powershell_encoded_command: `detect/detections/T1059.001_powershell_encoded_command/` triage.md · response.md · closure.md
- T1547.001_registry_run_key_persistence: `detect/detections/T1547.001_registry_run_key_persistence/` triage.md · response.md · closure.md
- T1218.011_rundll32_suspicious_execution: `detect/detections/T1218.011_rundll32_suspicious_execution/` triage.md · response.md · closure.md
- T1053.005_schtasks_suspicious_creation: `detect/detections/T1053.005_schtasks_suspicious_creation/` triage.md · response.md · closure.md
- T1053.005_powershell_scheduled_task_creation: `detect/detections/T1053.005_powershell_scheduled_task_creation/` triage.md · response.md · closure.md
- T1569.002_suspicious_service_installation: `detect/detections/T1569.002_suspicious_service_installation/` triage.md · response.md · closure.md

## Files

- `timeline.json`: every alert in order, with the event fields its rule read
- `observables.csv`: 37 values seen in these alerts (hosts, accounts, processes, command lines, registry keys, services, addresses, hashes); seen in the logs, not judged
- `analyst_closure.md`: the escalation, benign positive and false positive notes, pre-filled with what the logs show; the analyst picks one
- `evidence_request.md`: what to collect for these detections, in order, and what a log clear in this storyline took

<sub>Generated by RASD · Continuous Detection Assurance Framework</sub>
