# Evidence request · case-01-runnervmhh3zg

What to collect for the detections that fired in this storyline, the stores that roll over first at the top. The list comes from the survivability model (`dfir/trace/model.yml`): it says where each technique is documented to leave evidence, and the collector confirms what is there.

## Collect, in this order

| # | Where | Store | Artifact | Answers | State | For |
|---:|---|---|---|---|---|---|
| 1 | runnervmhh3zg | Background Activity Moderator key | BAM entry of the executable<br><sub>The full path and the last run only, per account; Windows 10 1709 and later</sub> | ran, when, who | on the host | `T1021.006_wsmprovhost_suspicious_child`, `T1059.001_powershell_encoded_command`, `T1218.011_rundll32_suspicious_execution`, `T1053.005_schtasks_suspicious_creation`, `T1053.005_powershell_scheduled_task_creation` |
| 2 | runnervmhh3zg | Prefetch folder | Prefetch file of the executable<br><sub>WSMPROVHOST.EXE and the child it started · The executable and its last eight run times, never the arguments or the account; on by default on workstations, off on servers</sub> | ran, when | on the host | `T1021.006_wsmprovhost_suspicious_child`, `T1685.005_event_log_clearing`, `T1685.005_system_log_cleared`, `T1059.001_powershell_encoded_command`, `T1218.011_rundll32_suspicious_execution`, `T1053.005_schtasks_suspicious_creation`, `T1053.005_powershell_scheduled_task_creation`, `T1569.002_suspicious_service_installation` |
| 3 | runnervmhh3zg | NTFS change journal | Change journal record of the file<br><sub>The task file created under System32\Tasks · A file name and a reason code (created, deleted, renamed), not the content</sub> | ran, when | on the host | `T1053.005_schtasks_suspicious_creation`, `T1053.005_powershell_scheduled_task_creation` |
| 4 | off the host | Security log of the file server | Security 4663 on the file server (object access) | ran, when, who, how | held by the security log of the file server | `T1552.001_honey_file_access` |
| 5 | runnervmhh3zg | Windows PowerShell log | Windows PowerShell 400 (engine started)<br><sub>HostApplication carries the command line of the PowerShell process; the channel is not in the forwarder baseline</sub> | ran, when, how | on the host | `T1059.001_powershell_encoded_command`, `T1053.005_powershell_scheduled_task_creation` |
| 6 | runnervmhh3zg | PowerShell operational log | PowerShell 4104 (script block)<br><sub>The commands of the remote session · Every block with Script Block Logging on (the lab turns it on); without it, practitioners report only the blocks PowerShell itself flags as suspicious</sub> | ran, when, who, how | on the host; a copy is in the SIEM | `T1021.006_wsmprovhost_suspicious_child`, `T1059.001_powershell_encoded_command`, `T1053.005_powershell_scheduled_task_creation` |
| 7 | runnervmhh3zg | Security log | Security 4624 (logon)<br><sub>The network logon of the remote session and its source address</sub> | when, who, origin | on the host; a copy is in the SIEM | `T1021.006_wsmprovhost_suspicious_child` |
| 8 | runnervmhh3zg | Security log | Security 4688 (process creation) | ran, when, who, how | only if collected: Audit Process Creation with the command line policy; the lab sets the policy and does not require the subcategory | `T1021.006_wsmprovhost_suspicious_child`, `T1685.005_event_log_clearing`, `T1059.001_powershell_encoded_command`, `T1547.001_registry_run_key_persistence`, `T1218.011_rundll32_suspicious_execution`, `T1053.005_schtasks_suspicious_creation`, `T1053.005_powershell_scheduled_task_creation`, `T1569.002_suspicious_service_installation` |
| 9 | runnervmhh3zg | Security log | Security 4697 (service installed) | ran, when, who, how | only if collected: Audit Security System Extension | `T1569.002_suspicious_service_installation` |
| 10 | runnervmhh3zg | Security log | Security 4698 (scheduled task created) | ran, when, who, how | only if collected: Audit Other Object Access Events | `T1053.005_schtasks_suspicious_creation`, `T1053.005_powershell_scheduled_task_creation` |
| 11 | runnervmhh3zg | Sysmon operational log | Sysmon 1 (ProcessCreate) | ran, when, who, how | on the host; a copy is in the SIEM | `T1021.006_wsmprovhost_suspicious_child`, `T1685.005_event_log_clearing`, `T1685.005_system_log_cleared`, `T1059.001_powershell_encoded_command`, `T1547.001_registry_run_key_persistence`, `T1218.011_rundll32_suspicious_execution`, `T1053.005_schtasks_suspicious_creation`, `T1053.005_powershell_scheduled_task_creation`, `T1569.002_suspicious_service_installation` |
| 12 | runnervmhh3zg | Sysmon operational log | Sysmon 10 (ProcessAccess)<br><sub>The account (SourceUser) is recorded from Sysmon 13.30 on</sub> | ran, when, who, how | on the host; a copy is in the SIEM | `T1003.001_lsass_memory_access` |
| 13 | runnervmhh3zg | Sysmon operational log | Sysmon 13 (registry value set) | ran, when, who, how | on the host; a copy is in the SIEM | `T1547.001_registry_run_key_persistence` |
| 14 | runnervmhh3zg | System log | System 104 (event log cleared)<br><sub>The clear record of the channel that was emptied · Written to the System log for every channel other than Security, the System log itself included</sub> | ran, when, who | on the host; a copy is in the SIEM | `T1685.005_event_log_clearing`, `T1685.005_system_log_cleared` |
| 15 | runnervmhh3zg | System log | System 7045 (service installed)<br><sub>The account is the SID in the event header</sub> | ran, when, who, how | on the host; a copy is in the SIEM | `T1569.002_suspicious_service_installation` |
| 16 | runnervmhh3zg | Task Scheduler operational log | Task Scheduler 106 (task registered) | ran, when, who | only if collected: The Microsoft-Windows-TaskScheduler/Operational channel, which is off on many builds | `T1053.005_schtasks_suspicious_creation`, `T1053.005_powershell_scheduled_task_creation` |
| 17 | runnervmhh3zg | WinRM operational log | WinRM 91 (shell created on the server)<br><sub>Names the resource the shell was created for, not the account</sub> | ran, when | on the host | `T1021.006_wsmprovhost_suspicious_child` |
| 18 | runnervmhh3zg | Run key value | Run key value<br><sub>The time is the key's last write, shared by every value under it</sub> | ran, when, how | on the host | `T1547.001_registry_run_key_persistence` |
| 19 | runnervmhh3zg | Service registry key | Service registry key<br><sub>The time is the key's last write</sub> | ran, when, how | on the host | `T1569.002_suspicious_service_installation` |
| 20 | runnervmhh3zg | Task definition (XML file and TaskCache key) | Task definition<br><sub>The action, the author and the registration date as the task's creator wrote them</sub> | ran, when, who, how | on the host | `T1053.005_schtasks_suspicious_creation`, `T1053.005_powershell_scheduled_task_creation` |

## Answers that rest on one artifact

Nothing else in the baseline answers these questions on the host, so the record and its SIEM copy are all there is. Preserve them first.

- `T1003.001_lsass_memory_access`: **ran, when, who, how** rest on Sysmon 10 (ProcessAccess)
- `T1021.006_wsmprovhost_suspicious_child`: **origin** rest on Security 4624 (logon)
- `T1685.005_event_log_clearing`: **how** rest on Sysmon 1 (ProcessCreate)
- `T1685.005_system_log_cleared`: **how** rest on Sysmon 1 (ProcessCreate)
- `T1218.011_rundll32_suspicious_execution`: **how** rest on Sysmon 1 (ProcessCreate)

<sub>Generated by RASD · Continuous Detection Assurance Framework</sub>
