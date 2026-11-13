# RASD-Trace: Evidence Survivability

A detection that fires answers one question: did we see it. The investigation that follows has to answer the rest - did it happen, when, under which account, with which command, from where - and an intruder who holds the host can remove what those answers rest on. RASD-Trace measures how hard that is for every detection, and whether a tested rule sees the attempt.

| File | Contents |
|---|---|
| [`model.yml`](model.yml) | The stores evidence lives in, the artifacts read from them, the questions each artifact answers, and the anti-forensic actions RASD knows: what each destroys, blinds and leaves behind |
| [`footprints.yml`](footprints.yml) | The artifacts each detection's technique writes, as its red test performs it |

`rasd trace` searches every sequence of catalogued actions before and after the technique and gives each detection and question one of three verdicts. `rasd trace <detection>` lists the witnesses of one detection in collection order, and `rasd trace <detection> --lost sysmon_log,security_log` answers the question an incident asks once logs are gone: what can still be proven, and from which artifact. The model, the search and its limits are described in [TRACE](../../docs/TRACE.md).

The entries are documented behaviour, each with its source and its basis; none is lab evidence, and no result here raises a detection's maturity.

## Results

<!-- rasd:trace:start -->
**Position:** An administrator on the host where the technique ran, with no reach to the domain controller, the file server, the decoy host or the SIEM.

18 detections modelled (4 not yet), 31 artifacts, 16 anti-forensic actions. Of 94 detection-question pairs: **38 out of reach**, **0 evident**, **56 exposed**.

| Detection | Alert | Ran | When | Who | How | Origin |
|---|---|---|---|---|---|---|
| `T1003.001_lsass_memory_access` | exposed (1) | exposed (1) | exposed (1) | exposed (1) | exposed (1) |  |
| `T1021.006_wsmprovhost_suspicious_child` | exposed (1) | exposed (3) | exposed (3) | exposed (2) | exposed (1) | exposed (1) |
| `T1053.005_powershell_scheduled_task_creation` | exposed (1) | exposed (5) | exposed (5) | exposed (3) | exposed (2) |  |
| `T1053.005_schtasks_suspicious_creation` | exposed (1) | exposed (5) | exposed (5) | exposed (3) | exposed (2) |  |
| `T1059.001_powershell_encoded_command` | exposed (1) | exposed (3) | exposed (3) | exposed (2) | exposed (1) |  |
| `T1218.011_rundll32_suspicious_execution` | exposed (1) | exposed (3) | exposed (3) | exposed (2) | exposed (1) |  |
| `T1547.001_registry_run_key_persistence` | exposed (1) | exposed (2) | exposed (2) | exposed (1) | exposed (2) |  |
| `T1569.002_suspicious_service_installation` | exposed (1) | exposed (3) | exposed (3) | exposed (1) | exposed (2) |  |
| `T1685.005_event_log_clearing` | exposed (1) | exposed (2) | exposed (2) | exposed (1) | exposed (1) |  |
| `T1685.005_security_log_cleared` | exposed (1) | exposed (2) | exposed (2) | exposed (1) | exposed (1) |  |
| `T1685.005_system_log_cleared` | exposed (1) | exposed (2) | exposed (2) | exposed (1) | exposed (1) |  |
| `T1558.003_kerberoasting_rc4_tgs` | out of reach | out of reach | out of reach | out of reach | out of reach | out of reach |
| `T1558.003_kerberoasting_volume` | out of reach | out of reach | out of reach | out of reach | out of reach | out of reach |
| `T1558.003_honey_spn_ticket_request` | out of reach | out of reach | out of reach | out of reach | out of reach | out of reach |
| `T1078.002_honey_account_authentication` | out of reach | out of reach | out of reach | out of reach |  | out of reach |
| `T1110.003_password_spray_burst` | out of reach | out of reach | out of reach | out of reach |  | out of reach |
| `T1552.001_honey_file_access` | out of reach | out of reach | out of reach | out of reach | out of reach |  |
| `T1046_decoy_service_interaction` | out of reach | out of reach | out of reach |  | out of reach | out of reach |

<sub>out of reach: no sequence of catalogued actions removes the answer · evident: every sequence that removes it raises a RASD alert · exposed (n): n actions remove it and raise none.</sub>

### How the quiet sequences begin

Every exposed answer is silenced by a sequence that first blinds the telemetry, then runs the technique, then removes what the host still holds. Grouped by the blinding step, with what that step itself sends to the SIEM before it takes effect (`rasd trace <detection>` prints each full sequence).

| Before the technique | Answers it silences | Clean-up actions after | What reaches the SIEM unread |
|---|---|---|---|
| Suspend the threads of the Event Log service | 28 | up to 4 | Sysmon 1 (ProcessCreate); The host's channels go quiet in the SIEM |
| Stop the Sysmon service | 17 | up to 4 | Sysmon 1 (ProcessCreate); Sysmon 4 (service state changed) |
| Stop the log forwarder, or block its connection | 11 | up to 0 | The host's channels go quiet in the SIEM |

### The rules that close them

Traces of anti-forensic actions that reach the SIEM and that no rule reads yet, in the order that removes the most exposure. Each row supposes the rules above it are written.

| Order | A rule that reads | Left by | Exposed pairs after |
|---|---|---|---|
| 1 | The host's channels go quiet in the SIEM | Suspend the threads of the Event Log service, Stop the log forwarder, or block its connection | 26 |
| 2 | Sysmon 4 (service state changed) | Stop the Sysmon service | 26 |
| 3 | Sysmon 1 (ProcessCreate) of `fltmc unload SysmonDrv` | Unload the Sysmon driver | 0 |

With these 3 rules every modelled answer is out of reach or evident.

### Evidence depth on the host

The same search on a host that forwards nothing: how many actions remove every witness of an answer, alerts or not. A depth of 1 is an answer that rests on a single store.

| Detection | Ran | When | Who | How | Origin |
|---|---|---|---|---|---|
| `T1003.001_lsass_memory_access` | 1 | 1 | 1 | 1 |  |
| `T1021.006_wsmprovhost_suspicious_child` | 3 | 3 | 2 | 1 | 1 |
| `T1053.005_powershell_scheduled_task_creation` | 5 | 5 | 3 | 2 |  |
| `T1053.005_schtasks_suspicious_creation` | 5 | 5 | 3 | 2 |  |
| `T1059.001_powershell_encoded_command` | 3 | 3 | 2 | 1 |  |
| `T1218.011_rundll32_suspicious_execution` | 3 | 3 | 2 | 1 |  |
| `T1547.001_registry_run_key_persistence` | 2 | 2 | 1 | 2 |  |
| `T1569.002_suspicious_service_installation` | 3 | 3 | 1 | 2 |  |
| `T1685.005_event_log_clearing` | 2 | 2 | 1 | 1 |  |
| `T1685.005_security_log_cleared` | 2 | 2 | 1 | 1 |  |
| `T1685.005_system_log_cleared` | 2 | 2 | 1 | 1 |  |

### Artifacts

| Artifact | Store | Answers | Basis | Limits |
|---|---|---|---|---|
| [Sysmon 1 (ProcessCreate)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) | Sysmon operational log | ran, when, who, how | vendor |  |
| [Sysmon 4 (service state changed)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) | Sysmon operational log | ran, when | vendor | Written when the service is stopped through the Service Control Manager |
| [Sysmon 10 (ProcessAccess)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) | Sysmon operational log | ran, when, who, how | vendor | The account (SourceUser) is recorded from Sysmon 13.30 on |
| [Sysmon 12 (registry object created or deleted)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) | Sysmon operational log | ran, when, who | vendor | Only for the keys the Sysmon configuration includes |
| [Sysmon 13 (registry value set)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) | Sysmon operational log | ran, when, who, how | vendor |  |
| [Security 1102 (audit log cleared)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102) | Security log | ran, when, who | vendor | Written whatever the audit policy says |
| [Security 4624 (logon)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) | Security log | when, who, origin | vendor |  |
| [Security 4688 (process creation)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688) (optional) | Security log | ran, when, who, how | vendor |  |
| [Security 4697 (service installed)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697) (optional) | Security log | ran, when, who, how | vendor |  |
| [Security 4698 (scheduled task created)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698) (optional) | Security log | ran, when, who, how | vendor |  |
| [Security 4699 (scheduled task deleted)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4699) (optional) | Security log | ran, when, who | vendor |  |
| [Security 4719 (audit policy changed)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4719) | Security log | ran, when, who | vendor |  |
| [System 104 (event log cleared)](https://docs.velociraptor.app/artifact_references/pages/windows.eventlogs.cleared) | System log | ran, when, who | vendor | Written to the System log for every channel other than Security, the System log itself included |
| [System 7045 (service installed)](https://docs.velociraptor.app/artifact_references/pages/windows.eventlogs.servicecreationcomspec) | System log | ran, when, who, how | vendor | The account is the SID in the event header |
| [PowerShell 4104 (script block)](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows) | PowerShell operational log | ran, when, who, how | vendor | Every block with Script Block Logging on (the lab turns it on); without it, practitioners report only the blocks PowerShell itself flags as suspicious |
| [Windows PowerShell 400 (engine started)](https://trustedsec.com/blog/building-a-detection-foundation-part-3-powershell-and-script-logging) | Windows PowerShell log | ran, when, how | practitioner | HostApplication carries the command line of the PowerShell process; the channel is not in the forwarder baseline |
| [Task Scheduler 106 (task registered)](https://docs.velociraptor.app/artifact_references/pages/windows.eventlogs.scheduledtasks) (optional) | Task Scheduler operational log | ran, when, who | vendor |  |
| [Task Scheduler 141 (task deleted)](https://docs.velociraptor.app/artifact_references/pages/windows.eventlogs.scheduledtasks) (optional) | Task Scheduler operational log | ran, when, who | vendor |  |
| [WinRM 91 (shell created on the server)](https://blog.lexfo.fr/Cobalt%20Strike%20Investigation%20Part%201.html) | WinRM operational log | ran, when | practitioner | Names the resource the shell was created for, not the account |
| [Application 3079 (change journal deleted)](https://redlotus.gitbook.io/redlotusguide/advanced-explanation-of-artifacts/file-system-activity/usn-journal-usdusnjrnl) | Application log | ran, when | practitioner |  |
| [Prefetch file of the executable](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf) | Prefetch folder | ran, when | vendor | The executable and its last eight run times, never the arguments or the account; on by default on workstations, off on servers |
| [BAM entry of the executable](https://docs.velociraptor.app/artifact_references/pages/windows.forensics.bam) | Background Activity Moderator key | ran, when, who | practitioner | The full path and the last run only, per account; Windows 10 1709 and later |
| [Change journal record of the file](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn) | NTFS change journal | ran, when | vendor | A file name and a reason code (created, deleted, renamed), not the content |
| [Task definition](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema) | Task definition (XML file and TaskCache key) | ran, when, who, how | vendor | The action, the author and the registration date as the task's creator wrote them |
| [Run key value](https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys) | Run key value | ran, when, how | vendor | The time is the key's last write, shared by every value under it |
| [Service registry key](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services) | Service registry key | ran, when, how | vendor | The time is the key's last write |
| [Security 4769 on the domain controller (service ticket requested)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769) | Security log of the domain controller | ran, when, who, how, origin | vendor |  |
| [Security 4768, 4771 and 4776 on the domain controller (authentication)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768) | Security log of the domain controller | ran, when, who, origin | vendor |  |
| [Security 4663 on the file server (object access)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4663) | Security log of the file server | ran, when, who, how | vendor |  |
| [OpenCanary record of the decoy host](https://opencanary.readthedocs.io/en/latest/) | Log of the decoy host | ran, when, how, origin | vendor |  |
| [The host's channels go quiet in the SIEM](https://www.splunk.com/en_us/blog/tips-and-tricks/how-to-determine-when-a-host-stops-sending-logs-to-splunk-expeditiously.html) | SIEM | ran, when | practitioner | Visible only to a search that watches each channel of each host for silence; a forwarder heartbeat alone misses a host whose event log stopped |

### Anti-forensic actions

| Action | Example | Destroys | Blinds | Leaves | Basis |
|---|---|---|---|---|---|
| Clear the Security log | `wevtutil cl Security` | Security log |  | Sysmon 1 (ProcessCreate) → `T1685.005_event_log_clearing`; Security 1102 (audit log cleared) → `T1685.005_security_log_cleared`; Prefetch file of the executable | vendor |
| Clear the System log | `wevtutil cl System` | System log |  | Sysmon 1 (ProcessCreate) → `T1685.005_event_log_clearing`; System 104 (event log cleared) → `T1685.005_system_log_cleared`; Prefetch file of the executable | vendor |
| Clear the Sysmon log | `wevtutil cl Microsoft-Windows-Sysmon/Operational` | Sysmon operational log |  | Sysmon 1 (ProcessCreate) → `T1685.005_event_log_clearing`; System 104 (event log cleared) → `T1685.005_system_log_cleared`; Prefetch file of the executable | vendor |
| Clear the PowerShell logs | `wevtutil cl Microsoft-Windows-PowerShell/Operational, then wevtutil cl "Windows PowerShell"` | Windows PowerShell log, PowerShell operational log |  | Sysmon 1 (ProcessCreate) → `T1685.005_event_log_clearing`; System 104 (event log cleared) → `T1685.005_system_log_cleared`; Prefetch file of the executable | vendor |
| Clear the Task Scheduler and WinRM logs | `wevtutil cl Microsoft-Windows-TaskScheduler/Operational, then wevtutil cl Microsoft-Windows-WinRM/Operational` | Task Scheduler operational log, WinRM operational log |  | Sysmon 1 (ProcessCreate) → `T1685.005_event_log_clearing`; System 104 (event log cleared) → `T1685.005_system_log_cleared`; Prefetch file of the executable | vendor |
| Delete the Prefetch files | `cmd /c del /q C:\Windows\Prefetch\*.pf` | Prefetch folder |  | Sysmon 1 (ProcessCreate); Change journal record of the file | vendor |
| Delete the BAM entries | `reg delete HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\&lt;SID&gt; /f (as SYSTEM)` | Background Activity Moderator key |  | Sysmon 1 (ProcessCreate); Prefetch file of the executable | practitioner |
| Delete the NTFS change journal | `fsutil usn deletejournal /d C:` | NTFS change journal |  | Sysmon 1 (ProcessCreate); Application 3079 (change journal deleted); Prefetch file of the executable | vendor |
| Delete the scheduled task | `schtasks /delete /tn &lt;task&gt; /f` | Task definition (XML file and TaskCache key) |  | Sysmon 1 (ProcessCreate); Task Scheduler 141 (task deleted); Security 4699 (scheduled task deleted); Change journal record of the file; Prefetch file of the executable | vendor |
| Delete the Run key value | `reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v &lt;name&gt; /f` | Run key value |  | Sysmon 1 (ProcessCreate); Sysmon 12 (registry object created or deleted); Prefetch file of the executable | vendor |
| Delete the service | `sc delete &lt;service&gt;` | Service registry key |  | Sysmon 1 (ProcessCreate); Prefetch file of the executable | vendor |
| Stop the Sysmon service | `sc stop Sysmon64` |  | Sysmon operational log | Sysmon 1 (ProcessCreate); Sysmon 4 (service state changed); Prefetch file of the executable | vendor |
| Unload the Sysmon driver | `fltmc unload SysmonDrv` |  | Sysmon operational log | Sysmon 1 (ProcessCreate); Prefetch file of the executable | practitioner |
| Clear the audit policy | `auditpol /clear /y` |  | Security log | Sysmon 1 (ProcessCreate); Security 4719 (audit policy changed); Prefetch file of the executable | vendor |
| [Suspend the threads of the Event Log service](https://github.com/hlldz/Phant0m) | `Invoke-Phant0m` |  | Application log, Windows PowerShell log, PowerShell operational log, Security log, Sysmon operational log, System log, Task Scheduler operational log, WinRM operational log | Sysmon 1 (ProcessCreate); The host's channels go quiet in the SIEM; Prefetch file of the executable | practitioner |
| Stop the log forwarder, or block its connection | `sc stop SplunkForwarder` |  | forwarding to the SIEM | Sysmon 1 (ProcessCreate); The host's channels go quiet in the SIEM; Prefetch file of the executable | vendor |

### Not modelled yet

| Detection | Why |
|---|---|
| `T1053.003_crontab_noninteractive_install` | Linux artifacts (auditd, the journal, shell history, crontab spool files) are not in the model yet |
| `T1059.004_linux_suspicious_shell_execution` | Linux artifacts are not in the model yet |
| `T1190_object_id_enumeration` | Web server artifacts (access log rotation, reverse proxy and WAF copies) are not in the model yet |
| `T1595.003_api_auth_probing` | Web server artifacts are not in the model yet |
<!-- rasd:trace:end -->
