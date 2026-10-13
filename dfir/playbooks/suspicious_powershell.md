---
playbook: suspicious_powershell
techniques: [T1059.001, T1027]
detections: [T1059.001_powershell_encoded_command, T1053.005_powershell_scheduled_task_creation]
red_tests: [powershell_encoded_command]
---

# DFIR Playbook: Suspicious PowerShell

## Trigger
PowerShell activity matched detection logic: an encoded command line (`-enc`, `-EncodedCommand` or any prefix of it), or PowerShell registering a scheduled task with an inline action.

## Required Data
- Process creation logs (Sysmon 1 or Security 4688 with command-line auditing)
- Parent process and process GUIDs
- User context and logon session
- Full command line
- Hostname
- Network activity (Sysmon 3, DNS 22, proxy)
- File writes (Sysmon 11)
- PowerShell script block logs (4104)

## First 15 Minutes
1. Validate host and user: is the user expected to run PowerShell on this host?
2. Review the parent process: Office, a browser, `mshta`, `wscript` or an unknown binary is a delivery path; SCCM `CcmExec.exe` is management.
3. Decode the command if encoded: `[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('<blob>'))` (UTF-16LE).
4. Check child processes of the PowerShell process.
5. Check outbound network activity from the PowerShell PID.
6. Search the same user and host ±30 minutes ([`user_host_window`](../queries/kql/user_host_window.kql)).

## Deep Investigation
- Process tree from the first suspicious ancestor down ([`process_tree`](../queries/kql/process_tree.kql))
- Persistence checks: scheduled tasks, services and Run keys created in the window ([`persistence_sweep`](../queries/kql/persistence_sweep.kql))
- File artifacts written by the process and its children
- Registry changes (Sysmon 12/13)
- Remote connections and the domains or IPs in the decoded script
- Related alerts on the same host or user in the last 7 days
- Authentication events from the host after the execution (lateral movement)

## Evidence to Collect
| Evidence | Source | Purpose |
|---|---|---|
| CommandLine | Sysmon EID 1 / Security 4688 | Identify executed logic |
| Decoded script | 4104 or decoded Base64 | Read what actually ran, even when the command line is truncated |
| ParentImage | Sysmon EID 1 | Determine launch source |
| Network connections | Sysmon EID 3 / proxy | Identify outbound behavior and second stages |
| File writes | Sysmon EID 11 | Identify payload artifacts |

## Escalate If
- Suspicious parent process (Office, browser, script host, unknown binary)
- Unknown encoded logic or a download cradle (`IEX`, `DownloadString`, `Invoke-WebRequest`)
- Unknown destination in the network activity
- Payload from a user-writable path
- Credential access indicators (LSASS access, Mimikatz strings)
- Persistence indicators (task, service, Run key created in the window)

## Closure Guidance
Close as benign only if the activity is verified as approved administration or automation, with no suspicious child process, persistence, file writes, or network activity. Record which management tool or script it was and add a tuning proposal to the detection's `tuning.yml` instead of a SIEM-only suppression.
