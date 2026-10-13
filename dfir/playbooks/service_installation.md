---
playbook: service_installation
techniques: [T1569.002, T1543.003, T1021.002]
detections: [T1569.002_suspicious_service_installation]
red_tests: [service_creation]
---

# DFIR Playbook: Service Installation

## Trigger
A new service was installed (System 7045) with a command interpreter, a share path, a user-writable path, a batch file, or the default name of a remote-execution tool (PsExec, PAExec, RemCom, CSExec, Impacket).

## Required Data
- System 7045 (service installed) and Security 4697 (service installed, with the installing account)
- Security 4624 type 3 and 5140 / 5145 (share access) on the same host just before the 7045
- Process creation on the host after the installation (the service's children)
- The service binary, if it still exists

## First 15 Minutes
1. Review ServiceName, ImagePath, AccountName and the host.
2. Check for a change record or known admin use of PsExec on this host.
3. Find the network logon (4624 type 3) seconds before the 7045: its `IpAddress` is the source host.
4. Check share access (5140/5145) to `ADMIN$` or `IPC$` from the same source.
5. Look for processes started by the service right after installation.

## Deep Investigation
- The source host: treat it as compromised until proven otherwise and run this playbook's first steps there
- What the service ran: `cmd.exe /c` and `%COMSPEC%` services run one command - find its output files (`\__output`, `execute.bat` for Impacket)
- Services installed on other hosts from the same source in the same hour ([`lateral_movement`](lateral_movement.md))
- Credentials used for the network logon and where else they logged on

## Evidence to Collect
| Evidence | Source | Purpose |
|---|---|---|
| 7045 / 4697 events | System / Security log | What was installed, when, by whom |
| Service configuration | `HKLM\SYSTEM\CurrentControlSet\Services\<name>` / `sc qc` | Binary path, account, start type |
| Network logon | Security 4624 type 3 | Source host and account |
| Share access | Security 5140 / 5145 | Binary copied to ADMIN$ |
| Service binary | `C:\Windows\<name>.exe` or the ImagePath | Hash and analysis before it is deleted |

## Escalate If
- ImagePath runs cmd or PowerShell, or lives under Temp, Public, AppData or Downloads
- The service name matches a remote-execution tool, or an eight-letter random binary in `%SystemRoot%`
- No matching change ticket or known admin activity
- The same source installed services on several hosts

## Closure Guidance
Close as benign only when a named administrator confirms the activity, the source is an admin jump host, and a change record covers it. Recommend correlation with the change system in the SIEM rather than filtering the service name (see the detection's `tuning.yml`).
