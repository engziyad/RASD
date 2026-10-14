---
playbook: event_log_clearing
techniques: [T1685.005]
detections: [T1685.005_event_log_clearing, T1685.005_security_log_cleared, T1685.005_system_log_cleared]
red_tests: [event_log_clearing]
---

# DFIR Playbook: Event Log Clearing

## Trigger
An event log was cleared: `wevtutil cl`, `Clear-EventLog`, `.ClearLog()`, WMI `ClearEventLog`, or the resulting Security 1102 / System 104 records.

## Required Data
- The process-level event (Sysmon 1) and the clear records (1102, 104)
- The SIEM's forwarded copy of the cleared log for the period before the clear
- Logon sessions of the account that cleared the log
- Activity of the same account on other hosts

## First 15 Minutes
1. Identify user, host and which log was cleared (`Channel_Cleared` in 104).
2. Check for a documented maintenance window or image build.
3. Pull the forwarded copy of the cleared log for the hour before the clear - that hour is what someone wanted gone.
4. Look for the process-level alert and the clear record together: both present means a hands-on-keyboard clear.
5. Scope the account: where else did it log on today?

## Deep Investigation
- Rebuild the timeline from forwarded logs (Security, Sysmon, PowerShell) before the clear
- Other anti-forensics on the host: Sysmon or EDR service stopped, audit policy changed (4719), log size reduced (`Limit-EventLog`)
- Credential access and persistence in the forwarded logs before the clear
- The same account clearing logs on other hosts

## Evidence to Collect
| Evidence | Source | Purpose |
|---|---|---|
| 1102 / 104 records | Security / System log | Who cleared which log and when |
| Clearing command | Sysmon EID 1 | Tool and exact command (and any /bu: backup path) |
| Forwarded logs before the clear | SIEM / WEF collector | Recover what the clear destroyed |
| Logon sessions of the account | Security 4624 / 4672 | Was the account itself compromised |

## Escalate If
- Any clear outside a documented maintenance window
- The Security, Sysmon or PowerShell log was targeted
- The account is not a known build or admin account
- Other anti-forensics found on the host

## Closure Guidance
Close as benign only for documented golden-image sealing on a known build host by its build account. Every other clear is escalated: clearing logs has no routine operational purpose on production hosts.
