---
playbook: lateral_movement
techniques: [T1021.002, T1021.006, T1569.002, T1053.005]
detections: [T1569.002_suspicious_service_installation, T1053.005_schtasks_suspicious_creation]
red_tests: [service_creation, scheduled_task_creation, winrm_access_validation]
---

# DFIR Playbook: Lateral Movement

## Trigger
Signs that one host executed code on another: a service installed over SMB (7045 after a 4624 type 3), a task created remotely (`schtasks /s`), a WinRM shell (`wsmprovhost.exe`), or a storyline in `rasd replay` with a pivot to another host.

## Required Data
- Network logons (4624 type 3) on the target, and explicit-credential logons (4648) on the source host, which names the target server
- Service installs (7045), remote tasks (4698), WinRM shells (WinRM 91, `wsmprovhost.exe` children)
- Share access (5140/5145) to ADMIN$, C$, IPC$
- Process creation on both hosts

## First 15 Minutes
1. Identify the source host and the account used (4624 `IpAddress`, `TargetUserName`).
2. Identify the mechanism: service, task, WinRM, WMI (`WmiPrvSE.exe` children).
3. List what ran on the target through that mechanism.
4. Check whether the same source reached other hosts in the same hour.
5. Decide containment for the source host - it is the one with the attacker on it.

## Deep Investigation
- The full path: initial host → each hop, with times and accounts (`rasd replay --assets` builds this for you)
- Credentials used for each hop and where they came from (LSASS access, Kerberoasting)
- Tools staged on targets (ADMIN$ writes, service binaries)
- Persistence left on each target

## Evidence to Collect
| Evidence | Source | Purpose |
|---|---|---|
| Network logons | Target Security 4624 (type 3); source Security 4648 | Source host and account per hop; 4648 on the source names the target and the credentials used |
| Execution mechanism | 7045 / 4698 / WinRM 91 | How code ran on the target |
| Share access | Security 5140 / 5145 | Tool transfer to the target |
| Remote process trees | Sysmon EID 1 on the target | What the attacker did after arriving |

## Escalate If
- Any remote execution from a workstation to a server
- Execution with an account that does not normally administer the target
- The same source reaching several hosts
- Remote execution followed by credential access on the target

## Closure Guidance
Close as benign only when a named administrator, an approved jump host and a change record explain every hop. Lateral movement findings are otherwise handed to incident response with the hop list attached.
