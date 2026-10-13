---
playbook: scheduled_task_persistence
techniques: [T1053.005]
detections: [T1053.005_schtasks_suspicious_creation, T1053.005_powershell_scheduled_task_creation]
red_tests: [scheduled_task_creation]
---

# DFIR Playbook: Scheduled Task Persistence

## Trigger
A scheduled task was created or changed with a suspicious action - a script interpreter, a user-writable path, a download, or remote creation as SYSTEM (`schtasks /create /s <host> /ru SYSTEM`) - through `schtasks.exe` or the PowerShell ScheduledTasks cmdlets.

## Required Data
- Process creation logs with the full command line
- Security 4698 (task created) / 4702 (task updated) with the task XML
- Microsoft-Windows-TaskScheduler/Operational (106 registered, 140 updated, 200/201 action started/completed)
- User context, logon session and source host for remote creation
- File hashes of the task action target

## First 15 Minutes
1. Validate host, user, task name and the command path of the action.
2. Pull the task definition: `schtasks /query /tn "<name>" /xml` or the 4698 `TaskContent`.
3. Check whether the action target exists and whether it already ran (TaskScheduler 200/201).
4. For `/s <host>`: the creating host is the one to investigate - pivot to it.
5. Search the same user and host ±30 minutes.

## Deep Investigation
- Process tree of the creator (who ran `schtasks` / PowerShell, and from what parent)
- The action target: hash, signer, first seen in the estate, network activity when it ran
- Hidden tasks: TaskCache entries under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree` without a matching XML file, or with the `SD` value removed
- Other persistence created in the window ([`persistence_sweep`](../queries/kql/persistence_sweep.kql))
- Network logons (4624 type 3) to the host just before a remote task creation

## Evidence to Collect
| Evidence | Source | Purpose |
|---|---|---|
| Task XML | `C:\Windows\System32\Tasks\<name>` / Security 4698 | Action, trigger, principal and author |
| TaskCache entry | `HKLM\...\Schedule\TaskCache\Tree\<name>` | Survives deletion of the XML; reveals hidden tasks |
| Creator command line | Sysmon EID 1 | Who created it and how |
| Action target | Disk / EDR | Hash and signer of what the task runs |
| Task run history | TaskScheduler 200 / 201 | Whether the payload already executed |

## Escalate If
- Remote creation with `/S` and `/RU SYSTEM`
- The action runs PowerShell, cmd, mshta, wscript, cscript, rundll32 or regsvr32
- The payload lives under AppData, ProgramData, Users\Public, Windows\Temp or Downloads
- The task name imitates a vendor (GoogleUpdate, OneDrive, Edge) but the path does not match the vendor
- The task already ran and the payload made network connections

## Closure Guidance
Close as benign only when the task belongs to a known management tool or an approved change, its action points to a signed binary in a protected path, and it was created by the expected account. Preserve the task XML in the ticket before anyone deletes the task.
