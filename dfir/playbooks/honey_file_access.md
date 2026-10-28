---
playbook: honey_file_access
techniques: [T1552.001, T1083, T1039]
detections: [T1552.001_honey_file_access, T1078.002_honey_account_authentication]
red_tests: [honey_file_access, honey_account_use]
---

# DFIR Playbook: Honey File Access

## Trigger
One of the decoy credential files from [`deceive/decoys.yml`](../../deceive/decoys.yml) was read, written or deleted (4663 with a data access through the file's audit entry) by a user account on the server that holds it. The files exist to be found by someone searching shares for passwords; attribute reads, the server's own machine account and the search indexer do not fire, so the alert means the file was opened.

## Required Data
- The 4663 event: `ObjectName`, `AccessList`, `SubjectUserName`, `ProcessName`, `Computer`
- Share session events on the same server around the access (5140, 5145), which carry the client address 4663 lacks
- Logons of the account on the server and on the client host (4624 / 4625)
- Honey account alerts in the following hours ([T1078.002_honey_account_authentication](../../detect/detections/T1078.002_honey_account_authentication/)): the file holds the lure credentials
- The deception log (declared scans, migrations, classification runs)

## First 15 Minutes
1. Confirm the path is a decoy in the inventory and that no declared scan, migration or classification run covers the time.
2. Identify the account (`SubjectUserName`) and the process (`ProcessName`: `System` means the read came over the share; a local process means someone was on the server). For a share read, find the client address in the 5145 event of the same `SubjectLogonId` ([`user_host_window`](../queries/kql/user_host_window.kql)).
3. Check the other decoy files: a search for credentials usually opens every file that looks like one, within minutes.
4. Watch the honey accounts: the spreadsheet names `svc_backup_adm` with a plausible wrong password and the honey SPN account; an authentication alert for either, after the read, confirms the credentials were taken and tried.

## Deep Investigation
- The account's full session on the server: every file read in the same `SubjectLogonId`, in order - the real documents taken next to the decoy
- The client host's timeline: the process that mounted the share and read the file (Explorer, a script, a tool enumerating shares), its parent, its network connections
- Earlier share enumeration from the client (5140 on many servers, `net view`, SharpShares-style tooling)
- How the account's credential reached the client: a logon from another host, a phishing session, a service

## Evidence to Collect
| Evidence | Source | Purpose |
|---|---|---|
| The 4663 event for the decoy | File server Security log | Which decoy, which account, which process, which access |
| Share access of the same session | File server Security 5140 / 5145 | The client address and the other files touched |
| Client host process telemetry | Sysmon 1 / 3, EDR on the client | The tool that read the file and what else it did |
| Account logons around the access | DC and client Security 4624 / 4625 | Where the account came from and went next |
| Honey account alerts after the read | T1078.002_honey_account_authentication | Whether the lure credentials were used |
| Decoy inventory entry and deception log | deceive/decoys.yml, the operator's log | When the decoy was planted and what it contains |

## Escalate If
- The account is not a documented administrator of the share
- Several decoy files, or decoys on several servers, were opened by the same account or from the same client
- A honey account alert follows the read (the credentials were used)
- Real documents were read in the same session

## Closure Guidance
Close as benign only when a named person explains the open (curiosity about a file called passwords is a finding for awareness, not an incident) and nothing else was read in the session, or when the deception log names a declared scan for that account and window. Everything else is an incident. Keep the decoy, rotate its contents and the lure credentials after the case, and record the touch in the deception log.
