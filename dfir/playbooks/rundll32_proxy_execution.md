---
playbook: rundll32_proxy_execution
techniques: [T1218.011]
detections: [T1218.011_rundll32_suspicious_execution]
red_tests: [rundll32_execution]
---

# DFIR Playbook: Rundll32 Proxy Execution

## Trigger
rundll32.exe ran with a script protocol (`javascript:`, `vbscript:`, `RunHTMLApplication`), a DLL from a user-writable path, the comsvcs MiniDump export, or no arguments at all (a common injection host).

## Required Data
- Process creation with the full command line and `OriginalFileName`
- Image loads (Sysmon 7) for the rundll32 process
- Network connections (Sysmon 3) and child processes
- The referenced DLL or script

## First 15 Minutes
1. Retrieve the referenced DLL, hash it and check its signer.
2. Review the parent process.
3. For a no-argument rundll32: look for network connections from that PID - that is an injected beacon.
4. For comsvcs MiniDump: switch to the [LSASS playbook](lsass_access.md).
5. Search the same user and host ±30 minutes.

## Deep Investigation
- How the DLL arrived: browser download, email attachment, archive extraction (Sysmon 11, Zone.Identifier)
- What it loaded (mshtml, jscript9, clr) and what it spawned
- Persistence that references the same DLL (Run keys, tasks, services)
- The same DLL hash elsewhere in the estate

## Evidence to Collect
| Evidence | Source | Purpose |
|---|---|---|
| Command line | Sysmon EID 1 | The export or script rundll32 executed |
| Referenced DLL | Disk / EDR | Hash, signer, first-seen date |
| Image loads | Sysmon EID 7 | Script engines or CLR inside rundll32 |
| Network connections | Sysmon EID 3 | Beaconing from a proxy process |

## Escalate If
- The DLL is unsigned or new to the environment
- `javascript:`, `vbscript:` or comsvcs MiniDump on the command line
- rundll32 with no arguments that makes network connections
- The parent is Office, a browser or a script host

## Closure Guidance
Close as benign only when the DLL is signed by a known vendor and the parent is that vendor's installer or updater (validate the signer, not the file name). Script protocols and comsvcs MiniDump are never closed as benign without a documented test.
