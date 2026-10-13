---
playbook: lsass_access
techniques: [T1003.001]
detections: [T1003.001_lsass_memory_access, T1218.011_rundll32_suspicious_execution]
red_tests: [lsass_memory_access]
---

# DFIR Playbook: LSASS Memory Access

## Trigger
A process opened `lsass.exe` with read-capable access rights (Sysmon 10), or rundll32 called the `comsvcs.dll` MiniDump export.

## Required Data
- Sysmon 10 with `GrantedAccess` and `CallTrace`
- Process creation of the source process and its parent
- File creation (Sysmon 11) of `.dmp` files
- Logon sessions on the host since the last reboot
- Network transfers from the host after the access

## First 15 Minutes
1. Identify the SourceImage, its signer, parent and user.
2. Check whether the source is a known EDR, AV or backup agent in this environment.
3. Search for a `.dmp` file written by the same process within 2 minutes (Sysmon 11).
4. Read the CallTrace: `dbghelp`/`dbgcore` or `comsvcs` frames mean a dump, not a handle check.
5. Treat it as credential theft until proven otherwise - start containment planning now.

## Deep Investigation
- Every account that logged on to the host since boot (4624; 4648 for credentials the host itself used explicitly): those credentials are exposed
- Use of those accounts elsewhere after the access: new logons, Kerberos tickets, remote services
- Exfiltration of the dump: network connections, archive creation, cloud uploads
- How the attacker got administrator rights on the host in the first place

## Evidence to Collect
| Evidence | Source | Purpose |
|---|---|---|
| Process access record | Sysmon EID 10 | GrantedAccess and CallTrace prove the dump |
| Source process tree | Sysmon EID 1 | Who launched the dumper |
| Dump file metadata | Sysmon EID 11 / disk | Path, size, hash - search for copies |
| Logon sessions since boot | Security 4624 / 4648 | Accounts whose credentials must be reset |

## Escalate If
- The source is unsigned, renamed, or in a user-writable path
- rundll32 with comsvcs.dll on the command line
- Any dump file created near the access
- Authentication anomalies from the host afterwards (NTLM from new places, logon type 9)

## Closure Guidance
Close as benign only for a documented support case (an administrator creating an LSASS dump for Microsoft support) or a security agent verified by signer and path. Otherwise reset every credential used on the host since boot - service accounts included - before closing.
