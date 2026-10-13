---
playbook: ad_reconnaissance
techniques: [T1087.002, T1069.002, T1018]
detections: []
red_tests: [ldap_enumeration]
---

# DFIR Playbook: Active Directory Reconnaissance

## Trigger
Signs of directory enumeration: a decoy account was read (4662 on an audited honeypot object), DC 1644 shows broad LDAP filters from a workstation, EDR reports an AD collection tool (SharpHound, ADExplorer, AdFind), or a host makes unusual numbers of LDAP connections.

## Required Data
- DC Directory Service 1644 (when Field Engineering logging is enabled) or EDR LDAP telemetry
- 4662 on audited objects
- Process creation and network connections (port 389/636/3268) on the source host

## First 15 Minutes
1. Identify the source host and the process making the LDAP connections.
2. Check which filters were run: `(servicePrincipalName=*)`, `adminCount=1`, Domain Admins membership, all computers.
3. Determine whether the account is an admin or a tool account that queries AD routinely.

## Deep Investigation
- Output files of collection tools on the host (zip/json from SharpHound)
- Follow-on activity: Kerberoasting, password spraying, lateral movement towards the systems that were enumerated
- The same queries from other hosts

## Evidence to Collect
| Evidence | Source | Purpose |
|---|---|---|
| LDAP filters and client | DC 1644 / EDR | What was enumerated and by whom |
| Decoy object reads | DC 4662 | High-confidence signal of enumeration |
| Source process | Sysmon EID 1 / 3 | The tool behind the queries |
| Collection output | Disk on the source host | Scope of what the attacker learned |

## Escalate If
- A decoy object was read
- SPN or Domain Admins enumeration from a workstation
- A known collection tool was executed
- Enumeration followed by credential attacks

## Closure Guidance
Close as benign only for documented IT or security tooling (asset discovery, identity governance) running from its known server with its service account.
