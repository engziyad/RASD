---
playbook: honey_account_use
techniques: [T1078.002, T1558.003, T1558.004, T1110.003]
detections: [T1078.002_honey_account_authentication, T1558.003_honey_spn_ticket_request]
red_tests: [honey_account_use, kerberoasting, password_spray_simulation]
---

# DFIR Playbook: Honey Account Use

## Trigger
A decoy domain account from [`deceive/decoys.yml`](../../deceive/decoys.yml) was presented to Windows authentication - a logon success or failure (4624, 4625), a TGT request or pre-authentication failure (4768, 4771), an NTLM validation (4776) - or a service ticket was requested for the honey SPN account (4769). Nobody is supposed to use these accounts, so the alert is a confirmed touch, not a suspicion: the question is who, from where, and what they read first.

## Required Data
- The alert event with `TargetUserName` (or `ServiceName`), `IpAddress` / `WorkstationName`, `Status` and the logon type
- DC Security 4624 / 4625 / 4768 / 4771 / 4776 / 4769 for the source host, one hour either side
- The deception log (who deployed the decoy, when its lure was last changed, declared audits and tests)
- Honey file alerts ([T1552.001_honey_file_access](../../detect/detections/T1552.001_honey_file_access/)) and decoy service alerts from the same hour
- LDAP reads of the decoy's attributes from the source, if collected (Directory Service 1644, EDR LDAP telemetry)

## First 15 Minutes
1. Confirm the account is in the inventory and that no declared audit or penetration test covers the time - the deception log is the source of truth, not the alert's own look.
2. Resolve the source: `IpAddress` to a host (DHCP, the asset list), `WorkstationName` when the address is a proxy or NAT; then the user logged on there ([`user_host_window`](../queries/kql/user_host_window.kql)).
3. Read the outcome. A 4625 / 4771 / 4776 means the lure's wrong password was tried: the intruder read the lure. A 4624 means the decoy's real password, which the lures never hold, is in the intruder's hands: treat it as an active intrusion. A 4768 with `PreAuthType` 0 means the account was AS-REP roasted and its hash is being cracked offline. A 4769 for the honey SPN means the whole SPN list was requested.
4. Check which lure led there: the honey file alerts of the same hour tell you the credentials file was read first; a 4769 burst from the same host tells you a Kerberoasting tool ran.

## Deep Investigation
- The source host's timeline around the attempt: process creation (the tool - Rubeus, Impacket, a PowerShell session), network connections to the domain controllers, LDAP queries (`(servicePrincipalName=*)`, `(userAccountControl:1.2.840.113556.1.4.803:=4194304)` for AS-REP targets)
- Every account that authenticated from the source host since the first decoy touch - the real credentials the intruder holds
- Other decoys touched from the same host or by the same user: the chain file -> account -> SPN -> decoy host shows the intruder's path
- How the source host was compromised (phishing, an exposed service, a previous lateral movement)

## Evidence to Collect
| Evidence | Source | Purpose |
|---|---|---|
| The alert event (4624/4625/4768/4771/4776 or 4769) | DC or server Security log | Which decoy, which outcome, from where |
| Authentication burst from the source | DC Security 4625 / 4771 / 4769 | A spray or a roasting run around the decoy |
| LDAP reads of the decoy's attributes | DC 1644 / EDR LDAP telemetry | When the lure was read, by which process |
| Source host process and network telemetry | Sysmon 1 / 3, EDR | The tool and the operator's session |
| Decoy inventory entry and deception log | deceive/decoys.yml, the operator's log | When the decoy was planted, by whom, what its lure says |

## Escalate If
- Any 4624 with a decoy account (the decoy's real password, which no lure holds, is in the intruder's hands)
- The source host is not a security team machine running a declared audit
- Other decoys alerted from the same host or user in the same hour
- A real privileged account authenticated from the source host after the decoy touch

## Closure Guidance
Close as a declared audit only when the deception log names the audit, the host and the window before the alert fired. Close as a mistake only when a named person explains how they came to use a decoy credential (a copied password list, a shared screen) and the honey file alert of the same hour agrees. Everything else is an incident: the decoy did its job. Whatever the verdict, keep the decoy in place, rotate its lure after the case, and record the touch in the deception log.
