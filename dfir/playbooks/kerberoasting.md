---
playbook: kerberoasting
techniques: [T1558.003, T1110.002]
detections: [T1558.003_kerberoasting_rc4_tgs, T1558.003_kerberoasting_volume]
red_tests: [kerberoasting, ldap_enumeration]
---

# DFIR Playbook: Kerberoasting

## Trigger
A domain controller issued an RC4-encrypted service ticket (4769, `TicketEncryptionType` 0x17) for a user-based service account, or the [Kerberoasting volume correlation](../../detect/correlations/T1558.003_kerberoasting_volume/) alerted: one client received service tickets for 5 or more distinct user-based service accounts in a 10-minute window, with any encryption type.

## Required Data
- DC Security 4769 for the requesting client
- LDAP queries for `servicePrincipalName` from the client (DC 1644 or EDR LDAP telemetry, if collected)
- Logons from the client host before and after
- Password age and encryption settings of the targeted service accounts

## First 15 Minutes
1. Identify the requesting account and the source IP (resolve the IP to a host).
2. Count distinct SPNs requested by that client in the last hour ([`kerberos_client_activity`](../queries/kql/kerberos_client_activity.kql)).
3. Check whether the source is a workstation (suspicious) or an application server (often legitimate).
4. Identify which targeted accounts are privileged.

## Deep Investigation
- The process on the client that requested the tickets (EDR, Sysmon 3 to port 88)
- SPN discovery before the requests (LDAP `(servicePrincipalName=*)`)
- Logons with the targeted service accounts afterwards, from new hosts - a cracked password in use
- How the requesting account was compromised

## Evidence to Collect
| Evidence | Source | Purpose |
|---|---|---|
| 4769 events for the client | DC Security log | Which SPNs, when, with which encryption |
| SPN discovery | DC 1644 / EDR LDAP telemetry | Confirms deliberate enumeration |
| Service account logons | DC 4624 / 4768 | Use of a cracked password |
| Account settings | AD (`msDS-SupportedEncryptionTypes`, `pwdLastSet`) | How crackable the targets are |

## Escalate If
- Three or more distinct SPNs requested in ten minutes
- The source is a workstation
- Targeted accounts are privileged service accounts
- A targeted account logs on from a new host afterwards

## Closure Guidance
Close as benign only when the source is an application server that legitimately requests that service and the account is documented as RC4-only (then raise a ticket to move it to AES). Whatever the verdict, rotate passwords of service accounts that were roasted from a workstation.
