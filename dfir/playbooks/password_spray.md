---
playbook: password_spray
techniques: [T1110.003]
detections: [T1110.003_password_spray_burst]
red_tests: [password_spray_simulation]
hunts: [queries/hunts/password_spray_burst.kql, queries/hunts/password_spray_burst.spl]
---

# DFIR Playbook: Password Spray

## Trigger
The [password-spray correlation](../../detect/correlations/T1110.003_password_spray_burst/) alerts: one client address failed authentication with a wrong password for 5 or more distinct accounts in a 10-minute window (4771 0x18 or 4625 0xC000006A). The alert carries the source (`IpAddress`), the window, the number of accounts and their names. The [password spray hunt](../../queries/hunts/password_spray_burst.kql) or identity protection can raise the same question.

## Required Data
- DC Security 4771 / 4776 / 4625 failures, and 4768 / 4624 successes, for the source
- The source's role (workstation, VPN pool, proxy, internet-facing server)
- Account lockout events (4740)

## First 15 Minutes
1. Identify the source (IP or workstation) and resolve it to a host or a VPN user.
2. Count distinct target accounts and the time span.
3. Check for any success from the same source after the failures: that account is compromised.
4. Check lockouts (4740) caused by the spray.

## Deep Investigation
- Activity of any account that succeeded: logons, mailbox access, VPN sessions
- How the source got the account list (LDAP enumeration, public directory, OSINT)
- Earlier sprays from the same source or with the same timing pattern

## Evidence to Collect
| Evidence | Source | Purpose |
|---|---|---|
| Failure burst | DC 4771 / 4625 (and 4776 for NTLM validation) | Accounts targeted, window and source |
| Successes after the burst | DC 4768 / 4624 | Accounts that fell to the spray |
| Lockouts | DC 4740 | Business impact of the spray |
| Source attribution | DHCP / VPN / asset inventory | Who or what was behind the IP |

## Escalate If
- Any successful authentication from the source after the failures
- The source is internal (a compromised host is spraying)
- Privileged accounts were in the target list

## Closure Guidance
Close as benign only for a misconfigured service or a scanner using stale credentials, identified by owner. For a real spray with no success: block the source, confirm MFA coverage for targeted accounts, and record the window.
