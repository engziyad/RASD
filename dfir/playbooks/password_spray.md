---
playbook: password_spray
techniques: [T1110.003]
detections: [T1110.003_password_spray_burst]
red_tests: [password_spray_simulation]
hunts: [queries/hunts/password_spray_hunt.kql, queries/hunts/password_spray_hunt.spl]
---

# DFIR Playbook: Password Spray

## Trigger
The correlation [Password Spray - One Source Failing Authentication for Many Accounts](../../detect/correlations/T1110.003_password_spray_burst/) alerts: one client address failed authentication for 5 or more distinct accounts in a 10-minute window - a wrong password (4771 0x18, 4625 0xC000006A), an account that does not exist (4768 0x6, 4625 0xC0000064) or a disabled, expired or locked account (4768 0x12). The alert carries the source (`IpAddress`), the window, the number of accounts and their names. The [password spray hunt](../../queries/hunts/password_spray_hunt.kql) or identity protection can raise the same question.

## Required Data
- DC Security 4771 / 4768 / 4776 / 4625 failures, and 4768 / 4624 successes, for the source
- The source's role (workstation, VPN pool, proxy, internet-facing server)
- Account lockout events (4740)

## First 15 Minutes
1. Identify the source (IP or workstation) and resolve it to a host or a VPN user.
2. Count distinct target accounts and the time span.
3. Check for any success from the same source after the failures: that account is compromised.
   Unknown-account failures (4768 0x6) in the list mean the attacker guessed names: look for the enumeration that produced the valid ones.
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
