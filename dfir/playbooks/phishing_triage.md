---
playbook: phishing_triage
techniques: [T1566.001, T1204.002, T1059.001]
detections: [T1059.001_powershell_encoded_command]
red_tests: [powershell_encoded_command]
---

# DFIR Playbook: Phishing Triage

## Trigger
A user reports a suspicious email, the mail gateway flags a delivered message, or an endpoint alert shows Office or a browser spawning PowerShell, mshta, wscript or rundll32 shortly after an email was opened.

## Required Data
- The original message with headers (EML / MSG), or the gateway record
- Mail gateway and sandbox verdicts
- Endpoint process creation on the recipient's host around the open time
- Proxy / DNS logs for the URLs in the message
- The list of all recipients of the same message

## First 15 Minutes
1. Get the original message (not a forward) and record sender, return path, subject, Message-ID and attachments.
2. Check SPF, DKIM and DMARC results in the headers and the sending infrastructure.
3. Detonate attachments and URLs in a sandbox; never open them on a workstation.
4. Find every recipient of the same message (Message-ID or sender + subject).
5. On recipients' hosts: did Office or the browser start a child process after the open time?

## Deep Investigation
- Clicks: proxy and DNS records for the URLs, per recipient
- Execution on hosts where a child process started ([suspicious PowerShell](suspicious_powershell.md))
- Credential entry on a phishing page (proxy POSTs, sign-ins from new locations afterwards)
- Mailbox rules created after the click (forwarding, deletion)

## Evidence to Collect
| Evidence | Source | Purpose |
|---|---|---|
| Original message and headers | Mailbox / gateway | Sender infrastructure and authentication results |
| Attachment and URL verdicts | Sandbox | What the payload does |
| Recipient list | Mail gateway message trace | Scope of the campaign |
| Office / browser child processes | Sysmon EID 1 | Who executed the payload |
| URL access | Proxy / DNS | Who clicked |

## Escalate If
- Any recipient host shows Office or a browser spawning a script host or PowerShell
- Credentials were entered on the linked page
- The sender impersonates an executive, a supplier or the organisation's own domain
- The payload is not detected by the gateway or endpoint protection

## Closure Guidance
Close as benign (marketing, simulation, legitimate sender) only after the headers and sandbox verdict confirm it. For malicious messages that nobody executed, purge them from all mailboxes, block the sender infrastructure and URLs, and record the indicators before closing.
