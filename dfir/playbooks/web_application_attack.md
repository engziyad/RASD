---
playbook: web_application_attack
techniques: [T1190, T1505.003, T1606]
detections: [T1190_api_auth_probing, T1190_object_id_enumeration]
red_tests: [api_auth_testing, idor_testing, jwt_testing, file_upload_testing, security_headers_testing]
---

# DFIR Playbook: Web Application Attack

## Trigger
A WAF block burst, a spike of 401/403 or 5xx responses from one client, sequential object-ID access, uploads of executable or double-extension files, or a report from the application team.

## Required Data
- Web server / reverse-proxy / load-balancer access logs (client IP, method, path, status, size, user agent)
- WAF logs with rule IDs and, for uploads, the multipart filename
- Application logs (authentication and authorization failures, exceptions)
- The upload directory and web root of the affected servers

## First 15 Minutes
1. Identify the client IP(s), user agent and time window.
2. Classify the activity: probing (many 401/403/404), data access (sequential IDs with 200), uploads, or exploitation attempts (payloads in parameters).
3. Check for successes inside the burst: 200 responses to paths that should require authorization, accepted uploads.
4. Block the client at the WAF if it is external and clearly malicious.

## Deep Investigation
- Data exposed: every object served to the client (IDOR) and its owner
- Uploaded files: list and hash files created in upload directories in the window; look for web shells
- Process creation by the web server's process (w3wp.exe, java, node) - a web shell executing commands
- Authentication: accounts the client logged in with and where else they were used

## Evidence to Collect
| Evidence | Source | Purpose |
|---|---|---|
| Access log window | Web / proxy logs | Every request of the client and its status |
| WAF events | WAF | What was blocked and what passed |
| Uploaded files | Upload directory / web root | Web shells and dropped content |
| Web server child processes | Sysmon EID 1 / EDR | Command execution through the application |
| Application auth logs | Application | Accounts used and authorization failures |

## Escalate If
- Any confirmed data exposure (foreign objects served)
- An accepted executable or script upload in a web-reachable folder
- The web server process spawning shells
- A forged token accepted (JWT alg none or signature not verified)

## Closure Guidance
Close as benign only for authorized security testing (scope letter, tester IP) or a misbehaving internal client. Confirmed application flaws go to the application owner with the RASD-Red findings file as reproduction steps.
