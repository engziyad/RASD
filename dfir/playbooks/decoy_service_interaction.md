---
playbook: decoy_service_interaction
techniques: [T1046, T1110.001, T1021.004]
detections: [T1046_decoy_service_interaction]
red_tests: [decoy_service_probe]
---

# DFIR Playbook: Decoy Service Interaction

## Trigger
The decoy host from [`deceive/decoys.yml`](../../deceive/decoys.yml) recorded an interaction from a client other than the authorised scanner: a port probe, a connection to one of its services, or a login attempt on one of them. Nothing on the network needs the decoy, so the record is reconnaissance or a credential guess, and the first question is which host made it and who was on it.

## Required Data
- The decoy records from the client (`src_host`), in order: `logtype`, `dst_port`, `logdata` (the credentials tried, the paths requested, the SSH client version)
- The client's identity: DHCP lease or asset list for `src_host`, its logged-on user (4624 on the client, EDR)
- Process and network telemetry of the client around the first record (Sysmon 1 / 3, auditd, EDR)
- Honey account and honey file alerts from the same client or user
- The deception log (declared scans, new monitoring pollers)

## First 15 Minutes
1. Confirm `node_id` is the inventory's decoy and that the deception log names no scan or asset discovery run for the time.
2. Resolve `src_host` to a host and a user. A server with a network management role is a candidate for a declared poller; a workstation is not.
3. Read the sequence of records: a SYN sweep over many ports (5001-5005) is a scanner; connections to SSH, RDP and SMB in a row are a hands-on operator; a login attempt (2000, 3001, 4002, 6001, 9001) carries the credential tried - check whether it belongs to a real account.
4. Check whether the same client touched other decoys: the honey files and the honey SPN point at this host, so a reader of the lures arrives here next.

## Deep Investigation
- The client's process tree around the first record: the scanner (nmap, masscan, a PowerShell sweep), the SSH or RDP client, the browser that opened the portal ([`process_tree`](../queries/kql/process_tree.kql))
- The client's other connections in the same window: which real hosts it scanned before and after the decoy (Sysmon 3, firewall logs)
- The credentials tried on the decoy: a real account name means the intruder already holds a user list; a real password means a credential is compromised
- How the client was compromised, and when the operator first logged on to it

## Evidence to Collect
| Evidence | Source | Purpose |
|---|---|---|
| Decoy records from the client | OpenCanary log of the decoy host | Every service touched, with timestamps and credentials tried |
| Client process telemetry | Sysmon 1 / auditd / EDR | The tool that made the connections |
| Client network connections | Sysmon 3 / firewall / NetFlow | The real hosts scanned around the decoy |
| Client logons | Security 4624 / auth.log on the client | Who was on the client |
| Decoy configuration and inventory entry | deceive/opencanary/settings.json, deceive/decoys.yml | Which services were enabled when the records were written |

## Escalate If
- The client is a workstation, or a server with no network management role
- A login attempt used a real account name or password of the organisation
- The client scanned real hosts in the same window
- Other decoys were touched from the same client or by the same user

## Closure Guidance
Close as a declared scan only when the deception log names the scanner, its address and the window; add the address to the decoy's tuning as a measured filter only when the scanner is permanent, and prefer excluding the decoy from the scanner's inventory. Close as a mistake only when a named administrator explains connecting to the decoy because it looked real, and the asset list is then fixed. Everything else is an incident: the first packet to the decoy was the intruder's. Keep the decoy running and record the touch in the deception log.
