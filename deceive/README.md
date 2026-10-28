# RASD-Deceive: Decoys as Tested Detections

Detection asks whether an attacker's behaviour can be told apart from everyone else's. Deception removes the question: a decoy is something nobody legitimate touches, so the first touch is the alert. RASD-Deceive brings that into the framework without changing what RASD is - every decoy is read by a Sigma rule that goes through the same pipeline as every other rule (tests, mutation testing, fuzzing, exact automata, behaviour proofs, query parity, SIEM queries, triage and response cards), is touched by a red test whose expected event is one of the rule's true positives, has a DFIR playbook and a purple scenario, and earns its maturity the same way: nothing here is "validated" until a lab run says so.

What is new is the thing the rules read. [`decoys.yml`](decoys.yml) is the single inventory of every decoy: the honey accounts, the honey SPN account, the honey credential files, the decoy network host. The rules name those identities, the tests prove them, the red tests touch them, the deployment script creates them, and `rasd deceive --check` fails the build when any of them drifts from the inventory.

| File | Contents |
|---|---|
| [`decoys.yml`](decoys.yml) | The inventory: each decoy's identity, what it looks like, its lure, the telemetry it produces, the detection that reads it, the red test that touches it; and the decoy classes RASD knows but has not built |
| [`Deploy-RasdDecoys.ps1`](Deploy-RasdDecoys.ps1) | Plants the honey accounts (lab domain) and the honey files with their audit entries (lab host), or removes them; the specification of a deployment, for the lab |
| [`Test-RasdDecoys.ps1`](Test-RasdDecoys.ps1) | The tripwire health check: every decoy still in place, with its lure, its audit entry, its ports answering |
| [`opencanary/settings.json`](opencanary/settings.json) | The decoy host's OpenCanary configuration: the modules the inventory enables, under the inventory's node_id |
| [`../tools/deceive.py`](../tools/deceive.py) | `rasd deceive`: the checks, the catalogue below, `--rename` and `--gaps` |
| [`../docs/DECEPTION.md`](../docs/DECEPTION.md) | The design: why decoys are first-class detections, how the chain of lures works, what is proven and what waits for the lab |

## The decoys

<!-- rasd:deceive-catalog:start -->
| Decoy | Looks like | Lure | Fires when | Detection | Red test |
|---|---|---|---|---|---|
| **honey_account_backup_admin** (account)<br>`svc_backup_adm` | A backup service account with an old, over-privileged feel; the kind of account whose password is "temporarily" written down | The description attribute names the spreadsheet that holds its password (the honey file below); the password written there is plausible and wrong, the decoy's real password is random and kept nowhere, so every attempt fails and every attempt alerts | Anyone presents the account to Windows authentication, with the lure's password or any other | [`T1078.002_honey_account_authentication`](../detect/detections/T1078.002_honey_account_authentication/) | [honey_account_use](../red/active_directory/honey_account_use/) |
| **honey_account_helpdesk_asrep** (account)<br>`adm_helpdesk_tier2` | A legacy helpdesk administrator account | Kerberos pre-authentication is disabled, so AS-REP roasting tools (Rubeus asreproast, GetNPUsers) select it and request its TGT | The account is AS-REP roasted, sprayed or used | [`T1078.002_honey_account_authentication`](../detect/detections/T1078.002_honey_account_authentication/) | [honey_account_use](../red/active_directory/honey_account_use/) |
| **honey_spn_sqlreport** (spn)<br>`svc_sqlreport`<br>`MSSQLSvc/sqlrpt01.lab.local:1433` | The service account of a reporting SQL Server instance | A registered service principal name, so (servicePrincipalName=*) enumeration lists it and Kerberoasting tools request its ticket together with the real ones; its host name resolves to the decoy host, whose MSSQL decoy answers on 1433 | Anyone requests a service ticket for the account | [`T1558.003_honey_spn_ticket_request`](../detect/detections/T1558.003_honey_spn_ticket_request/) | [honey_account_use](../red/active_directory/honey_account_use/) |
| **honey_file_service_accounts** (file)<br>`\\LAB-FS01\IT\Passwords\service_accounts.xlsx`<br>rule reads `\IT\Passwords\service_accounts.xlsx` | An administrator's spreadsheet of service accounts and passwords, in a folder named Passwords on the IT share | The sheet lists the honey accounts with plausible wrong passwords, the honey SPN account and the decoy host's portal, so whoever reads it and tries anything trips the next decoy | A user account reads, writes or deletes the file | [`T1552.001_honey_file_access`](../detect/detections/T1552.001_honey_file_access/) | [honey_file_access](../red/windows/honey_file_access/) |
| **honey_file_keepass** (file)<br>`\\LAB-FS01\IT\Tools\credentials_backup.kdbx`<br>rule reads `\IT\Tools\credentials_backup.kdbx` | A password-manager database backup left in a tools folder | It carries the KDBX signature and random content, so it cannot be opened; it only needs to be worth taking, and taking it is a read | A user account reads, writes or deletes the file | [`T1552.001_honey_file_access`](../detect/detections/T1552.001_honey_file_access/) | [honey_file_access](../red/windows/honey_file_access/) |
| **honey_file_vpn_codes** (file)<br>`\\LAB-FS01\Public\Onboarding\vpn_and_wifi_codes.txt`<br>rule reads `\Public\Onboarding\vpn_and_wifi_codes.txt` | An onboarding note with VPN and Wi-Fi codes, where new joiners find it and attackers look first | The note names the decoy host's portal and the helpdesk account, so following it trips the next decoy | A user account reads, writes or deletes the file | [`T1552.001_honey_file_access`](../detect/detections/T1552.001_honey_file_access/) | [honey_file_access](../red/windows/honey_file_access/) |
| **decoy_service_canary** (service)<br>`lab-canary-01` · 10.0.0.40<br>ftp, ssh, telnet, http, smb, mssql, rdp, vnc, portscan | A NAS and reporting SQL Server host - a NAS login page, SSH, FTP, Telnet, a Backups share, SQL Server, RDP and VNC - on an address nothing else uses | The honey files and the honey SPN point at it; a port scan finds it; its login pages take any credential and refuse it | Any client except the authorised scanner probes, connects to or logs on to one of its services | [`T1046_decoy_service_interaction`](../detect/detections/T1046_decoy_service_interaction/) | [decoy_service_probe](../red/linux/decoy_service_probe/) |

**Decoy chains** - what a lure leads to, so one touch becomes a second alert:

- `honey_file_service_accounts` leads to `honey_account_backup_admin`, `honey_spn_sqlreport`, `decoy_service_canary`
- `honey_file_vpn_codes` leads to `honey_account_helpdesk_asrep`, `decoy_service_canary`

| Decoy class | Status | ATT&CK techniques caught | D3FEND | Telemetry |
|---|---|---|---|---|
| Honey account | built | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) · [T1558.004](https://attack.mitre.org/techniques/T1558/004/) · [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | [D3-DUC](https://d3fend.mitre.org/technique/d3f:DecoyUserCredential) | Security 4624, 4625, 4768, 4771, 4776 |
| Honey service principal name | built | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | [D3-DUC](https://d3fend.mitre.org/technique/d3f:DecoyUserCredential) | Security 4769 |
| Honey credentials file | built | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) · [T1083](https://attack.mitre.org/techniques/T1083/) | [D3-DF](https://d3fend.mitre.org/technique/d3f:DecoyFile) | Security 4663 with a SACL |
| Decoy network service | built | [T1046](https://attack.mitre.org/techniques/T1046/) · [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | [D3-DNR](https://d3fend.mitre.org/technique/d3f:DecoyNetworkResource) | OpenCanary records |
| Honey account attribute read | planned · telemetry mapped and the red test can produce it today | [T1087.002](https://attack.mitre.org/techniques/T1087/002/) | [D3-DUC](https://d3fend.mitre.org/technique/d3f:DecoyUserCredential) | Security 4662 (an operation was performed on an object) on the domain controllers, through a SACL on the decoy account that audits reads of its attributes |
| Document beacon | planned · needs a red test step | [T1005](https://attack.mitre.org/techniques/T1005/) · [T1039](https://attack.mitre.org/techniques/T1039/) | [D3-DF](https://d3fend.mitre.org/technique/d3f:DecoyFile) | Web access log of the lab web server (webserver), a GET of a per-document token when the decoy document is opened |
| Honey credential in Windows Credential Manager | planned · needs a red test step | [T1555.004](https://attack.mitre.org/techniques/T1555/004/) | [D3-DUC](https://d3fend.mitre.org/technique/d3f:DecoyUserCredential) | Security 5379 (Credential Manager credentials were read) on the host that holds it |
| Decoy SMB share on a Windows server | planned · needs a red test step | [T1135](https://attack.mitre.org/techniques/T1135/) · [T1039](https://attack.mitre.org/techniques/T1039/) | [D3-DNR](https://d3fend.mitre.org/technique/d3f:DecoyNetworkResource) | Security 5140, 5145 (a network share object was accessed) on the server |
| Canary cloud access key | planned · needs a new log source | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) · [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | [D3-DUC](https://d3fend.mitre.org/technique/d3f:DecoyUserCredential) | Cloud audit log (an API call made with the decoy key) |

7 decoys (2 account, 1 spn, 3 file, 1 service) · 4 deception detections · 3 red tests touch them · operational metrics (time to first touch, decoys touched per intrusion) pending a lab run

<sub>Generated by tools/deceive.py from decoys.yml · RASD-Deceive</sub>
<!-- rasd:deceive-catalog:end -->

## How a touch becomes an alert

```text
Attacker enumerates the directory ─┬─ description of svc_backup_adm points at \IT\Passwords\service_accounts.xlsx
                                   ├─ adm_helpdesk_tier2 has no Kerberos pre-authentication (AS-REP bait)
                                   └─ svc_sqlreport holds an SPN (Kerberoasting bait)
Attacker reads the honey file ───── 4663 on the file server ─────────────────────► T1552.001_honey_file_access
Attacker tries a decoy password ─── 4625 / 4771 / 4776 on the DC ─────────────────► T1078.002_honey_account_authentication
Attacker roasts the directory ───── 4768 (PreAuthType 0), 4769 for the decoy SPN ─► T1078.002 and T1558.003_honey_spn_ticket_request
Attacker follows the lures ──────── a scan or a login on the decoy host ──────────► T1046_decoy_service_interaction
```

Each lure leads to the next decoy: the honey file names the honey accounts and the decoy host's portal, the honey SPN's host name resolves to the decoy host. One careless read becomes two or three alerts within minutes, and the DFIR playbooks follow that chain.

The lures hold **wrong** passwords. Every decoy account's real password is 40 random characters written nowhere, and no decoy belongs to any group, so a decoy credential never grants anything: every attempt to use one fails, and every attempt is the alert.

## Keeping decoys and rules in step

```bash
rasd deceive                     # the catalogue above, from decoys.yml
rasd deceive --check             # inventory <-> rules <-> tests <-> red tests <-> OpenCanary configuration (CI)
rasd deceive --rename svc_backup_adm <your name>       # adopt your own identity, everywhere, then: rasd build && rasd ci
rasd deceive --gaps              # the decoy classes not built, ranked like the detection backlog
```

`--check` proves, on every build: each decoy's detection and red test exist, and the red test triggers that detection; each identity (account name, SPN account, file path, node_id) is a value of its rule and appears in one of the rule's true positives; the decoy host's rule lists exactly the event codes of the modules the inventory enables, and `opencanary/settings.json` enables exactly those modules under the inventory's node_id; every lure's `credentials_for` names decoys that exist.

The shipped identities belong to the lab domain `lab.local` and are published in this repository: they are the shape of a decoy, not names to deploy. `--rename` rewrites an identity in the inventory, the rule, its tests, mutations and behaviour spec, the red test, the deployment scripts, the playbooks and the docs at once; `rasd build` then regenerates the queries and pages, and `rasd ci` re-proves everything with your names. The proofs are about your decoys, not the examples.

## Deploying in the lab

```powershell
.\deceive\Deploy-RasdDecoys.ps1 -LabConfirmed -Accounts            # lab domain admin: the three accounts
.\deceive\Deploy-RasdDecoys.ps1 -LabConfirmed -Files -Shares       # elevated, on the lab file host: the files, their audit entries, the audit policy, the shares
.\deceive\Test-RasdDecoys.ps1                                      # any time: is every decoy still in place?
```

The decoy host is a Linux VM at `10.0.0.40` running OpenCanary with [`opencanary/settings.json`](opencanary/settings.json); its log (`/var/tmp/opencanary.log`) is forwarded to the SIEM as the `opencanary/honeypot` log source ([mappings](../tools/mappings.yml)), and the lab DNS resolves `nas01.lab.local` and `sqlrpt01.lab.local` to it. The red tests [`honey_account_use`](../red/active_directory/honey_account_use/), [`honey_file_access`](../red/windows/honey_file_access/) and [`decoy_service_probe`](../red/linux/decoy_service_probe/) touch every decoy and are the lab steps that turn the four deception detections into evidence.

Deployment runs only on machines their owner marked as a RASD lab ([lab guard](../red/lab/README.md#lab-guard)). A production deployment takes the identities from the inventory through your own change process; the script is the specification of what to create, and `Test-RasdDecoys.ps1` is the check that it stayed that way.

## What is proven, what is pending

Proven on every build: the four rules fire on every documented way of touching a decoy and stay quiet on everything else (behaviour proofs over exact automata), every value of every rule is held in place by a test, the generated KQL and SPL return what the rules return, and the inventory agrees with the rules, the tests, the red tests and the decoy host's configuration.

Pending a lab run, like every other RASD detection: evidence that the decoys produce the events in a real domain, the SIEM alerts, and the operational deception metrics - time from first touch to alert, decoys touched per intrusion, how far an intruder gets before the first decoy fires. RASD does not estimate them; `rasd evidence` records them when the lab produces them.
