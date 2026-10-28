# RASD-Deceive: Deception as First-Class Detection

## Why decoys belong in a detection framework

Every rule in `detect/` answers one question: can this attacker behaviour be told apart from everyone else's? The answer costs tests, mutation proofs, fuzzing, exact automata, behaviour specs and tuning, because the behaviour is shared - administrators run PowerShell, services request Kerberos tickets, people open spreadsheets. A decoy changes the question. It is an account, a file, a service principal name or a host that nobody legitimate has any reason to touch, so the behaviour that matters is not *suspicious*, it is *any*. The first touch is the alert.

That makes a decoy the cheapest high-confidence detection a SOC can own, and the easiest one to get wrong: decoys drift (a helpful administrator cleans up the "unused" account), lose their audit entries, fall out of step with the rule that reads them, or are so obviously planted that nobody touches them. Deception products hide those failure modes behind a console. RASD puts them under the same proofs as every other rule.

RASD-Deceive therefore adds nothing new to the pipeline. It adds one new *source*, the inventory [`deceive/decoys.yml`](../deceive/decoys.yml), and one tool, `rasd deceive`, that proves the inventory and everything built on it agree. The four deception rules are ordinary Sigma rules in `detect/detections/`: they pass `rasd lint`, `test`, `mutate`, `fuzz`, `prove`, `parity` and `certify`, carry contracts, tuning guides and behaviour specs, generate KQL and SPL, triage, response and closure cards, are touched by red tests whose expected events are their own true positives, and have DFIR playbooks and purple scenarios. Their maturity is computed like everyone else's: **SIEM-Ready** today, **Validated** only when a lab run is committed.

## The decoys

| Decoy | Kind | What the attacker sees | Telemetry | Detection |
|---|---|---|---|---|
| `svc_backup_adm` | honey account | A backup service account whose description says its temporary password is in `\\LAB-FS01\IT\Passwords\service_accounts.xlsx` | Security 4624 / 4625 / 4768 / 4771 / 4776 | [T1078.002_honey_account_authentication](../detect/detections/T1078.002_honey_account_authentication/) |
| `adm_helpdesk_tier2` | honey account | A legacy helpdesk administrator with Kerberos pre-authentication disabled: AS-REP roasting tools select it | Security 4768 (`PreAuthType` 0), 4624 / 4625 / 4771 / 4776 | [T1078.002_honey_account_authentication](../detect/detections/T1078.002_honey_account_authentication/) |
| `svc_sqlreport` | honey SPN account | A reporting SQL Server's service account with a registered SPN whose host resolves to the decoy host: Kerberoasting tools request its ticket with every other SPN | Security 4769, any encryption type, any status | [T1558.003_honey_spn_ticket_request](../detect/detections/T1558.003_honey_spn_ticket_request/) |
| `\IT\Passwords\service_accounts.xlsx`, `\IT\Tools\credentials_backup.kdbx`, `\Public\Onboarding\vpn_and_wifi_codes.txt` | honey files | A spreadsheet of service accounts and passwords, a password-manager database, an onboarding note with VPN and Wi-Fi codes, each with an audit entry | Security 4663 (ReadData, WriteData, AppendData, Delete) on the file server | [T1552.001_honey_file_access](../detect/detections/T1552.001_honey_file_access/) |
| `lab-canary-01` | decoy host | A NAS and SQL Server host (OpenCanary): NAS login page, SSH, FTP, Telnet, a Backups share, SQL Server, RDP, VNC, on an address nothing uses | OpenCanary JSON records (`logtype`, `node_id`, `src_host`) | [T1046_decoy_service_interaction](../detect/detections/T1046_decoy_service_interaction/) |

Each class maps to a MITRE D3FEND decoy technique (D3FEND 1.6, under Decoy Object D3-DO): the accounts and the SPN account are Decoy User Credentials (D3-DUC), the files are Decoy Files (D3-DF), the host is a Decoy Network Resource (D3-DNR). The catalogue in [`deceive/README.md`](../deceive/README.md) is generated from the inventory and carries both mappings.

### The chain of lures

The decoys point at each other. The description of `svc_backup_adm` names the spreadsheet; the spreadsheet lists the honey accounts, the honey SPN account and the decoy host's portal; the onboarding note names the helpdesk decoy and the portal; the SPN's host name resolves to the decoy host, whose SQL Server decoy answers on 1433. An intruder who reads one lure and acts on it produces a second alert within minutes, from a different log source, on a different rule - the DFIR playbooks ([honey_account_use](../dfir/playbooks/honey_account_use.md), [honey_file_access](../dfir/playbooks/honey_file_access.md), [decoy_service_interaction](../dfir/playbooks/decoy_service_interaction.md)) follow that chain, and the inventory records it (`credentials_for`), so `rasd deceive --check` fails when a lure points at a decoy that does not exist.

### Decoys never grant anything

The passwords written in the lures are plausible and wrong. Every decoy account's real password is 40 random characters written nowhere, and no decoy belongs to any group. A credential taken from a lure fails every time it is tried, and every attempt is logged on the domain controller as the alert. A decoy account that *succeeds* in logging on (a 4624) therefore means its real password leaked some other way, and the playbooks treat it as the most serious case. The honey SPN account allows RC4 only, so tools that skip AES-enabled accounts to avoid the RC4 signature still select it; its 40-character password makes the ticket worthless to crack. The password-manager decoy carries the KDBX signature and random content: it cannot be opened, which does not matter, because taking it is a read.

## What `rasd deceive --check` proves, on every build

| Claim | Check |
|---|---|
| Every decoy is read by a rule that exists | `detection` names a folder in `detect/detections/` |
| The rule names the decoy exactly | the account name and its UPN form, the SPN account name and its realm form, the file path, the `node_id` are values of the rule's selections (case-insensitive) |
| A test holds the decoy in place | the identity appears in one of the rule's true positives - so `rasd prove` fails if the value is deleted from the rule, and `rasd test` fails if the event stops matching |
| The red test touches the decoy and the rule catches it | `red_test` names a test in `red/` whose steps trigger the detection; `rasd red --check` proves its sample event is a true positive that matches |
| The decoy host's rule and configuration agree with the inventory | the rule's `logtype` values are exactly the event codes (from `opencanary/logger.py`) of the modules the inventory enables; `deceive/opencanary/settings.json` enables exactly those modules under the inventory's `node_id` |
| Lures point at real decoys | every `credentials_for` entry is a decoy id |
| The classes are honest | a `built` class has decoys, a `planned` class says what telemetry it needs, whether RASD maps it, whether a red test can produce it, what is missing and what comes next; each names its D3FEND technique |
| The catalogue is current | `deceive/README.md` equals what the inventory renders (drift check, like every generated page) |

The rules themselves are proven by the rest of the pipeline. For the four deception rules today: every rule mutant killed (`rasd prove`), every behaviour variant proven for every possible event or proven quiet (`rasd certify`, 24 variants: 12 ways of touching a decoy caught, 12 exclusions quiet, no known gap), KQL and SPL identical to the engine on every test event and variant (`rasd parity`), Engineering Score 100.

## Adopting your own decoys

The identities in the repository are examples of the *shape* a decoy should have; they are public, and an attacker who read this repository knows them. `rasd deceive --rename OLD NEW` rewrites an identity in the inventory, the rule, its tests, mutations and behaviour spec, the red test and its scripts, the deployment and health-check scripts, the playbooks, the scenarios and the docs, in one pass (case variants in the tests follow the new name; JSON-escaped forms of file paths are handled). It refuses a name that already occurs anywhere those files are read - a decoy identity must be unique, or a real account would turn into a decoy - and a name a Sigma wildcard could misread. Then `rasd build` regenerates the queries and pages, and `rasd ci` re-proves everything: the automata, the parity verdicts and the behaviour proofs are now about *your* decoys. A unit test performs a rename on a copy of the repository and checks that the rule still fires on every renamed true positive and that `--check` still passes.

Names are the easy part. A decoy is only as good as its fit: a service account whose description reads like the ones around it, a file among real files with a history, a host in the asset list with a DNS name. The deployment script gives the files plausible timestamps and the SPN a host that resolves; the rest is yours, and the planned classes below say where RASD goes next.

## Deploying

In the lab, [`Deploy-RasdDecoys.ps1`](../deceive/Deploy-RasdDecoys.ps1) creates the accounts (with a lab domain admin), the files with their audit entries and the File System audit policy (elevated, on the lab file host), and the SMB shares; [`Test-RasdDecoys.ps1`](../deceive/Test-RasdDecoys.ps1) checks at any time that every decoy is still in place with its lure, its audit entry and its ports - the check deception products hide, made explicit, because a decoy that drifted stops alerting silently. The decoy host is a Linux VM running OpenCanary with [`deceive/opencanary/settings.json`](../deceive/opencanary/settings.json). Both scripts run only on machines their owner marked as a RASD lab ([lab guard](../red/lab/README.md#lab-guard)).

In production, the inventory is the specification and your change process is the tool: the same identities, the same lures, the same audit entries, created by whoever owns the directory and the file servers, then the same rules deployed from `queries/`, and `Test-RasdDecoys.ps1` on a schedule. RASD does not automate changes to a production directory.

The telemetry each decoy needs is listed in its contract and in [DATA_SOURCE_COVERAGE](DATA_SOURCE_COVERAGE.md): the Security log of domain controllers and member servers for the accounts, the Security log of the file servers with *Audit File System* and a SACL on each file, the OpenCanary log forwarded as the `opencanary/honeypot` log source ([mappings](../tools/mappings.yml)).

## What is pending

The same thing that is pending for every RASD detection: lab evidence. The three red tests ([honey_account_use](../red/active_directory/honey_account_use/), [honey_file_access](../red/windows/honey_file_access/), [decoy_service_probe](../red/linux/decoy_service_probe/)) are the lab steps; `rasd evidence` turns their runs and the exported logs into `evidence.md`, and only then do the four detections become **Validated** and their Operational Scores stop being pending. Operational deception metrics - time from first touch to alert, decoys touched per intrusion, how far an intruder gets before the first decoy fires - come from those runs and from real incidents, and are never estimated.

## Planned decoy classes

`rasd deceive --gaps` ranks the classes in the inventory that are not built, the way [the detection backlog](../intel/outputs/detection_backlog.md) ranks techniques: first the ones whose telemetry RASD already maps and whose red test can produce today, then those that need a red test step, then those that need a new log source. Today: a honey account attribute read (Security 4662 through a SACL on the decoy accounts, the AD reconnaissance item of the [roadmap](RELEASE_ROADMAP.md), which turns the T1087.002 backlog entry into a detection), a document beacon on the lab web server's access log, a honey credential in Windows Credential Manager (5379), a decoy SMB share (5140 / 5145), and a canary cloud access key once a cloud log source exists.
