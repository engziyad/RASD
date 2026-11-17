# RASD-Blindpath: The Route Through the Green Cells

A coverage map colours a technique green when a rule exists for it. It does not say whether an intruder who steps only on green cells is seen. `rasd blindpath` walks that way: from each origin to each target of an export, leg by leg, through the behaviours this rule set claims to detect, and names every leg where one of them can be done with no alert.

Nothing is called unseen without proof. Either the export holds no record of the sensor the rules read from that host (the verdict of [RASD-Silence](../../dfir/silence/README.md)), or one sequence of events of the behaviour is replayed through every rule and correlation and raises no alert. The events are not written for the occasion: they are a variant a behaviour spec documents and `rasd certify` shows slipping past the rule, or a correlation's own true positives paced one under its threshold. The method, the model and the limits are in [docs/BLINDPATH.md](../../docs/BLINDPATH.md); the model is [`model.yml`](model.yml).

```bash
rasd blindpath samples/silence/fleet.jsonl --assets samples/silence/assets.csv   # this page, on the sample fleet
rasd blindpath my-export.jsonl --assets assets.csv --certificate blindpath.md --html blindpath.html
rasd blindpath                                                                  # on Windows: this host, from its own event logs (read only)
```

## The sample fleet

The fleet is the one RASD-Silence reads: [`samples/silence/fleet.jsonl`](../../samples/silence/fleet.jsonl), one invented day of a domain controller, a file server and six workstations. The file server sends no Sysmon record and one workstation sends no Sysmon 10. Routes start on the workstations and end on the domain controller and the file server, as the roles of [`assets.csv`](../../samples/silence/assets.csv) say.

<!-- rasd:blindpath:start -->
**Sample fleet:** `samples/silence/fleet.jsonl`, 2221 records from 8 hosts over 23 h 59 min (2026-11-02 06:00:05 to 2026-11-03 05:59:15 UTC); origins and targets: the roles of the assets file.

**12 routes from 6 origins to 2 targets: 6 unseen end to end, 6 first seen at leg 3 (Move into the target, on rules with no behaviour spec).** 16 behaviours over 6 stages were walked on every host: 96 have a sensor in the export, 44 of them unseen (36 by a witness the engine replays, 8 for want of a sensor) and 52 seen. 23 ways around were replayed through 18 rules and 4 correlations; 22 raise no alert.

### The map

| Host | Role | Get in | Run code | Stay | Take credentials | Move in | Erase the record |
|---|---|---|---|---|---|---|---|
| DC01.corp.lab | domain-controller | - | open 1/2 | open 1/3 | open 3/3 | held* | held |
| SRV-FS01.corp.lab | server | - | open 2/2 | open 3/3 | open 3/3 | open 1/2 | held |
| WS01.corp.lab | workstation | - | open 1/2 | open 1/3 | open 3/3 | held* | held |
| WS02.corp.lab | workstation | - | open 1/2 | open 1/3 | open 3/3 | held* | held |
| WS03.corp.lab | workstation | - | open 1/2 | open 1/3 | open 3/3 | held* | held |
| WS04.corp.lab | workstation | - | open 1/2 | open 1/3 | open 3/3 | held* | held |
| WS05.corp.lab | workstation | - | open 1/2 | open 1/3 | open 3/3 | held* | held |
| WS06.corp.lab | workstation | - | open 1/2 | open 1/3 | open 3/3 | held* | held |

<sub>open n/m: n of the m behaviours of the stage that have a sensor in the export are unseen on that host · held: every one is seen · held*: seen, on rules with no behaviour spec · -: no behaviour of the stage has a sensor in the export.</sub>

### Routes

| From | To | Routes | Verdict | 1. Run code on the origin | 2. Take credentials from the origin | 3. Move into the target | 4. Run code on the target |
|---|---|---|---|---|---|---|---|
| WS01.corp.lab, WS02.corp.lab, WS03.corp.lab and 2 more | SRV-FS01.corp.lab | 5 | **unseen end to end** | open: Run PowerShell with an encoded command | open: Read the memory of LSASS, Request service tickets to crack (Kerberoasting), Try one password on many accounts | open: Run a command on the target through WinRM | open: Run PowerShell with an encoded command, Run code through rundll32 from a script handler or a user-writable folder |
| WS06.corp.lab | SRV-FS01.corp.lab | 1 | **unseen end to end** | open: Run PowerShell with an encoded command | open: Read the memory of LSASS, Request service tickets to crack (Kerberoasting), Try one password on many accounts | open: Run a command on the target through WinRM | open: Run PowerShell with an encoded command, Run code through rundll32 from a script handler or a user-writable folder |
| WS01.corp.lab, WS02.corp.lab, WS03.corp.lab and 2 more | DC01.corp.lab | 5 | seen at leg 3 | open: Run PowerShell with an encoded command | open: Read the memory of LSASS, Request service tickets to crack (Kerberoasting), Try one password on many accounts | held* | open: Run PowerShell with an encoded command |
| WS06.corp.lab | DC01.corp.lab | 1 | seen at leg 3 | open: Run PowerShell with an encoded command | open: Read the memory of LSASS, Request service tickets to crack (Kerberoasting), Try one password on many accounts | held* | open: Run PowerShell with an encoded command |

### Unseen, and the proof

| Behaviour | Stage | Hosts | Proof |
|---|---|---|---|
| Run PowerShell with an encoded command | Run code | DC01.corp.lab, WS01.corp.lab, WS02.corp.lab and 4 more | witness W4 of `T1059.001_powershell_encoded_command`: Quoted parts inside an argument · 1 event replayed through 18 rules and 4 correlations, no alert · 3 more ways |
| Register a scheduled task from PowerShell | Stay | DC01.corp.lab, WS01.corp.lab, WS02.corp.lab and 4 more | witness W8 of `T1053.005_powershell_scheduled_task_creation`: Environment variable in braces · 1 event replayed through 18 rules and 4 correlations, no alert · 3 more ways |
| Read the memory of LSASS | Take credentials | DC01.corp.lab, WS01.corp.lab, WS02.corp.lab and 3 more | witness W12 of `T1003.001_lsass_memory_access`: MsMpEng.exe directly in the Platform folder · 1 event replayed through 18 rules and 4 correlations, no alert · needs: Defender's tamper protection off on the host |
| Request service tickets to crack (Kerberoasting) | Take credentials | DC01.corp.lab, SRV-FS01.corp.lab, WS01.corp.lab and 5 more | witness W13 of `T1558.003_kerberoasting_volume`: paced under its threshold: 4 distinct ServiceName in each 10 min window, where the rule counts 5 · 12 events replayed through 18 rules and 4 correlations, no alert · inside the exclusion T1558.003_kerberoasting_rc4_tgs: AES tickets |
| Try one password on many accounts | Take credentials | DC01.corp.lab, SRV-FS01.corp.lab, WS01.corp.lab and 5 more | witness W15 of `T1110.003_password_spray_burst`: paced under its threshold: 4 distinct TargetUserName in each 10 min window, where the rule counts 5 · 12 events replayed through 18 rules and 4 correlations, no alert |
| Run PowerShell with an encoded command | Run code | SRV-FS01.corp.lab | dark: `T1059.001_powershell_encoded_command`: no Sysmon 1 (ProcessCreate) from this host is in the export |
| Run code through rundll32 from a script handler or a user-writable folder | Run code | SRV-FS01.corp.lab | dark: `T1218.011_rundll32_suspicious_execution`: no Sysmon 1 (ProcessCreate) from this host is in the export |
| Create a scheduled task with schtasks.exe that runs an interpreter or a user-writable file | Stay | SRV-FS01.corp.lab | dark: `T1053.005_schtasks_suspicious_creation`: no Sysmon 1 (ProcessCreate) from this host is in the export |
| Register a scheduled task from PowerShell | Stay | SRV-FS01.corp.lab | dark: `T1053.005_powershell_scheduled_task_creation`: no Sysmon 1 (ProcessCreate) from this host is in the export |
| Write a Run key that points to a user-writable folder | Stay | SRV-FS01.corp.lab | dark: `T1547.001_registry_run_key_persistence`: no Sysmon 13 (registry value set) from this host is in the export |
| Read the memory of LSASS | Take credentials | SRV-FS01.corp.lab | dark: `T1003.001_lsass_memory_access`: no Sysmon 10 (ProcessAccess) from this host is in the export |
| Run a command on the target through WinRM | Move in | SRV-FS01.corp.lab | dark: `T1021.006_wsmprovhost_suspicious_child`: no Sysmon 1 (ProcessCreate) from this host is in the export |
| Read the memory of LSASS | Take credentials | WS06.corp.lab | dark: `T1003.001_lsass_memory_access`: Microsoft-Windows-Sysmon/Operational is in the export and no Sysmon 10 (ProcessAccess) is in it: nothing shows the sensor was set to write one |

### The plan

The fewest changes after which every route is seen by a leg, for each leg in turn.

| Every route seen by | Changes | What changes |
|---|---|---|
| leg 1: Run code on the origin | 4 | On every origin:<br>`T1059.001_powershell_encoded_command`: close 'Base64 text shorter than 16 characters': Lower the floor to 4 Base64 characters (one character of script) after the -EncodedCommand spellings.<br>`T1059.001_powershell_encoded_command`: close 'Blanks around the switch inside its quotes (pwsh)': Allow a closing quote and further blanks between the switch and the Base64 text.<br>`T1059.001_powershell_encoded_command`: close 'Quoted parts inside an argument': Remove the quotes from the command line before matching (a normalized field), or allow a quote between every character of the switch and the Base64 run.<br>`T1059.001_powershell_encoded_command`: close 'White space inside the Base64 text': Allow white space between the Base64 characters, or count them across white space. |
| leg 2: Take credentials from the origin | 4 | The same as for leg 1.<br>This leg itself cannot be held by a change this model knows:<br>Request service tickets to crack (Kerberoasting) is paced under a threshold, which no rule change closes<br>Try one password on many accounts is paced under a threshold, which no rule change closes |
| leg 3: Move into the target | 1 | On every target:<br>SRV-FS01.corp.lab: turn on Sysmon 1 (ProcessCreate): Install Sysmon with a configuration that records process creation, and forward its channel |
| leg 4: Run code on the target | 1 | The same as for leg 3. |

### What each change buys alone

One change at a time: a sensor turned on on one host, or every documented variant of one rule closed.

| Change | Changes | Legs it holds | Routes it lets be seen | Every route seen by |
|---|---|---|---|---|
| `T1059.001_powershell_encoded_command`: close its 4 documented variants | 4 | 7 | 6 | leg 1 |
| SRV-FS01.corp.lab: turn on Sysmon 1 (ProcessCreate) | 1 | 1 | 6 | leg 3 |
| `T1053.005_powershell_scheduled_task_creation`: close its 4 documented variants | 4 | 7 | 0 | - |

### What each hold rests on

| Behaviour | Hosts | Rests on |
|---|---|---|
| Run code through rundll32 from a script handler or a user-writable folder | 7 | `T1218.011_rundll32_suspicious_execution`: its tests alone, no behaviour spec |
| Create a scheduled task with schtasks.exe that runs an interpreter or a user-writable file | 7 | `T1053.005_schtasks_suspicious_creation`: its tests alone, no behaviour spec |
| Write a Run key that points to a user-writable folder | 7 | `T1547.001_registry_run_key_persistence`: 2 variants proven to fire, 2 design exclusions |
| Install a service on the target that runs a command (PsExec style) | 8 | `T1569.002_suspicious_service_installation`: its tests alone, no behaviour spec |
| Run a command on the target through WinRM | 7 | `T1021.006_wsmprovhost_suspicious_child`: its tests alone, no behaviour spec |
| Clear the Security log | 7 | `T1685.005_event_log_clearing`: 5 variants proven to fire, 0 design exclusions; `T1685.005_security_log_cleared`: 1 variant proven to fire, 0 design exclusions · two records of the one act are read here: Sysmon 1 (ProcessCreate) and Security 1102 (audit log cleared) |
| Clear any other event log | 7 | `T1685.005_event_log_clearing`: 5 variants proven to fire, 0 design exclusions; `T1685.005_system_log_cleared`: 2 variants proven to fire, 0 design exclusions · two records of the one act are read here: Sysmon 1 (ProcessCreate) and System 104 (event log cleared) |
| Clear the Security log | 1 | `T1685.005_security_log_cleared`: 1 variant proven to fire, 0 design exclusions |
| Clear any other event log | 1 | `T1685.005_system_log_cleared`: 2 variants proven to fire, 0 design exclusions |

### Tripwires

Not counted for or against a route: a tripwire sees the intruder who touches it and no other.

| Decoy detection | Guards | State | Catches | Misses |
|---|---|---|---|---|
| `T1558.003_honey_spn_ticket_request` | Take credentials | armed on DC01.corp.lab | A roaster that requests a ticket for every account with a service principal name, at any pace and with any encryption type | A roaster that names its accounts and leaves the decoy out |
| `T1078.002_honey_account_authentication` | Take credentials | armed on DC01.corp.lab | A spray or a guess that includes a decoy account, at any pace | A list of accounts that leaves the decoys out |
| `T1552.001_honey_file_access` |  | armed on SRV-FS01.corp.lab | Reading, changing or deleting a decoy credentials file on a file share | An intruder who opens no decoy file |
| `T1046_decoy_service_interaction` |  | not in this export | A scan or a connection that touches the decoy host | An intruder who goes straight to the hosts it already knows |

### Variants the intruder does not choose

Documented, and not walked: the pipeline or the target decides them.

| Rule | Variant | Why |
|---|---|---|
| `T1003.001_lsass_memory_access` | Memory read access written in decimal | The collector writes the access mask; the intruder does not choose the pipeline. rasd doctor answers for an export. |
| `T1110.003_password_spray_burst` | NTLM credential validation on the domain controller | The sprayed host writes its own 4625 for every failure and the base rule counts it wherever that host's Security log is collected, so what stays out of the count is decided by the fleet's collection. |
| `T1190_object_id_enumeration` | The number in the query string | The application decides where an object's number travels. |
| `T1595.003_api_auth_probing` | Forbidden paths answered with 404 | The server decides which status hides a forbidden path. |
<!-- rasd:blindpath:end -->
