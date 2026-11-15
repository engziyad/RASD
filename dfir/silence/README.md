# RASD-Silence: Evidence of Absence

A rule that raised nothing is read as "nothing happened". It says that only when the sensor it reads was recording the whole time, no record is missing, and nothing emptied or stopped the log in between. Otherwise the quiet is a blind spot that looks like safety. RASD-Silence decides, for every detection and every host of an export, whether its quiet is evidence, and lists every stretch where it is not.

| File | Contents |
|---|---|
| [`model.yml`](model.yml) | What proves each sensor was recording the record a rule reads, the records that end that proof (a log cleared, a service stopped, a policy changed), the records between which a host was off, and the limits printed with every certificate |

`rasd silence <export>` gives each detection on each host one of three verdicts: **fired**, **attested** (quiet between two proofs that the sensor was recording, with every record between them present) or **unattested** (quiet, and nothing shows the sensor could have spoken), and writes a certificate with `--certificate`. On Windows, `rasd silence` with no export reads the host's own event logs. The model, the verdicts and their limits are described in [SILENCE](../../docs/SILENCE.md).

The entries of the model are documented behaviour, each with its basis; none is lab evidence, and no result here raises a detection's maturity.

## Results on the sample fleet

`samples/silence/fleet.jsonl` is one invented day of eight hosts as a SIEM would hold it, written by [`samples/silence/generate.py`](../../samples/silence/generate.py). Most of the fleet is quiet and provably so; each of the other hosts shows one way a quiet rule stops being evidence. `rasd silence samples/silence/fleet.jsonl --assets samples/silence/assets.csv` prints what follows.

<!-- rasd:silence:start -->
**Sample fleet:** `samples/silence/fleet.jsonl`, 2218 records from 8 hosts over 23 h 59 min (2026-11-02 06:00:35 to 2026-11-03 05:59:55 UTC).

106 detection-host pairs: 87 attested (82 by record sequence, 5 by rhythm), 5 fired, 14 unattested · 88.3% of the watched time attested · 3 breaks in the record (3 high).

| Detection | Reads | Hosts | Attested | Fired | Unattested | Watched time attested |
|---|---|---|---|---|---|---|
| `T1003.001_lsass_memory_access` | Sysmon 10 (ProcessAccess) | 8 | 5 | 1 | 2 | 70.9% |
| `T1021.006_wsmprovhost_suspicious_child` | Sysmon 1 (ProcessCreate) | 8 | 7 | 0 | 1 | 84.3% |
| `T1046_decoy_service_interaction` | OpenCanary record of the decoy host | 0 | 0 | 0 | 1 |  |
| `T1053.003_crontab_noninteractive_install` | linux/process_creation records | 0 | 0 | 0 | 1 |  |
| `T1053.005_powershell_scheduled_task_creation` | Sysmon 1 (ProcessCreate) | 8 | 7 | 0 | 1 | 84.3% |
| `T1053.005_schtasks_suspicious_creation` | Sysmon 1 (ProcessCreate) | 8 | 7 | 0 | 1 | 84.3% |
| `T1059.001_powershell_encoded_command` | Sysmon 1 (ProcessCreate) | 8 | 6 | 1 | 1 | 84.3% |
| `T1059.004_linux_suspicious_shell_execution` | linux/process_creation records | 0 | 0 | 0 | 1 |  |
| `T1078.002_honey_account_authentication` | Security 4768, 4771 and 4776 on the domain controller (authentication) | 8 | 8 | 0 | 0 | 97.6% |
| `T1218.011_rundll32_suspicious_execution` | Sysmon 1 (ProcessCreate) | 8 | 6 | 1 | 1 | 84.3% |
| `T1547.001_registry_run_key_persistence` | Sysmon 13 (registry value set) | 8 | 6 | 1 | 1 | 84.3% |
| `T1552.001_honey_file_access` | Security 4663 on the file server (object access) | 1 | 1 | 0 | 0 | 100% |
| `T1558.003_honey_spn_ticket_request` | Security 4769 on the domain controller (service ticket requested) | 1 | 1 | 0 | 0 | 100% |
| `T1558.003_kerberoasting_rc4_tgs` | Security 4769 on the domain controller (service ticket requested) | 1 | 1 | 0 | 0 | 100% |
| `T1569.002_suspicious_service_installation` | System 7045 (service installed) | 8 | 8 | 0 | 0 | 98.0% |
| `T1685.005_event_log_clearing` | Sysmon 1 (ProcessCreate) | 8 | 7 | 0 | 1 | 84.3% |
| `T1685.005_security_log_cleared` | Security 1102 (audit log cleared) | 8 | 8 | 0 | 0 | 97.6% |
| `T1685.005_system_log_cleared` | System 104 (event log cleared) | 8 | 7 | 1 | 0 | 98.0% |
| `T1110.003_password_spray_burst` | Security 4768, 4771 and 4776 on the domain controller (authentication) | 1 | 1 | 0 | 0 | 100% |
| `T1190_object_id_enumeration` | webserver records | 0 | 0 | 0 | 1 |  |
| `T1558.003_kerberoasting_volume` | Security 4769 on the domain controller (service ticket requested) | 1 | 1 | 0 | 0 | 100% |
| `T1595.003_api_auth_probing` | webserver records | 0 | 0 | 0 | 1 |  |

<sub>attested: quiet, between two proofs that the sensor was recording, with every record between them present · fired: the rule raised an alert · unattested: quiet, and nothing shows the sensor could have spoken.</sub>

### Breaks in the record

Every stretch a sensor's proof does not cover, the gravest first.

| Severity | Host | Channel | From | To | What the records say | The host meanwhile |
|---|---|---|---|---|---|---|
| high | WS03.corp.lab | Microsoft-Windows-Sysmon/Operational | 2026-11-02 15:05:02 | 2026-11-02 15:40:31 | 9 records gone between #44087 and #44097: the channel was cleared at 11-02 15:40 |  |
| high | WS05.corp.lab | 3 channels | 2026-11-03 00:57:43 | 2026-11-03 04:40:20 | no record for 3 h 34 min, then the previous shutdown was unexpected, the Event Log service started and the Sysmon service started, and no record of a stop before it | DC01.corp.lab recorded 4 events naming it meanwhile |
| high | WS04.corp.lab | Security | 2026-11-03 02:05:57 | 2026-11-03 02:42:09 | 21 records missing between #305060 and #305082, and no record says why |  |

Not counted for or against any detection: WS01.corp.lab shut down for 11 h 53 min (2026-11-02 18:02:05 to 2026-11-03 05:55:20).

### Quiet that proves nothing

| Detection | Host | Why | What would make it evidence |
|---|---|---|---|
| `T1003.001_lsass_memory_access` | SRV-FS01.corp.lab | no Sysmon 10 (ProcessAccess) from this host is in the export | Add a ProcessAccess rule for lsass.exe to the Sysmon configuration |
| `T1003.001_lsass_memory_access` | WS06.corp.lab | Microsoft-Windows-Sysmon/Operational is in the export and no Sysmon 10 (ProcessAccess) is in it: nothing shows the sensor was set to write one | Add a ProcessAccess rule for lsass.exe to the Sysmon configuration |
| `T1021.006_wsmprovhost_suspicious_child` | SRV-FS01.corp.lab | no Sysmon 1 (ProcessCreate) from this host is in the export | Install Sysmon with a configuration that records process creation, and forward its channel |
| `T1046_decoy_service_interaction` | none | no host in the export writes what this rule reads: OpenCanary record of the decoy host | Ship the decoy host's log, and touch the decoy on a schedule from a known address so its quiet can be told from its absence |
| `T1053.003_crontab_noninteractive_install` | none | no host in the export writes what this rule reads: linux/process_creation records | Export the linux/process_creation records |
| `T1053.005_powershell_scheduled_task_creation` | SRV-FS01.corp.lab | no Sysmon 1 (ProcessCreate) from this host is in the export | Install Sysmon with a configuration that records process creation, and forward its channel |
| `T1053.005_schtasks_suspicious_creation` | SRV-FS01.corp.lab | no Sysmon 1 (ProcessCreate) from this host is in the export | Install Sysmon with a configuration that records process creation, and forward its channel |
| `T1059.001_powershell_encoded_command` | SRV-FS01.corp.lab | no Sysmon 1 (ProcessCreate) from this host is in the export | Install Sysmon with a configuration that records process creation, and forward its channel |
| `T1059.004_linux_suspicious_shell_execution` | none | no host in the export writes what this rule reads: linux/process_creation records | Export the linux/process_creation records |
| `T1218.011_rundll32_suspicious_execution` | SRV-FS01.corp.lab | no Sysmon 1 (ProcessCreate) from this host is in the export | Install Sysmon with a configuration that records process creation, and forward its channel |
| `T1547.001_registry_run_key_persistence` | SRV-FS01.corp.lab | no Sysmon 13 (registry value set) from this host is in the export | Add a RegistryEvent rule for the Run keys to the Sysmon configuration |
| `T1685.005_event_log_clearing` | SRV-FS01.corp.lab | no Sysmon 1 (ProcessCreate) from this host is in the export | Install Sysmon with a configuration that records process creation, and forward its channel |
| `T1190_object_id_enumeration` | none | no host in the export writes what this rule reads: webserver records | Export the webserver records |
| `T1595.003_api_auth_probing` | none | no host in the export writes what this rule reads: webserver records | Export the webserver records |

### Sensors

| Host | Channel | Records | Record numbers | Grade | Quiet after | Breaks | Off | Note |
|---|---|---|---|---|---|---|---|---|
| DC01.corp.lab | Microsoft-Windows-Sysmon/Operational | 145 | 40001 to 40145 | sequence | 72 min | 0 |  |  |
| DC01.corp.lab | Security | 311 | 300001 to 300311 | sequence | 20 min | 0 |  |  |
| DC01.corp.lab | System | 47 | 12001 to 12047 | sequence | 2 h 13 min | 0 |  |  |
| SRV-FS01.corp.lab | Security | 118 |  | rhythm | 59 min | 0 |  | the export carries no record numbers |
| SRV-FS01.corp.lab | System | 50 |  | rhythm | 2 h 12 min | 0 |  | the export carries no record numbers |
| WS01.corp.lab | Microsoft-Windows-Sysmon/Operational | 114 | 42001 to 42114 | sequence | 29 min | 0 | 11 h 53 min |  |
| WS01.corp.lab | Security | 40 | 302001 to 302040 | sequence | 87 min | 0 | 11 h 53 min |  |
| WS01.corp.lab | System | 31 | 14001 to 14031 | sequence | too few records to say | 0 | 11 h 52 min |  |
| WS02.corp.lab | Microsoft-Windows-Sysmon/Operational | 162 | 43001 to 43162 | sequence | 68 min | 0 |  |  |
| WS02.corp.lab | Security | 74 | 303001 to 303074 | sequence | 89 min | 0 |  |  |
| WS02.corp.lab | System | 49 | 15001 to 15049 | sequence | 2 h 12 min | 0 |  |  |
| WS03.corp.lab | Microsoft-Windows-Sysmon/Operational | 154 | 44001 to 44163 | sequence | 72 min | 1 |  |  |
| WS03.corp.lab | Security | 73 | 304001 to 304073 | sequence | 89 min | 0 |  |  |
| WS03.corp.lab | System | 46 | 16001 to 16046 | sequence | 2 h 14 min | 0 |  |  |
| WS04.corp.lab | Microsoft-Windows-Sysmon/Operational | 159 | 45001 to 45159 | sequence | 68 min | 0 |  |  |
| WS04.corp.lab | Security | 69 | 305001 to 305090 | sequence | 1 h 48 min | 1 |  |  |
| WS04.corp.lab | System | 43 | 17001 to 17043 | sequence | 2 h 14 min | 0 |  |  |
| WS05.corp.lab | Microsoft-Windows-Sysmon/Operational | 143 | 46001 to 46143 | sequence | 72 min | 1 |  |  |
| WS05.corp.lab | Security | 63 | 306001 to 306063 | sequence | 89 min | 1 |  |  |
| WS05.corp.lab | System | 47 | 18001 to 18047 | sequence | 2 h 13 min | 1 |  |  |
| WS06.corp.lab | Microsoft-Windows-Sysmon/Operational | 154 | 47001 to 47154 | sequence | 73 min | 0 |  |  |
| WS06.corp.lab | Security | 76 | 307001 to 307076 | sequence | 89 min | 0 |  |  |
| WS06.corp.lab | System | 50 | 19001 to 19050 | sequence | 2 h 14 min | 0 |  |  |
<!-- rasd:silence:end -->
