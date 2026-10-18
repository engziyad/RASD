# Crontab Installed From Standard Input or a File

<!-- rasd:facts:start -->
| | |
|---|---|
| **ATT&CK** | [T1053.003](https://attack.mitre.org/techniques/T1053/003/) Scheduled Task/Job: Cron (execution, persistence, privilege-escalation) |
| **Severity** | `medium` |
| **Maturity** | **SIEM-Ready** ([model](../../../docs/RASD_MATURITY_MODEL.md)) |
| **Engineering Score** | 100/100 · operational pending - [run the lab](../../../docs/OPERATIONAL_VALIDATION.md) |
| **Tests** | 5 true positive · 7 true negative · 5 technique mutations |
| **Proof** | 100% of rule mutants killed · fuzzer resistance 100% over 29 variants |
| **Parity** | KQL and SPL identical to the rule on 120 events (RASD's offline KQL / SPL model, not yet a live SIEM) |
| **Public data** | fires on 1 of 4 public recordings of its behaviour · 1 alert · 0 labelled false positives · [evidence](public_evidence.md) |
| **Rule** | [`rule.yml`](rule.yml) · [KQL](../../../queries/kql/T1053.003_crontab_noninteractive_install.kql) · [SPL](../../../queries/spl/T1053.003_crontab_noninteractive_install.spl) |
| **Operations** | [triage](triage.md) · [response](response.md) · [closure](closure.md) · [tuning](tuning.yml) · [contract](contract.yml) |
| **Chain** | red: [cron_persistence](../../../red/linux/cron_persistence/) · DFIR: [linux_persistence](../../../dfir/playbooks/linux_persistence.md) · purple: [T1053.003_cron](../../../purple/scenarios/T1053.003_cron.md) |
<!-- rasd:facts:end -->

## Telemetry required
**Sysmon for Linux Event ID 1** (process creation). The rule reads the binary (`Image`) and its arguments (`CommandLine`). The generated KQL expects a `SysmonForLinux` parser function over the Syslog table and the SPL the Splunk Add-on for Sysmon for Linux; both are set in [`tools/mappings.yml`](../../../tools/mappings.yml).

## How the detection works
`crontab` replaces a user's whole cron table in three ways: an editor (`crontab -e`), standard input (`crontab -`) or a file (`crontab <file>`). A person at the keyboard uses the editor. Scripts, implants and intruders use the other two, usually after `crontab -l` so the existing jobs survive:

| Selection | Matches |
|---|---|
| `install_stdin` | `crontab -` and `crontab -u <user> -` |
| `install_file` | `crontab <file>` and `crontab -u <user> <file>` |

Listing (`-l`), editing (`-e`) and removing (`-r`) stay silent, and so does a `sudo crontab -` wrapper: the `crontab` process it starts raises the alert.

## Evasion & coverage gaps
- **Writing the cron files directly** - `/var/spool/cron/crontabs/<user>` or `/etc/cron.d/` written without the `crontab` binary. A file-event rule on those paths covers it.
- **Other schedulers** - systemd timers and `at` jobs.
- **Scripted editor** - `crontab -e` with `EDITOR` set to a non-interactive command.

## False positives & tuning
Configuration management that installs cron tables from a staged file. The [tuning guide](tuning.yml) proposes filtering Ansible's temporary module directory in the parent command line, and never a user name.

## Offensive validation
[`red/linux/cron_persistence`](../../../red/linux/cron_persistence/) adds one harmless line through `crontab -`, after reading the current table. Its expected event is one of this rule's true positives (CI proves it matches).

```bash
python3 red/run_red.py --test cron_persistence --lab-confirmed
python3 red/linux/export_sysmon_linux.py --since <start time printed by the run> --out lab-export.jsonl
rasd evidence --results <results>/emulation-results.json --logs lab-export.jsonl
```

## Test locally
```bash
rasd test --filter T1053.003
rasd prove --filter T1053.003
rasd parity --filter T1053.003
rasd explain T1053.003_crontab_noninteractive_install --tp 1
```
