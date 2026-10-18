# Linux Shell Executing Decoded Base64 or Code From a Temporary Directory

<!-- rasd:facts:start -->
| | |
|---|---|
| **ATT&CK** | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) Command and Scripting Interpreter: Unix Shell (execution) · related: [T1027](https://attack.mitre.org/techniques/T1027/) Obfuscated Files or Information (stealth) |
| **Severity** | `high` |
| **Maturity** | **SIEM-Ready** ([model](../../../docs/RASD_MATURITY_MODEL.md)) |
| **Engineering Score** | 100/100 · operational pending - [run the lab](../../../docs/OPERATIONAL_VALIDATION.md) |
| **Tests** | 11 true positive · 7 true negative · 6 technique mutations |
| **Proof** | 100% of rule mutants killed · fuzzer resistance 100% over 60 variants |
| **Parity** | KQL and SPL identical to the rule on 185 events (RASD's offline KQL / SPL model, not yet a live SIEM) |
| **Public data** | fires on 1 of 5 public recordings of its behaviour · 2 alerts · 0 labelled false positives · [evidence](public_evidence.md) |
| **Rule** | [`rule.yml`](rule.yml) · [KQL](../../../queries/kql/T1059.004_linux_suspicious_shell_execution.kql) · [SPL](../../../queries/spl/T1059.004_linux_suspicious_shell_execution.spl) |
| **Operations** | [triage](triage.md) · [response](response.md) · [closure](closure.md) · [tuning](tuning.yml) · [contract](contract.yml) |
| **Chain** | red: [suspicious_shell_execution](../../../red/linux/suspicious_shell_execution/) · DFIR: [linux_persistence](../../../dfir/playbooks/linux_persistence.md) · purple: [T1059.004_unix_shell](../../../purple/scenarios/T1059.004_unix_shell.md) |
<!-- rasd:facts:end -->

## Telemetry required
**Sysmon for Linux Event ID 1** (process creation). The rule reads the binary (`Image`) and its arguments (`CommandLine`). The generated KQL expects a `SysmonForLinux` parser function over the Syslog table and the SPL the Splunk Add-on for Sysmon for Linux; both are set in [`tools/mappings.yml`](../../../tools/mappings.yml).

## How the detection works
Two patterns, either one alerts:

| Selection | Matches |
|---|---|
| `susp_b64_pipe` | A command line that decodes Base64 (`-d`, `--decode`, `-di`) and pipes it into `sh`, `bash`, `dash`, `zsh` or `ksh`, also through `sudo` - the one-liner a web shell, an SSH command or a dropper runs with `sh -c` |
| `susp_tmp_binary` | A binary started from `/tmp`, `/var/tmp` or `/dev/shm` |
| `tmp_script_shell` and `tmp_script_path` | A shell whose first argument is a script in one of those directories, as the kernel records a script with a shebang started by its path (`/tmp/script.sh` becomes `/bin/sh /tmp/script.sh`) |

## Evasion & coverage gaps
- **Interactive pipelines** - typed in an open shell, `base64 -d` and `sh` are separate processes and no command line holds both. Hunt for `base64 -d` followed within a second by a shell with the same parent.
- **Other interpreters** - `python3 /tmp/x.py` or `perl /tmp/x.pl` are out of scope for this rule.
- **Other writable directories** - `~/.cache`, `/run/user/<uid>` and similar.
- **Relative invocation** - a script started as `./script.sh` from inside `/tmp` is logged as `/bin/sh ./script.sh`, with no `/tmp/` in the command line.
- **Shell options before the script, or sudo with options** - `sh -x /tmp/a.sh` and `| sudo -u root sh` do not match the regular expressions.

## False positives & tuning
Installers and package builds that unpack helpers into `/tmp`. The [tuning guide](tuning.yml) proposes filtering package-manager parents, and never Base64 piped into a shell or anything in `/dev/shm`.

## Offensive validation
[`red/linux/suspicious_shell_execution`](../../../red/linux/suspicious_shell_execution/) runs both patterns with payloads that only print the run marker. Both expected events are true positives of this rule (CI proves they match).

```bash
python3 red/run_red.py --test suspicious_shell_execution --lab-confirmed
python3 red/linux/export_sysmon_linux.py --since <start time printed by the run> --out lab-export.jsonl
rasd evidence --results <results>/emulation-results.json --logs lab-export.jsonl
```

## Test locally
```bash
rasd test --filter T1059.004
rasd prove --filter T1059.004
rasd parity --filter T1059.004
rasd explain T1059.004_linux_suspicious_shell_execution --tp 1
```
