# Run Key Persistence Pointing to Suspicious Location

<!-- rasd:facts:start -->
| | |
|---|---|
| **ATT&CK** | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) · persistence |
| **Severity** | `medium` |
| **Maturity** | **SIEM-Ready** ([model](../../../docs/RASD_MATURITY_MODEL.md)) |
| **Engineering score** | 100/100 · operational pending - [run the lab](../../../docs/OPERATIONAL_VALIDATION.md) |
| **Tests** | 13 true positive · 4 true negative · 4 technique mutations |
| **Proof** | 100% of rule mutants killed · fuzzer resistance 100% over 62 variants |
| **Parity** | KQL and SPL identical to the rule on 189 events |
| **Rule** | [`rule.yml`](rule.yml) · [KQL](../../../queries/kql/T1547.001_registry_run_key_persistence.kql) · [SPL](../../../queries/spl/T1547.001_registry_run_key_persistence.spl) |
| **Operations** | [triage](triage.md) · [response](response.md) · [tuning](tuning.yml) · [contract](contract.yml) |
| **Chain** | red: [run_key_persistence](../../../red/windows/run_key_persistence/) · DFIR: [run_key_persistence](../../../dfir/playbooks/run_key_persistence.md) · purple: [T1547.001_run_key](../../../purple/scenarios/T1547.001_run_key.md) |
<!-- rasd:facts:end -->

## Telemetry required
Sysmon **EID 13 (RegistryEvent - Value Set)** with includes for `CurrentVersion\Run` and `RunOnce` (present in most community Sysmon configs).

## How the detection works
Writing a Run key value is extremely common for legitimate software, so alerting on the key alone is noise. The rule requires the **data** to point to a user-writable path or a script interpreter, then filters well-known per-user apps (OneDrive, Teams). Any path under `AppData` counts, because malware commonly hides in random folders under `AppData\Local` as well as `Roaming`; the filters are what keep this precise, and CI proves each one is needed via a true-negative test. The negative test with a suspicious path under a *non-Run* key proves the key selection is doing its job.

## Evasion & coverage gaps
- Other autostart locations: `Winlogon\Userinit`, `Shell`, `Image File Execution Options`, Startup folder, `UserInitMprLogonScript`. Each deserves its own rule.
- Payload in a trusted path (DLL side-loading next to a legitimate EXE).
- Registry writes via direct `NtSetValueKey` are still seen by Sysmon, but values written offline (hive edit) are not.

## False positives & tuning
Per-user installers (Slack, Zoom, Discord, Spotify) living in `AppData`. Add filters with the full path pattern.

Every tuning - applied, proposed or rejected - is recorded in [`tuning.yml`](tuning.yml). `python rasd.py tune --filter T1547.001` measures each proposal before it is applied: how many attack variants it would hide against how many corpus alerts it would remove.

## Offensive validation
[`red/windows/run_key_persistence`](../../../red/windows/run_key_persistence/) produces exactly the telemetry this rule needs, and its expected event is one of this rule's true positives (CI proves it matches). Run it on a lab VM, export the logs and turn the run into evidence:

```powershell
.\red\Invoke-PurpleEmulation.ps1 -Test run_key_persistence -LabConfirmed
.\red\Export-LabTelemetry.ps1 -Since (Get-Date).AddHours(-1)
```

```bash
python rasd.py evidence --results <results>/emulation-results.json --logs lab-export.jsonl
```

## Validate locally
```bash
python rasd.py test --filter T1547.001
python rasd.py prove --filter T1547.001
python rasd.py parity --filter T1547.001
python rasd.py explain T1547.001_registry_run_key_persistence --tp 1
```
