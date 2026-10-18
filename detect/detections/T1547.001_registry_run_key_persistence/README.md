# Run Key Persistence Pointing to Suspicious Location

<!-- rasd:facts:start -->
| | |
|---|---|
| **ATT&CK** | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder (persistence, privilege-escalation) |
| **Severity** | `medium` |
| **Maturity** | **SIEM-Ready** ([model](../../../docs/RASD_MATURITY_MODEL.md)) |
| **Engineering Score** | 100/100 · operational pending - [run the lab](../../../docs/OPERATIONAL_VALIDATION.md) |
| **Tests** | 20 true positive · 6 true negative · 4 technique mutations |
| **Proof** | 100% of rule mutants killed · fuzzer resistance 100% over 96 variants |
| **Parity** | KQL and SPL identical to the rule on 289 events · Defender advanced hunting identical on the same events (RASD's offline KQL / SPL model, not yet a live SIEM) |
| **Public data** | fires on 7 of 7 public recordings of its behaviour · held-out: 2 of 2 · 7 alerts · 0 labelled false positives · in-sample (changed after replaying them) · [evidence](public_evidence.md) |
| **Rule** | [`rule.yml`](rule.yml) · [KQL](../../../queries/kql/T1547.001_registry_run_key_persistence.kql) · [SPL](../../../queries/spl/T1547.001_registry_run_key_persistence.spl) · [Defender](../../../queries/mde/T1547.001_registry_run_key_persistence.kql) |
| **Operations** | [triage](triage.md) · [response](response.md) · [closure](closure.md) · [tuning](tuning.yml) · [contract](contract.yml) |
| **Chain** | red: [run_key_persistence](../../../red/windows/run_key_persistence/) · DFIR: [run_key_persistence](../../../dfir/playbooks/run_key_persistence.md) · purple: [T1547.001_run_key](../../../purple/scenarios/T1547.001_run_key.md) |
<!-- rasd:facts:end -->

## Telemetry required
Sysmon **EID 13 (RegistryEvent - Value Set)** with includes for `CurrentVersion\Run` and `RunOnce` (present in most community Sysmon configs).

## How the detection works
Writing a Run key value is extremely common for legitimate software, so alerting on the key alone is noise. The rule requires the **data** to point to a user-writable path (AppData, ProgramData, Users\Public, Windows\Temp, Windows\Tasks or Downloads), an unexpanded variable for one (`%TEMP%`, `%APPDATA%` ... - REG_EXPAND_SZ data keeps the variable as text), a binary or script straight in a user profile (`C:\Users\bob\x.exe`), or to start a script interpreter or a proxy binary (Windows PowerShell, PowerShell 7 `pwsh`, mshta, wscript, cscript, rundll32, regsvr32, `cmd /c`). It covers Run and RunOnce, native and WOW6432Node. It then filters two per-user apps by their **whole** value: OneDrive's own `OneDrive.exe [/background]`, and classic Teams' `Update.exe --processStart "Teams.exe"`. Anything else under those folders, or anything appended after them, still alerts. Any path under `AppData` counts, because malware commonly hides in random folders under `AppData\Local` as well as `Roaming`; the filters are what keep this precise, and CI proves each one is needed via a true-negative test. The negative test with a suspicious path under a *non-Run* key proves the key selection is doing its job.

## Evasion & coverage gaps
- Two Run keys ATT&CK lists under T1547.001 are not read: `...\Policies\Explorer\Run` and `...\CurrentVersion\RunOnceEx`.
- Other autostart locations: `Winlogon\Userinit`, `Shell`, `Image File Execution Options`, Startup folder, `UserInitMprLogonScript`. Each deserves its own rule.
- Payload in a trusted path (DLL side-loading next to a legitimate EXE).
- Registry writes via direct `NtSetValueKey` are still seen by Sysmon, but values written offline (hive edit) are not.

## False positives & tuning
Per-user installers (Slack, Zoom, Discord, Spotify) living in `AppData`. Add filters with the full path pattern.

Every tuning - applied, proposed or rejected - is recorded in [`tuning.yml`](tuning.yml). `rasd tune --filter T1547.001` measures each proposal before it is applied: how many attack variants it would hide against how many corpus alerts it would remove.

## Offensive validation
[`red/windows/run_key_persistence`](../../../red/windows/run_key_persistence/) is built to produce the telemetry this rule reads, and its expected event is one of this rule's true positives (CI proves it matches). Run it on a lab VM, export the logs and turn the run into evidence:

```powershell
.\red\Invoke-RasdEmulation.ps1 -Test run_key_persistence -LabConfirmed
.\red\Export-LabTelemetry.ps1 -Since (Get-Date).AddHours(-1) -OutFile .\lab-export.jsonl
```

```bash
rasd evidence --results <results>/emulation-results.json --logs lab-export.jsonl
```

## Test locally
```bash
rasd test --filter T1547.001
rasd prove --filter T1547.001
rasd parity --filter T1547.001
rasd explain T1547.001_registry_run_key_persistence --tp 1
```
