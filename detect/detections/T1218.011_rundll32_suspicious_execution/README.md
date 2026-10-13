# Rundll32 Proxy Execution From Suspicious Context

<!-- rasd:facts:start -->
| | |
|---|---|
| **ATT&CK** | [T1218.011](https://attack.mitre.org/techniques/T1218/011/) · defense-evasion |
| **Severity** | `high` |
| **Maturity** | **SIEM-Ready** ([model](../../../docs/RASD_MATURITY_MODEL.md)) |
| **Engineering score** | 100/100 · operational pending - [run the lab](../../../docs/OPERATIONAL_VALIDATION.md) |
| **Tests** | 13 true positive · 6 true negative · 4 technique mutations |
| **Proof** | 100% of rule mutants killed · fuzzer resistance 100% over 108 variants |
| **Parity** | KQL and SPL identical to the rule on 605 events |
| **Rule** | [`rule.yml`](rule.yml) · [KQL](../../../queries/kql/T1218.011_rundll32_suspicious_execution.kql) · [SPL](../../../queries/spl/T1218.011_rundll32_suspicious_execution.spl) |
| **Operations** | [triage](triage.md) · [response](response.md) · [tuning](tuning.yml) · [contract](contract.yml) |
| **Chain** | red: [lsass_memory_access](../../../red/windows/lsass_memory_access/) · red: [rundll32_execution](../../../red/windows/rundll32_execution/) · DFIR: [lsass_access](../../../dfir/playbooks/lsass_access.md) · DFIR: [rundll32_proxy_execution](../../../dfir/playbooks/rundll32_proxy_execution.md) · purple: [T1218.011_rundll32](../../../purple/scenarios/T1218.011_rundll32.md) |
<!-- rasd:facts:end -->

## Telemetry required
Sysmon **EID 1** - the generated KQL and SPL read Sysmon. Security **4688** (with command-line auditing) works after remapping `NewProcessName` / `ParentProcessName` in `tools/mappings.yml`; it has no `OriginalFileName`, so the renamed-binary branch goes blind.

## How the detection works
`rundll32.exe` is signed by Microsoft and therefore often trusted by application control. The rule combines the image (path **or** `OriginalFileName`, so renaming does not help) with **any one of four abuse patterns** (`1 of susp_*`):

| Selection | Abuse |
|---|---|
| `susp_script` | `javascript:` / `RunHTMLApplication` proxying script execution through mshtml |
| `susp_path` | DLL loaded from AppData, ProgramData, Users\Public, Windows\Temp or Downloads (`\` or `/` separators) |
| `susp_minidump` | comsvcs.dll MiniDump LSASS dumping, by export name or by ordinal (`#24`, `#+0000024`) |
| `susp_noargs` | rundll32 with **no arguments**, a classic sacrificial process for injection (Cobalt Strike's default `spawnto`) |

## Evasion & coverage gaps
- DLLs copied into `System32` first (requires admin) - cover with file-creation monitoring.
- Export called by ordinal from a legitimately-located but malicious DLL. (The comsvcs MiniDump ordinal `#24` and the mshtml ordinal `#135` are covered - the fuzzer and the tests prove it.)
- Network beaconing from rundll32 (Sysmon EID 3) is a powerful complement for the no-args case.

## False positives & tuning
Old installers that unpack DLLs into `%TEMP%`. Validate the parent process and the signer of the loaded DLL (Sysmon EID 7).

Every tuning - applied, proposed or rejected - is recorded in [`tuning.yml`](tuning.yml). `python rasd.py tune --filter T1218.011` measures each proposal before it is applied: how many attack variants it would hide against how many corpus alerts it would remove.

## Offensive validation
[`red/windows/rundll32_execution`](../../../red/windows/rundll32_execution/) produces exactly the telemetry this rule needs, and its expected event is one of this rule's true positives (CI proves it matches). Run it on a lab VM, export the logs and turn the run into evidence:

```powershell
.\red\Invoke-PurpleEmulation.ps1 -Test rundll32_execution -LabConfirmed
.\red\Export-LabTelemetry.ps1 -Since (Get-Date).AddHours(-1)
```

```bash
python rasd.py evidence --results <results>/emulation-results.json --logs lab-export.jsonl
```

## Validate locally
```bash
python rasd.py test --filter T1218.011
python rasd.py prove --filter T1218.011
python rasd.py parity --filter T1218.011
python rasd.py explain T1218.011_rundll32_suspicious_execution --tp 1
```
