# Windows Event Log Clearing via Command Line

<!-- rasd:facts:start -->
| | |
|---|---|
| **ATT&CK** | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) Indicator Removal: Clear Windows Event Logs (defense-evasion) |
| **Severity** | `high` |
| **Maturity** | **SIEM-Ready** ([model](../../../docs/RASD_MATURITY_MODEL.md)) |
| **Engineering Score** | 100/100 · operational pending - [run the lab](../../../docs/OPERATIONAL_VALIDATION.md) |
| **Tests** | 11 true positive · 6 true negative · 4 technique mutations |
| **Proof** | 100% of rule mutants killed · fuzzer resistance 100% over 103 variants |
| **Parity** | KQL and SPL identical to the rule on 1667 events · Defender advanced hunting identical on the same events |
| **Public data** | fires on 1 of 1 public recordings of its behaviour · held-out: 2 of 2 · 2 alerts · 0 labelled false positive · [evidence](public_evidence.md) |
| **Rule** | [`rule.yml`](rule.yml) · [KQL](../../../queries/kql/T1070.001_event_log_clearing.kql) · [SPL](../../../queries/spl/T1070.001_event_log_clearing.spl) · [Defender](../../../queries/mde/T1070.001_event_log_clearing.kql) |
| **Operations** | [triage](triage.md) · [response](response.md) · [closure](closure.md) · [tuning](tuning.yml) · [contract](contract.yml) |
| **Chain** | red: [event_log_clearing](../../../red/windows/event_log_clearing/) · DFIR: [event_log_clearing](../../../dfir/playbooks/event_log_clearing.md) · purple: [T1070.001_event_log_clearing](../../../purple/scenarios/T1070.001_event_log_clearing.md) |
<!-- rasd:facts:end -->

## Telemetry required
Sysmon **EID 1** - the generated KQL and SPL read Sysmon. Security **4688** (with command-line auditing) works after remapping `NewProcessName` / `ParentProcessName` in `tools/mappings.yml`; it has no `OriginalFileName`, so the renamed-binary branch goes blind. The resulting artifacts are Security **1102** and System **104** - forward both to the SIEM as an independent detection.

## How the detection works
Covers the command-line methods for clearing a log:

| Selection | Method |
|---|---|
| `selection_wevtutil_*` | `wevtutil cl` / `clear-log` - binary matched by path **or** `OriginalFileName`, so a renamed copy still fires |
| `selection_ps_*` | `Clear-EventLog`, `Remove-EventLog`, `Limit-EventLog` (shrinking a log so evidence is overwritten) and the .NET `EventLogSession.ClearLog()` from Windows PowerShell or PowerShell 7, renamed or not |
| `selection_wmi` | The WMI `ClearEventLog` method from **any** client: `wmic nteventlog ... call cleareventlog`, `Invoke-CimMethod -MethodName ClearEventLog` or `.ClearEventlog()` |

Detecting at process creation records **who** ran it, and still alerts when the attacker cleared the local log but forwarding had already shipped the command.

## Evasion & coverage gaps
- Clearing through the Event Viewer GUI or the Win32 API (`ClearEventLogW`) from a custom binary - only 1102/104 will show.
- **Selective** event deletion / log tampering (e.g. Mimikatz `event::drop`, Invoke-Phant0m killing EventLog threads) - detect via **gaps in log volume** (heartbeat monitoring) instead.

## False positives & tuning
VDI / golden-image sealing scripts. These run in maintenance windows on known build hosts - filter by host group.

Every tuning - applied, proposed or rejected - is recorded in [`tuning.yml`](tuning.yml). `rasd tune --filter T1070.001` measures each proposal before it is applied: how many attack variants it would hide against how many corpus alerts it would remove.

## Offensive validation
[`red/windows/event_log_clearing`](../../../red/windows/event_log_clearing/) produces exactly the telemetry this rule needs, and its expected event is one of this rule's true positives (CI proves it matches). Run it on a lab VM, export the logs and turn the run into evidence:

```powershell
.\red\Invoke-RasdEmulation.ps1 -Test event_log_clearing -LabConfirmed
.\red\Export-LabTelemetry.ps1 -Since (Get-Date).AddHours(-1)
```

```bash
rasd evidence --results <results>/emulation-results.json --logs lab-export.jsonl
```

## Test locally
```bash
rasd test --filter T1070.001
rasd prove --filter T1070.001
rasd parity --filter T1070.001
rasd explain T1070.001_event_log_clearing --tp 1
```
