# Scheduled Task Registered via PowerShell ScheduledTasks Cmdlets

<!-- rasd:facts:start -->
| | |
|---|---|
| **ATT&CK** | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) · persistence, execution, privilege-escalation |
| **Severity** | `medium` |
| **Maturity** | **SIEM-Ready** ([model](../../../docs/RASD_MATURITY_MODEL.md)) |
| **Engineering score** | 100/100 · operational pending - [run the lab](../../../docs/OPERATIONAL_VALIDATION.md) |
| **Tests** | 14 true positive · 6 true negative · 3 technique mutations |
| **Proof** | 100% of rule mutants killed · fuzzer resistance 100% over 158 variants |
| **Parity** | KQL and SPL identical to the rule on 659 events |
| **Rule** | [`rule.yml`](rule.yml) · [KQL](../../../queries/kql/T1053.005_powershell_scheduled_task_creation.kql) · [SPL](../../../queries/spl/T1053.005_powershell_scheduled_task_creation.spl) |
| **Operations** | [triage](triage.md) · [response](response.md) · [tuning](tuning.yml) · [contract](contract.yml) |
| **Chain** | red: [scheduled_task_creation](../../../red/windows/scheduled_task_creation/) · DFIR: [lateral_movement](../../../dfir/playbooks/lateral_movement.md) · DFIR: [scheduled_task_persistence](../../../dfir/playbooks/scheduled_task_persistence.md) · DFIR: [suspicious_powershell](../../../dfir/playbooks/suspicious_powershell.md) · purple: [T1053.005_scheduled_task](../../../purple/scenarios/T1053.005_scheduled_task.md) |
<!-- rasd:facts:end -->

## Why this rule exists
The [schtasks rule](../T1053.005_schtasks_suspicious_creation/) only sees `schtasks.exe`. Tasks registered with the PowerShell ScheduledTasks module never spawn it. This rule closes that gap for command-line usage, which deepens T1053.005 coverage instead of overloading one rule.

## Telemetry required
Sysmon **EID 1** - the generated KQL and SPL read Sysmon. Security **4688** (with command-line auditing) works after remapping `NewProcessName` / `ParentProcessName` in `tools/mappings.yml`; it has no `OriginalFileName`, so the renamed-binary branch goes blind. For cmdlets executed inside script files, enable **Script Block Logging (4104)**: they never appear on a process command line.

## How the detection works
`Register-ScheduledTask` alone is common in admin scripts, so it must be combined with **one** suspicious indicator (`1 of susp_*`). `Set-ScheduledTask` is covered too: rewriting the action of an existing task is quieter than creating a new one.

| Selection | Meaning |
|---|---|
| `susp_action` | The task action is built inline with `New-ScheduledTaskAction` (with `-Execute` or positionally) - typical of one-liner persistence |
| `susp_payload` | `$env:TEMP`, `$env:APPDATA` or a URL on the command line |
| `susp_payload_path` | Any AppData, ProgramData, Users\Public, Windows\Temp or Downloads path, with `\` or `/` separators |

Registering a task from a vendor XML definition in Program Files does not match, as the true-negative tests prove.

## Evasion & coverage gaps
- Cmdlets inside a `.ps1` file: only 4104 sees them.
- COM API (`Schedule.Service`) from VBScript, JScript or .NET.
- Base64-encoded commands: covered by [T1059.001](../T1059.001_powershell_encoded_command/), not here.

## False positives & tuning
Login scripts and configuration management that register tasks inline. Allow-list by parent process and script path, and add each allow-listed case as a true-negative test first.

Every tuning - applied, proposed or rejected - is recorded in [`tuning.yml`](tuning.yml). `python rasd.py tune --filter T1053.005` measures each proposal before it is applied: how many attack variants it would hide against how many corpus alerts it would remove.

## Offensive validation
[`red/windows/scheduled_task_creation`](../../../red/windows/scheduled_task_creation/) produces exactly the telemetry this rule needs, and its expected event is one of this rule's true positives (CI proves it matches). Run it on a lab VM, export the logs and turn the run into evidence:

```powershell
.\red\Invoke-PurpleEmulation.ps1 -Test scheduled_task_creation -LabConfirmed
.\red\Export-LabTelemetry.ps1 -Since (Get-Date).AddHours(-1)
```

```bash
python rasd.py evidence --results <results>/emulation-results.json --logs lab-export.jsonl
```

## Validate locally
```bash
python rasd.py test --filter T1053.005
python rasd.py prove --filter T1053.005
python rasd.py parity --filter T1053.005
python rasd.py explain T1053.005_powershell_scheduled_task_creation --tp 1
```
