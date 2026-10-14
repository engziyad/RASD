# Scheduled Task Created With Suspicious Action

<!-- rasd:facts:start -->
| | |
|---|---|
| **ATT&CK** | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) Scheduled Task/Job: Scheduled Task (execution, persistence, privilege-escalation) |
| **Severity** | `medium` |
| **Maturity** | **SIEM-Ready** ([model](../../../docs/RASD_MATURITY_MODEL.md)) |
| **Engineering Score** | 100/100 · operational pending - [run the lab](../../../docs/OPERATIONAL_VALIDATION.md) |
| **Tests** | 19 true positive · 6 true negative · 7 technique mutations |
| **Proof** | 100% of rule mutants killed · fuzzer resistance 100% over 181 variants |
| **Parity** | KQL and SPL identical to the rule on 1772 events · Defender advanced hunting identical on the same events |
| **Public data** | fires on 10 of 11 public recordings of its behaviour · held-out: 6 of 6 · 16 alerts · 0 labelled false positive · [evidence](public_evidence.md) |
| **Rule** | [`rule.yml`](rule.yml) · [KQL](../../../queries/kql/T1053.005_schtasks_suspicious_creation.kql) · [SPL](../../../queries/spl/T1053.005_schtasks_suspicious_creation.spl) · [Defender](../../../queries/mde/T1053.005_schtasks_suspicious_creation.kql) |
| **Operations** | [triage](triage.md) · [response](response.md) · [closure](closure.md) · [tuning](tuning.yml) · [contract](contract.yml) |
| **Chain** | red: [scheduled_task_creation](../../../red/windows/scheduled_task_creation/) · DFIR: [lateral_movement](../../../dfir/playbooks/lateral_movement.md) · DFIR: [scheduled_task_persistence](../../../dfir/playbooks/scheduled_task_persistence.md) · purple: [T1053.005_scheduled_task](../../../purple/scenarios/T1053.005_scheduled_task.md) |
<!-- rasd:facts:end -->

## Telemetry required
Sysmon **EID 1** - the generated KQL and SPL read Sysmon. Security **4688** (with command-line auditing) works after remapping `NewProcessName` / `ParentProcessName` in `tools/mappings.yml`; it has no `OriginalFileName`, so the renamed-binary branch goes blind. Complement with Security **4698 (scheduled task created)**, which contains the full task XML, and the `Microsoft-Windows-TaskScheduler/Operational` log.

## How the detection works
The rule fires on `schtasks /create` **or** `/change` (a new task, or the action of an existing task hijacked) **and** an action that is suspicious on its own (`1 of susp_*`):

| Selection | Meaning |
|---|---|
| `susp_action` | `%TEMP%`, `%APPDATA%`, PowerShell, `cmd /c`, mshta, wscript, cscript, regsvr32, or a URL in the action |
| `susp_writable_path` | Any AppData, ProgramData, Users\Public, Windows\Temp or Downloads path - with `\` **or** `/` separators, because Windows accepts both |
| `susp_system_remote` | Remote creation as SYSTEM (`/s <host>` with `/ru SYSTEM` or `NT AUTHORITY\SYSTEM`, in any order and quoting) - a lateral-movement pattern |

The switch is matched as a switch (`/create` or `-create` surrounded by whitespace), not as text inside a path, and the binary is matched by path **or** `OriginalFileName`, so a renamed copy of schtasks.exe still fires. Legitimate vendor tasks pointing to `Program Files` do not match, which keeps the alert volume low enough for a SOC queue.

## Evasion & coverage gaps
- Tasks created through the COM API or WMI never spawn `schtasks.exe` - cover with **4698**. The PowerShell cmdlets are covered by [Scheduled Task Registered via PowerShell ScheduledTasks Cmdlets](../T1053.005_powershell_scheduled_task_creation/).
- Tasks created by writing XML directly to `C:\Windows\System32\Tasks` plus registry (`TaskCache`) - "hidden task" tradecraft.
- Benign path in the task, malicious content in the referenced script.

## False positives & tuning
IT automation scheduling PowerShell scripts, and Office Click-to-Run, whose `Integrator.exe` registers Office's update and telemetry tasks with `schtasks /Create /XML` files under `C:\ProgramData\Microsoft\ClickToRun` - the writable-path branch reads the whole command line, so every host where Office is installed or updated raises it (public data, [held-out evidence](public_evidence.md)). Allow-list by task name **and** script path, never by task name alone; the [tuning guide](tuning.yml) proposes a filter for the Click-to-Run case on its parent and folder.

Every tuning - applied, proposed or rejected - is recorded in [`tuning.yml`](tuning.yml). `rasd tune --filter T1053.005` measures each proposal before it is applied: how many attack variants it would hide against how many corpus alerts it would remove.

## Offensive validation
[`red/windows/scheduled_task_creation`](../../../red/windows/scheduled_task_creation/) produces exactly the telemetry this rule needs, and its expected event is one of this rule's true positives (CI proves it matches). Run it on a lab VM, export the logs and turn the run into evidence:

```powershell
.\red\Invoke-RasdEmulation.ps1 -Test scheduled_task_creation -LabConfirmed
.\red\Export-LabTelemetry.ps1 -Since (Get-Date).AddHours(-1)
```

```bash
rasd evidence --results <results>/emulation-results.json --logs lab-export.jsonl
```

## Test locally
```bash
rasd test --filter T1053.005
rasd prove --filter T1053.005
rasd parity --filter T1053.005
rasd explain T1053.005_schtasks_suspicious_creation --tp 1
```
