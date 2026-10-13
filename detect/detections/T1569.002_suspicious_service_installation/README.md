# Suspicious Service Installation (PsExec-style / Command Services)

<!-- rasd:facts:start -->
| | |
|---|---|
| **ATT&CK** | [T1569.002](https://attack.mitre.org/techniques/T1569/002/) · execution, lateral-movement |
| **Severity** | `high` |
| **Maturity** | **SIEM-Ready** ([model](../../../docs/RASD_MATURITY_MODEL.md)) |
| **Engineering score** | 100/100 · operational pending - [run the lab](../../../docs/OPERATIONAL_VALIDATION.md) |
| **Tests** | 17 true positive · 5 true negative · 4 technique mutations |
| **Proof** | 100% of rule mutants killed · fuzzer resistance 100% over 61 variants |
| **Parity** | KQL and SPL identical to the rule on 308 events |
| **Rule** | [`rule.yml`](rule.yml) · [KQL](../../../queries/kql/T1569.002_suspicious_service_installation.kql) · [SPL](../../../queries/spl/T1569.002_suspicious_service_installation.spl) |
| **Operations** | [triage](triage.md) · [response](response.md) · [tuning](tuning.yml) · [contract](contract.yml) |
| **Chain** | red: [service_creation](../../../red/windows/service_creation/) · DFIR: [lateral_movement](../../../dfir/playbooks/lateral_movement.md) · DFIR: [service_installation](../../../dfir/playbooks/service_installation.md) · purple: [T1569.002_service_execution](../../../purple/scenarios/T1569.002_service_execution.md) |
<!-- rasd:facts:end -->

## Telemetry required
Windows **System log Event ID 7045** (Service Control Manager - new service installed). Enabled by default. Optionally Security **4697** if *Audit Security System Extension* is enabled.

## How the detection works
Most SMB lateral movement (PsExec, Impacket `psexec.py` / `smbexec.py`, CrackMapExec, many C2 `jump` commands) creates a service on the target. The rule matches **tool fingerprints** rather than one tool (`1 of susp_*`):

| Selection | Fingerprint |
|---|---|
| `susp_path` | A command interpreter (`%COMSPEC%`, `cmd /c`, `cmd.exe /Q /c`, PowerShell) or a share path (`\ADMIN$\`, `\\127.0.0.1\`) in the ImagePath |
| `susp_writable_path` | AppData, Users\Public, Windows\Temp or Downloads, with `\` or `/` separators |
| `susp_script` | A `.bat` / `.cmd` service binary - CreateProcess runs it through cmd.exe implicitly |
| `susp_name` | Default service names of PsExec (`PSEXESVC`), PAExec, RemCom, CSExec and Impacket smbexec (`BTOBTO`) |
| `susp_random_exe` | Impacket psexec's `%SystemRoot%\<8 random letters>.exe` |

Rule mutation testing marks two of the names as *equivalent* (default PsExec and smbexec also match another selection); they stay for attribution, with the reason recorded in `tests/mutations.yml`.

## Evasion & coverage gaps
- Service name and binary randomized + binary placed in `System32` (requires custom tooling).
- Modifying an **existing** service's `ImagePath` (`sc config`) - no 7045; cover with Sysmon EID 13 on `Services\*\ImagePath`.
- WMI / WinRM / DCOM lateral movement - different telemetry entirely.

## False positives & tuning
Administrators using Sysinternals PsExec. Correlate with change management and the source host (Security 4624 logon type 3 just before).

Every tuning - applied, proposed or rejected - is recorded in [`tuning.yml`](tuning.yml). `python rasd.py tune --filter T1569.002` measures each proposal before it is applied: how many attack variants it would hide against how many corpus alerts it would remove.

## Offensive validation
[`red/windows/service_creation`](../../../red/windows/service_creation/) produces exactly the telemetry this rule needs, and its expected event is one of this rule's true positives (CI proves it matches). Run it on a lab VM, export the logs and turn the run into evidence:

```powershell
.\red\Invoke-PurpleEmulation.ps1 -Test service_creation -LabConfirmed
.\red\Export-LabTelemetry.ps1 -Since (Get-Date).AddHours(-1)
```

```bash
python rasd.py evidence --results <results>/emulation-results.json --logs lab-export.jsonl
```

## Validate locally
```bash
python rasd.py test --filter T1569.002
python rasd.py prove --filter T1569.002
python rasd.py parity --filter T1569.002
python rasd.py explain T1569.002_suspicious_service_installation --tp 1
```
