# Security Audit Log Cleared (Event 1102)

<!-- rasd:facts:start -->
| | |
|---|---|
| **ATT&CK** | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) · defense-evasion |
| **Severity** | `high` |
| **Maturity** | **SIEM-Ready** ([model](../../../docs/RASD_MATURITY_MODEL.md)) |
| **Engineering score** | 100/100 · operational pending - [run the lab](../../../docs/OPERATIONAL_VALIDATION.md) |
| **Tests** | 5 true positive · 4 true negative · 2 technique mutations |
| **Proof** | 100% of rule mutants killed · fuzzer resistance 100% over 4 variants |
| **Parity** | KQL and SPL identical to the rule on 133 events |
| **Rule** | [`rule.yml`](rule.yml) · [KQL](../../../queries/kql/T1070.001_security_log_cleared.kql) · [SPL](../../../queries/spl/T1070.001_security_log_cleared.spl) |
| **Operations** | [triage](triage.md) · [response](response.md) · [tuning](tuning.yml) · [contract](contract.yml) |
| **Chain** | red: [event_log_clearing](../../../red/windows/event_log_clearing/) · DFIR: [event_log_clearing](../../../dfir/playbooks/event_log_clearing.md) · purple: [T1070.001_event_log_clearing](../../../purple/scenarios/T1070.001_event_log_clearing.md) |
<!-- rasd:facts:end -->

## Why this rule exists
Three rules cover log clearing from different angles:

| Rule | Proves |
|---|---|
| [Command-line clearing](../T1070.001_event_log_clearing/) | Someone **ran** a clearing tool, and who |
| [Security 1102](../T1070.001_security_log_cleared/) | The Security log **was** cleared |
| [System 104](../T1070.001_system_log_cleared/) | Another log **was** cleared |

This rule is outcome-based: it fires whatever tool, GUI or API was used, and covers the **Security** log.

## Telemetry required
Security **1102**, forwarded to the SIEM. Forwarding matters most here: the local copy is exactly what was destroyed.

## How the detection works
Outcome-based: Security **1102** is written by the Event Log service whenever the Security log is cleared, whatever tool, GUI or API did it. The rule is a single event ID on purpose - there is no benign variant to filter, only maintenance windows to correlate in the SIEM.

## Evasion & coverage gaps
- Stopping the EventLog service or tampering with forwarding **before** clearing. Monitor for gaps in log volume per host (heartbeat).
- Selective deletion of individual events (e.g. thread suspension of the EventLog service) leaves no clear event.
- See [System 104](../T1070.001_system_log_cleared/) for the logs this rule does not cover.

## False positives & tuning
Golden-image sealing and VDI build pipelines. Scope exceptions to known build hosts and maintenance windows, never by user alone.

Every tuning - applied, proposed or rejected - is recorded in [`tuning.yml`](tuning.yml). `python rasd.py tune --filter T1070.001` measures each proposal before it is applied: how many attack variants it would hide against how many corpus alerts it would remove.

## Offensive validation
[`red/windows/event_log_clearing`](../../../red/windows/event_log_clearing/) produces exactly the telemetry this rule needs, and its expected event is one of this rule's true positives (CI proves it matches). Run it on a lab VM, export the logs and turn the run into evidence:

```powershell
.\red\Invoke-PurpleEmulation.ps1 -Test event_log_clearing -LabConfirmed -IncludeSecurityLogClear
.\red\Export-LabTelemetry.ps1 -Since (Get-Date).AddHours(-1)
```

```bash
python rasd.py evidence --results <results>/emulation-results.json --logs lab-export.jsonl
```

## Validate locally
```bash
python rasd.py test --filter T1070.001
python rasd.py prove --filter T1070.001
python rasd.py parity --filter T1070.001
python rasd.py explain T1070.001_security_log_cleared --tp 1
```
