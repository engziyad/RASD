# Security Audit Log Cleared (Event 1102)

<!-- rasd:facts:start -->
| | |
|---|---|
| **ATT&CK** | [T1685.005](https://attack.mitre.org/techniques/T1685/005/) Disable or Modify Tools: Clear Windows Event Logs (defense-impairment) |
| **Severity** | `high` |
| **Maturity** | **SIEM-Ready** ([model](../../../docs/RASD_MATURITY_MODEL.md)) |
| **Engineering Score** | 100/100 · operational pending - [run the lab](../../../docs/OPERATIONAL_VALIDATION.md) |
| **Tests** | 5 true positive · 4 true negative · 2 technique mutations |
| **Proof** | 100% of rule mutants killed · fuzzer resistance 100% over 4 variants |
| **Behaviour proof** | 1 of 1 variant proven for every event · no known gap ([certificate](../../../docs/CERTIFICATES.md#t1685005-security-audit-log-cleared-event-1102)) |
| **Parity** | KQL and SPL identical to the rule on 439 events (RASD's offline KQL / SPL model, not yet a live SIEM) |
| **Public data** | fires on 2 of 2 public recordings of its behaviour · held-out: 1 of 1 · 2 alerts · 0 labelled false positives · [evidence](public_evidence.md) |
| **Rule** | [`rule.yml`](rule.yml) · [KQL](../../../queries/kql/T1685.005_security_log_cleared.kql) · [SPL](../../../queries/spl/T1685.005_security_log_cleared.spl) |
| **Operations** | [triage](triage.md) · [response](response.md) · [closure](closure.md) · [tuning](tuning.yml) · [contract](contract.yml) |
| **Chain** | red: [event_log_clearing](../../../red/windows/event_log_clearing/) · DFIR: [event_log_clearing](../../../dfir/playbooks/event_log_clearing.md) · purple: [T1685.005_event_log_clearing](../../../purple/scenarios/T1685.005_event_log_clearing.md) |
<!-- rasd:facts:end -->

## Why this rule exists
Three rules cover log clearing from different angles:

| Rule | Proves |
|---|---|
| [Windows Event Log Clearing via Command Line](../T1685.005_event_log_clearing/) | Someone **ran** a clearing tool, and who |
| [Security Audit Log Cleared (Event 1102)](../T1685.005_security_log_cleared/) | The Security log **was** cleared |
| [Windows Event Log Cleared (System Event 104)](../T1685.005_system_log_cleared/) | Another log **was** cleared |

This rule is outcome-based: it fires whatever tool, GUI or API asked the Event Log service to clear the **Security** log.

## Telemetry required
Security **1102**, forwarded to the SIEM. Forwarding matters most here: the local copy is exactly what was destroyed.

## How the detection works
Outcome-based: Security **1102** is written by the Event Log service whenever it clears the Security log, whatever tool, GUI or API asked it to. The rule is a single event ID on purpose - there is no benign variant to filter, only maintenance windows to correlate in the SIEM. Unlike the 104 rule it does not yet require the provider (`Microsoft-Windows-Eventlog`), so a 1102 written by another provider would match too; the provider check is planned ([roadmap](../../../docs/RELEASE_ROADMAP.md)).

## Evasion & coverage gaps
- Stopping the EventLog service or tampering with forwarding **before** clearing. Monitor for gaps in log volume per host (heartbeat).
- Silencing the log without clearing it (Invoke-Phant0m killing the EventLog service threads, Mimikatz `event::drop` patching the service in memory), deleting individual records, or stopping the service and deleting the `.evtx` file writes no clear event.
- See [Windows Event Log Cleared (System Event 104)](../T1685.005_system_log_cleared/) for the logs this rule does not cover.

## False positives & tuning
Golden-image sealing and VDI build pipelines. Scope exceptions to known build hosts and maintenance windows, never by user alone.

Every tuning - applied, proposed or rejected - is recorded in [`tuning.yml`](tuning.yml). `rasd tune --filter T1685.005` measures each proposal before it is applied: how many attack variants it would hide against how many corpus alerts it would remove.

## Offensive validation
[`red/windows/event_log_clearing`](../../../red/windows/event_log_clearing/) is built to produce the telemetry this rule reads, and its expected event is one of this rule's true positives (CI proves it matches). Run it on a lab VM, export the logs and turn the run into evidence:

```powershell
.\red\Invoke-RasdEmulation.ps1 -Test event_log_clearing -LabConfirmed -IncludeSecurityLogClear
.\red\Export-LabTelemetry.ps1 -Since (Get-Date).AddHours(-1) -OutFile .\lab-export.jsonl
```

```bash
rasd evidence --results <results>/emulation-results.json --logs lab-export.jsonl
```

## Test locally
```bash
rasd test --filter T1685.005
rasd prove --filter T1685.005
rasd parity --filter T1685.005
rasd explain T1685.005_security_log_cleared --tp 1
```
