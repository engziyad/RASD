# Closure Note

Keep it short and factual: what was observed, what it was, and why it is closed. Record only what was actually checked - no actions or evidence that did not happen.

```text
Alert:        <detection id> on <host> at <time UTC>
Observed:     <what the telemetry showed, one or two lines>
Verified:     <what was checked: parent process, signer, change record, user confirmation>
Disposition:  Benign Positive (expected, authorized activity) | False Positive (the rule matched something it should not)
Tuning:       <none | tuning.yml proposal id>
```

Confirmed malicious activity is not closed from the queue: it is escalated to incident response with the evidence table and timeline attached.

Every detection also has this note already shaped for it, with its own first checks, known benign sources, tuning ids, escalation conditions and evidence list: `closure.md` next to its rule, for example [T1021.006_wsmprovhost_suspicious_child](../../detect/detections/T1021.006_wsmprovhost_suspicious_child/closure.md).

## Example

The alert below is from the [sample replay corpus](../../samples/replay/lab-day.jsonl). Only the `Observed` line comes from the telemetry; the `Verified` line shows what an analyst still has to check and record before closing.

```text
Alert:        T1569.002_suspicious_service_installation on SRV-APP02 at 2026-10-05 14:03 UTC
Observed:     System 7045: service PSEXESVC, ImagePath %SystemRoot%\PSEXESVC.exe, account LocalSystem.
Verified:     <change record id> covers PsExec use on SRV-APP02 in this window; <who confirmed, and how>;
              <source host and account of the network logon that installed it (4624 type 3 on SRV-APP02)>.
Disposition:  Benign Positive
Tuning:       none - correlate with change records in the SIEM (see tuning.yml, psexec_service_name rejected)
```
