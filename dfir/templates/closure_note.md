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

```text
Alert:        T1569.002_suspicious_service_installation on SRV-APP02 at 2026-10-05 14:03 UTC
Observed:     PSEXESVC installed from 10.20.30.21 (admin jump host) by CORP\it.admin.
Verified:     Change CHG-0000 covers PsExec patching on SRV-APP02 in this window; admin confirmed.
Disposition:  Benign Positive
Tuning:       none - correlate with change records in the SIEM (see tuning.yml, psexec_service_name rejected)
```
