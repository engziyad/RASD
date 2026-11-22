# Analyst notes · Case 02 · ::ffff:127.0.0.1

Drafted by `rasd replay` from the logs only. Fill in only what you checked. A storyline is escalated, not closed from the queue, unless every alert in it is explained.

## Escalation to incident response

```text
Case:         case-02-ffff-127.0.0.1 · ::ffff:127.0.0.1 · 2026-11-22 17:17:54 → 17:17:57 UTC
Observed:     17:17:54 T1595.003 API Probing - One Client Rejected on Many Distinct Paths
              17:17:57 T1190 Object ID Enumeration - One Client Walking Single-Owner Objects
Other hosts:  17:24:53 runnervmhh3zg T1021.006 Suspicious Child Process of a WinRM Session Host
              17:25:30 runnervmhh3zg T1569.002 Suspicious Service Installation (PsExec-style / Command Services)
Who / where:  - on ::ffff:127.0.0.1
Risk:         storyline 18/100 · highest alert 55 (T1190)
Escalated:    <the condition met, from the detection cards>
Preserved:    <what is saved, and where>
Containment:  none yet | <action taken, time UTC>
```

## Benign Positive

```text
Case:         case-02-ffff-127.0.0.1 · ::ffff:127.0.0.1 · 2026-11-22 17:17:54 → 17:17:57 UTC
Alerts:       2 alerts, 2 techniques on ::ffff:127.0.0.1 (17:17:54 → 17:17:57 UTC)
Checked:      <the triage step from each detection card> -> <result>
Benign:       <the approved activity> - confirmed by <change record, owner or ticket>
Disposition:  Benign Positive
```

## False Positive

```text
Case:         case-02-ffff-127.0.0.1 · ::ffff:127.0.0.1 · 2026-11-22 17:17:54 → 17:17:57 UTC
Alerts:       2 alerts, 2 techniques on ::ffff:127.0.0.1 (17:17:54 → 17:17:57 UTC)
Why not:      <the field that matched, and what it really was>
Disposition:  False Positive
Follow-up:    <events sent to detection engineering as true negatives | not yet>
```
