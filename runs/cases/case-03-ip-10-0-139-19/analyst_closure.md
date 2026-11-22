# Analyst notes · Case 03 · ip-10-0-139-19

Drafted by `rasd replay` from the logs only. Fill in only what you checked. A storyline is escalated, not closed from the queue, unless every alert in it is explained.

## Escalation to incident response

```text
Case:         case-03-ip-10-0-139-19 · ip-10-0-139-19 · 2026-11-22 17:17:43 → 17:20:47 UTC
Observed:     17:17:43 T1053.003 Crontab Installed From Standard Input or a File
              17:20:47 T1059.004 Linux Shell Executing Decoded Base64 or Code From a Temporary Directory
              17:20:47 T1059.004 Linux Shell Executing Decoded Base64 or Code From a Temporary Directory
Other hosts:  17:24:53 runnervmhh3zg T1021.006 Suspicious Child Process of a WinRM Session Host
              17:25:30 runnervmhh3zg T1569.002 Suspicious Service Installation (PsExec-style / Command Services)
Who / where:  runner on ip-10-0-139-19
Risk:         storyline 16/100 · highest alert 60 (T1059.004)
Escalated:    <the condition met, from the detection cards>
Preserved:    <what is saved, and where>
Containment:  none yet | <action taken, time UTC>
```

## Benign Positive

```text
Case:         case-03-ip-10-0-139-19 · ip-10-0-139-19 · 2026-11-22 17:17:43 → 17:20:47 UTC
Alerts:       3 alerts, 2 techniques on ip-10-0-139-19 (17:17:43 → 17:20:47 UTC)
Checked:      <the triage step from each detection card> -> <result>
Benign:       <the approved activity> - confirmed by <change record, owner or ticket>
Disposition:  Benign Positive
```

## False Positive

```text
Case:         case-03-ip-10-0-139-19 · ip-10-0-139-19 · 2026-11-22 17:17:43 → 17:20:47 UTC
Alerts:       3 alerts, 2 techniques on ip-10-0-139-19 (17:17:43 → 17:20:47 UTC)
Why not:      <the field that matched, and what it really was>
Disposition:  False Positive
Follow-up:    <events sent to detection engineering as true negatives | not yet>
```
