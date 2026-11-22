# Analyst notes · Case 01 · runnervmhh3zg

Drafted by `rasd replay` from the logs only. Fill in only what you checked. A storyline is escalated, not closed from the queue, unless every alert in it is explained.

## Escalation to incident response

```text
Case:         case-01-runnervmhh3zg · runnervmhh3zg · 2026-11-22 17:23:19 → 17:25:30 UTC
Observed:     17:23:19 T1003.001 Suspicious Process Access to LSASS Memory
              17:23:29 T1003.001 Suspicious Process Access to LSASS Memory
              17:23:56 T1003.001 Suspicious Process Access to LSASS Memory
              17:23:56 T1003.001 Suspicious Process Access to LSASS Memory
              17:24:06 T1003.001 Suspicious Process Access to LSASS Memory
              17:24:16 T1003.001 Suspicious Process Access to LSASS Memory
              17:24:26 T1003.001 Suspicious Process Access to LSASS Memory
              17:24:36 T1003.001 Suspicious Process Access to LSASS Memory
              17:24:46 T1003.001 Suspicious Process Access to LSASS Memory
              17:24:53 T1021.006 Suspicious Child Process of a WinRM Session Host
              17:24:56 T1003.001 Suspicious Process Access to LSASS Memory
              17:24:56 T1685.005 Windows Event Log Clearing via Command Line
              17:24:56 T1685.005 Windows Event Log Cleared (System Event 104)
              17:24:59 T1685.005 Windows Event Log Cleared (System Event 104)
              17:24:59 T1552.001 Deception - Honey Credentials File Opened
              17:25:02 T1059.001 PowerShell Execution With Encoded Command
              17:25:05 T1547.001 Run Key Persistence Pointing to Suspicious Location
              17:25:06 T1003.001 Suspicious Process Access to LSASS Memory
              17:25:07 T1218.011 Rundll32 Proxy Execution From Suspicious Context
              17:25:16 T1003.001 Suspicious Process Access to LSASS Memory
              17:25:24 T1053.005 Scheduled Task Created With Suspicious Action
              17:25:26 T1053.005 Scheduled Task Registered via PowerShell ScheduledTasks Cmdlets
              17:25:26 T1003.001 Suspicious Process Access to LSASS Memory
              17:25:30 T1569.002 Suspicious Service Installation (PsExec-style / Command Services)
Who / where:  NT SERVICE\Splunkd, runnervmhh3zg\runneradmin, runneradmin, LocalSystem on runnervmhh3zg
Risk:         storyline 100/100 · highest alert 80 (T1552.001)
Escalated:    <the condition met, from the detection cards>
Preserved:    <what is saved, and where>
Containment:  none yet | <action taken, time UTC>
```

## Benign Positive

```text
Case:         case-01-runnervmhh3zg · runnervmhh3zg · 2026-11-22 17:23:19 → 17:25:30 UTC
Alerts:       24 alerts, 9 techniques on runnervmhh3zg (17:23:19 → 17:25:30 UTC)
Checked:      <the triage step from each detection card> -> <result>
Benign:       <the approved activity> - confirmed by <change record, owner or ticket>
Disposition:  Benign Positive
```

## False Positive

```text
Case:         case-01-runnervmhh3zg · runnervmhh3zg · 2026-11-22 17:23:19 → 17:25:30 UTC
Alerts:       24 alerts, 9 techniques on runnervmhh3zg (17:23:19 → 17:25:30 UTC)
Why not:      <the field that matched, and what it really was>
Disposition:  False Positive
Follow-up:    <events sent to detection engineering as true negatives | not yet>
```
