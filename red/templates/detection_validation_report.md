# Detection Validation Report

Produced from `python rasd.py evidence` output for one lab run.

| Detection | Expected from step | Verdict | Telemetry latency | SIEM latency | Operational score |
|---|---|---|---|---|---|
| | | FIRED / MISSED | | | |

## Missed detections
For each MISSED detection, the cause found, in this order of checks:
1. Was the event logged on the host? (audit policy, Sysmon configuration)
2. Was it exported / forwarded? (export window, forwarding)
3. Did its fields arrive intact? (`rasd doctor` on the export)
4. Does the rule cover this variant? (new true positive, rule change, re-run)

## Follow-up
| Item | Owner | Tracking |
|---|---|---|
| | | |
