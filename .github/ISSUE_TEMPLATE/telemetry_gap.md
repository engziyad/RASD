---
name: Telemetry gap
about: A detection or red test is missing the events or fields it needs
title: "[Telemetry] <source / event>"
labels: telemetry
---

# Telemetry Gap

## Affected detections / red tests
-

## Missing data
| Source | Event | Field(s) | Symptom (absent, renamed, truncated) |
|---|---|---|---|
| | | | |

## How it was found
- [ ] `python rasd.py doctor <export>` output attached
- [ ] `python rasd.py evidence` reported MISSED
- [ ] Other:

## Proposed fix
Audit policy, Sysmon configuration, forwarding, or a field mapping in `tools/mappings.yml`:
