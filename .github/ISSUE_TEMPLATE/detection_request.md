---
name: Detection request
about: Ask for a new detection or coverage of a technique
title: "[Detection] <technique or behaviour>"
labels: detection
---

# Detection Request

## Behaviour
What should be detected, in one or two sentences.

## ATT&CK
Technique ID(s):

## Why it matters
Threat report, incident, or audit finding that motivates it (link if possible):

## Telemetry available
| Source | Event | Collected today? |
|---|---|---|
| | | yes / no / unknown |

## Example events
Paste sanitized events (no real hostnames, users or IPs):

```json
```

## Acceptance
- [ ] Red test in `red/` that produces the telemetry
- [ ] Detection with TP/TN tests, mutations, contract and tuning guide
- [ ] DFIR playbook, CTI mapping and purple scenario updated
