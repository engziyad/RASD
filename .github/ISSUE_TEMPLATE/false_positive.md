---
name: False positive
about: A detection fired on benign activity
title: "[FP] <detection id>"
labels: false-positive
---

# False Positive Report

## Detection
Name:

## Environment
SIEM:
Data source:
Field mapping:

## Event Sample
Paste sanitized event:

```json
```

## Why It Is Benign
Explain:

## Suggested Tuning
Add filter or context:

Before a filter is merged it is added to `tuning.yml` as `proposed`, the event becomes a true-negative test, and `rasd tune` must show it hides no attack variant.
