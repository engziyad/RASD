# Executive Summary

RASD answers one question for every attack technique it covers: would we detect it, and can we prove it?

<!-- rasd:executive:start -->
| | |
|---|---|
| **Detections** | 22 (18 single-event rules, 4 correlations) across 17 ATT&CK techniques and 10 tactics |
| **Platforms** | Windows, Active Directory, Linux, web applications |
| **Proven in the repository** | 22 of 22 SIEM-Ready: tests, rule mutation proof, KQL and SPL parity, evasion fuzzing · Engineering Score 100/100 |
| **Replayed on public data** | 16/22 detections fire on the pinned public attack data that records their behaviour · 114 in-sample files from 3 sources (219 with the held-out files) · 253 alerts on the recorded attacks, 555 on the labs' own activity (each explained), 1 labelled false positive on these lab captures · held-out: 25 of 26 expectations met, in 23 of 105 files labelled before their first replay ([public data](PUBLIC_DATA_VALIDATION.md)) |
| **Behaviour proofs** | 81 variants of documented attacker behaviour over 16 detections: 37 proven for every event, 18 known gaps (each shown by an engine-confirmed event), 26 exclusions proven quiet ([certificates](CERTIFICATES.md)) |
| **Edit equivalence** | `rasd certify --equiv REF` compares every rule with its version at a git ref and proves the edit preserves every event's verdict, or shows the event it changes ([CERTIFY](CERTIFY.md#comparing-two-versions-of-a-rule)) |
| **Deception** | 7 decoys (2 account, 1 spn, 3 file, 1 service) read by 4 deception detections and touched by 3 red tests · inventory, rules, tests, red tests and the decoy host's configuration agree · 5 decoy classes planned ([DECEPTION](../docs/DECEPTION.md), [inventory](../deceive/)) |
| **Evidence survivability** | 94 detection-question pairs over 18 detections: 38 out of reach, 0 evident, 56 exposed to a sequence that raises no alert · 3 rules on anti-forensic traces would leave 0 exposed · 31 artifacts, 16 anti-forensic actions, documented behaviour pending lab runs ([TRACE](../docs/TRACE.md), [results](../dfir/trace/)) |
| **Evidence of absence** | 10 sensor proofs, 12 records that end one and 2 kinds of time off modelled · on the sample fleet (8 hosts, 2221 records): 99 detection-host pairs, 80 attested (76 by record sequence, 4 by rhythm), 5 fired, 14 unattested · 3 breaks in the record found · documented behaviour pending lab runs ([SILENCE](../docs/SILENCE.md), [results](../dfir/silence/)) |
| **The unseen route** | 16 behaviours over 6 stages, 23 ways around replayed through the engine (22 raise no alert) · on the sample fleet (8 hosts): 12 routes from an origin to a target, 6 unseen end to end and 6 seen on the way (6 of them on rules with no behaviour spec) · 1 change is the fewest after which every route is seen (by leg 3) · documented behaviour pending lab runs ([BLINDPATH](../docs/BLINDPATH.md), [results](../purple/blindpath/)) |
| **Detection health** | 5 watchdog searches in SPL and KQL over the 16 kinds of event the rules read, each row naming the detections it blinds; generated, not yet run on a live SIEM · on the sample (8 hosts, a baseline of 2794 events, then a day of 795): 4 detections blind, 13 degraded, 4 healthy, 1 with nothing to compare ([HEALTH](../docs/HEALTH.md), [watchdogs](../queries/health/README.md)) |
| **RASD-Agent's lane** | 19 candidate detections drafted by a language model and kept by the gates of `rasd grow`, reviewed by no person, and counted in no number of this page but this one; none reaches the core without a person's approval of its exact text ([GOVERNANCE](../docs/GOVERNANCE.md)) · of the 604 techniques and sub-techniques of ATT&CK v20.1 that are drafted on their own, 17 have a core detection, 397 are in the agent's queue and 171 are out of reach of the logs RASD reads ([GROW](../docs/GROW.md), [candidates](../detect/candidates/README.md)) |
| **Validated (lab evidence)** | 15 of 22 · Operational Score 56/100 · 15 of 15 evidence files are recomputed from the raw lab runs kept in the repository on every build (3 parts of 1 run): a rule edited until it no longer fires on its run loses its evidence ([lab runs](../purple/lab_runs/README.md)) |
| **Analyst guidance** | 22 of 22 with triage, response, closure and escalation notes · 17 DFIR playbooks |
| **Measured gaps** | 4 gaps without a detection (ldap_enumeration, privilege_escalation_checks, file_upload_testing, jwt_testing) · 1 posture check without a detection (security_headers_testing) |

**Status:** 15 of 22 detections Validated (lab evidence); the other 7 wait for a lab run ([evidence plan](EVIDENCE_PLAN.md)).

<sub>Counted by `tools/chain.py` on every build.</sub>
<!-- rasd:executive:end -->

## What it is

A detection repository built as a chain. Each technique is defined as a controlled lab attack with its expected telemetry, and ends as a tested Sigma rule with Splunk and Sentinel queries, triage and response notes, a DFIR playbook and a threat-intelligence mapping. Code checks every link on each change; nothing depends on someone remembering to review it.

## What is proven, and what is not

| Proven inside the repository | Needs a real lab run |
|---|---|
| The rule matches the attack and stays quiet on normal activity | The attack produces the event on a real host |
| Every part of the rule is needed: removing any value, field or branch fails a test | The log pipeline keeps the fields the rule reads |
| The generated Splunk and Sentinel queries return exactly what the rule returns, in RASD's own SPL / KQL interpreters | The SIEM raises the alert, and how long it takes |
| Renamed binaries and command-line tricks do not slip past the rule | The analyst gets the artifacts, and the host is clean afterwards |

The left column holds for every detection. The right column is what `rasd evidence` records from a lab run, with the SHA-256 of every input file. Until that run happens the Operational Score stays pending. It is never estimated.

## Why it matters to a security team

- A rule that drifts from its SIEM query, or loses a branch in an edit, fails CI before it reaches production.
- Noise is measured before deployment: replay and near-miss analysis show which normal activity sits one field away from an alert.
- Every alert arrives with first checks, escalation conditions, containment steps and closure notes written for that detection.
- Gaps are listed as gaps. Domains without data (cloud, email, network) are planned, not claimed.

## Where to look

| Question | Answer |
|---|---|
| Which attacks would we catch today? | [Executive matrix](../purple/executive_matrix.md) |
| What does it take to prove them? | [Evidence plan](EVIDENCE_PLAN.md) |
| How do we bring the detections into our SIEM? | [Enterprise adoption](ENTERPRISE_ADOPTION.md) |
| What comes next? | [Roadmap](RELEASE_ROADMAP.md) |

## Limits

- Lab evidence comes from an isolated lab. It proves the chain works end to end; it does not replace a test on your own telemetry.
- The rules read Sysmon for Windows and Linux, the Windows Security and System logs, and web access logs. A detection whose source is not collected is blind ([data source coverage](DATA_SOURCE_COVERAGE.md)).
- Correlation thresholds are starting points. Measure them against your own traffic with `rasd replay` and `rasd nearmiss` before alerting on them.
