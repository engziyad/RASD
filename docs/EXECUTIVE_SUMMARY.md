# Executive Summary

RASD answers one question for every attack technique it covers: would we detect it, and can we prove it?

<!-- rasd:executive:start -->
| | |
|---|---|
| **Detections** | 18 (14 single-event rules, 4 correlations) across 14 ATT&CK techniques and 9 tactics |
| **Platforms** | Windows, Active Directory, Linux, web applications |
| **Proven in the repository** | 18 of 18 SIEM-Ready: tests, rule mutation proof, KQL and SPL parity, evasion fuzzing · Engineering Score 100/100 |
| **Replayed on public data** | 16/18 detections fire on the pinned public attack data that records their behaviour · 114 in-sample files from 3 sources (219 with the held-out files) · 253 alerts on the recorded attacks, 555 on the labs' own activity (each explained), 1 labelled false positive on these lab captures · held-out: 25 of 26 expectations met, in 23 of 105 files labelled before their first replay ([public data](PUBLIC_DATA_VALIDATION.md)) |
| **Behaviour proofs** | 25 variants of documented attacker behaviour over 5 detections: 12 proven for every event, 12 known gaps (each shown by an engine-confirmed event), 1 exclusion proven quiet ([certificates](CERTIFICATES.md)) |
| **Validated (lab evidence)** | 0 of 18 · Operational Score pending |
| **Analyst guidance** | 18 of 18 with triage, response, closure and escalation notes · 14 DFIR playbooks |
| **Measured gaps** | 4 gaps without a detection (ldap_enumeration, privilege_escalation_checks, file_upload_testing, jwt_testing) · 1 posture check without a detection (security_headers_testing) |

**Status:** SIEM-Ready, not yet Validated: 18 of 18 detections are SIEM-Ready and 16 fire on public attack datasets, meeting 25 of 26 expectations in 23 of 105 held-out files ([public data](PUBLIC_DATA_VALIDATION.md)); none has lab evidence yet ([evidence plan](EVIDENCE_PLAN.md)).

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
