# Release Roadmap

## v1.0 — Detection-as-Code lab (released)
Sigma rules with an offline engine, KQL / SPL conversion, true-positive and true-negative tests, detection contracts, generated triage and response cards, mutation tests, ATT&CK coverage, a quality score and a safe emulation script.

## v2.0 — RASD Attack-to-Defense Validation Framework (released)
| Area | Delivered |
|---|---|
| Structure | Five pillars: `red/`, `detect/`, `dfir/`, `intel/`, `purple/` |
| Red | 19 offensive tests defined by `test.yml` (Windows, Active Directory, web, Linux), generated documents, runners for PowerShell and Python, artifact collection and verified cleanup, telemetry exporter |
| Detect | Contract v2 (risk model, L1/L2/IR actions, maturity), tuning guides, rule mutation proof, query parity, evasion fuzzer, RE2 lint, semantic diff, overlap, explain, doctor |
| Evidence | `rasd evidence`: lab results + telemetry + SIEM alerts → hashed evidence files; Operational Validation Score |
| DFIR | 14 playbooks with evidence tables, investigation queries, templates, investigation and timeline models |
| Intel | CTI-to-detection workflow and templates, technique / data-source / actor maps, worked analysis |
| Purple | Scenarios for every covered technique, generated validation, evidence and latency matrices |
| Operations | Replay with contract risk scoring, storylines and noise forecast; tuning impact analysis |
| Governance | Maturity model enforced in CI, split Engineering / Operational scores, GitHub templates, link checker |

## v2.1 — Correlations, near misses and evidence-ready lab (this release)
| Area | Delivered |
|---|---|
| Correlations | Sigma v2 correlation rules (`event_count`, `value_count`) in `detect/correlations/`: offline engine, SPL / KQL conversion, Splunk alerts that run once per window over exactly that window. Two detections: password spraying (T1110.003, closing a declared gap) and Kerberoasting by volume (T1558.003, catching AES roasting) |
| Correlation proof | `rasd correlate`: event-sequence scenarios, parameter mutation testing (threshold, window, group-by, count type, normalisation), aggregation parity of the generated SPL and KQL on scenarios and seeded random sequences for the rule and every mutant, and a verified burst guarantee (2T-1 always alerts) |
| Near misses | `rasd nearmiss`: traffic one field edit away from an alert, proven by engine-confirmed witnesses; boundary load per condition and whether a true negative pins it (a CI gate); correlation threshold headroom, with the single-event rules that caught a near miss |
| Integration | Correlations in replay storylines, evidence (bound to the run's own events), doctor, benchmark, chain maturity and metrics, scores, coverage layer, role views, red tests (`correlations:` per step, sample scenario executed in CI) |
| Lab | Reviewer improvements merged and hardened: streaming telemetry export without field collisions, lab-run manifest with input hashes, alert export host from the alert itself, real PowerShell tests under pwsh |
| Accuracy | Telemetry doctor counts a field only over the events it belongs to; Kerberos and logon addresses normalised for grouping |

## v3.0 — Evidence-backed Operational Reference (goal)
The aim of v3.0 is that every covered detection reaches the **Reference** maturity level on evidence, not on claims.

| Item | Done when |
|---|---|
| Lab evidence for every covered detection | `evidence.md` committed for all detections; Operational Score ≥ 80 each |
| SIEM results in evidence | Alert exports from Splunk and Sentinel passed to `rasd evidence` |
| Actor map re-checked | `intel/mappings/actors.yml` carries a `last_checked` date |
| Web log source | Web / WAF mapping in `tools/mappings.yml`; rules for the web red tests' gaps |
| Linux log source | auditd / Sysmon for Linux mapping; rules for cron persistence, encoded shell, execution from /tmp |
| Correlation evidence | The password spray lab run turned into `detect/correlations/T1110.003_password_spray_burst/evidence.md` (correlation support itself shipped in v2.1) |
| AD reconnaissance | Decoy-account rule (4662) validated by the `ldap_enumeration` test |
| WinRM | Rule for suspicious children of `wsmprovhost.exe`, validated by `winrm_access_validation` |

Progress is visible at any time in the [validation matrix](../purple/validation_matrix.md) and [metrics](RASD_METRICS.md).
