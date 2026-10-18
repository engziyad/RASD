# Release Roadmap

## v1.0: first public release (this release)
| Area | Delivered |
|---|---|
| Structure | Five pillars: `red/`, `detect/`, `dfir/`, `intel/`, `purple/` |
| Log sources | Windows: Sysmon (1, 10, 13), Security (1102, 4625, 4768, 4769, 4771), System (104, 7045). Linux: Sysmon for Linux (1). Web: access log, W3C or combined format. Each mapped to Sentinel and Splunk in `tools/mappings.yml` |
| Detect | Sigma rules with an offline engine, KQL / SPL conversion, true-positive and true-negative tests, contract v2 (risk model, L1/L2/IR actions, maturity), tuning guides, rule mutation proof, query parity, evasion fuzzer, RE2 lint, semantic diff, overlap, explain, doctor, ATT&CK coverage |
| Correlations | Sigma v2 correlation rules (`event_count`, `value_count`) in `detect/correlations/`: offline engine, SPL / KQL conversion, Splunk alerts that run once per window over exactly that window. Four detections: password spraying (T1110.003), Kerberoasting by volume (T1558.003, catching AES roasting), API authentication probing (T1595.003) and object-ID enumeration (T1190) |
| Correlation proof | `rasd correlate`: event-sequence scenarios, parameter mutation testing (threshold, window, group-by, count type, normalisation), aggregation parity of the generated SPL and KQL on scenarios and seeded random sequences for the rule and every mutant, and a verified burst guarantee (2T-1 always alerts) |
| Near misses | `rasd nearmiss`: traffic one field edit away from an alert, proven by engine-confirmed witnesses; boundary load per condition and whether a true negative pins it (a CI gate); correlation threshold headroom, with the single-event rules that caught a near miss |
| Red | 19 offensive tests defined by `test.yml` (Windows, Active Directory, web, Linux): 14 linked to a detection, 5 kept as measured gaps or posture checks. Generated documents, runners for PowerShell and Python, artifact collection and verified cleanup, streaming telemetry export (Windows, Sysmon for Linux, web access log), lab-run manifest with input hashes |
| Evidence | `rasd evidence`: lab results + telemetry + SIEM alerts → hashed evidence files, correlations bound to the run's own events; Operational Score |
| Public data | `rasd datasets`: files from Splunk Attack Data, OTRF Security-Datasets and EVTX-ATTACK-SAMPLES pinned to commits and SHA-256, replayed through every rule with every alert explained; reduced extracts re-checked in CI and fed to query parity; four rules and one correlation improved from what the replay showed ([results](PUBLIC_DATA_VALIDATION.md)) |
| DFIR | 14 playbooks with evidence tables, investigation queries, templates, investigation and timeline models |
| Intel | CTI-to-detection workflow and templates, technique / data-source / actor maps, worked analysis |
| Purple | Scenarios for every covered technique, generated validation, evidence and latency matrices |
| Operations | Replay with contract risk scoring, storylines (single-event and correlation alerts) and noise forecast; tuning impact analysis; telemetry doctor; benchmark |
| Governance | Maturity model enforced in CI, split Engineering / Operational Scores, GitHub templates, link checker, real PowerShell tests under pwsh |
| ATT&CK v19.2 | Primary mappings follow ATT&CK v19.2: the log-clearing detections are T1685.005 (Defense Impairment) and Defense Evasion tags became Stealth; legacy v18 aliases keep T1070.001 resolvable ([aliases](../intel/mappings/attack_v18_aliases.yml)) |
| Gaps closed | WinRM remote execution (T1021.006), crontab persistence (T1053.003), Unix shell execution (T1059.004), API authentication probing (T1595.003) and object-ID enumeration (T1190): each was a red test without a detection, and each red test's expected event or scenario now fires its detection in CI |

## v2.0: Reference on lab evidence (goal)
The aim of v2.0 is that every covered detection reaches the **Reference** maturity level on evidence, not on claims.

| Item | Done when |
|---|---|
| Lab evidence for every covered detection | `evidence.md` committed for all detections; Operational Score ≥ 80 each. Order and commands: [EVIDENCE_PLAN](EVIDENCE_PLAN.md) |
| SIEM results in evidence | Alert exports from Splunk and Sentinel passed to `rasd evidence` |
| SIEM replay of the public datasets | The Splunk Attack Data files indexed with their sourcetypes and the generated SPL run over them, each count compared with the engine's ([checklist](PUBLIC_DATA_VALIDATION.md#siem-replay-checklist)) |
| Next rules from public data | Rules for the behaviours public data showed and no rule reads yet: cron directory writes, netcat shells, NTLM sprays by workstation, explicit-credential sprays, local logon sprays, service ImagePath registry writes, LSASS dump command lines ([list](PUBLIC_DATA_VALIDATION.md#next-rules-from-public-data)) |
| Actor map re-checked | `intel/mappings/actors.yml` carries a `last_checked` date (done 2026-10-13) |
| Correlation evidence | The password spray, API probing and object-ID enumeration lab runs turned into `evidence.md` for each correlation |
| AD reconnaissance | Decoy-account rule (4662) validated by the `ldap_enumeration` test |
| Rule fixes found in review | Each needs a new public dataset run, because `results.json` records the rules that produced it: the PE name `sctasks.exe` for renamed copies of schtasks.exe; a word boundary before `Register-` / `Set-ScheduledTask` (an `Unregister-ScheduledTask` cleanup that names `$env:TEMP` fires today); mshtml `#135` called by ordinal without a script protocol; loopback shares written as `\\localhost\` or another 127.x address; the `Policies\Explorer\Run` and `RunOnceEx` keys; `Provider_Name` on the 1102 rule; shell options and sudo options before a script in the Linux shell rule; the schtasks action words matched in `/tr` only. Until then each is documented in its detection's README |
| Kerberoasting by volume | A red step that requests service tickets for five or more lab SPNs in one window, so `T1558.003_kerberoasting_volume` can be Validated (today no step names it) |
| Web token and upload abuse | Rules for the `jwt_testing` and `file_upload_testing` gaps, once the lab web server logs the fields they need (token rejection reason, upload file name) |
| Linux privilege-escalation recon | A rule or hunt for the `privilege_escalation_checks` gap, measured against a Linux administration baseline before it is enabled |

## After v2.0: new data domains

No rule is written for a domain before lab data for it exists in the repository. A rule that never ran against its log source cannot be tested, proven or tuned, so each domain enters in the same order: log source mapping in `tools/mappings.yml`, a recorded lab sample or a red test, then the rule with its tests.

| Domain | Log source | First detections planned | Lab data to collect first |
|---|---|---|---|
| Identity (Entra ID) | Sign-in and audit logs | Password spray on cloud accounts (T1110.003), MFA request flooding (T1621), credentials added to an application (T1098.001) | A free developer tenant with test accounts; sign-in and audit log export |
| Cloud control plane (AWS, Azure) | CloudTrail, Azure Activity | Logging stopped or changed (T1685.002), access keys created for another user (T1098.001), discovery bursts (T1580) | A lab account; CloudTrail and Activity log export |
| Email | Mailbox audit and message trace | Inbox rules forwarding mail outside the organisation (T1114.003) | A test mailbox in the developer tenant |
| WAF | ModSecurity audit log or a cloud WAF log | One client triggering many blocked rules in a short window (T1190) | ModSecurity in front of the lab web application |
| Network (NDR) | Zeek conn, dns and http logs | Fixed-interval beaconing (T1071.001), DNS tunnelling by volume (T1071.004) | Zeek on a lab span port, logs exported as JSONL |

Progress is visible at any time in the [validation matrix](../purple/validation_matrix.md) and [metrics](RASD_METRICS.md).
