<div align="center">

# RASD — Attack-to-Defense Validation Framework

<img src="docs/assets/banner.svg" alt="RASD - Attack-to-Defense Validation Framework" width="760">

**RASD // Offensive Validation • Detection Logic • Operational Evidence**

*Attack simulated. Signals captured. Logic tested. Response ready.*

[![Detection CI](https://github.com/engziyad/detection-as-code-purple-lab/actions/workflows/detection-ci.yml/badge.svg)](https://github.com/engziyad/detection-as-code-purple-lab/actions/workflows/detection-ci.yml)
![Backends](https://img.shields.io/badge/backends-KQL%20%7C%20SPL-87af87)
![ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-d7af87)
![License](https://img.shields.io/badge/license-MIT-bcbcbc)

</div>

RASD is a cybersecurity validation framework that connects offensive security labs, detection engineering, DFIR playbooks, CTI mapping, and purple-team validation into one measurable workflow.

**RASD = Resilient Adversary Signal Detection** — an attack-to-defense validation framework built to transform adversary behavior into tested detections, investigation workflows, CTI mappings, and operational evidence.

> RASD does not stop at detection logic.
> Each technique is mapped across offensive validation, telemetry, detection, triage, response, intelligence context, and measurable operational evidence.

<!-- rasd:readme-metrics:start -->
| | |
|---|---|
| **Detections · techniques** | 13 detections (11 single-event, 2 correlations) across 9 ATT&CK techniques |
| **Offensive tests** | 19: 9 mapped to current detections (only these can raise the Operational Score) · 10 gap or posture tests reserved for future coverage |
| **Tests** | 182 cases · 296 mutations · 943 fuzzer variants (0 bypasses) |
| **Proof** | 159/159 rule mutants killed or accepted · 4396 parity verdicts per backend (0 divergences) |
| **Correlations** | 20 scenarios · 14/14 parameter mutants killed · 2560 aggregation parity runs (0 divergences) · burst guarantee verified |
| **Near misses** | 132 events one field edit away from an alert, on 8 boundaries (8 pinned by a true negative) · correlation headroom T1110.003 4, T1558.003 1 |
| **Engineering Quality Score** | 100/100 |
| **Operational Validation Score** | pending a real lab run |
| **Chain completeness** | 162/180 items ([validation matrix](purple/validation_matrix.md)) |

<sub>Counted by `tools/chain.py` on every build.</sub>
<!-- rasd:readme-metrics:end -->

## Core Pillars

| Pillar | Purpose |
|---|---|
| [RASD-Red](red/) | Controlled offensive validation |
| [RASD-Detect](detect/) | Detection engineering and SIEM logic |
| [RASD-DFIR](dfir/) | Investigation, evidence, and response |
| [RASD-Intel](intel/) | CTI to detection opportunities |
| [RASD-Purple](purple/) | Attack-to-defense validation |

## Workflow

```text
Red behavior generates telemetry.
Telemetry drives detection logic.
Detection triggers investigation.
Investigation produces evidence.
CTI gives context.
Purple validation measures the full chain.
```

```text
Adversary Behavior → Controlled Offensive Validation → Expected Telemetry → Detection Logic → SPL / KQL
→ Test Cases → Mutation Testing → DFIR Playbook → CTI Mapping → Purple Scenario → Operational Evidence → Metrics & Quality Score
```

## What RASD proves that a rule repository cannot

| Claim | How RASD proves it |
|---|---|
| The rule catches the attack | True-positive tests, hand-written technique mutations, and an **evasion fuzzer** that generates renamed binaries, forward-slash paths, parameter prefixes, hex/decimal encodings and ordinal exports - against a regression baseline |
| Every part of the rule is needed | **Rule mutation testing** (`rasd prove`): every value, field and branch of every rule is deleted in turn, and a test must fail each time. It found 45% of the original rule logic unproven by any test; today every mutant is killed |
| The SIEM query is the tested rule | **Query parity** (`rasd parity`): the generated KQL and SPL are parsed back and evaluated with each SIEM's own semantics on thousands of events. It found that Splunk silently dropped events with a missing field under `NOT`; the converter now reads those fields null-safely |
| Attacks no single event shows are caught | **Sigma correlation detections** (`rasd correlate`): a password spray and Kerberoasting by volume, as tested rules rather than hunts. Every threshold, window, group-by and normalisation is held in place by an event-sequence scenario (parameter mutation testing); the generated SPL and KQL aggregations are parsed back and must return the engine's exact alerts for the rule and every mutant; and each carries a **proven burst guarantee** - 9 or more accounts in 10 minutes always alert, whatever the window alignment |
| You know where false positives will come from | **Near-miss analysis** (`rasd nearmiss`): every event one field edit away from an alert, each proven by a witness the engine confirms, grouped by the condition holding it back; CI fails when a boundary carrying traffic has no true negative pinning it. For correlations, the headroom between the busiest quiet window and the threshold |
| It stays quiet on normal activity | True-negative tests, a filter-coverage gate, and **tuning impact analysis** (`rasd tune`) that measures every proposed filter: attack variants hidden versus corpus alerts removed |
| The analyst knows what to do | Triage and response cards generated from each detection's contract (L1 / L2 / IR actions, risk model, evidence, containment) and a DFIR playbook for every technique |
| The offensive test and the rule agree | Every red test's sample event **is** one of its detection's true positives, and CI proves it matches |
| It was proven in a real environment | `rasd evidence` joins a lab run, its telemetry export and optional SIEM alerts, and writes evidence only when the rule really fired on an event bound to that run (host or client address, time window, run marker) - with the SHA-256 of every input |
| Nothing is overstated | Maturity levels and both scores are computed; a contract cannot claim more than the repository proves. Without lab evidence a detection stops at **SIEM-Ready** (deployable, not validated), and the Operational Score stays **pending** until a real run is committed |

## Quick start

Requires Python 3.10+ and PyYAML.

```bash
pip install -r requirements.txt
python rasd.py ci                 # everything CI runs, in order
python rasd.py chain              # the 20-point attack-to-defense map per technique
python rasd.py correlate -v       # the correlation proofs, scenario by scenario and mutant by mutant
python rasd.py nearmiss           # traffic one field edit away from an alert; correlation headroom
python rasd.py replay samples/replay/lab-day.jsonl --assets samples/replay/assets.csv --users samples/replay/users.csv --html report.html
```

Real evidence, on an isolated Windows lab VM that forwards to Splunk ([lab kit](red/lab/README.md)):

```powershell
.\red\lab\Test-LabReadiness.ps1 -Fix                 # Sysmon live probe, audit policy, forwarder, connection

# Safe default: skips credential access (LSASS dump) and the Security-log clear
.\red\lab\Invoke-RasdLabRun.ps1 -LabConfirmed

# Full validation attempt for every Windows detection (disposable VM, snapshot first)
.\red\lab\Invoke-RasdLabRun.ps1 -LabConfirmed -IncludeCredentialAccess -IncludeSecurityLogClear -Spn <lab SPN> -UserList <lab accounts>
```

A run produces one workstation zip; Kerberoasting and the password spray also need the DC's export (`dc-export.jsonl`) and the SIEM part needs the Splunk alert export (`siem-alerts.csv`):

```bash
python rasd.py evidence --results emulation-results.json --logs lab-export.jsonl dc-export.jsonl --siem-alerts siem-alerts.csv
```

Logs from Elastic, Sentinel ASIM, Defender advanced hunting or Splunk CIM run through the same rules with a [telemetry profile](mappings/README.md): `--profile auto`.

## The `rasd` command

| Stage | Command | What it does |
|---|---|---|
| Author | `new` | Scaffold a detection that fails CI until every file is complete |
| Verify | `lint` | Rules, contracts, tuning guides, evidence files, deep static checks (RE2-safe regex, field names, unused selections) |
| | `test` · `mutate` | True-positive / true-negative samples; technique and case mutations |
| | `fuzz` | Automatic evasion variants against a regression baseline |
| | `prove` | Rule mutation testing: is every value, field and branch proven by a test? |
| | `parity` | The generated KQL and SPL return exactly what the tested rule returns |
| | `correlate` | Sigma correlations: scenarios, parameter mutants, aggregation parity, burst guarantee; `--logs` finds correlation alerts in an export |
| | `nearmiss` | Events one field edit away from an alert, the condition holding them back and the true negative pinning it; correlation threshold headroom |
| | `tune` | Security cost and noise benefit of every tuning |
| | `diff` · `overlap` | Events that change verdict against a git ref; detections that co-fire |
| Understand | `explain` | Why a rule matched (or did not) an event, field by field |
| | `score` | Engineering Quality Score and Operational Validation Score |
| Deploy | `build` · `convert` | KQL + SPL for rules and correlations, cards, views, coverage, scores, banner, chain outputs |
| | `doctor` | Is a log export ready for the rules: READY / DEGRADED / BLIND per rule; `--profile` reads ECS, CIM, ASIM or Defender exports |
| | `profiles` | Which telemetry profile fits an export, and which log sources each profile carries |
| | `splunk` | The detections as a Splunk app: one scheduled alert per rule and per correlation (once per window), indexes, forwarder inputs, the alert export for evidence |
| Operate | `red` | Validate and render every offensive test from its test.yml |
| | `replay` | Run every rule and correlation over logs: risk-ranked alerts, noise forecast, attack storylines |
| | `benchmark` | Events per second through rules and correlations, peak memory, slowest rule and regex - on an export or on N synthetic events; `--stream` keeps memory flat at any size |
| | `evidence` | Turn a real lab run into verifiable evidence (FIRED / MISSED), for rules and correlations |
| | `chain` · `links` | The completeness map, maturity, matrices and metrics; every Markdown link resolves |
| All | `ci` | Everything the pipeline runs |

## Coverage

What the repository detects today, and what it only exercises. Detections are counted from `detect/detections` and `detect/correlations`; red tests without a detection are measured gaps, not coverage.

| Area | Status | What exists |
|---|---|---|
| Windows process activity (Sysmon 1) | Covered | PowerShell encoded commands, scheduled tasks (schtasks and cmdlets), rundll32 proxy execution, wevtutil log clearing |
| Windows process access (Sysmon 10) | Covered | LSASS memory access |
| Windows registry (Sysmon 13) | Covered | Run / RunOnce persistence |
| Windows Security log | Covered | Security log cleared (1102), RC4 Kerberos service tickets (4769); wrong-password failures (4771, 4625) and service tickets of any encryption (4769) counted by the correlations |
| Windows System log | Covered | Other logs cleared (104), suspicious service installation (7045) |
| Active Directory | Partial | Kerberoasting (RC4 rule + encryption-agnostic volume correlation); password spray (correlation, validated by its red test's scenario); LDAP enumeration and WinRM as red tests only |
| Web applications | Red tests only | API auth, IDOR, JWT, file upload, security headers - no web detection yet |
| Linux | Red tests only | Cron persistence, shell patterns, privilege-escalation recon - no Linux detection yet |
| Cloud (Entra ID, AWS, Azure) | Not covered | - |
| Email | Not covered | - |
| WAF / NDR | Not covered | - |

## Repository layout

```text
RASD
├── red/        → Offensive Validation      19 tests: Windows, Active Directory, web, Linux
├── detect/     → Detection Engineering     detections, correlations, coverage, quality, evasion baseline
├── dfir/       → Investigation & Response  playbooks, queries, templates, models
├── intel/      → CTI to Detection          templates, technique and actor maps, analyses
├── purple/     → Attack-to-Defense         scenarios, validation / evidence / latency matrices
├── mappings/   → Telemetry profiles: ECS, CIM, ASIM, Defender → rule field names
├── docs/       → Architecture, metrics, maturity, governance
├── tools/      → Automation, scoring, validation, generation
├── schemas/    → Contract, mutation and tuning schemas
├── queries/    → SPL / KQL / Hunts / Splunk app
├── tests/      → Unit and framework tests
└── .github/    → CI, issue templates, PR template
```

## Documentation

| | |
|---|---|
| [RASD_OVERVIEW](docs/RASD_OVERVIEW.md) · [RASD_ARCHITECTURE](docs/RASD_ARCHITECTURE.md) | What RASD is and how it is built |
| [ATTACK_TO_DEFENSE_CHAIN](docs/ATTACK_TO_DEFENSE_CHAIN.md) | Every link of the chain and the check that enforces it |
| [RASD_MATURITY_MODEL](docs/RASD_MATURITY_MODEL.md) · [QUALITY_MODEL](docs/QUALITY_MODEL.md) | Maturity levels; Engineering and Operational scores |
| [DETECTION_ACCEPTANCE_CRITERIA](docs/DETECTION_ACCEPTANCE_CRITERIA.md) · [WRITING_DETECTIONS](docs/WRITING_DETECTIONS.md) | When a detection is complete; how to write one |
| [CORRELATIONS](docs/CORRELATIONS.md) | Correlation detections: format, semantics, scenarios, proofs, burst guarantee, SIEM scheduling |
| [OPERATIONAL_VALIDATION](docs/OPERATIONAL_VALIDATION.md) · [SIEM_DEPLOYMENT_NOTES](docs/SIEM_DEPLOYMENT_NOTES.md) | Lab runs and evidence; deploying to Sentinel and Splunk |
| [RASD_METRICS](docs/RASD_METRICS.md) · [DATA_SOURCE_COVERAGE](docs/DATA_SOURCE_COVERAGE.md) | Counted metrics; telemetry dependencies |
| [CONTROL_EVIDENCE](docs/CONTROL_EVIDENCE.md) · [role views](docs/views/) | Evidence for audit; SOC, IR, GRC and purple-team views |
| [RELEASE_ROADMAP](docs/RELEASE_ROADMAP.md) | v2.1 (this release) and v3.0: Evidence-backed Operational Reference |
| [GUIDE_AR](docs/GUIDE_AR.md) | الدليل الكامل بالعربي |

## Scope and safety

Offensive tests run only with an explicit lab confirmation, on disposable machines you own. Credential access and Security-log clearing are opt-in, every artifact carries a run marker so cleanup can only touch what the test created, web tests refuse public targets, and the password-spray simulation cannot succeed by design and skips any account one more failure could lock. The lab Sysmon configuration is intentionally verbose for validation: do not deploy `red/lab/sysmon-rasd.xml` to production. Samples and replay data are synthetic; no production logs belong in this repository.

## License

[MIT](LICENSE)

<p align="center"><sub>By: @ZiyadSOC</sub></p>
