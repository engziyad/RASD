<div align="center">

# RASD: Attack-to-Defense Validation Framework

<img src="docs/assets/banner.svg" alt="RASD - Attack-to-Defense Validation Framework" width="760">

**RASD // Offensive Validation • Detection Logic • Operational Evidence**

*Attack simulated. Signals captured. Logic tested. Response ready.*

[![Detection CI](https://github.com/engziyad/RASD/actions/workflows/detection-ci.yml/badge.svg)](https://github.com/engziyad/RASD/actions/workflows/detection-ci.yml)
![Backends](https://img.shields.io/badge/backends-KQL%20%7C%20SPL-87af87)
![ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-d7af87)
![License](https://img.shields.io/badge/license-MIT-bcbcbc)

<!-- rasd:status:start -->
![detections: 22](https://img.shields.io/badge/detections-22-87afaf)
![engineering: 100/100](https://img.shields.io/badge/engineering-100%2F100-87af87)
![operational: 56/100](https://img.shields.io/badge/operational-56%2F100-d7af87)
![public data: 16/22](https://img.shields.io/badge/public%20data-16%2F22-87afaf)
![validated: 15/22](https://img.shields.io/badge/validated-15%2F22-bcbcbc)

**Status:** 15 of 22 detections Validated (lab evidence); the other 7 wait for a lab run ([evidence plan](docs/EVIDENCE_PLAN.md)).
<!-- rasd:status:end -->

</div>

## What RASD is

**RASD (Resilient Adversary Signal Detection)** turns an attack technique into a detection that is proven at every step. The attack is run in a lab, its telemetry is captured, the rule is tested and mutated until no part of it is unproven, the SIEM query is shown to be the same rule, and the analyst gets the triage and response notes.

Nothing on this page is typed by hand that the repository can count: every number below is computed on each build, and a detection is called **Validated** only when it fired on a real attack step.

## 🧭 How it works

```text
 Attack step ─► Telemetry ─► Detection rule ─► KQL / SPL ─► Triage & response ─► Lab evidence
```

| | Link of the chain | What makes it more than a claim |
|:-:|---|---|
| 🔴 | **Attack** | Offensive tests that run only on a machine its owner marked as a lab, and clean up after themselves |
| 📡 | **Telemetry** | A contract per detection: the log source, the events and the fields the rule cannot work without |
| 🎯 | **Detection** | True and false positives, attacker mutations, an evasion fuzzer, and every rule compiled to exact automata |
| 🔁 | **SIEM query** | The generated KQL and SPL are parsed back and must return the rule's verdict on every event |
| 🧑‍💻 | **Triage and response** | Cards, closure and escalation notes, and a DFIR playbook for every technique |
| 🧪 | **Evidence** | Written only when the rule fired on telemetry bound to a real lab run, and recomputed from the raw run on every build |

## ✅ What is proven today

<!-- rasd:readme-metrics:start -->
| ✅ Proven by the build | |
|---|---|
| **Library** | 22 detections (18 single-event, 4 correlations) across 17 ATT&CK techniques |
| **Tests** | 403 cases · 640 mutations · 1621 evasion variants, 0 bypasses |
| **Rule logic** | 291/291 rule mutants killed or accepted · 22/22 rules as exact automata |
| **SIEM queries** | 16284 parity verdicts per backend, 0 divergences (offline model of KQL and SPL) |
| **Public attack data** | 16/22 detections fire on pinned public datasets |
| **Engineering Score** | 100/100 |

| 🧪 Proven in a lab | |
|---|---|
| **Validated** | 15 of 22 detections fired on a real attack step in a lab |
| **Evidence** | 15 of 15 evidence files are recomputed from the raw lab runs kept in the repository on every build (3 parts of 1 run): a rule edited until it no longer fires on its run loses its evidence ([lab runs](purple/lab_runs/README.md)) |
| **Operational Score** | 56/100 over 15 detections |
| **Live SIEM** | 0 of 15 evidence files carry an alert raised by a live SIEM |
| **Waiting** | 7 detections, each with the lab machine and step it needs ([evidence plan](docs/EVIDENCE_PLAN.md)) |

<sub>Counted by `tools/chain.py` on every build · [every number](docs/RASD_METRICS.md)</sub>
<!-- rasd:readme-metrics:end -->

## 🚀 Quick start

Requires Python 3.10+ and PyYAML.

```bash
git clone https://github.com/engziyad/RASD.git && cd RASD
python3 -m venv .venv && . .venv/bin/activate     # Windows: py -m venv .venv, then .venv\Scripts\activate
pip install -e .
rasd ci                  # everything the CI workflow proves, in order
rasd health --sample     # a day the log pipeline breaks, and the detections it blinds
rasd advise              # what to do next, and why that first
```

[Every command](docs/COMMANDS.md) · [run the lab](red/lab/README.md) · [take it into your SIEM](docs/ENTERPRISE_ADOPTION.md) · [الدليل بالعربي](docs/GUIDE_AR.md)

## 🗂️ Modules

| | Module | The question it answers | Open |
|:-:|---|---|---|
| 🔴 | **RASD-Red** | Can the technique be run safely, repeatably, and cleaned up? | [red/](red/) · [lab kit](red/lab/README.md) |
| 🎯 | **RASD-Detect** | Does the rule catch it in every form, and is the SIEM query the same rule? | [detect/](detect/) · [proofs](docs/PROOFS.md) |
| 🧮 | **Correlations** | What about attacks no single event shows? | [CORRELATIONS](docs/CORRELATIONS.md) |
| 🪤 | **RASD-Deceive** | Is the first touch of a decoy an alert? | [deceive/](deceive/) · [DECEPTION](docs/DECEPTION.md) |
| 🔬 | **RASD-DFIR** | What does the analyst do when it fires? | [dfir/](dfir/) |
| 🧾 | **RASD-Trace** | Can an intruder erase the evidence, and is the attempt seen? | [TRACE](docs/TRACE.md) |
| 🤫 | **RASD-Silence** | When a rule stayed quiet, does that prove nothing happened? | [SILENCE](docs/SILENCE.md) |
| 🕳️ | **RASD-Blindpath** | Can an intruder cross from host to host with no alert? | [BLINDPATH](docs/BLINDPATH.md) |
| 🩺 | **RASD-Health** | Is every detection still being fed, today? | [HEALTH](docs/HEALTH.md) · [watchdogs](queries/health/README.md) |
| 🧠 | **RASD-Intel** | Which technique should be covered next, and who uses it? | [intel/](intel/) |
| 🟣 | **RASD-Purple** | Did the whole chain hold in a lab? | [purple/](purple/) · [lab runs](purple/lab_runs/README.md) |
| 🤖 | **RASD-Agent** | What comes next, and what did the agent draft that a person still has to decide? | [AGENT](docs/AGENT.md) · [GOVERNANCE](docs/GOVERNANCE.md) |

## 📚 Documentation

| | Section | Pages |
|:-:|---|---|
| 🧭 | **Start** | [Overview](docs/RASD_OVERVIEW.md) · [Architecture](docs/RASD_ARCHITECTURE.md) · [What RASD proves](docs/PROOFS.md) · [Commands](docs/COMMANDS.md) · [Coverage and layout](docs/COVERAGE.md) · [Executive summary](docs/EXECUTIVE_SUMMARY.md) |
| 📏 | **Rules of the house** | [Maturity model](docs/RASD_MATURITY_MODEL.md) · [Quality model](docs/QUALITY_MODEL.md) · [Acceptance criteria](docs/DETECTION_ACCEPTANCE_CRITERIA.md) · [Writing detections](docs/WRITING_DETECTIONS.md) · [Sigma support](docs/SIGMA_SUPPORT.md) · [The chain](docs/ATTACK_TO_DEFENSE_CHAIN.md) |
| 🔐 | **Proofs** | [Certify](docs/CERTIFY.md) · [Certificates](docs/CERTIFICATES.md) · [Correlations](docs/CORRELATIONS.md) · [Public attack data](docs/PUBLIC_DATA_VALIDATION.md) |
| 🧪 | **Lab** | [Operational validation](docs/OPERATIONAL_VALIDATION.md) · [Evidence plan](docs/EVIDENCE_PLAN.md) · [Lab runs](purple/lab_runs/README.md) · [SIEM scorecard](docs/SIEM_VALIDATION_SCORECARD.md) |
| 🛰️ | **Operations** | [Health](docs/HEALTH.md) · [Silence](docs/SILENCE.md) · [Trace](docs/TRACE.md) · [Blindpath](docs/BLINDPATH.md) · [Deception](docs/DECEPTION.md) · [Enterprise adoption](docs/ENTERPRISE_ADOPTION.md) · [SIEM deployment](docs/SIEM_DEPLOYMENT_NOTES.md) |
| 🤖 | **Agent** | [Agent](docs/AGENT.md) · [The lane it grows](docs/GROW.md) · [Governance](docs/GOVERNANCE.md) · [The counsel](agent/ADVICE.md) · [Candidates](detect/candidates/README.md) |
| 📊 | **Numbers** | [Metrics](docs/RASD_METRICS.md) · [Data sources](docs/DATA_SOURCE_COVERAGE.md) · [Control evidence](docs/CONTROL_EVIDENCE.md) · [Role views](docs/views/) · [Detection backlog](intel/outputs/detection_backlog.md) |
| 🗺️ | **Project** | [Roadmap](docs/RELEASE_ROADMAP.md) · [Contributing](CONTRIBUTING.md) · [الدليل بالعربي](docs/GUIDE_AR.md) |

## 🛡️ Scope and safety

Offensive tests run only with an explicit lab confirmation, on disposable machines you own or on a hosted runner that exists for one run ([lab workflow](.github/workflows/lab-run.yml)), and a [lab guard](red/lab/README.md#lab-guard) checks the machine itself: a test refuses to run on any host its owner has not marked as a lab, so a script started by mistake on a work machine stops before it does anything. Credential access and Security-log clearing are opt-in and never run on a machine that is not yours, every artifact carries a run marker so cleanup can only touch what the test created, web tests refuse public targets, connect only to the address they checked and never follow a redirect, and the password-spray simulation cannot succeed by design and skips any account one more failure could lock. The lab Sysmon configuration is intentionally verbose for validation: do not deploy `red/lab/sysmon-rasd.xml` to production. Samples and replay data are synthetic; `purple/lab_runs` holds the raw files of lab runs made on machines that existed for the run; `datasets/extracts` holds reduced events from public attack datasets under their own licenses ([notice](datasets/NOTICE.md)); no production logs belong in this repository.

## License

[MIT](LICENSE)

<p align="center"><sub>By: @ZiyadSOC</sub></p>
