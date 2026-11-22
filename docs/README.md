# RASD documentation

Every page, module and command of RASD, by the layer it belongs to. New here: read the [Overview](RASD_OVERVIEW.md), then the [status](../status/README.md) of every detection. Nothing was removed to make the front page short: every page is linked from here.

## How a detection moves through the layers

```text
 Attack step ─► Telemetry ─► Detection rule ─► KQL / SPL ─► Triage & response ─► Lab evidence ─► Verdict
```

| | Link of the chain | Layer | What makes it more than a claim |
|:-:|---|---|---|
| 🔴 | **Attack** | Foundation | Offensive tests that run only on a machine its owner marked as a lab, and clean up after themselves |
| 📡 | **Telemetry** | Foundation | A contract per detection: the log source, the events and the fields the rule cannot work without |
| 🎯 | **Detection** | Foundation, tested in Assurance | True and false positives, attacker mutations, an evasion fuzzer, and every rule compiled to exact automata |
| 🔁 | **SIEM query** | Assurance | The generated KQL and SPL are parsed back and must return the rule's verdict on every event |
| 🧑‍💻 | **Triage and response** | Foundation | Cards, closure and escalation notes, and a DFIR playbook for every technique |
| 🧪 | **Evidence** | Assurance | Written only when the rule fired on telemetry bound to a real lab run, and recomputed from the raw run on every build |
| 🧭 | **Verdict** | Decision | One record per detection: Verified, Partially Verified, Unverified, Failed, Blocked, Degraded, Stale or Unknown, with the reason and the next action ([status](../status/README.md)) |

## 🧱 Foundation: what a detection is made of

| | Module | The question it answers | Open |
|:-:|---|---|---|
| 🎯 | **RASD-Detect** | Is the rule written once, with its telemetry contract, tests, triage and response? | [detect/](../detect/) · [writing detections](WRITING_DETECTIONS.md) |
| 🧮 | **Correlations** | What about attacks no single event shows? | [CORRELATIONS](CORRELATIONS.md) |
| 🔴 | **RASD-Red** | Can the technique be run safely, repeatably, and cleaned up? | [red/](../red/) · [lab kit](../red/lab/README.md) |
| 🪤 | **RASD-Deceive** | Is the first touch of a decoy an alert? | [deceive/](../deceive/) · [DECEPTION](DECEPTION.md) |
| 🔬 | **RASD-DFIR** | What does the analyst do when it fires? | [dfir/](../dfir/) |
| 🧠 | **RASD-Intel** | Which technique should be covered next, and who uses it? | [intel/](../intel/) · [detection backlog](../intel/outputs/detection_backlog.md) |
| 🌱 | **RASD-Agent's lane** | Can the library grow without a person, and stay apart from the core until one reviews it? | [GROW](GROW.md) · [GOVERNANCE](GOVERNANCE.md) · [candidates](../detect/candidates/README.md) |

Rules of the house: [maturity model](RASD_MATURITY_MODEL.md) · [quality model](QUALITY_MODEL.md) · [acceptance criteria](DETECTION_ACCEPTANCE_CRITERIA.md) · [Sigma support](SIGMA_SUPPORT.md) · [the chain](ATTACK_TO_DEFENSE_CHAIN.md) · [coverage and layout](COVERAGE.md) · [data sources](DATA_SOURCE_COVERAGE.md)

## 🧪 Assurance: everything that tests it

| | Module | The question it answers | Open |
|:-:|---|---|---|
| 🔐 | **Proofs in code** | Does the rule catch the attack in every form, and is the SIEM query the same rule? | [PROOFS](PROOFS.md) · [CERTIFY](CERTIFY.md) · [certificates](CERTIFICATES.md) |
| 📼 | **Public attack data** | Does it fire on attacks other people recorded, and on files labelled before it saw them? | [PUBLIC_DATA_VALIDATION](PUBLIC_DATA_VALIDATION.md) · [datasets/](../datasets/) |
| 🟣 | **RASD-Purple** | Did the whole chain hold in a lab, with a live SIEM beside it? | [purple/](../purple/) · [lab runs](../purple/lab_runs/README.md) · [operational validation](OPERATIONAL_VALIDATION.md) · [evidence plan](EVIDENCE_PLAN.md) · [SIEM scorecard](SIEM_VALIDATION_SCORECARD.md) |
| 🩺 | **RASD-Health** | Is every detection still being fed, today? | [HEALTH](HEALTH.md) · [watchdogs](../queries/health/README.md) |
| 🧾 | **RASD-Trace** | Can an intruder erase the evidence, and is the attempt seen? | [TRACE](TRACE.md) |
| 🤫 | **RASD-Silence** | When a rule stayed quiet, does that prove nothing happened? | [SILENCE](SILENCE.md) |
| 🕳️ | **RASD-Blindpath** | Can an intruder cross from host to host with no alert? | [BLINDPATH](BLINDPATH.md) |

## 🧭 Decision: what is true, and what to do next

| | Page | What it says | Open |
|:-:|---|---|---|
| 📊 | **Status** | Every detection's verdict, what proves it stage by stage, the reason for every gap, the next action, and the contradictions checked between components; `rasd status` prints the same record | [status](../status/README.md) · [status.json](../status/status.json) |
| 🤖 | **The counsel** | RASD-Agent's ranked findings for the analyst, the engineer, the purple team and the executive, each with its evidence and next step; its lab-run findings read the status record | [ADVICE](../agent/ADVICE.md) · [AGENT](AGENT.md) |
| 🗂️ | **For a reader who decides** | The executive summary, the executive matrix, every number, and the control evidence for an audit | [executive summary](EXECUTIVE_SUMMARY.md) · [executive matrix](../purple/executive_matrix.md) · [metrics](RASD_METRICS.md) · [control evidence](CONTROL_EVIDENCE.md) · [role views](views/) |

## Taking it into your SIEM

[Enterprise adoption](ENTERPRISE_ADOPTION.md) · [SIEM deployment notes](SIEM_DEPLOYMENT_NOTES.md) · [every command](COMMANDS.md)

## The project

[Architecture](RASD_ARCHITECTURE.md) · [roadmap](RELEASE_ROADMAP.md) · [contributing](../CONTRIBUTING.md) · [الدليل بالعربي](GUIDE_AR.md)

<sub>RASD · Continuous Detection Assurance Framework</sub>
