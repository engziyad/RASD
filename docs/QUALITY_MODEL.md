# RASD Quality Model

`tools/score.py` gives every detection two separate scores. The rule of both is the same: **every point comes from something a script can verify** in this repository - no reviewer opinion, no self-assessment. The live numbers are in [detect/quality/QUALITY.md](../detect/quality/QUALITY.md).

## Engineering Quality Score
Measures detection engineering completeness - whether the detection is built right.

| Area | Weight | Earned by |
|---|---:|---|
| Tests | 25% | 4+ true positives (30% of the area), 4+ true negatives (30%), and the rule mutation proof score (40%). Any failing test zeroes the area. |
| Telemetry Contract | 20% | Required events declared (6), every field the rule uses declared (8), telemetry risks rated (6) |
| False Positive Handling | 15% | Documented FP sources (5), TN volume (5), every `filter_*` proven by a TN event (5) |
| Evasion Awareness | 15% | 3+ blind spots (4), README evasion section (3), technique mutation tests passing (4), evasion-fuzzer resistance (4) |
| SIEM Portability | 10% | Converts to KQL (5) and SPL (5) **and** query parity proves each backend returns exactly what the rule returns |
| Response Playbook | 10% | Triage checks, escalation criteria, evidence list, containment steps, L1 / L2 / IR actions (2 each) |
| Documentation | 5% | README sections for telemetry, logic and false positives (3), a valid tuning guide (2) |

**Correlation detections** are scored on the same seven areas from what `rasd correlate` proves ([CORRELATIONS.md](CORRELATIONS.md)). Tests: base-rule true positives (20%) and true negatives (20%), scenarios that fire (10%) and stay silent (10%), and a proof score (40%) that is the lower of the base rule's mutation proof and the share of parameter mutants killed; a failing test or scenario zeroes the area. Evasion awareness counts the base rule's technique mutations (2) and the verified burst guarantee (2) in place of the 4 mutation points. SIEM portability needs, per backend, both the base filter parity and the aggregation parity.

## Operational Validation Score
Measures whether the detection was proven in a real lab telemetry flow. It is read only from the front matter of `detect/detections/<id>/evidence.md`, which `python rasd.py evidence` writes from a real run - with the SHA-256 of the results file, every telemetry export and every SIEM alert export.

| Area | Weight | Earned by |
|---|---:|---|
| Lab Evidence | 35% | The rule fired on telemetry exported from the lab, inside the emulation step's window |
| SIEM Result | 25% | The SIEM raised a matching alert in the window (alert export passed with `--siem-alerts`) |
| Detection Latency | 15% | Step start to SIEM alert: ≤ 60 s = 15, ≤ 5 min = 10, ≤ 15 min = 5. `evidence.md` also shows the parts: telemetry latency (step start → event logged) and SIEM pipeline delay (event → alert: forwarding, indexing and up to 5 minutes of schedule wait) |
| DFIR Evidence | 15% | The runner collected the test's DFIR artifacts and recorded their SHA-256 |
| Cleanup Verification | 10% | The test's cleanup script verified the host is clean (exit code 0) |

Without a lab run the score is **pending**, shown as such everywhere, and never estimated.

## Rules
- A detection does not get 100/100 without a real `evidence.md`: the Engineering Score can reach 100 on its own, the Operational Score cannot.
- A detection cannot be marked Validated or Reference without lab evidence ([maturity model](RASD_MATURITY_MODEL.md)).
- The weights are a published opinion about what matters, not a law. Change them in `tools/score.py` and `tools/evidence.py` and every table recomputes. The principle does not change: no points without verifiable evidence.

## What the scores are not
They do not measure how often a rule fires in production, its detection rate against a real adversary, or analyst time per alert. Those need production telemetry and belong in SOC metrics.
