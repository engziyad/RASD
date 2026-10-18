# Control Evidence

For auditors and GRC: what RASD can show as evidence that a detection control exists, works and is maintained - and where each artifact lives.

| Control objective | Evidence | Location | How it stays current |
|---|---|---|---|
| A detection exists for the technique | Rule, contract, ATT&CK mapping | `detect/detections/<id>/` | Lint in CI on every change |
| It detects the attack | True-positive tests, technique mutations, fuzzer resistance | `tests/`, `rasd fuzz` | CI runs them on every change |
| Every part of it is tested | Rule mutation proof score | `rasd prove` | CI fails on any surviving mutant |
| It does not alert on normal activity | True-negative tests, filter-coverage gate | `tests/true_negative.jsonl` | CI |
| The deployed query is the tested logic | Query parity verdicts | `rasd parity` | CI fails on any divergence |
| Tuning does not blind it | Tuning guide with measured impact | `tuning.yml`, `rasd tune` | CI fails on a proposed filter that hides an attack variant |
| Analysts know what to do | Triage and response cards, closure and escalation notes, DFIR playbooks | `triage.md`, `response.md`, `closure.md`, `dfir/playbooks/` | Generated from the contract; links checked in CI |
| It can be proven in a real environment | Lab evidence with input hashes | `evidence.md` (none yet: no lab run is committed) | Written only by `rasd evidence` from a real run |
| Limitations are known | Blind spots, coverage depth, measured gaps | `contract.yml`, [validation matrix](../purple/validation_matrix.md) | Contract checked in CI; matrix generated |
| Changes are reviewed | Pull request template and CI history | `.github/` | Every merge |

The role view for this audience is [docs/views/GRC_Audit.md](views/GRC_Audit.md); the counted metrics are in [RASD_METRICS.md](RASD_METRICS.md).

## Evidence types per detection
Every contract lists its `governance.evidence_type` (detection rule, test results, generated SIEM query, ATT&CK mapping, response playbook). Lab evidence is added by the existence of a valid `evidence.md`, never by editing the contract.
