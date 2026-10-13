# Detection Acceptance Criteria

A detection is considered complete only when it includes:

| Criterion | Where | Enforced by |
|---|---|---|
| Detection logic | `rule.yml` | `validate.py` (metadata, UUID, tags, folder, condition, deep lint) |
| Telemetry contract | `contract.yml` | `validate.py` + `schemas/contract.schema.json` |
| Required fields | `contract.yml` `data_contract.required_fields` | every field the rule uses must be declared |
| True-positive tests | `tests/true_positive.jsonl` | `run_tests.py` (4+ for full score) |
| True-negative tests | `tests/true_negative.jsonl` | `run_tests.py`; every `filter_*` proven by a TN |
| Mutation tests | `tests/mutations.yml` | `mutation_test.py`; `prove.py` (no surviving rule mutant) |
| SPL output | `queries/spl/<id>.spl` | generated, drift-checked, parity-proven |
| KQL output | `queries/kql/<id>.kql` | generated, drift-checked, parity-proven |
| Triage guide | `triage.md` | generated from the contract |
| Response guide | `response.md` | generated from the contract (L1 / L2 / IR actions, evidence, containment) |
| Tuning guidance | `tuning.yml` | `validate.py` structure; `tune.py --check` (no proposed filter hides an attack variant) |
| ATT&CK mapping | `rule.yml` tags, `contract.yml` primary and related techniques | `validate.py` |
| Coverage depth | `contract.yml` `coverage_depth` | `validate.py` |
| Known blind spots | `contract.yml` `detection_logic.blind_spots` (2+) | `validate.py` |
| Evidence status | `evidence.md` (or *pending*) | `validate.py` format check; `chain.py` maturity |

A **correlation detection** meets the same criteria through its base rule, plus: event-sequence scenarios that fire and stay silent, every parameter mutant killed by a scenario, aggregation parity of its SPL and KQL, and a verified burst guarantee - all enforced by `correlate.py` ([CORRELATIONS.md](CORRELATIONS.md)).

Beyond the detection itself, the technique is complete only when the chain around it is: a red test, a DFIR playbook, a CTI mapping and a purple scenario (see [ATTACK_TO_DEFENSE_CHAIN.md](ATTACK_TO_DEFENSE_CHAIN.md)).

Scaffold a detection that already has every file and fails CI until each `TODO` is replaced:

```bash
python rasd.py new T1021.006 winrm_remote_shell
```
