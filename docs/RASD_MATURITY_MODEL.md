# RASD Maturity Model

`tools/chain.py` computes each detection's level from the repository and fails CI when a contract's declared `maturity` is higher than what can be proven. Levels are cumulative: a detection holds a level only when it meets that level and every level below it.

## Level 1: Draft
Detection idea exists: a rule file in a valid detection folder.

## Level 2: Tested
Detection has TP/TN tests: at least 4 true positives and 4 true negatives, all passing.

## Level 3: Hardened
Detection has mutation tests and tuning guidance: technique mutations pass, the rule mutation proof score is 100%, the evasion fuzzer finds no unaccepted bypass, and a valid `tuning.yml` exists.

## Level 4: SIEM-Ready
Detection has triage, response, and deployable queries: triage and response cards exist, KQL and SPL are generated, and query parity is proven with zero divergences. SIEM-Ready means ready to deploy and validate - not validated: the word *Operational* is reserved for evidence from a real lab run (the Operational Score).

## Level 5: Validated
Detection has lab evidence from real telemetry: a valid `evidence.md` written by `rasd evidence` from a real lab run, recording that the rule fired.

## Level 6: Reference
Detection has offensive validation, telemetry contract, detection logic, DFIR playbook, CTI mapping, purple scenario, evidence, and both scores. It requires Validated, plus a red test that triggers it, a DFIR playbook, an actor mapping, a purple scenario, an Engineering Score of 100 and an Operational Score of at least 80.

## Correlation detections

Correlations hold the same levels, from what `rasd correlate` proves ([CORRELATIONS.md](CORRELATIONS.md)): **Tested** counts the base rule's true positives and negatives and requires every scenario to behave; **Hardened** requires the base rule's mutation tests, a base-rule proof of 100%, every parameter mutant killed, no fuzzer bypass and a tuning guide; **SIEM-Ready** requires the cards, the generated SPL and KQL, and both the base filter parity and the aggregation parity; **Validated** requires a correlation evidence file from a lab run in which the run's own events reached the threshold.

## Rule

A detection cannot be marked as Reference-level until it has lab evidence. The current level of every detection is in the [validation matrix](../purple/validation_matrix.md#maturity-per-detection).
