# RASD Overview

**RASD: Resilient Adversary Signal Detection.** An attack-to-defense validation framework that turns adversary behaviour into tested detections, investigation workflows, CTI mappings and operational evidence.

> RASD does not stop at detection logic. Each technique is mapped across offensive validation, telemetry, detection, triage, response and intelligence context, with a place for measurable operational evidence that stays pending until a lab run is committed.

## The problem it answers

Most detection repositories stop at a rule file. Nobody can say whether the rule fires on the real attack, whether the SIEM query behaves like the rule, whether the alert is actionable, or whether anyone ever ran the attack to check. RASD answers each of those questions with something a script can verify.

| Question a CISO or auditor asks | Where RASD answers it |
|---|---|
| Does the rule catch the attack? | True-positive tests, mutation tests, the evasion fuzzer |
| Does it stay quiet on normal activity? | True-negative tests, filter-coverage gate, tuning impact analysis |
| Is every part of the rule actually needed and tested? | Rule mutation testing (`rasd prove`) |
| Does the rule logic hold for every possible value, not just the samples? | Exact automata (`rasd certify`): each rule compiled over every Unicode character, with an engine-confirmed event that fires it and the nearest one that does not |
| Does the query in Splunk / Sentinel do the same as the tested rule? | Query parity (`rasd parity`); aggregation parity for correlations (`rasd correlate`) |
| Can it see attacks no single event shows - a password spray, a burst of service tickets, one client probing many protected API paths? | Sigma correlation detections with scenarios, parameter mutants and a proven burst guarantee (`rasd correlate`) |
| Where will false positives come from? | Near-miss analysis (`rasd nearmiss`): traffic one field edit away from an alert, and threshold headroom |
| What does the analyst do when it fires? | Triage card, response card, DFIR playbook |
| Who uses this technique against organisations like ours? | Actor tradecraft map, CTI-to-detection reports |
| Was it ever proven in a real environment? | Offensive tests, telemetry export, `rasd evidence`, Operational Score |
| What can we not see? | Blind spots, coverage depth, measured gaps in the validation matrix |

## The five pillars

| Pillar | Folder | Purpose |
|---|---|---|
| RASD-Red | [`red/`](../red/) | Controlled offensive validation that produces measurable telemetry |
| RASD-Detect | [`detect/`](../detect/) | Detection engineering: rules, contracts, tests, SIEM queries, quality |
| RASD-DFIR | [`dfir/`](../dfir/) | Investigation playbooks, evidence, timelines, response |
| RASD-Intel | [`intel/`](../intel/) | CTI turned into detection opportunities and hunts |
| RASD-Purple | [`purple/`](../purple/) | Attack-to-defense validation across the whole chain |

## Workflow

```text
Red behavior generates telemetry.
Telemetry drives detection logic.
Detection triggers investigation.
Investigation produces evidence.
CTI gives context.
Purple validation measures the full chain.
```

## Two honest scores

- **Engineering Score**: is the detection built right? Tests, contract, false-positive handling, evasion awareness, SIEM portability, response, documentation. It can reach 100 inside the repository.
- **Operational Score**: was it proven in a real lab telemetry flow? Lab evidence, SIEM result, detection latency, DFIR evidence, cleanup. It stays **pending** until a real run is committed, and no detection reaches the *Validated* or *Reference* maturity level without it.

Start with [ATTACK_TO_DEFENSE_CHAIN.md](ATTACK_TO_DEFENSE_CHAIN.md), then [RASD_ARCHITECTURE.md](RASD_ARCHITECTURE.md).
