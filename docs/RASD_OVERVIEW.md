# RASD Overview

**RASD: Resilient Adversary Signal Detection.** A continuous detection assurance framework: one record of every detection's state, from its rule and the telemetry it needs to the attack step that fired it in a lab and the alert a live SIEM raised, with the reason for every gap and the next action.

> A detection is not working because its tests pass. RASD calls a detection **Verified** only when its attack step fired in a lab and a live SIEM raised the alert, and it names everything short of that with the reason the lab recorded.

## The problem it answers

Most detection repositories stop at a rule file. Nobody can say whether the rule fires on the real attack, whether the SIEM query behaves like the rule, whether the alert is actionable, or whether anyone ever ran the attack to check. RASD answers each of those questions with something a script can verify.

## The five questions

A head of cyber defence asks five questions of a detection library. RASD answers each from the record every build writes, and `rasd status` prints the same answers ([status](../status/README.md)).

| Question | Where RASD answers it |
|---|---|
| What can we detect? | The library: rules and correlations, each with its telemetry contract, triage and response |
| What proves it? | The code checks, which can fail a detection, and the lab run with a live SIEM beside it, which can verify one |
| Is it still working? | RASD-Health on production telemetry (`rasd status --health`), and the freshness of the lab evidence |
| Where are the gaps, and why? | `rasd status --gaps`: every detection short of Verified, with the reason its lab run recorded |
| What should be fixed now? | `rasd status --next`: each action once, with the detections it moves on |

## Three layers

| Layer | What it holds | Modules |
|---|---|---|
| **Foundation** | What a detection is made of: the Sigma rule, its telemetry contract, the offensive step that reaches it, its triage, response and DFIR playbook, the decoys it reads, the intelligence that ranks what comes next | [RASD-Detect](../detect/) · [RASD-Red](../red/) · [RASD-DFIR](../dfir/) · [RASD-Deceive](DECEPTION.md) · [RASD-Intel](../intel/) · [RASD-Agent's lane](GROW.md) |
| **Assurance** | Everything that tests it. In code: tests, mutations, the evasion fuzzer, query parity, exact automata. In a lab: public attack data, lab runs kept with their raw files, a live SIEM's alerts, evidence recomputed on every build. In your own logs: health, evidence survivability, evidence of absence, the unseen route | [Proofs](PROOFS.md) · [public data](PUBLIC_DATA_VALIDATION.md) · [RASD-Purple](../purple/) · [RASD-Health](HEALTH.md) · [RASD-Trace](TRACE.md) · [RASD-Silence](SILENCE.md) · [RASD-Blindpath](BLINDPATH.md) |
| **Decision** | One record per detection: its verdict, what proves it stage by stage, the reason for every gap, the next action, and any contradiction between components | [status](../status/README.md) · [RASD-Agent's counsel](AGENT.md) |

The Assurance layer tests what the Foundation holds, and the Decision layer reads both. Modules report what they measure; only the Decision layer gives a detection its verdict.

## Eight verdicts

| Verdict | Meaning |
|---|---|
| **Verified** | fired on a real attack step in a lab, and a live SIEM raised its alert; the evidence is fresh |
| **Partially Verified** | fired on its attack step in a lab, but the SIEM alert or the verified cleanup is missing |
| **Unverified** | passes its code checks; no lab run has fired it on its attack step yet |
| **Failed** | a check it must pass did not: a test, a proof, its lab step or the SIEM |
| **Blocked** | the lab could not run its attack step, for a reason the run recorded, or no step reaches it |
| **Degraded** | proven in a lab, and production health now says its events are not arriving as they should |
| **Stale** | its lab evidence is more than 90 days older than the record's date |
| **Unknown** | its Foundation is incomplete (no tests, or no telemetry contract), so there is nothing to judge |

The first rule that holds decides, failures first; the [status page](../status/README.md#how-a-verdict-is-reached) lists the rules in order.

## Every question, and where it is answered

| Question a CISO or auditor asks | Where RASD answers it |
|---|---|
| Does the rule catch the attack? | True-positive tests, mutation tests, the evasion fuzzer |
| Does it stay quiet on normal activity? | True-negative tests, filter-coverage gate, tuning impact analysis |
| Is every part of the rule actually needed and tested? | Rule mutation testing (`rasd prove`) |
| Does the rule logic hold for every possible value, not just the samples? | Exact automata (`rasd certify`): each rule compiled over every Unicode character, with an engine-confirmed event that fires it and the nearest one that does not |
| Does it catch the attack however the attacker writes it? | Behaviour proofs (`rasd certify`): documented attacker variants proven caught for every possible event, or the gap shown with a replayed event ([certificates](CERTIFICATES.md)) |
| Does the query in Splunk / Sentinel do the same as the tested rule? | Query parity (`rasd parity`); aggregation parity for correlations (`rasd correlate`) |
| Can it see attacks no single event shows - a password spray, a burst of service tickets, one client probing many protected API paths? | Sigma correlation detections with scenarios, parameter mutants and a proven burst guarantee (`rasd correlate`) |
| Where will false positives come from? | Near-miss analysis (`rasd nearmiss`): traffic one field edit away from an alert, and threshold headroom |
| What does the analyst do when it fires? | Triage card, response card, DFIR playbook |
| Who uses this technique against organisations like ours? | Actor tradecraft map, CTI-to-detection reports |
| Was it ever proven in a real environment? | Offensive tests, telemetry export, `rasd evidence`, Operational Score |
| What can we not see? | Blind spots, coverage depth, measured gaps in the validation matrix |
| What catches the attacker who evades every rule? | RASD-Deceive (`rasd deceive`): decoys nobody legitimate touches, read by rules proven like every other, and the inventory that keeps them real |
| Can the intruder take the evidence away, and would we see the attempt? | RASD-Trace (`rasd trace`): every sequence of anti-forensic actions around each technique searched; each answer out of reach, evident or exposed, and the rules that close the exposure in order |
| When nothing fires, is that evidence that nothing happened? | RASD-Silence (`rasd silence`): each detection on each host attested only between two proofs that its sensor was recording, with every record between them present; any other quiet named with its reason, and every break in the record listed |
| Can an intruder cross the covered techniques from one host to another with no alert? | RASD-Blindpath (`rasd blindpath`): every route from an origin to a target walked leg by leg; a behaviour unseen only when its sensor is not in the export or a witness replayed through every rule raises no alert; the routes unseen end to end, and the fewest changes after which every route is seen |
| Is every detection still being fed, today? | RASD-Health (`rasd health`): today's telemetry against a baseline, a verdict for every detection, and each break named once with the detections it takes with it: a silent host, a fall in volume, a field lost or renamed, command lines cut short, events that arrive after the search has looked, a search the scheduler skipped; the same watch generated as SPL and KQL searches ([HEALTH](HEALTH.md)) |
| What should we do next, and why that first? | RASD-Agent (`rasd advise`): every measurement above turned into ranked findings with the evidence and the exact next step, for the analyst, the engineer, the purple team and the executive; it remembers your decisions, reads your telemetry, explains alerts and drafts changes the gates verify |
| Can the library grow without waiting for a person, and stay honest about it? | RASD-Agent's lane (`rasd grow`): the whole ATT&CK matrix as a queue; a language model drafts a rule and its tests for the next technique, every gate decides, the proof is computed from the exact automata, and what is kept lives in `detect/candidates`, apart from the core and outside its numbers, proven again on every run ([design](GROW.md)) |
| Who decides that what the agent drafted is right? | A person, with `rasd review`: a verdict recorded against the exact rule text in a ledger the unattended run may not change, promotion only for an approved text, every decision of either side in a chained audit trail, and a run that can be rolled back ([GOVERNANCE](GOVERNANCE.md)) |

## Workflow

```text
A red step generates telemetry.
The telemetry drives a tested rule.
The rule and its SIEM query are proven to be the same rule.
A lab run, with a live SIEM beside it, shows that the rule fires.
The evidence is recomputed from the raw run on every build.
The status record turns every check into one verdict, its reason and the next action.
```

## Two honest scores

- **Engineering Score**: is the detection built right? Tests, contract, false-positive handling, evasion awareness, SIEM portability, response, documentation. It can reach 100 inside the repository, and it never makes a detection Verified.
- **Operational Score**: was it proven in a real lab telemetry flow? Lab evidence, SIEM result, detection latency, DFIR evidence, cleanup. It stays **pending** until a real run is committed, and no detection reaches the *Validated* or *Reference* maturity level without it.

Then: the [status](../status/README.md) of every detection, the [architecture](RASD_ARCHITECTURE.md), and [every page by layer](README.md).
