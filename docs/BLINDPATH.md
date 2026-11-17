# RASD-Blindpath: The Route Through the Green Cells

A coverage map colours a technique green when a rule exists for it. The map says which cells have a rule. It does not say whether an intruder who steps only on green cells, from the first host to the last, is ever seen. RASD-Blindpath walks that way and answers with proof: a route that is unseen end to end, the first leg where each other route is seen, and the fewest changes after which every route is seen.

```bash
rasd blindpath my-export.jsonl --assets assets.csv      # every route from an origin to a target: unseen, or seen at which leg
rasd blindpath my-export.jsonl --certificate route.md   # the certificate: every verdict with its proof, the plan and the limits
rasd blindpath my-export.jsonl --html route.html        # the same as one page, with the map of every host and stage
rasd blindpath my-export.jsonl --origin WS01 --target DC01
rasd blindpath my-export.jsonl --baseline last.json     # what changed since an earlier answer; exit 1 when it got worse
rasd blindpath my-export.jsonl --witnesses w.jsonl      # the events of every witness, to replay through your own SIEM
rasd blindpath                                          # on Windows: this host's own event logs, read only
rasd blindpath --check                                  # the model against the rules, the specs and the engine (in CI)
```

The results for the sample fleet of this build are in [purple/blindpath](../purple/blindpath/README.md).

## The claim

One sentence, written in [`purple/blindpath/model.yml`](../purple/blindpath/model.yml) and printed on every certificate:

> A route from an origin to a target is unseen when, at every leg, one behaviour this rule set claims to detect can be done there with no alert: either the export holds no record of the sensor its rules read from that host, or one sequence of events of that behaviour, replayed through every rule and correlation, raises none.

The blind one in the name is the defender. A green map is read as sight, and the tool shows where it is not. The intruder it reasons about is written beside the claim: an administrator on every host it acts on, who chooses how each act is written and at what pace, and who cannot change the telemetry pipeline, the SIEM or what a target answers.

## Why a route, and not a rule

Every other proof in RASD is about one rule: it fires on its tests, it survives mutation, its SIEM queries agree with it, its behaviour spec names the variants that slip past it. A study of 292 widely used Sigma rules found that at least 44% can be evaded with simple changes to the command line ([Uetz et al., USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/uetz)), so a list of such variants is expected, and RASD keeps one per rule. A list does not say what it costs. One variant in one rule may be harmless because the next leg of every intrusion is seen anyway, and another may be the last gap of a way that reaches the domain controller in silence. Blindpath composes what the repository already proves, rule by rule and host by host, into the one question a defender asks of a map: is there a way through.

## The model

| Part | What it says |
|---|---|
| `claim`, `position` | The sentence above, and who walks |
| `stages` | The stages of an intrusion, in the order the map shows them: get in, run code, stay, take credentials, move in, erase the record |
| `route` | The legs every route walks, each a stage at one end: run code on the origin, take credentials from the origin, move into the target, run code on the target |
| `steps` | One act, and every rule that watches it (its observers). Two ways to the same end are two steps |
| `ways` | Every variant a behaviour spec marks `expect: bypass` for an observer, and who decides it: the `intruder`, who writes it at will, or the `environment`, the pipeline or the target, in which case it is listed and never walked. `needs` is what a variant asks for beyond the position |
| `tripwires` | The decoy detections, each with what it catches and what it misses |
| `origins`, `targets` | The roles of the assets file that start and end a route |
| `limits` | What a certificate does not say |

`rasd blindpath --check` holds the model against the repository. Every detection and correlation must be the observer of a step, a tripwire, or listed apart with its reason. Every documented variant of an observer must be placed under `ways`. The tripwires must be the detections of the decoy inventory, no more and no fewer. A rule or a variant added without a place in the model fails the build, so the map cannot fall behind the rules.

## What makes a behaviour unseen

A step is judged on one host at a time. Each of its observers is in one of three states there, read from the answer of [RASD-Silence](SILENCE.md) for the same export:

| State | Meaning |
|---|---|
| live | The sensor the rule reads is shown to record on that host (the rule is attested or fired) |
| dark | The export holds no record of that sensor from that host, or the record is written and the rule cannot read it |
| absent | No host of the export writes what the rule reads; a step whose observers are all absent is not walked |

A rule that reads a record of the host itself (a process, a registry value, a service) is judged on that host. A rule that reads what an observer records for others (the tickets and logons a domain controller writes) is judged on the hosts that write those records, and is seen if any of them is live.

The step is then **unseen** in two cases only.

**Dark.** No observer is live. Each one is named with the reason RASD-Silence gives and with what turns its sensor on.

**Witness.** The live observers read one kind of record, and one sequence of events of the act, replayed through every rule and correlation of the build, raises no alert from a rule that is live on that host. The events come from three places, all of them already proven in the repository:

1. A variant the behaviour spec of an observer marks `expect: bypass` and the model gives to the intruder. `rasd certify` builds the event and confirms with the engine that the rule misses it; Blindpath replays the same event through every other rule too, because a variant that slips one rule may be caught by another.
2. A true positive of a threshold correlation, paced one under its count: four distinct accounts in each ten-minute window where the rule counts five, in three windows two lengths apart, so that a sliding window sees no more than a tumbling one. `--check` holds the pace exact: one more in a window must alert.
3. A documented variant of a correlation's base rule, sent as a burst that would always alert if its events were counted.

An event a spec leaves short is dressed as its sensor writes it (the channel, the event id, a time) and must still route to the log source of its rule and still be an event of its variant, or it is not used.

Two more rules keep the verdict sound:

- When the live observers read **different records of the one act** (the process that clears a log, and the record Windows writes when a log is cleared), the step is seen. A variant that slips the first rule says nothing about the second record, and two variants of two rules are not taken to be one act.
- A witness may stand inside a design exclusion of another observer, and the report says so. The Kerberoasting witness is the volume correlation's own true positive with AES tickets: the RC4 rule excludes AES by design, and the correlation counts it, so the pace under the correlation's threshold is what leaves it unseen.

A step that is not unseen is **seen**, with what the hold rests on: the variants proven to fire, the design exclusions, or the rule's tests alone when it has no behaviour spec.

## The map and the routes

A leg is **open** on a host when one behaviour of its stage is unseen there: the intruder chooses the technique. It is **held** when every behaviour of the stage with a sensor in the export is seen, and marked when that rests on rules with no behaviour spec. The map shows this for every host and every stage.

A route goes from an origin to a target. With an assets file (`ip,host,role`) the roles of the model decide the ends; without one the hosts that record tickets and logons for others are the targets and the rest are origins; `--origin` and `--target` name them directly. A route is **unseen end to end** when every leg is open, and otherwise it is **seen at** its first held leg. Routes whose legs read the same are grouped.

## The plan

The plan answers what to change first. For each leg in turn it gives the fewest changes after which every route is seen by that leg:

- **a variant closed in a rule**, with the change its behaviour spec writes;
- **a sensor turned on on a host**, with the instruction RASD-Silence gives for it.

The search is exact. Every route is seen by a leg exactly when every origin holds one of its legs up to there, or every target does, so the two sides are solved apart, each as the smallest union of one repair per host, by branch and bound. If the search ever stops at its budget the plan says it is not proven the fewest. Every plan is then applied to the model and walked again, and a plan that leaves a route unseen is an error, not a result.

Some legs cannot be held by any change the model knows, and the plan says which and why. A threshold can always be walked under, so no rule change makes a paced spray or a paced roast seen. What sees those is a decoy, which is why the tripwires are shown beside them.

## What each change buys

The plan is the fewest changes together. Beside it every change is also taken alone: a sensor turned on on one host, or every documented variant of one rule closed (a rule is one piece of work, whatever the number of its variants). For each, the walk is done again with only that change in place, and the table gives the legs it holds, the routes it lets be seen, and the leg by which every route is then seen. A change that buys nothing alone is not listed. It shows which rule is worth the next hour: on the sample fleet two changes each end every unseen route, one sensor on one server and one rule with four variants, and only the second moves the first sight to the first leg.

## Since the baseline

`--json` writes the whole answer. Given back as `--baseline` on a later run, it is compared with the new one for the hosts the two share: the routes that are now unseen or seen later, the legs that were held and are now open, the behaviours that turned unseen, and the same in the other direction. The command exits 1 when a route or a leg got worse, so a pipeline that changes a rule, a collector or a Sysmon configuration stops before a way through opens, and says which way. Hosts that joined or left the export are named and not judged.

## Tripwires

A decoy detection sees the intruder who touches the decoy and no other. Counting it as sight would overstate the defence against an intruder who names its accounts, and counting it as nothing would hide the one control that does not depend on pace or wording. So tripwires are shown with their state in the export (armed, dark, not in this export), what each catches and what it misses, and they are never counted for or against a route.

## This host

On Windows, `rasd blindpath` with no export reads the host's own Sysmon, Security and System channels through RASD-Silence's reader, for the last `--days` (7 by default). It only reads: nothing on the host is changed, no technique is run and nothing leaves the host. It waits for Enter, prints the answer, and writes the certificate and the page beside it. With one host the walk is the walk on that host alone.

## The certificate

`--certificate` writes the claim, the position, every input with its SHA-256, the window, the origins and the targets, the map, every route with its legs, every unseen behaviour with its proof, the plan, what each hold rests on, the tripwires, the variants the intruder does not choose, each witness with its first event and its source, the limits, and the command that made it. `--json` holds the same with every event of every witness. `--witnesses` writes those events alone as JSONL, each marked with its witness, its behaviour and its rule: `rasd replay` reads the file, and so does a test index of your SIEM, which is where the claim matters. If your deployed rules alert on a witness, your deployment sees more than these rules do; if they stay quiet, the gap is confirmed where it counts. `--strict` exits 1 when a route is unseen end to end, for a pipeline that should stop on one.

## How it stands with the rest

| Tool | What it answers | What RASD-Blindpath adds |
|---|---|---|
| A coverage map (`rasd coverage`, an ATT&CK layer) | Which techniques have a rule | Whether the techniques that have one can still be walked unseen, on which host, and where that leads |
| `rasd certify`, `rasd fuzz` | Which variants slip past one rule | Which of them matter: the ones that open a leg of a route, replayed through every other rule |
| `rasd silence` | Whether a quiet rule is evidence on a host | What a sensor that does not record costs: the routes it opens |
| `rasd replay` | What fired on the logs you have | What would not fire on logs you do not have yet |
| `rasd trace` | Whether the evidence of a technique can be taken away | Whether the technique is seen at all |
| Attack path tools | Which permissions lead to the domain | Which of the acts on the way are seen |
| Breach and attack simulation | Whether the attacks it runs raise alerts | A proof that needs no agent and runs nothing: the variants are searched, not sampled |

Placing sensors on an attack graph so that every path is watched is an old idea (Noel and Jajodia, Optimal IDS Sensor Placement and Alert Prioritization Using Attack Graphs, Journal of Network and Systems Management, 2008). What we did not find is that question asked of a detection rule set with the proofs a repository like this one already holds: a path made only of behaviours the rules claim, each unseen step tied to an event the engine replays or to a sensor the export does not hold. That is a statement about what we found, not a proof that nobody built it.

## Limits

- The walk stays on the behaviours this rule set claims to detect. A technique no rule covers is unseen with no proof needed; the measured gaps are in the [validation matrix](../purple/validation_matrix.md). The result is a floor under the blindness, not its size.
- Held means that no way around is known here. It is not proof that none exists, and a rule with no behaviour spec holds on its tests alone.
- A witness proves that the rules stay quiet on those events. That the events are the act is what the behaviour spec and the rule's own true positives state, with their sources; they were not produced on a host here, and the lab runs that do so are part of v2.0.
- Dark means the export holds no record of that sensor from that host. A sensor that records and is not exported reads the same.
- Every origin is taken to reach every target. The export says nothing of the network between them.
- The plan counts changes, not their cost, and takes a closed variant to change nothing else in its rule; `rasd certify --equiv` proves that for the edit itself.
- An observer that records for other hosts is judged on the hosts whose records are in the export. A domain controller that sends no ticket or logon record is not known to be one.

## How it was checked

Beside the unit tests, every unseen verdict on the sample fleet is derived a second time in the tests without the tool's own logic: a witness is replayed through the engine again and must alert on no rule that RASD-Silence shows recording on that host, and a dark verdict must find every observer unattested there. Every plan is compared with an exhaustive search over smaller sets of changes on the sample fleet, and with the walk of the model after the plan is applied. Verdicts are checked to move one way only when a sensor is turned on or a variant is closed, on fleets changed at random. Every row of what a change buys is compared with a full walk of the model with that change in place, and the witness file is replayed through the engine and must raise nothing. The reading of a live Windows host is RASD-Silence's; this release adds no code that touches the host.

## Extending the model

1. A new detection: name it as the observer of a step (a new step when it watches a new act, an existing one when it reads another record of the same act), or as a tripwire when it is a decoy.
2. A new `expect: bypass` variant in a behaviour spec: place it under `ways` with `by: intruder` (and `needs` when it asks for more than the position) or `by: environment` with the reason.
3. A new stage or leg: add it to `stages` and, when every route must walk it, to `route`.
4. Run `rasd blindpath --check`, then `rasd build`.
