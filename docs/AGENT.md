# RASD-Agent: The Counsel

Every tool in RASD answers one question with a measurement: does the rule catch the variant, is the boundary pinned, does the query return what the rule returns. None of them says what to do next, for whom, and why that before anything else. RASD-Agent does. `rasd advise` reads what every tool measured on this build and turns it into ranked findings, each with the evidence behind it, the exact next step and a stable id, for four people: the analyst, the detection engineer, the purple team and the executive. It remembers what you decided about each finding and ranks accordingly, measures whether its own counsel led to work that got done, reads your own telemetry when you give it an export, explains an alert field by field, and drafts changes that pass the repository's gates before they are written anywhere. A language model is optional; everything it writes is gated by the engine, the tests and the proofs, and the gates decide.

The agent keeps RASD's rule: nothing is estimated. A finding exists because a tool measured it, a priority says how far it is from a proof, and the generated page [`agent/ADVICE.md`](../agent/ADVICE.md) is counted on every build and checked for drift in CI like every other generated file.

## What it is for

| Who | Asks | `rasd advise` answers with |
|---|---|---|
| Analyst | What is blind in our telemetry, what will be noisy, what does this alert mean, which decoy fires next | `--logs <export>`: READY / DEGRADED / BLIND per rule with the fix, the rules that would alert more than N times a day and the proposed tuning that quiets them without hiding an attack variant, storylines, your own near misses; `--explain <detection> --event <alert>`: the match field by field, the contract's first checks, escalation and containment, the deception chain before and after this alert |
| Detection engineer | What is unproven, which known gap has a fix, which rule comes next, is this tuning safe | Surviving rule mutants with a candidate test, unpinned boundaries with the event that pins them, every known behaviour gap with its engine-confirmed event and the fix the spec records, tunings measured on the corpus and against the behaviour spec, the backlog in its order; `--propose` drafts the change and verifies it |
| Purple team | Which lab run validates most, which decoy to plant next, what no red step reaches | The lab waves ranked by the detections they would validate with their commands, detections no offensive step reaches, planned decoy classes ranked by what they still need, red tests that run without a detection |
| Executive | How far is RASD proven, what does it cover, what should we fund next | Maturity and evidence counts, tactics without a detection, each tracked group's open procedures, the data sources most detections depend on, breadth stated plainly, and the lab run as the step that turns SIEM-Ready into Validated |

`rasd advise` prints every role; `--for <role>` narrows it; `--json` gives the same as data.

## How a finding is made

Each finding carries a stable id, a priority, the roles it concerns, a title, the evidence (what was measured, with the numbers), the next step (a command when there is one) and, when the agent can draft the change, what `--propose` would write. The ids are built from the family and the thing measured, so the same finding has the same id on every build until the repository changes.

| Family | Measured by | Finding | Priority | Drafts |
|---|---|---|---|---|
| `evidence.wave.*` | the red tests' steps and `evidence.md` files | a lab wave (Windows VM, opt-in steps, domain controller, WinRM target, Linux, web) and the detections without evidence it would validate, with its commands | now for the largest wave, next for the others | the commands |
| `evidence.unreachable.*` | the red tests | a detection no offensive step names | next | - |
| `tests.*` `proof.*` `fuzz.*` `parity.*` `correlate.*` `certify.failed.*` `score.*` `chain.*` `tune.broken.*` `tune.risky.*` | `rasd test`, `prove`, `fuzz`, `parity`, `correlate`, `certify`, `score`, `chain`, `tune` | anything not fully proven: a failing test, a surviving or stale rule mutant, an evasion bypass, a query divergence, a failed certificate, a score under 100, a missing chain item, a broken or risky tuning | now | a true positive or true negative for a survivor, when `prove --suggest` finds one |
| `certify.gap.*` | the behaviour certificates | a documented variant the rule does not catch, its engine-confirmed event and the fix the spec records | next | with a model: a rule edit, gated (below) |
| `nearmiss.*` `headroom.*` | `rasd nearmiss` on the replay corpus | a boundary that holds traffic back and no true negative pins; a correlation whose quietest window sits one unit under its threshold; a threshold not measured | next (unmeasured: planned) | the example event as a true negative |
| `tune.proposed.*` `tune.spec.*` | `rasd tune` on the corpus and `certify` with the filter in the rule | a proposed tuning safe to apply where its noise source exists; or one that is safe on the corpus but contradicts the behaviour spec | planned | the filter in the rule, the entry applied, and the tests that prove it |
| `backlog.*` | `intel/mappings/backlog.yml`, `actors.yml` | the next rule, in the backlog's order (lab-ready first, then a red step away, then a new log source), with the tracked groups documented using the technique | next for lab-ready, planned for the rest | a scaffold; with a model, a candidate rule and tests, gated |
| `deceive.*` | `deceive/decoys.yml` | a decoy class not built and what it still needs | planned, awareness | the inventory entry to complete |
| `public.*` `public.holdout.*` `public.missed.*` | `rasd datasets` | a detection no public dataset records (with the catalogue's reason); a held-out expectation missed; an expectation a dataset holds that the rule did not meet | planned / next / now | - |
| `tactic.*` `actor.*` `coverage.breadth` | the ATT&CK reference in `tools/common.py`, `actors.yml` | a tactic with no detection; a tracked group's open procedures; breadth in one sentence | planned | - |
| `emulate.*` | `actors.yml`, the red tests | an emulation plan per tracked group: the red tests that exercise its procedures, those with a detection to prove and those that are measured gaps, with the runner command for each | planned | - |
| `source.*` | the data sources per detection | a data source that feeds a quarter or more of the detections, and the techniques that go dark with it | awareness | - |
| `red.hunt.*` `red.posture.*` | the red tests | a test covered by a hunting query only; a posture check | planned, awareness | - |
| `telemetry.*` `noise.*` `replay.storylines` `nearmiss.env.*` `headroom.env.*` `profile.*` | `rasd doctor`, `replay`, `nearmiss`, `tune`, `profiles` on **your export** (`--logs`) | blind or degraded detections and the fix; noisy rules and the measured tuning that quiets them; storylines; your own boundaries and headroom; the telemetry profile the export looks like | now for blind, next for noisy and degraded | - |

Priorities: **now** blocks a proof or the next maturity level; **next** is a measured gap with a known step; **planned** is ranked work; **awareness** changes nothing today. Within a priority the findings are ordered by how much they cover (detections validated, events held back, alerts removed) and then by id, so the order is the same on every machine.

## What the agent learns, and how you can check it

Three things, all recorded in the repository where anyone can read them.

**Your decisions.** `rasd advise --decide <id> accept|reject|defer --note "why" [--until YYYY-MM-DD] [--by name]` appends to [`agent/decisions.yml`](../agent/decisions.yml). A rejected finding is set aside: still measured, no longer ranked, listed with its reason. A deferred finding waits until its date. An accepted finding stays ranked and carries the decision. When a family of findings (`certify.gap`, `backlog`, `tune.proposed` ...) has been rejected twice, the agent ranks that family one level lower from then on and says so in the ledger. The file is validated in CI: every entry needs a well-formed id, a decision, a date, a reason for a rejection and a date for a deferral.

**What became of them.** An accepted finding that no longer appears was resolved. The ledger on the page counts accepted, resolved, open, rejected and deferred, so the question "does the counsel lead to work that gets done" has a number, computed, not claimed.

**Your telemetry.** `rasd advise --logs <export> [--profile auto] [--learn]` runs the doctor, the replay, the near-miss analysis and the tuning measurement on your own events and ranks what they say. `--learn` writes [`agent/environment.yml`](../agent/) with the counts and verdicts (events, routed, alerts, ready / degraded / blind, noisy and silent rules) and never a value from a log; the file is ignored by git because it describes your environment, not the repository. The generated page describes the repository only, so it is identical on every machine.

What the agent does not learn: it never changes a rule, a threshold or a tuning on its own, never raises a maturity level and never estimates a score. Learning changes the order and the visibility of its counsel; the proofs decide the rest.

## Explaining an alert

```bash
rasd advise --explain T1078.002 --event alert.json          # the alert as JSON, or a .jsonl file (first record)
rasd advise --explain T1218 --tp 1                          # a detection's own sample
```

The explanation is computed: the rule's condition and every selection, field by field, with the values that matched; what the behaviour means (from the rule); the contract's first checks, escalation criteria and containment; the rule's known blind spots; and for a deception rule the chain of lures, which decoy was touched, what led the attacker there and which detection to expect next. With a model configured, a short narrative follows, marked as prose that is not verified; the event's values are not sent unless `--share-events` is passed, and then a redacted copy goes (addresses, host and account names replaced by placeholders).

## Proposals: drafted, verified, applied by you

```bash
rasd advise --propose <finding id>      # writes agent/proposals/<id>/PROPOSAL.md and the files under files/
rasd advise --apply <finding id>        # copies the files into the working tree and runs the gates that concern them
```

A proposal is written only after it is verified in memory; when a check fails, nothing is written and the reason is printed. Each kind has its gates:

| Kind | Finding | What is drafted | Verified before writing |
|---|---|---|---|
| tests | `nearmiss.*`, `proof.*` with a candidate | one true negative (the event the boundary holds back) or the true positive / negative that kills a surviving mutant | the engine reads the event with the expected verdict; no identical test exists |
| tuning | `tune.proposed.*` | the filter selection in `rule.yml` (the condition gains `and not <filter>` unless it already negates every `filter_*`), the entry turned from proposed to applied in `tuning.yml`, and the tests the filter needs: for every value a look-alike true negative that only the filter decides, built from the rule's own true positives, and for every condition of the filter a true positive it must not cover; a corpus alert the filter removes is added as a true negative too | the filter hides no attack variant and removes corpus alerts (`rasd tune`); every existing test keeps its verdict; the behaviour certificate holds with the filter in the rule; the written rule reads back as the measured tuning; the look-alikes exercise the filter (the linter's filter coverage) and the rule mutation proof stays at 100% with prove's full suite (tests, mutations, fuzzer variants, accepted mutants) |
| rule-edit | `certify.gap.*` | the engine-confirmed event as a pending true positive; with a model, a candidate edit of the detection block, the event appended to the true positives and `behavior.yml` with the variant now expecting to fire | the engine compiles the edit; every existing test keeps its verdict; the variant's event matches; KQL and SPL convert; the certificate holds with the spec as it must then read (every variant ok, every exclusion still proven quiet, nothing proven before lost, the gap variant now proven for every event); the rule mutation proof does not fall |
| scaffold | `backlog.*` | the folder `rasd new` makes, with the rule's description, log source, references and tags from the backlog entry; with a model, a candidate rule and eight tests | the model's rule compiles, its four true positives match and its four true negatives stay quiet, both backends convert it, the automata compile it; otherwise the computed scaffold is written and the refusal is recorded. A scaffold fails CI until its contract, tuning guide, tests and README are complete, by design |
| decoy | `deceive.*` | a draft inventory entry for the planned class with every field a built decoy carries | `rasd deceive --check` refuses it until the rule and the red test exist; the entry says so |
| commands | `evidence.wave.*` | the lab wave's commands | a procedure, not a file change |

`--apply` copies the proposal's files into the working tree (scaffolding a new detection folder first when needed), runs `rasd lint`, `test`, `prove`, `certify --check`, `tune --check` and `parity` for the detections it touched (`deceive --check` for the inventory), records the decision as `applied` in `decisions.yml`, and stops. You review the diff, run `rasd ci`, and commit through a pull request. The agent never commits and never pushes.

## The model, when you configure one

The counsel never needs a model. One adds what computation cannot: a narrative for an analyst, a first draft of a rule edit or of a new rule, an answer to a free question. Configuration is by environment variable only ([tools/agent_model.py](../tools/agent_model.py)):

| Variable | Meaning |
|---|---|
| `RASD_MODEL` | the model name; unset means no model, every command still runs |
| `RASD_MODEL_URL` | the server: any server that speaks the chat-completions API (`POST <url>/chat/completions`, the form most hosted and self-hosted servers accept), or a local Ollama (`http://localhost:11434`) |
| `RASD_MODEL_KEY` | bearer token, when the server needs one |
| `RASD_MODEL_PROVIDER` | `chat` or `ollama` (default: `ollama` for a URL on port 11434, else `chat`) |
| `RASD_MODEL_TIMEOUT` | seconds to wait (default 120) |

`rasd advise --model-status` says what is configured. The model answers at temperature 0 with one JSON object; an answer that is not JSON or lacks a required key is refused. What leaves the machine is rule text, test events and counts from the repository, which are public, plus a redacted event only with `--share-events`. Where the model is used and what gates it:

- `--explain`: a narrative with the next checks and when to close, under the computed explanation, marked as not verified.
- `--propose certify.gap.*`: a rule edit, kept only when the gates above accept it; the proposal records whether the draft was accepted or refused and why.
- `--propose backlog.*`: a rule and tests, kept only when the gates accept them.
- `--ask "question"`: an answer grounded on the counsel's findings that match the question, the repository's counts and the page sections that match best, with the sources it used. Without a model, `--ask` prints those findings and sections.

The gates decide, not the model: a model that writes a rule which hides a true negative, breaks a certificate or lowers the mutation proof gets nothing into the repository, and the refusal is recorded in the proposal.

## What the agent will not do

It advises on defence and emulation inside RASD's lab discipline. It does not write or run attacks against hosts, does not build malware or exploits, does not act on a network, and does not touch anything outside the repository. It does not commit, push, or change a rule, a threshold, a maturity level or a score on its own. It does not send your logs anywhere unless you pass `--share-events`, and then only a redacted copy to the server you configured.

## Commands

```bash
rasd advise                                   # the counsel, every role
rasd advise --for analyst|engineer|purple|executive
rasd advise --logs export.jsonl --profile auto [--learn] [--noisy 20]
rasd advise --explain <detection> --event alert.json [--share-events]
rasd advise --explain <detection> --tp 1
rasd advise --propose <finding id>
rasd advise --apply <finding id> [--by name]
rasd advise --decide <finding id> accept|reject|defer --note "..." [--until 2027-01-31] [--by name]
rasd advise --ask "question"
rasd advise --json [file]
rasd advise --write                            # agent/ADVICE.md (part of rasd build)
rasd advise --check                            # CI: the page is current, decisions.yml is valid
rasd advise --model-status
```

## Limits, stated

The counsel is as good as what the tools measure: a gap no tool sees is not a finding. Breadth is stated, not solved, by the agent: it ranks the next rules, it does not write the fifty that ATT&CK would still list. The `--ask` retrieval is keyword based and the model narrative is prose; both are labelled so. The look-alike tests the tuning proposal builds cover filters written with equality, `contains`, `startswith` and `endswith`; a filter written as a regular expression needs its tests written by hand, and the proposal says so instead of guessing. An applied tuning that contradicts a behaviour spec is refused until the exclusion is declared in the spec with its reason, because a certificate that stops holding is worth more than a quieter rule.
