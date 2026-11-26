# RASD-Agent's lane: detections grown with no person in the loop

`rasd advise` counsels; a person decides. `rasd grow` is the part of RASD-Agent that works alone: it takes the next ATT&CK technique RASD has no rule for, has the configured language model draft a rule with its tests, runs the draft through every gate, keeps it when all of them accept it, and moves to the next technique. Nobody has to be there for a candidate to be drafted.

That is only safe because of where the result goes, and of what the agent cannot do with it. RASD holds two libraries, and the agent writes to one of them. Whether a candidate is right is a person's decision, taken with `rasd review` and recorded against the exact rule text; nothing the agent drafts reaches the core, a generated query or the Splunk app any other way ([GOVERNANCE](GOVERNANCE.md)).

| | Core | Candidates |
|---|---|---|
| Where | [`detect/detections/`](../detect/detections/), [`detect/correlations/`](../detect/correlations/) | [`detect/candidates/`](../detect/candidates/README.md) |
| Written by | a person | a language model, for RASD-Agent |
| Reviewed by a person | yes | when someone does: [`rasd review`](GOVERNANCE.md), shown on each candidate's page |
| Kept when | `rasd ci` passes and a person merges it | every gate of `rasd grow` accepts it |
| Counted in the scores, the coverage map, the certificates, RASD-Trace, RASD-Silence and RASD-Blindpath | yes | never |
| Maturity | Draft to Reference ([model](RASD_MATURITY_MODEL.md)) | none: a candidate is a candidate |

Every number RASD publishes about the core stays what it was. The lane has its own page, [`detect/candidates/README.md`](../detect/candidates/README.md), one row in the metrics that says how many candidates there are and how many a person has reviewed, and one finding in [the counsel](../agent/ADVICE.md) that hands them to people: which candidates wait for a review, and which of them the backlog already asks for.

## The queue: the whole matrix

`intel/mappings/attack_enterprise.json` is the ATT&CK Enterprise matrix: every active technique and sub-technique with its name as ATT&CK writes it, its tactics, its platforms, the number of documented groups that use it and the day it was created. `rasd grow --sync <bundle>` writes it from MITRE's own STIX bundle ([attack-stix-data](https://github.com/mitre-attack/attack-stix-data)) and records the bundle's SHA-256; a bundle whose version, date or technique names are not what a release looks like is refused. A unit test holds it against the reference the core uses (`TECHNIQUES` in `tools/common.py`): every technique the core maps has the same name and the same tactics in both. A release that drops, renames or moves one of them is held, not written: the core's mapping is a person's to bring up to it first, and until then the lane keeps the release it has.

Each technique stands in exactly one place:

| Standing | Meaning |
|---|---|
| core | a core detection or correlation carries it |
| candidate | the lane holds a candidate for it |
| queued | within reach, not drafted yet |
| declined | the model answered that no log source RASD reads records it; kept with the reason, and asked again only when the field vocabulary of the log sources changes |
| refused, parked | its drafts failed a gate; tried again in later runs, and parked after 4 refusals until the next RASD version |
| out of reach | its platforms are neither Windows nor Linux: cloud, SaaS, identity providers, network devices, containers, ESXi, macOS only, and what happens before the intrusion |
| parent | it has sub-techniques, and is drafted through them |

The queue is ordered by evidence, not by preference: the techniques used by the most documented groups come first, then the ones a gate refused, fewest attempts first. It covers the matrix as it is today, techniques that have been in it for a decade and the ones the last release added alike, and a new release enters it with the next `--sync`.

## A draft

One JSON object. The model is given the technique, the log sources with the exact fields each one writes and one event of each from the core's own tests, one draft the gates accepted for another technique (a unit test keeps that example passing every gate), and the reason the previous draft was refused when there was one, in this run or in an earlier one.

| Key | What it is |
|---|---|
| `observable` | `false` with a `reason` when no log source RASD reads records the behaviour; the technique is declined |
| `logsource` | one of `process_creation`, `process_access`, `registry_set`, `windows/security`, `windows/system`, `linux/process_creation`, `webserver` |
| `name`, `title`, `description`, `level` | the folder name, the rule's title and description, its severity |
| `detection` | the Sigma detection block: selections of plain values and one condition |
| `true_positives`, `true_negatives` | at least 4 events each, flat, with a `_case` label |
| `false_positives`, `blind_spots`, `first_checks` | what an analyst needs beside the rule |

Everything else in a candidate is computed: the rule's id, tags, references and date, the missing tests, the proof numbers, the KQL and SPL queries, the page.

## The gates

A draft is refused by the first gate that does not hold, and the refusal, in words, is what the model is given for its second draft.

| Gate | What must hold |
|---|---|
| form | every key is present and text is within bounds; prose is plain sentences, with no placeholder, address, Markdown or bracket, and no identifier ATT&CK has retired; selection names, fields and values are one line of printable text, so what a draft holds is exactly what its page and its queries show; at most ten selections, and no regular expression that repeats a repeating group |
| engine | the rule compiles; every true positive matches and every true negative stays quiet |
| vocabulary | every field of the rule and of every test event is one the log source writes, spelled as it writes it; the linter has no remark (a case-sensitive regular expression or a very short substring is one) |
| routing | every test event is an event of that log source, as `rasd replay` routes it |
| evasion | every variation the fuzzer makes of a true positive still matches: case, spacing, a quoted or full-path program, a renamed binary, forward slashes, numbers written another way |
| exclusions | every selection that can take an event out of the rule is found from what the condition does, must be named `filter_*`, and reads no field that says who ran it, on which machine or from which address; each has a true negative that only it keeps quiet |
| noise | the rule fires on no event the repository records as benign: the true negatives of every other rule that reads the same log source |
| novelty | the true positives are not all caught by a rule that already exists |
| parity | the generated KQL and SPL return the rule's verdict on every event of its corpus, in RASD's offline model of each language |
| proof | every value, field, branch and operand of the rule is held by a test |

## The proof is computed

The last gate does not ask the model for more. RASD mutates the rule the way `rasd prove` does (drop a value, a field, a branch, an operand) and runs the tests against each mutant. For a mutant that survives, the agent builds the event that tells it from the rule: from the tests it has when one edit is enough, otherwise from the exact automata of `rasd certify`, kept as close to a real test event as the proof allows. The event joins the tests, labelled `computed`. When the automata prove that no event can tell the mutant from the rule, the part is redundant and the smaller rule is kept. A candidate is written only when no mutant survives, so its mutation proof is complete by construction, with no mutant accepted on a written reason.

## The ledger

[`agent/growth.yml`](../agent/growth.yml) records each technique the agent has handled: accepted with the candidate, declined with the reason, refused with the gate's last words and the number of runs that tried. No run repeats another's work, and `rasd grow --check` fails when the ledger and the lane disagree.

## Every run proves the lane again

Before it drafts, a run puts each candidate it holds through every gate once more and rewrites what is generated (the proof numbers, the page, the queries). A candidate that no longer passes, because a rule of the core now records one of its events as benign, because the fuzzer learned a variation it misses, or because ATT&CK withdrew its technique, is retired: its folder is removed, the reason goes to the ledger and the technique returns to the queue. The same check runs in `rasd ci`, so a change to the core that breaks a candidate is seen in the pull request that makes it; `rasd grow --run` retires it with or without a model.

## Turning it on

The lane needs a language model; without one nothing is drafted and every other command of RASD runs as before. The model is the one RASD-Agent already uses ([AGENT](AGENT.md#the-model-when-you-configure-one)): any server that speaks the chat-completions API, or a local Ollama.

On a workstation:

```bash
export RASD_MODEL=<model name>
export RASD_MODEL_URL=<server>            # the chat-completions server, or http://localhost:11434 for Ollama
export RASD_MODEL_KEY=<token>             # when the server needs one
rasd grow --run --max 5
```

Unattended: [`.github/workflows/agent-grow.yml`](../.github/workflows/agent-grow.yml) runs every day and on demand (Actions, RASD-Agent · grow, Run workflow). It is skipped until the repository has a model, under Settings, Secrets and variables, Actions:

| Tab | Name | Value |
|---|---|---|
| Variables | `RASD_MODEL` | the model name; while it is unset the job is skipped |
| Variables | `RASD_MODEL_URL` | the chat-completions server, up to and without `/chat/completions` |
| Secrets | `RASD_MODEL_KEY` | the server's token |
| Variables, optional | `RASD_MODEL_PROVIDER` | `chat` or `ollama`, when the URL does not say it |
| Variables, optional | `RASD_GROW_MAX`, `RASD_GROW_TRIES` | candidates to accept and drafts to ask for in one run (5 and 20 when unset) |

A scheduled workflow runs from the default branch only, so the lane starts with the release that carries it on `main`.

Each run, in order:

1. reads the latest ATT&CK release and syncs the reference (a release that disagrees with the core's mapping is held, with a warning);
2. runs `rasd grow --run`: the candidates are proven again, then the model drafts down the queue;
3. runs `rasd build`, then the gate every change passes: `ruff`, `mypy` and the whole of `rasd ci`, and checks that the build leaves the tree as it is. When that fails with this run's candidates in the tree, they are set aside (`rasd grow --set-aside`): removed, recorded as refused with that reason, and the gate runs once more without them. A candidate that breaks a check the lane's own gates do not make is therefore drafted again with that said, parked after 4 runs, and never blocks the lane;
4. runs `rasd grow --guard`: nothing differs from the last commit but the lane's own files, which are its folder, its ledger, new lines at the end of its audit trail, the ATT&CK reference and the four generated pages that state its numbers or name its candidates. A run that changed the front page, a core rule, a test, a tool, a workflow or a person's review is refused here;
5. commits the lane to the branch it started from and starts the CI workflow on that commit.

A run whose gate fails without its candidates too publishes nothing. A run in which the model stops answering publishes what the gates had accepted before that, then fails so that it is seen. The key is given to the drafting step alone.

What leaves the machine is the prompt: the technique's public description, RASD's field vocabulary and one test event of each log source from this repository. Nothing from anyone's logs.

## Drafts from a folder

`rasd grow --run --drafts DIR` reads `DIR/<technique>.json` instead of calling a model: for a model that is not reached over an API, and for running a draft through the gates again. The gates are the same. A rule a person writes does not belong in the lane; it goes to the core, through review.

## Reviewing and promoting a candidate

`rasd review <candidate>` shows a reviewer the rule, everything it will never alert on, its tests and the four questions no gate can answer, and with `--logs <export>` the events of the reviewer's own telemetry it fires on; `--approve`, `--revise` or `--reject` records the verdict with the reviewer's name against the SHA-256 of the rule text. `rasd review <candidate> --promote` then turns an approved candidate into the start of a core detection: the rule and the tests carried over byte for byte, the contract, the tuning guide and the mutation tests left for a person to write, and from there the behaviour spec and the lab run, through `rasd ci` and a pull request. The technique then stands as core. Who may do what, the audit trail and how a run is rolled back are in [GOVERNANCE](GOVERNANCE.md).

## Commands

```bash
rasd grow                              # where the lane stands, and what comes next
rasd grow --json                       # the same as JSON
rasd grow --run [--max N] [--tries N]  # prove the candidates again, then draft down the queue
rasd grow --run --only T1136.001       # one technique
rasd grow --run --attack BUNDLE.json   # give the model each technique's description from the bundle
rasd grow --run --drafts DIR           # drafts from a folder
rasd grow --run --report run.json --note note.txt   # what the run did, and the note to commit it with
rasd grow --sync BUNDLE.json           # rebuild the ATT&CK reference from an official Enterprise bundle
rasd grow --check                      # CI: every candidate, the ledger and the page
rasd grow --guard                      # nothing but the lane's own files differs from the last commit; the audit trail only grew
rasd grow --set-aside run.json         # take what that run accepted out again, recorded as refused
rasd grow --write                      # regenerate the lane's pages (part of rasd build)
rasd review                            # the people's side: the board, a dossier, a verdict, promotion, rollback, the trail
rasd review --logs export.jsonl        # the board beside your own logs: the candidates that fire, and the events the core is silent on
```

Exit codes: 0 done; 1 a check failed, or the model stopped answering three times in a row (what the gates had accepted is kept); 2 the model is misconfigured; 3 `--sync` held a release that disagrees with the core.

## Limits, stated

- **A candidate is proven consistent, not proven true.** The gates prove that the rule does what its tests say, that the tests leave no part of the rule unheld, and that the queries agree with the rule. They cannot prove that the test events are what a real host writes, nor that the behaviour is the technique the candidate is filed under: a model wrote both, and no lab run stands behind them. That is why a candidate carries no maturity and no score.
- **The notes are a model's.** False positives, blind spots and first checks are bounded and screened for form, not checked for truth.
- **A request can be poisoned; an answer still has to pass.** The technique's description comes from a public catalogue and is given to the model marked as reference material. No wording makes a model immune to what it reads, so the control is on the way out: an answer that excludes a person or a machine, hides an exclusion, or carries a link is refused, and each such draft is a test ([GOVERNANCE](GOVERNANCE.md#what-a-draft-cannot-smuggle-in)).
- **One event, seven log sources.** The lane drafts single-event rules for the log sources listed above. Behaviour that needs a count over time, a log source RASD does not read, or two events joined, is declined or refused, and stays in the queue's record. The techniques of cloud, identity, email and network platforms are counted as out of reach until the core reads their logs ([roadmap](RELEASE_ROADMAP.md#after-v20-new-data-domains)).
- **The noise gate knows only this repository.** A rule that is quiet on every benign event here can still be noisy in an environment; `rasd doctor`, `rasd replay` and `rasd tune` on your own export are the measure of that, as for any rule.
- **It writes rules, never attacks.** The lane drafts detections and the events that test them. It does not write offensive tests, exploits or malware, and it does not run anything against a host.
- **Breadth costs.** Each draft is one model call of a few thousand tokens; a run is bounded by `--max` and `--tries`, and a technique that keeps failing is parked, not retried forever.
- **A new ATT&CK release can wait for a person.** When a release changes a technique the core maps, the lane stays on the release it has until `tools/common.py` follows; the run says so and goes on.
- **A quiet repository is paused by GitHub.** A scheduled workflow stops running in a repository with no activity for 60 days. The lane's own commits are activity; a lane with nothing left to draft is not, and the workflow then needs to be enabled again by hand.
- **A protected branch needs an exception.** The scheduled run commits to the branch it started from. Where `main` requires a pull request, give GitHub Actions a place in the rule's bypass list, or the run stops at its last step and publishes nothing ([CONTRIBUTING](../CONTRIBUTING.md#rasd-agents-lane)).
- **ATT&CK is MITRE's.** Technique names and identifiers are reproduced under the ATT&CK terms of use ([licence](../intel/mappings/ATTACK_LICENSE.txt)); descriptions are read from the bundle at run time and never stored.
