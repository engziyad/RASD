# Governance of RASD-Agent's Lane

RASD-Agent drafts candidate detections with no person in the loop ([GROW](GROW.md)). This page is about everything that happens after a draft: who may decide that a candidate is right, what is recorded, what the agent can never do, and how a decision is undone.

One rule holds the rest together:

> **The agent drafts. A person decides. Passing every test is not a decision.**

```bash
rasd review                                   # the board: every candidate and where it stands with people
rasd review T1105                             # the dossier of one candidate, with what only a person can judge
rasd review --logs export.jsonl               # the board beside your own logs: what fires, and what the core says nothing about
rasd review T1105 --logs export.jsonl         # the dossier with the events of your logs the rule fires on
rasd review T1105 --approve --by "Your Name" --rate logic=5 telemetry=5 noise=4 mapping=5
rasd review T1105 --revise  --by "Your Name" --note "what to change"
rasd review T1105 --reject  --by "Your Name" --note "why it is wrong"
rasd review T1105 --promote --by "Your Name"  # approved only: it becomes the start of a core detection
rasd review --rollback RUN --by "Your Name" --note "why"
rasd review --audit                           # the trail, and whether its chain holds
rasd review --check                           # the records hold together (in CI)
```

## Who can do what

| | RASD-Agent, unattended | A person |
|---|---|---|
| Draft a candidate into `detect/candidates` | yes, through every gate | yes, with `rasd grow --run --drafts` |
| Approve, send back or reject a candidate | **no** | `rasd review` |
| Put a rule into the core library | **no** | `rasd review --promote`, after an approval of that exact text |
| Put a rule into a generated query or the Splunk app | **no**: they are built from the core only | by promoting it |
| Change `agent/reviews.yml` | **no**: the run fails | through `rasd review` |
| Change or remove a line of the audit trail | **no**: the run fails | not without breaking the chain |
| Change the front page, a core rule, a test, a tool or a workflow | **no**: the run fails | through a pull request, like any change |
| Take a candidate out | when a gate stops accepting it | `--reject`, `--withdraw`, `--rollback` |

The left column is enforced, not promised. Before an unattended run publishes anything, `rasd grow --guard` fails it if any file outside the lane's own differs from the last commit, and the review ledger is not one of the lane's files. The Splunk app and every generated query are built from `detect/detections` and `detect/correlations`; `rasd review --check` fails the build if a candidate's name or rule id appears in any of them, or if a rule drafted by the agent sits in the core with no promotion on record.

## A review

The gates prove that a rule is well-formed, catches its own examples under every variation, agrees with its SIEM queries and holds no untested part. They cannot know whether the rule means what the technique means. `rasd review <candidate>` puts on one page what a reviewer needs to judge that:

| On the page | Why |
|---|---|
| The rule, and **what it will never alert on** | Every exclusion, listed first. An exclusion is found by what the condition does, not by how a selection is named |
| The events it fires on and stays quiet on | The examples the model chose, and the ones the proof added |
| What the gates measured | Rule mutants killed, attacker variations matched, parity events |
| Four questions only a person can answer | **logic**: does it describe the technique or only its examples · **telemetry**: are the log source and fields right · **noise**: would it stay quiet on ordinary administration · **mapping**: are the technique and the severity right |
| With `--logs`, the events of your own telemetry it fires on | Something to answer **logic** and **noise** from: an export goes through the candidate exactly as `rasd replay` puts it through the core, and the events a core detection alerts on as well are counted apart. The board lists first the candidates that fire. Nothing is written, and a candidate that fires on your logs is still a candidate |

A verdict is recorded in [`agent/reviews.yml`](../agent/reviews.yml) with the reviewer's name, the date and the **SHA-256 of the rule text that was judged**:

- **approve** – the candidate may be promoted. It is still outside the core until someone does.
- **revise** – it stays in the lane, marked, and cannot be promoted.
- **reject** – it leaves the lane, and the next draft of its technique is given the reviewer's words.

A review stands only for the text it judged. If the rule changes afterwards, by the agent or by anyone, the review no longer counts: the page says `not reviewed (an earlier text was)` and promotion is refused.

## Promotion

`rasd review <candidate> --promote` needs a standing approval. It copies the rule and the tests into `detect/detections` byte for byte, so the text in the core is the text that was approved, and scaffolds the contract, tuning guide, mutation tests and README with the candidate's own notes and `TODO` marks. CI refuses the detection until a person has written them. From there it is a core detection like any other: lab evidence, behaviour specification and all.

## The audit trail

[`agent/audit.jsonl`](../agent/audit.jsonl) holds one line for every decision taken in the lane, by either side:

| Event | Signed by | Recorded |
|---|---|---|
| `drafted` | RASD-Agent | candidate, technique, SHA-256 of the rule, the run, a fingerprint of the model's configuration, SHA-256 of the request and of the answer |
| `refused` · `declined` | RASD-Agent | technique, the gate's reason, the run |
| `retired` · `set_aside` | RASD-Agent | candidate, why a gate or the pipeline stopped accepting it |
| `reviewed` | a person | candidate, SHA-256 of the rule, verdict, note |
| `promoted` | a person | candidate, the core detection, SHA-256 of the rule, who approved it |
| `withdrawn` | a person | candidate, reason |
| `backfilled` | RASD-Agent | a candidate that was in the lane before the trail was kept |

Each line carries the SHA-256 of the line before it. A line edited, removed or moved breaks the chain at that point, and `rasd review --audit` says where. An unattended run may only add lines at the end; anything else fails its guard. The trail records a fingerprint of the model's configuration, never its name: enough to tell two models apart and to roll one back.

## Undoing

| To undo | Command | What happens |
|---|---|---|
| One candidate | `rasd review <candidate> --withdraw --by … --note …` | It leaves the lane; its technique returns to the queue with the reason |
| Everything one run drafted | `rasd review --rollback <run> --by … --note …` | Every candidate that run wrote, and that still holds that text, leaves the lane |
| An approval | review it again: `--revise` or `--reject` | The latest review of the current text is the one that stands |
| A promotion | a normal revert of the commit | The core is changed only through pull requests, like every other detection |

## What a draft cannot smuggle in

The model is given text it did not write: the technique's description from a public catalogue, and the reason its last draft was refused. Both are marked as reference material, flattened to one line and cut at a length, and the instructions say they are never instructions. That is a courtesy. The control is that **whatever a model is talked into, its answer still has to pass the gates**, and the gates refuse:

| A draft that | Is refused because |
|---|---|
| Excludes a user, a host, an address or a logon session | An exclusion says what a program is or does, never who ran it or where. That decision belongs to the person who promotes the rule |
| Hides an exclusion under a name like `selection_ok` | Exclusions are found from the condition's behaviour and must be named `filter_…`, so the reviewer sees every one |
| Carries a link, an image, a table bar or a bracket in any text | Titles, descriptions, notes and case labels are plain sentences: nothing in a candidate's page is clickable but what the tool wrote |
| Names its folder to leave the lane (`../…`) | A name is a few lowercase words |
| Reads a field the log source does not write, or one spelled with look-alike letters | The vocabulary of each log source is fixed |
| Uses a regular expression that repeats a repeating group | It can stall a search engine on one event |
| Holds more than ten selections, a time window, a non-printable character, an oversized value | A candidate is one event and one screen |

Each row is a test in `tests/test_governance.py`, written as the hostile draft itself.

## Measuring the agent against people

Every review is a measurement of what the gates let through. `rasd review` prints, from the ledger: how many candidates people have reviewed, how many were right as drafted, sent back or rejected, the mean of each of the four ratings, and, where two people reviewed the same text, how often they agreed. The lane's page states the same numbers.

**No review has been written to fill that table.** The candidates in the lane are listed as not reviewed until a person reviews them.

## Limits

- A review is a person's word with a name on it. RASD records who and when and binds it to the text; it does not verify the reviewer's identity. In a repository with protected branches, the pull request that carries the review is that verification.
- The gates and the hostile-draft tests cover what could be thought of. A reviewer reading the exclusions and the examples is the control for what was not.
- The trail proves that nothing was changed after it was written. It cannot prove that something was written at all; that is why `rasd review --check` also requires every candidate and every review to have its line.
- Candidates are not validated in a lab, whatever their review says. Lab evidence starts after promotion ([evidence plan](EVIDENCE_PLAN.md)).

<sub>RASD · Continuous Detection Assurance Framework</sub>
