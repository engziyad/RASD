# Contributing to RASD

Every change a person makes reaches `main` through a branch and a pull request. `main` is protected: no direct pushes, and the CI gate must pass before a merge. A change is never published to `main` on a schedule or by hand without the gate. One lane is published without a person, behind the same gate and held to its own files: [RASD-Agent's lane](#rasd-agents-lane).

## The flow

1. Branch from an up-to-date `main`:
   ```bash
   git checkout main && git pull --ff-only origin main && git checkout -b <topic>
   ```
2. Make the change. For a rule change keep its tests, its `behavior.yml` and the generated files in step.
3. Run the gates locally before pushing:
   ```bash
   rasd ci                                   # the full pipeline (see the gates below)
   rasd certify --equiv origin/main          # for a rule change: meaning preserved, or the changed event is intended
   rasd build                                # commit any regenerated files
   ```
4. Push the branch and open a pull request. The [pull request template](.github/pull_request_template.md) lists the gates; paste the proof output.
5. CI runs on the pull request: the full pipeline, the Python 3.10 and 3.13 compatibility matrix, and the semantic diff against the base branch. A red gate blocks the merge.
6. Review, then merge. Never push to `main` directly.

## The gates

Each step of a safe release maps to a check CI already enforces.

| Release step | Enforced by |
|---|---|
| Verify base | the branch is up to date with `main`; the working tree is clean |
| Full CI | `rasd ci`: lint, unit tests, mutations, fuzz, rule proofs, parity, certify, correlate, nearmiss, tune, red, deceive, trace, silence, blindpath, grow, Splunk app, profiles, datasets, evidence, health, review, build, chain, advise, links |
| Formal proofs and certificates | `rasd certify --check` (inside `rasd ci`): every rule compiles to exact automata, every behaviour spec gets its expected verdict, and the certificate pages are current |
| Differential | `rasd parity` (the generated SPL and KQL match the engine) and `rasd diff --base origin/<base>` (the events whose verdict changes in this PR) and `rasd certify --equiv origin/main` (the rule's own meaning across the edit) |
| Lab evidence still holds | `rasd evidence --check` (inside `rasd ci`): every `evidence.md` that cites a lab run kept in [`purple/lab_runs`](purple/lab_runs/README.md) is, byte for byte, what that run gives with the rules of this change. A rule edited until it no longer fires on its run fails here |
| No stale output | the "generated files are out of date" check fails the build until `rasd build` is committed |

If any gate is red the release is blocked: fix it on the branch, never merge around it. An inconclusive result (a refused construct, a search that hit a limit) is not a pass.

## Protect `main` (one time, repository owner)

GitHub UI: **Settings -> Branches -> Add branch protection rule** (or a ruleset) for `main`:

- Require a pull request before merging.
- Require status checks to pass before merging, and require branches to be up to date first. Select the RASD CI checks once they have run on a pull request (the `RASD CI` workflow's jobs).
- Optionally, do not allow administrators to bypass the above.

With the GitHub CLI (confirm the exact check name from the first pull request's **Checks** tab, then):

```bash
gh api --method PUT -H "Accept: application/vnd.github+json" \
  /repos/engziyad/RASD/branches/main/protection \
  -F "required_status_checks[strict]=true" \
  -F "required_status_checks[checks][][context]=RASD · Red → Detect → DFIR → Intel → Purple" \
  -F "enforce_admins=false" \
  -F "required_pull_request_reviews[required_approving_review_count]=0" \
  -F "restrictions=null"
```

## RASD-Agent's lane

[`detect/candidates`](detect/candidates/README.md) is grown by RASD-Agent with no person in the loop ([GROW](docs/GROW.md)). The scheduled workflow [`agent-grow.yml`](.github/workflows/agent-grow.yml) commits to `main` on its own, under four conditions the workflow enforces and unit tests hold in place:

- **The same gate.** It runs `ruff`, `mypy` and the whole of `rasd ci` on the exact tree it is about to commit, and checks that the build leaves that tree as it is. A red gate publishes nothing.
- **Its own files only.** `rasd grow --guard` fails the run when anything differs from the last commit outside the lane's folder, its ledger (`agent/growth.yml`), new lines at the end of its audit trail (`agent/audit.jsonl`), the ATT&CK reference (`intel/mappings/attack_enterprise.json`) and the four generated pages that state the lane's numbers or name its candidates. It cannot change the front page, a core rule, a test, a tool or a workflow.
- **Never a person's decision.** The review ledger (`agent/reviews.yml`) is not one of the lane's files: a run that changed it is refused. Approving a candidate and promoting it into the core are done by a person with `rasd review` ([GOVERNANCE](docs/GOVERNANCE.md)).
- **Off until configured.** The job is skipped while the repository variable `RASD_MODEL` is unset.

A candidate is promoted into the core by a person: `rasd review <candidate> --promote` after an approval of its exact rule text, then a branch and a pull request like any detection. With `main` protected as below, the workflow's push needs an exception for GitHub Actions in the rule's bypass list; without one the lane stays where its last run left it and the run says so.

## Lab runs

A detection becomes Validated through a lab run, never through an edit. [`lab-run.yml`](.github/workflows/lab-run.yml) is started by a person from the Actions tab, runs the safe default steps on hosted runners that exist for one run, and pushes the evidence with the raw runs as a branch `lab-evidence/run-<id>`: open a pull request from that branch like any other change. With `accept` typed in its **splunk** box it also puts a live Splunk Enterprise beside each host and brings the alerts back with the run; that word is the acceptance of Splunk's terms by the person who types it, so nobody types it for someone else. It never pushes to the branch it ran from, and it never runs the opt-in steps (LSASS memory, Security-log clear): those and the domain controller need a lab of your own ([lab kit](red/lab/README.md)). Keep a run in `purple/lab_runs` only when every file in it may be public.

## Keep out of the repository

Synthetic data and lab evidence only. No secrets, no employer or work telemetry, no production data, and no vendor product names. The decoy identities in `deceive/decoys.yml` are lab examples: never commit the identities of decoys deployed in a real environment (`rasd deceive --rename` works on your own copy, not on a pull request).
