# Contributing to RASD

Every change reaches `main` through a branch and a pull request. `main` is protected: no direct pushes, and the CI gate must pass before a merge. A change is never published to `main` on a schedule or by hand without the gate.

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
| Full CI | `rasd ci`: lint, unit tests, mutations, fuzz, rule proofs, parity, certify, correlate, nearmiss, tune, red, Splunk app, profiles, datasets, build, chain, links |
| Formal proofs and certificates | `rasd certify --check` (inside `rasd ci`): every rule compiles to exact automata, every behaviour spec gets its expected verdict, and the certificate pages are current |
| Differential | `rasd parity` (the generated SPL and KQL match the engine) and `rasd diff --base origin/<base>` (the events whose verdict changes in this PR) and `rasd certify --equiv origin/main` (the rule's own meaning across the edit) |
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

## Keep out of the repository

Synthetic data and lab evidence only. No secrets, no employer or work telemetry, no production data, and no vendor product names.
