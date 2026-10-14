# Writing Detections

## Quality bar

A detection is merged only when **all** of the following are true:

- [ ] It targets a **behaviour**, not a single tool name, hash or IP.
- [ ] It has at least one `true_positive` sample taken from real emulation (or faithfully reconstructed from it).
- [ ] It has `true_negative` samples representing the **closest benign activity** you can find, not unrelated events.
- [ ] Every filter is justified by a true-negative test case (CI enforces this).
- [ ] It has a complete `contract.yml`: required events and fields, telemetry risks, 2+ blind spots, coverage depth with a reason, triage and response.
- [ ] Techniques with known evasion tricks ship `tests/mutations.yml`.
- [ ] It has a `tuning.yml`: every filter in the rule recorded as an applied tuning, proposals measured with `rasd tune`.
- [ ] `rasd prove` kills every rule mutant (or the survivor is accepted as equivalent with a written reason).
- [ ] `rasd parity` shows zero divergences for KQL and SPL.
- [ ] A red test in `red/` produces its telemetry, and that test's sample event is one of the rule's true positives.
- [ ] Its README documents logic, **evasion gaps** and tuning.
- [ ] `rasd ci` passes and generated files are committed.

## Correlation detections

When the attack is only visible in aggregate - many accounts, many service tickets, many hosts - write a Sigma correlation in `detect/correlations/<Technique>_<name>/` instead ([format, semantics and proofs](CORRELATIONS.md)):

- [ ] The **base rule** (`base.yml`, with a `name:`) keeps exactly the events worth counting, with filters and tests like any rule; `correlation.generate` is `false`.
- [ ] **Scenarios** cover the threshold exactly, one below it, many sources each below it, one value repeated (for `value_count`), a slow burst inside one window, and every normalisation the group-by relies on.
- [ ] `rasd correlate` kills every **parameter mutant** with a verdict flip, shows zero **aggregation parity** divergences, and the README states the **burst guarantee**.
- [ ] Known limits of tumbling windows are pinned as `known_limit` scenarios, not hidden.

## Conventions

| Item | Convention |
|---|---|
| Folder | `<TechniqueID>_<snake_case_name>`, e.g. `T1003.001_lsass_memory_access` |
| Rule ID | Random UUIDv4, never reused |
| Tags | Tactic tags plus at least one `attack.tXXXX` tag matching the folder |
| Status | `experimental` → `test` (passes CI) → `stable` (in production 30+ days with acceptable FP rate) |
| Selections | `selection_*` for what to match, `filter_*` for exclusions, `susp_*` for alternative indicators combined with `1 of susp_*` |
| Paths | Match with `endswith '\binary.exe'`, never `contains 'binary'` |

## Writing good tests

Each line in a `.jsonl` file is one event. Use field names as they appear in Sysmon / Windows logs, and add a `_case` field describing what the sample represents. It appears in the test report.

```json
{"_case": "renamed binary caught via OriginalFileName", "EventID": 1, "Image": "C:\\Users\\Public\\svc.exe", "OriginalFileName": "PowerShell.EXE", "CommandLine": "svc.exe -EncodedCommand VwBy..."}
```

The most valuable true-negative cases are the ones that **almost** match:

- the same binary doing something legitimate,
- the same command-line flag in a different program,
- the known management agent that uses the same technique.

## Writing the contract

The contract is what other teams read, so write it for them:

- **required_fields**: every field the rule matches on. CI fails if the rule uses one you did not declare.
- **telemetry_risk**: what breaks the rule if missing or truncated, rated low to critical.
- **blind_spots**: concrete procedures the rule cannot see. These become the purple-team backlog.
- **coverage_depth**: `partial` when only some procedures are covered, `high` when the outcome is caught regardless of method. Always give the reason.
- **triage / response**: short, imperative, ordered. Evidence before containment.

- **risk_model**: a base score and the conditions that raise or lower it, taken from [`detect/risk_conditions.yml`](../detect/risk_conditions.yml). `auto` conditions are resolved by `rasd replay`; `analyst` conditions become questions on the triage card.
- **response**: `l1_action`, `l2_action` and `ir_action` say who does what; then evidence before containment.
- **maturity**: never higher than what `rasd chain` computes (CI enforces it).

After editing a contract, run `rasd build` and commit the regenerated cards.

## Writing mutations

```yaml
mutations:
  - name: ru_before_s            # snake_case, describes the variant
    base: 3                      # 1-based line in true_positive.jsonl to copy
    set: {CommandLine: "schtasks /create /ru SYSTEM ... /s FS01"}
    should_match: true           # false for benign look-alikes
```

Good mutations come from how the program parses input (abbreviations, prefixes, ordering, quoting), not random noise.

## Proving the rule

```bash
rasd test --filter T1218          # true positives match, true negatives do not
rasd prove --filter T1218 --suggest   # every value, field and branch is needed by a test
rasd fuzz --filter T1218 -v       # automatic evasion variants
rasd parity --filter T1218        # the KQL and SPL behave like the rule
rasd explain T1218 --tp 3         # why an event matched, field by field
rasd diff --base origin/main      # which events change verdict in this pull request
```

`rasd prove --suggest` prints a candidate event for each surviving mutant - edit it for realism, then add it as a true positive or true negative.

## Common mistakes

1. **Filtering a whole directory** (`C:\Windows\System32\`) and accidentally excluding the LOLBin you are trying to catch. See the LSASS rule for the right pattern.
2. **Matching literal flags** (`-enc`) when the program accepts abbreviations and alternative prefixes.
3. **Matching the image name only**: attackers rename binaries. Add `OriginalFileName`.
4. **No negative tests**: a rule that matches everything passes every positive test.
5. **Dead filters**: a filter for something the selection never matches. Harmless today, misleading tomorrow. The filter coverage gate catches it.
6. **Untested list values**: a value in a list that no test depends on can be deleted without CI noticing. `rasd prove` finds every one.
7. **Regex that only Python accepts**: lookarounds and backreferences pass the offline tests and then fail in Sentinel (RE2). The linter rejects them.
8. **Assuming `|re` ignores case**: by the Sigma specification it does not. Command lines, paths and registry keys on Windows are case-insensitive, so start every such pattern with `(?i)` (or use `|re|i`). The engine, pySigma and both SIEM backends then agree, and the linter warns about a case-sensitive pattern.
9. **Quoting and dash variants**: Windows strips quotes during argument parsing (`"-enc"` is `-enc`), PowerShell 7 accepts `--`, and both accept en dash, em dash and horizontal bar as `-`. The fuzzer generates all of them.
