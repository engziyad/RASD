# RASD Pull Request

## Change Type
- [ ] Red validation
- [ ] New detection
- [ ] Detection tuning
- [ ] New test cases
- [ ] Mutation coverage
- [ ] DFIR playbook
- [ ] CTI mapping
- [ ] Purple scenario
- [ ] Documentation
- [ ] SIEM mapping

## Checklist
- [ ] Red validation updated
- [ ] Expected telemetry documented
- [ ] rule.yml updated
- [ ] contract.yml updated
- [ ] TP/TN tests added
- [ ] mutations added
- [ ] SPL/KQL generated
- [ ] triage.md updated
- [ ] response.md updated
- [ ] CTI mapping updated
- [ ] Purple scenario updated
- [ ] Evidence status reviewed
- [ ] Engineering and Operational Scores reviewed

## Proof
Paste the relevant output:

```text
rasd ci
rasd diff --base origin/main --fuzz
```

<!-- CI blocks the merge on: failing tests, surviving rule mutants, parity divergences, new evasion bypasses,
     risky proposed tunings, maturity over-claims, chain gaps, broken links, or stale generated files. -->
