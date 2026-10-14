# Enterprise Adoption

How an organisation brings RASD's detections into its own SIEM without importing risk: check the telemetry first, measure noise on its own logs, deploy in stages, and prove each rule in a lab before relying on it.

## Before you start

| Need | Why |
|---|---|
| The log sources the rules read: Sysmon (Windows and Linux), Windows Security and System logs, web access logs | `rasd doctor` reports READY, DEGRADED or BLIND per rule on an export of your own logs |
| Splunk or Microsoft Sentinel | Queries are generated for both and proven equal to the tested rules |
| A lab you own | Offensive tests run only on disposable lab machines, never on production hosts or accounts |
| An owner per detection | Each contract names an owner, and each `tuning.yml` sets a review cadence |

## 1 · Check the telemetry

Export a day of logs from the SIEM in JSON lines, then:

```bash
rasd doctor export.jsonl --profile auto
```

`--profile auto` reads Elastic ECS, Splunk CIM, Sentinel ASIM or Defender field names, and Security 4688 where Sysmon is not deployed ([profiles](../profiles/README.md)). Deploy the rules that come back READY. A DEGRADED rule names the missing or truncated field; a BLIND rule names the missing source.

When no public profile fits (a product's own schema, an in-house pipeline), add a profile for it in your own copy of the repository, not in the public one. Name it by its role, never by a product or an organisation: `edr-generic`, `email-gateway-generic`, `ndr-generic`, `dlp-generic`, `pam-generic`, `iam-generic`, `waf-generic`, `database-activity-generic`. A profile only fills fields the events lack (see the [profile format](../profiles/README.md)), so `rasd doctor --profile <name>` shows at once which rules it makes READY. Vendor-specific mappings and anything that names an employer's tools belong in a private fork or an internal branch.

## 2 · Measure noise on your own logs

```bash
rasd replay export.jsonl --profile auto --assets assets.csv --users users.csv --html replay.html
rasd nearmiss
rasd tune
```

The replay gives the alert volume per rule on your traffic, with the contract's risk score per alert; `--case-dir reports/cases` adds a case folder per attack storyline for the analysts ([DFIR](../dfir/README.md#from-replayed-logs-to-a-case)). Near misses show the activity one field away from an alert. `rasd tune` measures every proposed filter: the attack variants it would hide against the alerts it removes.

## 3 · Map the queries to your SIEM

Table and field names live in one file, [`tools/mappings.yml`](../tools/mappings.yml). Change them there and run `rasd build`; `rasd parity` and `rasd correlate` then prove the regenerated queries still return what the rules return. Specifics per SIEM: [SIEM deployment notes](SIEM_DEPLOYMENT_NOTES.md).

## 4 · Deploy in stages

1. Schedule the queries as searches that only record results, for one or two weeks.
2. Compare the volume with the replay forecast. Tune through `tuning.yml` and its tests, not inside the SIEM alone, so the change is measured and kept.
3. Turn alerting on rule by rule, starting with the high-severity, low-noise detections.
4. Name every SIEM rule after its detection id. Alerts then match back to the rule, its triage card and its evidence.

## 5 · Prove each rule

Run the detection's offensive step in the lab and give the run's zip and exports to `rasd evidence --run` ([evidence plan](EVIDENCE_PLAN.md)). A detection reaches Validated only when its `evidence.md` is committed, and the evidence file names the run, the host, the matching event and the hash of every input.

## Roles

| Role | Works from |
|---|---|
| SOC L1 | [Triage cards](views/SOC_L1.md): what fired, first checks, when to escalate |
| SOC L2 | Response cards, closure and escalation notes per detection (`closure.md`), [DFIR playbooks](../dfir/playbooks/) |
| Incident response | [Evidence and containment](views/Incident_Response.md), [DFIR templates](../dfir/templates/) |
| Detection engineering | Rules, tests, mutation proof, parity, near misses, tuning impact |
| GRC and audit | [Control evidence register](views/GRC_Audit.md), stated limitations, hashed evidence files |
| Purple team | Offensive tests, [blind spots per detection](views/Purple_Team.md), [validation matrix](../purple/validation_matrix.md) |

## Change control

- Every rule change runs the full pipeline: tests, rule mutation proof, query parity, correlation proofs, near-miss gate and the drift check on generated files.
- `rasd diff --base <tag>` lists the events whose verdict changes between two versions; a lost true positive fails the command.
- A false positive closed by an analyst goes back to detection engineering as a true-negative test case, so the fix stays fixed.

## Data handling

- Never commit production logs. The samples in this repository are synthetic, and `datasets/extracts` holds reduced events from public attack datasets under their own licenses.
- Keep raw lab exports outside the repository. Commit only `evidence.md`, which carries their SHA-256.
- The lab Sysmon configuration in `red/lab` is verbose on purpose. Do not deploy it to production.

## What to measure

| Measure | Source |
|---|---|
| Rules READY on your telemetry | `rasd doctor` on a fresh export, each quarter |
| Alerts per day per rule, against the forecast | The SIEM, `rasd replay` |
| Detections with lab evidence | [Evidence matrix](../purple/evidence_matrix.md) |
| Time from attack step to SIEM alert | [Detection latency](../purple/detection_latency.md) |
| False positives closed per rule, and the test cases added for them | Closure notes, `tests/true_negative.jsonl` |
