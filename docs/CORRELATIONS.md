# Correlation Detections

Some attacks are invisible one event at a time. One failed logon is a typo; one failed logon for each of nine accounts from one workstation in eight seconds is a password spray. One service ticket is normal; tickets for every service account in the domain from one client is Kerberoasting. RASD expresses these as **Sigma correlation rules** (Sigma specification v2) and proves them as hard as every single-event rule.

| Correlation | Condition | Base rule |
|---|---|---|
| [Password Spray - One Source Failing Authentication for Many Accounts](../detect/correlations/T1110.003_password_spray_burst/) | 5+ distinct `TargetUserName` per `IpAddress` in a 10-minute window | failed authentication: 4771 `0x18` (wrong password), 4768 `0x6` / `0x12` (unknown or disabled account), 4625 `0xC000006A` / `0xC0000064` (wrong password, no such user); machine accounts and local sources excluded |
| [Kerberoasting - One Client Requesting Tickets for Many Service Accounts](../detect/correlations/T1558.003_kerberoasting_volume/) | 5+ distinct `ServiceName` per `IpAddress` in a 10-minute window | successful service tickets for user-based accounts, any encryption |
| [API Probing - One Client Rejected on Many Distinct Paths](../detect/correlations/T1595.003_api_auth_probing/) | 5+ distinct `cs-uri-stem` per `c-ip` in a 5-minute window | web requests answered 401 or 403, CORS preflights excluded |
| [Object ID Enumeration - One Client Walking Single-Owner Objects](../detect/correlations/T1190_object_id_enumeration/) | 3+ distinct `cs-uri-stem` per `c-ip` in a 1-minute window | `GET` of a single-owner object (basket, user, account, profile, wallet) by numeric ID |

The web correlations read access logs with the W3C / Sigma webserver field names (`c-ip`, `cs-uri-stem`, `sc-status`); [`tools/mappings.yml`](../tools/mappings.yml) renames them to plain column names for each SIEM (`clientip` / `cIP`), so the generated queries stay valid.

## Folder

```text
detect/correlations/<Technique>_<name>/
├── correlation.yml   the Sigma correlation rule: type, rules, group-by, timespan, condition
├── base.yml          the base rule it counts - a normal Sigma rule with a `name:`, never an alert on its own
├── contract.yml      as for every detection, with detection_logic.type: correlation
├── tuning.yml        every filter of the base rule as an applied tuning; proposals; never-tune rules
├── triage.md · response.md · closure.md · README.md
└── tests/
    ├── true_positive.jsonl · true_negative.jsonl   single events for the base rule
    ├── mutations.yml                               technique mutations of the base rule
    └── scenarios.yml                               event sequences that must fire, or stay silent
```

```yaml
# correlation.yml
correlation:
  type: value_count            # or event_count
  rules: [auth_failure]
  group-by: [IpAddress]
  timespan: 10m                # minutes dividing an hour, or hours dividing a day
  condition: {gte: 5, field: TargetUserName}
  generate: false              # the base rule never alerts alone
```

## Semantics

Identical in the offline engine, the generated SPL and the generated KQL - and proven identical:

- **Windows are tumbling and aligned to the clock**: 10:00-10:10, 10:10-10:20 (UTC). A timespan is whole minutes dividing an hour (1-60) or whole hours dividing a day (1-24), so Splunk (`bin span=600s`, aligned to the epoch) and Sentinel (`bin(TimeGenerated, 600s)`) cut the windows at the same instants, and a cron schedule can run once per window.
- **Missing or empty values are ignored**: an event without a group-by value, or without the counted value, is not counted.
- **Values are compared exactly**, as `dc()` and `make_set()` do, after the normalisations in [`tools/mappings.yml`](../tools/mappings.yml) (`correlation.normalize`). Kerberos events log an IPv4 client as `::ffff:10.0.0.5` and logon events as `10.0.0.5`; without normalisation one spraying host would split into two groups, and each half could stay under the threshold.
- **Exact distinct counts in KQL**: `array_length(make_set(F))`, not `dcount()`, which is a HyperLogLog estimate and could miss a threshold.
- **Field names**: offline, the engine and the parity models read field names case-insensitively, while SIEM columns are case-sensitive. The linter checks every rule field against the log source's vocabulary, and exports from other pipelines go through a [telemetry profile](../profiles/README.md) that gives the fields their rule names.

## Scenarios

`tests/scenarios.yml` describes sequences compactly. Each event is `defaults` plus its own fields, `at` seconds after the scenario's `start`; `count` and `every` repeat an entry; `set` fills `{n}` with 1, 2, 3...; `Field: null` removes a default.

```yaml
defaults: {Channel: Security, EventID: 4771, Status: '0x18', IpAddress: '::ffff:10.0.0.21'}
scenarios:
  - name: one user with a stale saved password retrying twelve times
    expect: silent
    start: '2026-10-12T08:30:00Z'
    events:
      - {at: 0, every: 30, count: 12, TargetUserName: omar}
  - name: six accounts split 3 + 3 by a window boundary
    expect: silent
    known_limit: Tumbling windows cut a burst at the boundary; 9 or more accounts always alert
    start: '2026-10-12T10:07:00Z'
    events:
      - {at: 0, every: 60, count: 3, set: {TargetUserName: 'lab.user{n:02d}'}}
      - {at: 240, every: 60, count: 3, set: {TargetUserName: 'lab.user1{n}'}}
```

`expect: fire` can pin the alerting groups (`groups: ['10.0.0.21']`) and the number of alerts (`alerts: 1`). A `known_limit` scenario documents a real blind spot as a test, so the limit cannot change unnoticed.

## What `rasd correlate` proves

| Check | What fails it |
|---|---|
| Rule | Malformed `correlation.yml`; `rules` not naming the base rule; `generate` not false; base rule lint errors; a field the correlation groups or counts missing from the contract; a filter without a true negative or an applied tuning |
| Base rule | A true positive that does not fire, a true negative that does, a fuzzer variant that evades it, a base-rule mutant no test kills (as `rasd prove`), a KQL / SPL filter that differs from the rule (as `rasd parity`) |
| Scenarios | A sequence that does not fire or stay silent as declared |
| Parameter mutants | Threshold +1 and -1, window x2 and /2, each group-by field dropped, events counted instead of distinct values, each normalisation dropped - each one must get at least one scenario wrong: a verdict that flips (preferred, and required for every shipped correlation by the test suite), or a different alerting group or number of alerts. A mutant that survives is a parameter no test defends |
| Aggregation parity | The generated SPL and KQL are parsed back from their text and run with each SIEM's semantics - `where` keeps only true, `eval` / `extend` (an empty string an SPL `eval` produces is a value, not null), `bin`, `stats by` drops null groups while `summarize by` keeps `""`, exact distinct counts. They must return the engine's alerts exactly (window, group, count, event count, first and last event) on every scenario and 150 seeded random sequences, for the correlation **and for every mutant** |
| Burst guarantee | See below |
| Queries | `queries/{spl,kql}/correlations/<id>.*` differ from the generator (`--check`) |

The parity models have teeth: the test suite injects fourteen classic converter bugs - a lost normalisation, a missing not-null or not-empty test, the wrong span, `count` instead of `dc`, an off-by-one threshold, a dropped group-by, binning `_time` in place, a field read without its EventData extraction - and each one is caught.

## Burst guarantee

Tumbling windows can split a burst at a boundary. For a threshold T, a burst of n distinct values inside one window length always leaves ceil(n/2) on one side of any boundary, so:

- **2T-1 always alerts**, whatever the alignment: 9 for T = 5.
- **2T-2 can be split** (T-1 / T-1) so that nothing alerts: 8 for T = 5.

The arithmetic is the proof; `rasd correlate` also checks both with the engine - the burst at 120 alignments x 3 spreads, and the split - and every correlation README states its guarantee. It is why the lab password spray uses 9 or 10 accounts, and why a tuning guide must never raise a threshold without re-reading it. In real traffic, `rasd nearmiss` lists the bursts a boundary did split: a group that reached the threshold within one window length of sliding time but in no single clock window.

## In the SIEM

- **Splunk**: the [RASD app](../queries/splunk_app/README.md) runs each correlation once per window length over the last two windows plus 3 minutes of indexing delay - for the 10-minute correlations `*/10 * * * *` over `-23m@m` to `-3m@m`, for API probing (5 minutes) `*/5` over `-13m@m`, for object-ID enumeration (1 minute) `*/1` over `-5m@m` - and keeps only the most recent window that is complete inside that range (for a 10-minute window: `| addinfo | where window_start>=info_min_time AND window_start+600<=info_max_time AND window_start+600>info_max_time-600`). Consecutive runs tile time, so each window is reported whole by exactly one run - with the search head in UTC or any fixed-offset time zone, even one whose local cron times are not window boundaries (+5:30, +5:45) - and `realtime_schedule = 0` catches up a skipped run. Where the search head observes daylight saving, a window can be dropped or repeated at the two transitions each year; run it in UTC to avoid that. Events indexed more than 3 minutes late are missed by the alert. It alerts once per window and group, and writes the group (the client address) as `alert_host` to `rasd_alerts`, so `rasd evidence` can bind the alert to the lab host.
- **Sentinel**: schedule each KQL query every window length with a lookback of two windows (every 10 minutes over 20 for the spray and Kerberoasting by volume, 5 over 10 for API probing, 1 over 2 for object-ID enumeration), so every window is seen whole at least once, and group alerts on `window_start` and the group-by fields, so a window seen by two runs raises one incident. For an at-least condition a window cut by the lookback can only count less, never invent an alert. Widen the lookback when ingestion is slower than the margin it leaves.

## Everywhere else

| Command | What it does with correlations |
|---|---|
| `rasd correlate --logs export.jsonl` | Correlation alerts in your own logs (with `--profile` for ECS, CIM, ASIM, Defender) |
| `rasd replay` | Correlation alerts join the storyline of the host they came from, timed at the event that reached the threshold |
| `rasd evidence` | A step's `correlations` fire only on alerts that belong to the run: grouped by client, every client value of the group must be the emulation host (one of its addresses or names); grouped by the target or not at all, only events whose activity came from the host are counted. A spray from another client, even one aimed at the host, never counts. Evidence records the window, group, count and the moment the threshold was reached |
| `rasd nearmiss` | Threshold headroom: the highest count a quiet window reached; windows one below the threshold, with the single-event rules that still caught them; and bursts a window boundary split |
| `rasd doctor` | Readiness through the base rule, with the fields the correlation groups and counts |
| `rasd benchmark` | Events per second through every correlation |
| `rasd chain` · `score` · `coverage` | Maturity, Engineering Score, the 20-point map and the ATT&CK layer count correlations like rules |
