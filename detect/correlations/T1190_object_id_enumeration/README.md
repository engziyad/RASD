# Object ID Enumeration - One Client Walking Single-Owner Objects

<!-- rasd:facts:start -->
| | |
|---|---|
| **ATT&CK** | [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing Application (initial-access) |
| **Severity** | `high` |
| **Type** | Sigma correlation · >= 3 distinct cs-uri-stem per c-ip in 1m windows · base rule [`web_object_id_request`](base.yml) |
| **Maturity** | **SIEM-Ready** ([model](../../../docs/RASD_MATURITY_MODEL.md)) |
| **Engineering Score** | 100/100 · operational pending - [run the lab](../../../docs/OPERATIONAL_VALIDATION.md) |
| **Tests** | base rule: 5 true positive · 6 true negative · 5 technique mutations · 10 scenarios (4 fire, 6 silent) |
| **Proof** | base rule: 100% of 2 mutants killed · fuzzer n/a (no evasion strategy applies to its fields) · correlation: 5/5 parameter mutants killed |
| **Behaviour proof** | base rule: 1 of 3 variants proven for every event · 2 known gaps, each with an engine-confirmed event ([certificate](../../../docs/CERTIFICATES.md#t1190-web-request-for-a-single-owner-object-by-numeric-id)) |
| **Parity** | base filter identical on 80 events · aggregation identical in SPL and KQL on 960 runs (160 sequences × 6 parameter sets) |
| **Guarantee** | a burst of 5+ always alerts, whatever the window alignment (checked with the engine at 120 alignments × 3 spreads); 4 can be split by a boundary |
| **Public data** | no public dataset records it yet · [why](public_evidence.md) |
| **Rule** | [`correlation.yml`](correlation.yml) · [`base.yml`](base.yml) · [KQL](../../../queries/kql/correlations/T1190_object_id_enumeration.kql) · [SPL](../../../queries/spl/correlations/T1190_object_id_enumeration.spl) · [scenarios](tests/scenarios.yml) |
| **Operations** | [triage](triage.md) · [response](response.md) · [closure](closure.md) · [tuning](tuning.yml) · [contract](contract.yml) |
| **Chain** | red: [idor_testing](../../../red/web/idor_testing/) · DFIR: [web_application_attack](../../../dfir/playbooks/web_application_attack.md) · purple: [T1190_object_id_enumeration](../../../purple/scenarios/T1190_object_id_enumeration.md) |
<!-- rasd:facts:end -->

## Why T1190
Walking other users' objects through an ID the application fails to authorize is exploitation of the public-facing application itself: broken object-level authorization (OWASP API1, IDOR) is the vulnerability, and the walk is the request that uses it - the data comes back through the flaw, not through stolen credentials or a scan. That is [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/). The related API-probing correlation is mapped differently on purpose: rejected requests across many paths find endpoints rather than exploit one, so [`T1595.003_api_auth_probing`](../T1595.003_api_auth_probing/) is [T1595.003 Active Scanning: Wordlist Scanning](https://attack.mitre.org/techniques/T1595/003/) (reconnaissance), with T1190 as a related technique.

## Telemetry required
A **web server or reverse-proxy access log** with the client address (`c-ip`), method (`cs-method`) and path (`cs-uri-stem`). The generated KQL reads `W3CIISLog` and the SPL reads `sourcetype=access_combined`; another table only needs its column names in [`tools/mappings.yml`](../../../tools/mappings.yml). [`red/web/export_access_log.py`](../../../red/web/export_access_log.py) turns a combined-format access log into the JSONL that `rasd` reads.

## How the detection works
Each user owns one basket, one user record, one wallet. Reading your own is normal; reading three in a minute is how broken object-level authorization (IDOR / BOLA) is found and then used to scrape data. This is a [Sigma correlation rule](correlation.yml) (`value_count`) over a [base rule](base.yml):

| Part | What it does |
|---|---|
| Base rule `web_object_id_request` | Keeps `GET` requests for `basket`, `user`, `account`, `profile` or `wallet` (singular or plural) addressed by a numeric ID at the end of the path. Never alerts on its own. |
| Correlation | Counts **distinct object paths** per **client address** in tumbling **1-minute** windows and alerts at **3 or more**, whatever the response - a denied walk is the attacker learning where the check holds. |

Edit the object types in [`base.yml`](base.yml) to the single-owner objects of your own application.

## Evasion & coverage gaps
- **IDs outside the path** - in the query string or the request body.
- **Non-numeric identifiers** - UUIDs and slugs.
- **Other object types** - anything not in the base rule's list.
- **Window boundary** - 3 or 4 objects can be split by a boundary (pinned as a known-limit scenario); 5 or more always alert.

## False positives & tuning
Support consoles and load tests. The [tuning guide](tuning.yml) prefers moving a support console to its own path prefix over excluding its address, and never drops denied requests from the count.

## Offensive validation
[`red/web/idor_testing`](../../../red/web/idor_testing/) logs in as one lab account and reads baskets 1 to 5 - five objects, exactly the smallest walk that always alerts.

```bash
python3 red/run_red.py --test idor_testing --lab-confirmed --target http://127.0.0.1:3000
python3 red/web/export_access_log.py --input <access log> --since <start time printed by the run> --out web-export.jsonl
rasd evidence --results <results>/emulation-results.json --logs web-export.jsonl
```

## Test locally
```bash
rasd correlate --filter T1190_object -v
```
