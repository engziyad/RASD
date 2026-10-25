# API Probing - One Client Rejected on Many Distinct Paths

<!-- rasd:facts:start -->
| | |
|---|---|
| **ATT&CK** | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) Active Scanning: Wordlist Scanning (reconnaissance) |
| **Severity** | `medium` |
| **Type** | Sigma correlation · >= 5 distinct cs-uri-stem per c-ip in 5m windows · base rule [`web_request_rejected`](base.yml) |
| **Maturity** | **SIEM-Ready** ([model](../../../docs/RASD_MATURITY_MODEL.md)) |
| **Engineering Score** | 100/100 · operational pending - [run the lab](../../../docs/OPERATIONAL_VALIDATION.md) |
| **Tests** | base rule: 5 true positive · 5 true negative · 5 technique mutations · 11 scenarios (3 fire, 8 silent) |
| **Proof** | base rule: 100% of 4 mutants killed · fuzzer n/a (no evasion strategy applies to its fields) · correlation: 5/5 parameter mutants killed |
| **Behaviour proof** | base rule: 1 of 3 variants proven for every event · 1 known gap, each with an engine-confirmed event · 1 exclusion proven quiet ([certificate](../../../docs/CERTIFICATES.md#t1595003-web-request-rejected-with-401-or-403)) |
| **Parity** | base filter identical on 76 events · aggregation identical in SPL and KQL on 966 runs (161 sequences × 6 parameter sets) |
| **Guarantee** | a burst of 9+ always alerts, whatever the window alignment (checked with the engine at 120 alignments × 3 spreads); 8 can be split by a boundary |
| **Public data** | no public dataset records it yet · [why](public_evidence.md) |
| **Rule** | [`correlation.yml`](correlation.yml) · [`base.yml`](base.yml) · [KQL](../../../queries/kql/correlations/T1595.003_api_auth_probing.kql) · [SPL](../../../queries/spl/correlations/T1595.003_api_auth_probing.spl) · [scenarios](tests/scenarios.yml) |
| **Operations** | [triage](triage.md) · [response](response.md) · [closure](closure.md) · [tuning](tuning.yml) · [contract](contract.yml) |
| **Chain** | red: [api_auth_testing](../../../red/web/api_auth_testing/) · DFIR: [web_application_attack](../../../dfir/playbooks/web_application_attack.md) · purple: [T1595.003_api_auth_probing](../../../purple/scenarios/T1595.003_api_auth_probing.md) |
<!-- rasd:facts:end -->

## Telemetry required
A **web server or reverse-proxy access log** with the client address (`c-ip`), method (`cs-method`), path (`cs-uri-stem`) and status (`sc-status`). The generated KQL reads `W3CIISLog` and the SPL reads `sourcetype=access_combined` (nginx, Apache, Node); another table only needs its column names in [`tools/mappings.yml`](../../../tools/mappings.yml). [`red/web/export_access_log.py`](../../../red/web/export_access_log.py) turns a combined-format access log into the JSONL that `rasd` reads.

## How the detection works
A user whose session expired retries the same few paths. Someone probing protected endpoints - with no token, a malformed one, or a token the server never issued - walks many. This is a [Sigma correlation rule](correlation.yml) (`value_count`) over a [base rule](base.yml):

| Part | What it does |
|---|---|
| Base rule `web_request_rejected` | Keeps requests answered 401 or 403. CORS preflights (`OPTIONS`) are left out. Never alerts on its own. |
| Correlation | Counts **distinct paths** per **client address** in tumbling **5-minute** windows and alerts at **5 or more**. |

## Evasion & coverage gaps
- **Distributed probing** - many client addresses, each under the threshold.
- **Slow probing** - fewer than 5 rejected paths per client in every 5-minute window.
- **Proxies** - a reverse proxy that logs its own address hides the client; log `X-Forwarded-For` as `c-ip`.
- **Window boundary** - 5 to 8 paths can be split by a boundary (pinned as a known-limit scenario); 9 or more always alert.
- **Not-found responses** - only 401 and 403 count, so a directory or file brute force that is mostly answered 404 stays silent (one of the [true negatives](tests/true_negative.jsonl)). This rule sees wordlist scanning only where the guessed paths exist and are protected.
- **DNS brute forcing** - subdomain wordlists never reach the web server; that needs DNS query logs, which RASD does not read.

## False positives & tuning
Single-page applications with an expired session and approved scanners. The [tuning guide](tuning.yml) keeps CORS preflights out and proposes handling the scanner by schedule, not by excluding its address.

## Offensive validation
[`red/web/api_auth_testing`](../../../red/web/api_auth_testing/) calls six protected Juice Shop paths with no token, a malformed token and a foreign-signed JWT. Pass `--endpoints` with 9 or more protected paths of your application for the burst guarantee.

```bash
python3 red/run_red.py --test api_auth_testing --lab-confirmed --target http://127.0.0.1:3000
python3 red/web/export_access_log.py --input <access log> --since <start time printed by the run> --out web-export.jsonl
rasd evidence --results <results>/emulation-results.json --logs web-export.jsonl
```

## Test locally
```bash
rasd correlate --filter T1595.003_api -v
```
