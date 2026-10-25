# Kerberoasting - One Client Requesting Tickets for Many Service Accounts

<!-- rasd:facts:start -->
| | |
|---|---|
| **ATT&CK** | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) Steal or Forge Kerberos Tickets: Kerberoasting (credential-access) |
| **Severity** | `high` |
| **Type** | Sigma correlation · >= 5 distinct ServiceName per IpAddress in 10m windows · base rule [`service_ticket_user_account`](base.yml) |
| **Maturity** | **SIEM-Ready** ([model](../../../docs/RASD_MATURITY_MODEL.md)) |
| **Engineering Score** | 100/100 · operational pending - [run the lab](../../../docs/OPERATIONAL_VALIDATION.md) |
| **Tests** | base rule: 4 true positive · 7 true negative · 6 technique mutations · 10 scenarios (5 fire, 5 silent) |
| **Proof** | base rule: 100% of 12 mutants killed · fuzzer resistance 100% over 18 variants · correlation: 7/7 parameter mutants killed |
| **Behaviour proof** | base rule: 1 of 3 variants proven for every event · no known gap · 2 exclusions proven quiet ([certificate](../../../docs/CERTIFICATES.md#t1558003-service-ticket-issued-for-a-user-based-service-account)) |
| **Parity** | base filter identical on 258 events · aggregation identical in SPL and KQL on 1280 runs (160 sequences × 8 parameter sets) |
| **Guarantee** | a burst of 9+ always alerts, whatever the window alignment (checked with the engine at 120 alignments × 3 spreads); 8 can be split by a boundary |
| **Public data** | fires on 1 of 1 public recordings of its behaviour · 1 alert · 0 labelled false positives · [evidence](public_evidence.md) |
| **Rule** | [`correlation.yml`](correlation.yml) · [`base.yml`](base.yml) · [KQL](../../../queries/kql/correlations/T1558.003_kerberoasting_volume.kql) · [SPL](../../../queries/spl/correlations/T1558.003_kerberoasting_volume.spl) · [scenarios](tests/scenarios.yml) |
| **Operations** | [triage](triage.md) · [response](response.md) · [closure](closure.md) · [tuning](tuning.yml) · [contract](contract.yml) |
| **Chain** | DFIR: [kerberoasting](../../../dfir/playbooks/kerberoasting.md) · purple: [T1558.003_kerberoasting](../../../purple/scenarios/T1558.003_kerberoasting.md) |
<!-- rasd:facts:end -->

## Telemetry required
Security **4769** (a Kerberos service ticket was requested) on **domain controllers** - *Audit Kerberos Service Ticket Operations* (Success). The client address (`IpAddress`) and the service account (`ServiceName`) are the fields the correlation groups and counts.

## How the detection works
Kerberoasting tools enumerate the service principal names in the domain and request a ticket for each one, then crack the tickets offline. One ticket is normal; tickets for many **user-based** service accounts from one client within minutes are not.

This is a [Sigma correlation rule](correlation.yml) (`value_count`) over a [base rule](base.yml):

| Part | What it does |
|---|---|
| Base rule `service_ticket_user_account` | Keeps successful service tickets (status `0x0`) for services that run under a user account, with **any encryption type**. Drops computer accounts (`$`), `krbtgt` and requests from the domain controller itself. Never alerts on its own. |
| Correlation | Counts **distinct `ServiceName`** per **`IpAddress`** in tumbling **10-minute** windows and alerts at **5 or more**. |
| Normalisation | `::ffff:10.0.0.21` and `10.0.0.21` are one client ([`tools/mappings.yml`](../../../tools/mappings.yml)), so events collected through two pipelines are not split. |

It complements the single-event rule [Kerberoasting - RC4 Service Ticket Requested for User Account](../../detections/T1558.003_kerberoasting_rc4_tgs/): that rule fires on one RC4 ticket but cannot see AES roasting (Rubeus `/aes`); this correlation ignores the encryption type and catches roasting by volume.

## What RASD proves about it
`rasd correlate --filter T1558.003 -v` checks, on every commit:

- **Base rule** - true positives fire, true negatives stay silent, every value, field and branch is held in place by a test, fuzzer variants still fire, and its KQL and SPL filters equal the rule.
- **Scenarios** - ten event sequences: a roasting tool requesting every SPN, exactly the threshold, one below it, AES-only roasting, five clients opening five services, one application server renewing the same ticket, a slow roast, one client seen through two pipelines, computer and krbtgt tickets, and one pinned known limit.
- **Correlation mutants** - threshold +1 and -1, window x2 and /2, no group-by, events counted instead of service accounts, no address normalisation: each one gets at least one scenario wrong.
- **Aggregation parity** - the generated [SPL](../../../queries/spl/correlations/T1558.003_kerberoasting_volume.spl) and [KQL](../../../queries/kql/correlations/T1558.003_kerberoasting_volume.kql) are parsed back and run with each SIEM's semantics; they return exactly the engine's alerts on every scenario and on 150 seeded random sequences, for the rule and for every mutant.
- **Burst guarantee** - a burst of **9 or more service accounts within 10 minutes always alerts**, whatever the window alignment: a boundary leaves at least five on one side. The engine confirms it at 120 alignments × 3 spreads, and that 8 can be split 4 + 4.

## Evasion & coverage gaps
- **Targeted roasting** - one to four accounts per 10 minutes stays under the threshold. The RC4 single-event rule still fires on RC4 tickets, but **AES roasting of one to four accounts is caught by neither rule**. A honeypot SPN account (any ticket request for it is an alert) is the recommended control; RASD has no rule for it yet.
- **Several sources** - roasting spread over several clients, each below the threshold.
- **AS-REP roasting** - accounts without Kerberos pre-authentication are attacked through 4768, not 4769.
- **Window boundary** - 5 to 8 service accounts that straddle a boundary are split (pinned as a known-limit scenario); 9 or more always alert.

## False positives & tuning
Monitoring and application servers that talk to many services running under different user accounts, and administrators' jump hosts. The [tuning guide](tuning.yml) prefers moving those services to gMSA - which the base rule already ignores - over excluding the client.

## Offensive validation
The [kerberoasting red test](../../../red/active_directory/kerberoasting/) requests a single ticket by design (it validates the RC4 rule without touching more accounts than needed), so it does not reach this threshold. The correlation is proven by its scenarios and aggregation parity; a lab run against 9 or more lab SPNs would be needed for operational evidence.

## Test locally
```bash
rasd correlate --filter T1558.003 -v
rasd correlate --logs samples/replay/lab-day.jsonl
```
