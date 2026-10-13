# Password Spray - One Source Failing Authentication for Many Accounts

<!-- rasd:facts:start -->
| | |
|---|---|
| **ATT&CK** | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) · credential-access |
| **Severity** | `high` |
| **Type** | Sigma correlation · >= 5 distinct TargetUserName per IpAddress in 10m windows · base rule [`auth_failure_wrong_password`](base.yml) |
| **Maturity** | **SIEM-Ready** ([model](../../../docs/RASD_MATURITY_MODEL.md)) |
| **Engineering score** | 100/100 · operational pending - [run the lab](../../../docs/OPERATIONAL_VALIDATION.md) |
| **Tests** | base rule: 5 true positive · 9 true negative · 8 technique mutations · 10 scenarios (5 fire, 5 silent) |
| **Proof** | base rule: 100% of 18 mutants killed · fuzzer resistance 100% over 14 variants · correlation: 7/7 parameter mutants killed |
| **Parity** | base filter identical on 280 events · aggregation identical in SPL and KQL on 1280 runs (160 sequences × 8 parameter sets) |
| **Guarantee** | a burst of 9+ always alerts, whatever the window alignment (checked with the engine at 120 alignments × 3 spreads); 8 can be split by a boundary |
| **Rule** | [`correlation.yml`](correlation.yml) · [`base.yml`](base.yml) · [KQL](../../../queries/kql/correlations/T1110.003_password_spray_burst.kql) · [SPL](../../../queries/spl/correlations/T1110.003_password_spray_burst.spl) · [scenarios](tests/scenarios.yml) |
| **Operations** | [triage](triage.md) · [response](response.md) · [tuning](tuning.yml) · [contract](contract.yml) |
| **Chain** | red: [password_spray_simulation](../../../red/active_directory/password_spray_simulation/) · DFIR: [password_spray](../../../dfir/playbooks/password_spray.md) · purple: [T1110.003_password_spray](../../../purple/scenarios/T1110.003_password_spray.md) |
<!-- rasd:facts:end -->

## Telemetry required
Security **4771** (Kerberos pre-authentication failed) on **domain controllers** - *Audit Kerberos Authentication Service* (Failure) - and Security **4625** (an account failed to log on) on domain controllers **and member servers** that accept network or RDP logons - *Audit Logon* (Failure). Both carry the client address (`IpAddress`) and the account (`TargetUserName`).

## How the detection works
A password spray tries one or two passwords against many accounts, few enough times per account to stay under the lockout threshold. No single failure is suspicious. The shape is: **many distinct accounts, one source, a short window** - something no single-event rule can express.

This is a [Sigma correlation rule](correlation.yml) (`value_count`) over a [base rule](base.yml):

| Part | What it does |
|---|---|
| Base rule `auth_failure_wrong_password` | Keeps wrong-password failures only: 4771 with failure code `0x18`, 4625 with sub-status `0xC000006A`, hex or decimal. Drops machine accounts and attempts without a remote address. Never alerts on its own. |
| Correlation | Counts **distinct `TargetUserName`** per **`IpAddress`** in tumbling **10-minute** windows and alerts at **5 or more**. |
| Normalisation | `::ffff:10.0.0.21` (Kerberos events) and `10.0.0.21` (logon events) are one client ([`tools/mappings.yml`](../../../tools/mappings.yml)), so a spray that mixes Kerberos and NTLM is counted once instead of split in two. |

Counting distinct accounts instead of events is what separates a spray from one user whose saved password went stale and retries all morning - one of the [scenarios](tests/scenarios.yml) that proves it.

## What RASD proves about it
`python rasd.py correlate --filter T1110.003 -v` checks, on every commit:

- **Base rule** - true positives fire, true negatives stay silent, every value, field and branch is held in place by a test (rule mutation testing), fuzzer variants (decimal codes, case, IPv4 without `::ffff:`) still fire, and its KQL and SPL filters equal the rule.
- **Scenarios** - ten event sequences: the lab emulation, exactly the threshold, one below it, five users mistyping on five workstations, one user retrying twelve times, a slow spray, mixed Kerberos and NTLM, two sprayers at once, machine accounts, and one pinned known limit.
- **Correlation mutants** - threshold +1 and -1, window x2 and /2, no group-by, events counted instead of accounts, no address normalisation: each one gets at least one scenario wrong, so none of these parameters can change unnoticed.
- **Aggregation parity** - the generated [SPL](../../../queries/spl/correlations/T1110.003_password_spray_burst.spl) and [KQL](../../../queries/kql/correlations/T1110.003_password_spray_burst.kql) are parsed back from their text and run with each SIEM's semantics. They return exactly the engine's alerts - window, source, count, first and last event - on every scenario and on 150 seeded random sequences, for the rule and for every mutant.
- **Burst guarantee** - windows are tumbling, so a boundary can split a burst. A burst of **9 or more accounts within 10 minutes always alerts**, whatever the alignment: a boundary leaves at least half of nine - five - on one side. The engine confirms it at 120 alignments × 3 spreads, and that 8 can be split 4 + 4. That is why the lab spray uses 9 or 10 accounts, and `rasd nearmiss` reports any burst a boundary did split in real traffic.

## Evasion & coverage gaps
- **Low and slow** - 4 accounts per source per 10 minutes never alerts. Hunt over hours with the same base rule: a copy of the correlation with a longer timespan moves the guarantee with it.
- **Distributed sources** - many sources, each below the threshold. In a hunt, group by `TargetUserName` over a long window to find one account failing from many sources.
- **Window boundary** - 5 to 8 accounts that straddle a boundary are split (pinned as a known-limit scenario); 9 or more always alert. `rasd nearmiss <export>` lists the bursts this happened to.
- **Cloud identity** - Entra ID sign-ins are out of scope; this correlation reads on-premises Windows events.
- **NTLM against member servers** - the domain controller's 4776 has no client address, so member server 4625 events must be collected.

## False positives & tuning
Jump hosts, VDI brokers and terminal servers relay many users' logons, and scanners test credentials. The [tuning guide](tuning.yml) proposes giving such a host its own, higher threshold instead of excluding it: a compromised broker is the best spraying host on the network.

## Offensive validation
[`red/active_directory/password_spray_simulation`](../../../red/active_directory/password_spray_simulation/) makes one failed LDAP bind per lab account with a random 40-character password, so no attempt can succeed. Give it 9 or 10 lab accounts so the burst guarantee applies, export the domain controller's Security log, and turn the run into evidence:

```powershell
.\red\Invoke-PurpleEmulation.ps1 -Test password_spray_simulation -LabConfirmed -UserList .\lab-users.txt
.\red\Export-LabTelemetry.ps1 -LogName Security -EventId 4771,4776,4625 -OutFile .\dc-export.jsonl   # on the DC
```

```bash
python rasd.py correlate --logs dc-export.jsonl
python rasd.py evidence --results <results>/emulation-results.json --logs dc-export.jsonl
```

## Validate locally
```bash
python rasd.py correlate --filter T1110.003 -v
python rasd.py correlate --logs samples/replay/lab-day.jsonl
```
