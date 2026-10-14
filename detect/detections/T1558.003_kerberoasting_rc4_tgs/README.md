# Kerberoasting - RC4 Service Ticket Requested for User Account

<!-- rasd:facts:start -->
| | |
|---|---|
| **ATT&CK** | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) Steal or Forge Kerberos Tickets: Kerberoasting (credential-access) |
| **Severity** | `medium` |
| **Maturity** | **SIEM-Ready** ([model](../../../docs/RASD_MATURITY_MODEL.md)) |
| **Engineering Score** | 100/100 · operational pending - [run the lab](../../../docs/OPERATIONAL_VALIDATION.md) |
| **Tests** | 5 true positive · 6 true negative · 6 technique mutations |
| **Proof** | 100% of rule mutants killed · fuzzer resistance 100% over 23 variants |
| **Parity** | KQL and SPL identical to the rule on 544 events |
| **Public data** | fires on 3 of 3 public recordings of its behaviour · held-out: 0 of 1 · 13 alerts · 0 labelled false positive · [evidence](public_evidence.md) |
| **Rule** | [`rule.yml`](rule.yml) · [KQL](../../../queries/kql/T1558.003_kerberoasting_rc4_tgs.kql) · [SPL](../../../queries/spl/T1558.003_kerberoasting_rc4_tgs.spl) |
| **Operations** | [triage](triage.md) · [response](response.md) · [closure](closure.md) · [tuning](tuning.yml) · [contract](contract.yml) |
| **Chain** | red: [kerberoasting](../../../red/active_directory/kerberoasting/) · DFIR: [kerberoasting](../../../dfir/playbooks/kerberoasting.md) · purple: [T1558.003_kerberoasting](../../../purple/scenarios/T1558.003_kerberoasting.md) |
<!-- rasd:facts:end -->

## Telemetry required
Security **4769 (A Kerberos service ticket was requested)** on **domain controllers**. Requires *Audit Kerberos Service Ticket Operations* (Success).

## How the detection works
Any authenticated user can request a service ticket for any SPN; the ticket is encrypted with the service account's password hash and can be cracked offline. Attack tools request **RC4 (0x17)** tickets because RC4 is far faster to crack than AES. In a domain where accounts support AES, a successful RC4 TGS for a **user-based** service account is anomalous. Machine accounts (`$`) and `krbtgt` are excluded because their passwords are long and random.

For production, pair this single-event rule with an **aggregation hunt**: one client requesting many distinct SPNs within minutes.

## Evasion & coverage gaps
- Attackers requesting **AES** tickets (Rubeus `/aes`) to blend in. The rule cannot see them; the [volume hunt](../../../queries/hunts/kerberoasting_volume_hunt.kql) counts service tickets of every encryption type per client, so volume-based AES roasting still surfaces there.
- Targeted roasting of a single account - low volume; rely on **honeypot SPN accounts** (any ticket request = alert).
- Roasting run **on a domain controller**: tickets requested from `::1`, the domain controller itself, are filtered out with its own service traffic. Public data shows Rubeus run on a domain controller requesting 30 RC4 tickets that way ([held-out evidence](public_evidence.md)). Watch for interactive logons and tool execution on domain controllers instead.
- The real fix: gMSA or 25+ character passwords for service accounts, and disabling RC4.

### Aggregation hunt

Ready-to-use versions: [`kerberoasting_volume_hunt`](../../../queries/hunts/kerberoasting_volume_hunt.spl) (volume only) and [`kerberoasting_contextual_hunt`](../../../queries/hunts/kerberoasting_contextual_hunt.spl) (adds asset and account context, outputs a risk score). Both ship as `.spl` and `.kql` in [`queries/hunts/`](../../../queries/hunts/).

KQL:

```kql
SecurityEvent
| where EventID == 4769 and TicketEncryptionType == "0x17" and Status == "0x0"
| where ServiceName !endswith "$" and ServiceName != "krbtgt"
| summarize SPNs = dcount(ServiceName), Services = make_set(ServiceName, 50)
    by TargetUserName, IpAddress, bin(TimeGenerated, 10m)
| where SPNs >= 3
```

## False positives & tuning
Legacy systems that only support RC4. Inventory them, set `msDS-SupportedEncryptionTypes`, and filter by `ServiceName` with a documented exception.

Every tuning - applied, proposed or rejected - is recorded in [`tuning.yml`](tuning.yml). `rasd tune --filter T1558.003` measures each proposal before it is applied: how many attack variants it would hide against how many corpus alerts it would remove.

## Offensive validation
[`red/active_directory/kerberoasting`](../../../red/active_directory/kerberoasting/) produces exactly the telemetry this rule needs, and its expected event is one of this rule's true positives (CI proves it matches). Run it on a lab VM, export the logs and turn the run into evidence:

```powershell
.\red\Invoke-RasdEmulation.ps1 -Test kerberoasting -LabConfirmed -Spn <lab SPN>
.\red\Export-LabTelemetry.ps1 -Since (Get-Date).AddHours(-1)
```

```bash
rasd evidence --results <results>/emulation-results.json --logs lab-export.jsonl
```

## Test locally
```bash
rasd test --filter T1558.003
rasd prove --filter T1558.003
rasd parity --filter T1558.003
rasd explain T1558.003_kerberoasting_rc4_tgs --tp 1
```
