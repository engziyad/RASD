# Kerberoasting - RC4 Service Ticket Requested for User Account

<!-- rasd:facts:start -->
| | |
|---|---|
| **ATT&CK** | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) Steal or Forge Kerberos Tickets: Kerberoasting (credential-access) |
| **Severity** | `medium` |
| **Maturity** | **SIEM-Ready** ([model](../../../docs/RASD_MATURITY_MODEL.md)) |
| **Engineering Score** | 100/100 · operational pending - [run the lab](../../../docs/OPERATIONAL_VALIDATION.md) |
| **Tests** | 11 true positive · 9 true negative · 6 technique mutations |
| **Proof** | 100% of rule mutants killed · fuzzer resistance 100% over 53 variants |
| **Behaviour proof** | 2 of 5 variants proven for every event · no known gap · 3 exclusions proven quiet ([certificate](../../../docs/CERTIFICATES.md#t1558003-kerberoasting---rc4-service-ticket-requested-for-user-account)) |
| **Parity** | KQL and SPL identical to the rule on 685 events (RASD's offline KQL / SPL model, not yet a live SIEM) |
| **Public data** | fires on 3 of 3 public recordings of its behaviour · held-out: 0 of 1 · 13 alerts · 0 labelled false positives · [evidence](public_evidence.md) |
| **Rule** | [`rule.yml`](rule.yml) · [KQL](../../../queries/kql/T1558.003_kerberoasting_rc4_tgs.kql) · [SPL](../../../queries/spl/T1558.003_kerberoasting_rc4_tgs.spl) |
| **Operations** | [triage](triage.md) · [response](response.md) · [closure](closure.md) · [tuning](tuning.yml) · [contract](contract.yml) |
| **Chain** | red: [kerberoasting](../../../red/active_directory/kerberoasting/) · DFIR: [kerberoasting](../../../dfir/playbooks/kerberoasting.md) · purple: [T1558.003_kerberoasting](../../../purple/scenarios/T1558.003_kerberoasting.md) |
<!-- rasd:facts:end -->

## Telemetry required
Security **4769 (A Kerberos service ticket was requested)** on **domain controllers**. Requires *Audit Kerberos Service Ticket Operations* (Success).

## How the detection works
Any authenticated user can request a service ticket for any SPN; the ticket is encrypted with the service account's password hash and can be cracked offline. Attack tools request **RC4 (0x17)** tickets because RC4 is far faster to crack than AES; the rule also matches the other crackable types, RC4-HMAC-EXP (0x18) and DES (0x1, 0x3), in hex or decimal. In a domain where accounts support AES, a successful RC4 TGS for a **user-based** service account is anomalous. Machine accounts (`$`) and `krbtgt` are excluded because their passwords are long and random.

Pair this single-event rule with the volume correlation [T1558.003_kerberoasting_volume](../../correlations/T1558.003_kerberoasting_volume/) - one client requesting tickets for 5 or more service accounts in 10 minutes, whatever the encryption type - and with the hunts below.

## Evasion & coverage gaps
- Attackers requesting **AES** tickets (Rubeus `/aes`) to blend in. The rule cannot see them; the volume correlation and the [volume hunt](../../../queries/hunts/kerberoasting_volume_hunt.kql) count service tickets of every encryption type per client, so AES roasting of 5 or more accounts still surfaces there.
- **AES roasting of one to four accounts** stays under the correlation's threshold and is invisible to this RC4 rule. A honeypot SPN account (any ticket request for it is an alert) is the recommended control; RASD has no rule for it yet.
- Roasting run **on a domain controller**: tickets requested from the loopback (`::1`, `127.0.0.1`, `::ffff:127.0.0.1` - the same forms the volume correlation filters), the domain controller itself, are filtered out with its own service traffic. Public data shows Rubeus run on a domain controller requesting 30 RC4 tickets that way ([held-out evidence](public_evidence.md)). Watch for interactive logons and tool execution on domain controllers instead.
- The real fix: gMSA or 25+ character passwords for service accounts, and disabling RC4.

### Aggregation hunt

Ready-to-use versions: [`kerberoasting_volume_hunt`](../../../queries/hunts/kerberoasting_volume_hunt.spl) (volume only) and [`kerberoasting_contextual_hunt`](../../../queries/hunts/kerberoasting_contextual_hunt.spl) (adds asset and account context, outputs a risk score). Both ship as `.spl` and `.kql` in [`queries/hunts/`](../../../queries/hunts/).

The shipped hunts count every encryption type and read the 4769 fields from `EventData`, as the generated queries do.

## False positives & tuning
Legacy systems that only support RC4. Inventory them, set `msDS-SupportedEncryptionTypes`, and filter by `ServiceName` with a documented exception.

Every tuning - applied, proposed or rejected - is recorded in [`tuning.yml`](tuning.yml). `rasd tune --filter T1558.003` measures each proposal before it is applied: how many attack variants it would hide against how many corpus alerts it would remove.

## Offensive validation
[`red/active_directory/kerberoasting`](../../../red/active_directory/kerberoasting/) is built to produce the telemetry this rule reads, and its expected event is one of this rule's true positives (CI proves it matches). Run it on a lab VM, export the logs and turn the run into evidence:

```powershell
.\red\Invoke-RasdEmulation.ps1 -Test kerberoasting -LabConfirmed -Spn <lab SPN>   # an SPN account set to RC4 only, or the DC issues AES
.\red\Export-LabTelemetry.ps1 -Since (Get-Date).AddHours(-1) -OutFile .\lab-export.jsonl
# 4769 is logged on the domain controller: export it there too
.\red\Export-LabTelemetry.ps1 -LogName Security -EventId 4769 -Since (Get-Date).AddHours(-1) -OutFile .\dc-export.jsonl
```

```bash
rasd evidence --results <results>/emulation-results.json --logs lab-export.jsonl dc-export.jsonl
```

## Test locally
```bash
rasd test --filter T1558.003
rasd prove --filter T1558.003
rasd parity --filter T1558.003
rasd explain T1558.003_kerberoasting_rc4_tgs --tp 1
```
