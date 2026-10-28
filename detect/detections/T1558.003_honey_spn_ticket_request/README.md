# Deception - Service Ticket Requested for a Honey SPN Account

<!-- rasd:facts:start -->
| | |
|---|---|
| **ATT&CK** | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) Steal or Forge Kerberos Tickets: Kerberoasting (credential-access) |
| **Severity** | `high` |
| **Maturity** | **SIEM-Ready** ([model](../../../docs/RASD_MATURITY_MODEL.md)) |
| **Engineering Score** | 100/100 · operational pending - [run the lab](../../../docs/OPERATIONAL_VALIDATION.md) |
| **Tests** | 7 true positive · 7 true negative · 9 technique mutations |
| **Proof** | 100% of rule mutants killed · fuzzer resistance 100% over 32 variants |
| **Behaviour proof** | 2 of 4 variants proven for every event · no known gap · 2 exclusions proven quiet ([certificate](../../../docs/CERTIFICATES.md#t1558003-deception---service-ticket-requested-for-a-honey-spn-account)) |
| **Parity** | KQL and SPL identical to the rule on 571 events (RASD's offline KQL / SPL model, not yet a live SIEM) |
| **Public data** | no public dataset records it yet · [why](public_evidence.md) |
| **Rule** | [`rule.yml`](rule.yml) · [KQL](../../../queries/kql/T1558.003_honey_spn_ticket_request.kql) · [SPL](../../../queries/spl/T1558.003_honey_spn_ticket_request.spl) |
| **Operations** | [triage](triage.md) · [response](response.md) · [closure](closure.md) · [tuning](tuning.yml) · [contract](contract.yml) |
| **Chain** | red: [honey_account_use](../../../red/active_directory/honey_account_use/) · DFIR: [honey_account_use](../../../dfir/playbooks/honey_account_use.md) · DFIR: [kerberoasting](../../../dfir/playbooks/kerberoasting.md) · purple: [T1558.003_honey_spn](../../../purple/scenarios/T1558.003_honey_spn.md) · purple: [T1558.003_kerberoasting](../../../purple/scenarios/T1558.003_kerberoasting.md) |
<!-- rasd:facts:end -->

Part of [RASD-Deceive](../../../deceive/): the decoy this rule watches is defined once in [`deceive/decoys.yml`](../../../deceive/decoys.yml), planted by [`Deploy-RasdDecoys.ps1`](../../../deceive/Deploy-RasdDecoys.ps1), and `rasd deceive --check` fails the build when the inventory, this rule and its tests disagree.

## Telemetry required
Security **4769 (A Kerberos service ticket was requested)** on **domain controllers**, success and failure (*Audit Kerberos Service Ticket Operations*). The decoy service account `svc_sqlreport` must exist with its service principal name (`MSSQLSvc/sqlrpt01.lab.local:1433` in the shipped inventory) and a host name that resolves, so the SPN looks like every other one in the directory.

## How the detection works
Kerberoasting starts with `(servicePrincipalName=*)`: the tool lists every account with an SPN and requests a ticket for each, because it cannot tell which service account has a weak password until the tickets are cracked. A decoy account with an SPN is therefore requested together with the real ones. No service answers to that SPN and no user ever asks for it, so **any** 4769 whose `ServiceName` is the decoy - RC4 or AES, issued or refused, from a workstation or from the domain controller itself - is the signal.

This is the control the RC4 rule [T1558.003_kerberoasting_rc4_tgs](../T1558.003_kerberoasting_rc4_tgs/) names as its own gap: a tool that requests **AES** tickets (`Rubeus /aes`) for **one to four accounts** stays invisible to the RC4 rule and under the threshold of the volume correlation [T1558.003_kerberoasting_volume](../../correlations/T1558.003_kerberoasting_volume/). The decoy is requested all the same.

## Evasion & coverage gaps
- A tool that requests tickets only for **hand-picked SPNs** (a known SQL server's `MSSQLSvc`) never asks for the decoy. The RC4 rule and the volume correlation cover the targeted case; the decoy covers the enumeration case, which is how roasting is usually run.
- An attacker who **recognises the decoy**: an SPN whose host does not resolve, a service account whose `lastLogon` is empty or whose `pwdLastSet` never moved. The deployment script registers the host in DNS and refreshes the account's attributes; keeping them plausible is operational work, not a rule change.
- The same **telemetry risks** as every 4769 rule: a domain controller whose Security log is not forwarded, or Kerberos Service Ticket Operations auditing off.
- Decoys that **drift from the inventory**: a renamed or removed account stops alerting silently. `rasd deceive --check` compares the inventory with the rule and the tests on every build; `Test-RasdDecoys.ps1` compares it with the directory in the lab.

## False positives & tuning
A vulnerability scanner or an Active Directory assessment tool that requests a ticket for every SPN it finds behaves exactly like the attacker and alerts once per run. Do not filter it: register the run in the deception log and close the alert as the declared assessment. Every tuning - applied, proposed or rejected - is recorded in [`tuning.yml`](tuning.yml), and `rasd tune --filter T1558.003_honey` measures a proposal before it is applied.

## Offensive validation
[`red/active_directory/honey_account_use`](../../../red/active_directory/honey_account_use/) requests one service ticket for the honey SPN with `KerberosRequestorSecurityToken`, exactly as the Kerberoasting test does for a real SPN; the domain controller's 4769 is one of this rule's true positives (CI proves it matches). Run it on a lab workstation, export the domain controller's Security log and turn the run into evidence:

```powershell
.\red\Invoke-RasdEmulation.ps1 -Test honey_account_use -LabConfirmed
.\red\Export-LabTelemetry.ps1 -LogName Security -EventId 4625,4771,4776,4768,4769 -Since (Get-Date).AddHours(-1) -OutFile .\dc-export.jsonl   # on the domain controller
```

```bash
rasd evidence --results <results>/emulation-results.json --logs dc-export.jsonl
```

## Test locally
```bash
rasd test --filter T1558.003_honey
rasd prove --filter T1558.003_honey
rasd certify --filter T1558.003_honey -v
rasd parity --filter T1558.003_honey
rasd explain T1558.003_honey_spn_ticket_request --tp 1
rasd deceive --check
```
