# Deception - Authentication Attempt With a Honey Account

<!-- rasd:facts:start -->
| | |
|---|---|
| **ATT&CK** | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) Valid Accounts: Domain Accounts (initial-access, persistence, privilege-escalation, stealth) · related: [T1558.004](https://attack.mitre.org/techniques/T1558/004/) Steal or Forge Kerberos Tickets: AS-REP Roasting (credential-access) · related: [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Brute Force: Password Spraying (credential-access) |
| **Severity** | `high` |
| **Maturity** | **SIEM-Ready** ([model](../../../docs/RASD_MATURITY_MODEL.md)) |
| **Engineering Score** | 100/100 · operational pending - [run the lab](../../../docs/OPERATIONAL_VALIDATION.md) |
| **Tests** | 12 true positive · 11 true negative · 11 technique mutations |
| **Proof** | 100% of rule mutants killed · fuzzer resistance 100% over 34 variants |
| **Behaviour proof** | 6 of 8 variants proven for every event · no known gap · 2 exclusions proven quiet ([certificate](../../../docs/CERTIFICATES.md#t1078002-deception---authentication-attempt-with-a-honey-account)) |
| **Parity** | KQL and SPL identical to the rule on 622 events (RASD's offline KQL / SPL model, not yet a live SIEM) |
| **Public data** | no public dataset records it yet · [why](public_evidence.md) |
| **Rule** | [`rule.yml`](rule.yml) · [KQL](../../../queries/kql/T1078.002_honey_account_authentication.kql) · [SPL](../../../queries/spl/T1078.002_honey_account_authentication.spl) |
| **Operations** | [triage](triage.md) · [response](response.md) · [closure](closure.md) · [tuning](tuning.yml) · [contract](contract.yml) |
| **Chain** | red: [honey_account_use](../../../red/active_directory/honey_account_use/) · DFIR: [honey_account_use](../../../dfir/playbooks/honey_account_use.md) · DFIR: [honey_file_access](../../../dfir/playbooks/honey_file_access.md) · purple: [T1078.002_honey_account](../../../purple/scenarios/T1078.002_honey_account.md) |
<!-- rasd:facts:end -->

Part of [RASD-Deceive](../../../deceive/): the decoys this rule watches are defined once in [`deceive/decoys.yml`](../../../deceive/decoys.yml), planted by [`Deploy-RasdDecoys.ps1`](../../../deceive/Deploy-RasdDecoys.ps1), and `rasd deceive --check` fails the build when the inventory, this rule and its tests disagree.

## Telemetry required
Security **4624 / 4625** (logon success and failure) on domain controllers and on every member server that accepts logons (*Audit Logon*, success and failure); **4768 / 4771** (Kerberos TGT request, pre-authentication failure) and **4776** (NTLM credential validation) on domain controllers (*Audit Kerberos Authentication Service* and *Audit Credential Validation*, success and failure). The decoy accounts must exist in the directory with their lures: `svc_backup_adm` carries a pointer to the honey credentials file in its description attribute, `adm_helpdesk_tier2` has Kerberos pre-authentication disabled.

## How the detection works
Nobody uses a honey account. Its name and its lure are built for the attacker who enumerates the directory: a service account whose description says where its password is written down, an administrative-looking account whose pre-authentication flag makes it roastable offline. The rule reads every authentication path to a domain account - interactive and network logons, Kerberos AS-REQ, NTLM validation - and fires on **any** event whose `TargetUserName` is a decoy, written as a sAMAccountName or as a UPN, whatever the outcome. A failure means the lure was read and tried (the lures hold plausible wrong passwords, and the decoys' real passwords are random and kept nowhere); a success means the decoy's own password was obtained some other way, which is the most serious case; a 4768 with `PreAuthType` 0 means the account was AS-REP roasted.

The rule has no filter by design: an attacker on a trusted administration host must trip it like anyone else. What is yours to change is the list of names, with `rasd deceive --rename svc_backup_adm <your name>`, which rewrites the inventory, this rule, its tests and behaviour spec together so the proofs keep holding.

## Evasion & coverage gaps
- An attacker who **recognises the decoys** and leaves them alone: an account that never logged on, a name outside the naming convention, a description that looks planted. The remedy is operational - names and descriptions that fit your directory, a last-logon date kept fresh by the deployment script - not a rule change.
- **Enumeration without authentication**: reading the description attribute or the `userAccountControl` flag over LDAP logs nothing this rule reads. Only the use of what was read does. Directory Service event 1644 (expensive LDAP queries) and EDR LDAP telemetry cover the read itself; neither is mapped in RASD yet.
- A logon that reaches a **server whose Security log is not forwarded**, or an NTLM validation on a domain controller with Credential Validation auditing off, leaves no event. The data contract lists both as critical telemetry risks.
- Decoys that **drift from the inventory**: a renamed or deleted decoy stops alerting silently. `rasd deceive --check` compares the inventory with the rule and the tests on every build; `Test-RasdDecoys.ps1` compares it with the directory in the lab.

## False positives & tuning
A password audit or an account-discovery tool run by the security team that authenticates as every account it finds, and a penetration test that was not told which accounts are decoys. Neither is filtered: register the activity in the deception log and close the alerts as the declared audit. Every tuning - applied, proposed or rejected - is recorded in [`tuning.yml`](tuning.yml), and `rasd tune --filter T1078.002` measures a proposal before it is applied.

## Offensive validation
[`red/active_directory/honey_account_use`](../../../red/active_directory/honey_account_use/) binds to the lab domain as `svc_backup_adm` with a wrong password (one LDAP bind, as the password spray simulation does) and requests a service ticket for the honey SPN account; the domain controller logs 4771 for the bind, which is one of this rule's true positives (CI proves it matches). Run it on a lab workstation, export the domain controller's Security log and turn the run into evidence:

```powershell
.\red\Invoke-RasdEmulation.ps1 -Test honey_account_use -LabConfirmed
.\red\Export-LabTelemetry.ps1 -LogName Security -EventId 4625,4771,4776,4768,4769 -Since (Get-Date).AddHours(-1) -OutFile .\dc-export.jsonl   # on the domain controller
```

```bash
rasd evidence --results <results>/emulation-results.json --logs dc-export.jsonl
```

## Test locally
```bash
rasd test --filter T1078.002
rasd prove --filter T1078.002
rasd certify --filter T1078.002 -v
rasd parity --filter T1078.002
rasd explain T1078.002_honey_account_authentication --tp 1
rasd deceive --check
```
