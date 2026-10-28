# Deception - Honey Credentials File Opened

<!-- rasd:facts:start -->
| | |
|---|---|
| **ATT&CK** | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) Unsecured Credentials: Credentials In Files (credential-access) · related: [T1083](https://attack.mitre.org/techniques/T1083/) File and Directory Discovery (discovery) |
| **Severity** | `high` |
| **Maturity** | **SIEM-Ready** ([model](../../../docs/RASD_MATURITY_MODEL.md)) |
| **Engineering Score** | 100/100 · operational pending - [run the lab](../../../docs/OPERATIONAL_VALIDATION.md) |
| **Tests** | 9 true positive · 9 true negative · 13 technique mutations |
| **Proof** | 100% of rule mutants killed · fuzzer resistance 100% over 9 variants |
| **Behaviour proof** | 1 of 5 variants proven for every event · no known gap · 4 exclusions proven quiet ([certificate](../../../docs/CERTIFICATES.md#t1552001-deception---honey-credentials-file-opened)) |
| **Parity** | KQL and SPL identical to the rule on 717 events (RASD's offline KQL / SPL model, not yet a live SIEM) |
| **Public data** | no public dataset records it yet · [why](public_evidence.md) |
| **Rule** | [`rule.yml`](rule.yml) · [KQL](../../../queries/kql/T1552.001_honey_file_access.kql) · [SPL](../../../queries/spl/T1552.001_honey_file_access.spl) |
| **Operations** | [triage](triage.md) · [response](response.md) · [closure](closure.md) · [tuning](tuning.yml) · [contract](contract.yml) |
| **Chain** | red: [honey_file_access](../../../red/windows/honey_file_access/) · DFIR: [honey_file_access](../../../dfir/playbooks/honey_file_access.md) · purple: [T1552.001_honey_file](../../../purple/scenarios/T1552.001_honey_file.md) |
<!-- rasd:facts:end -->

Part of [RASD-Deceive](../../../deceive/): the decoy files this rule watches are defined once in [`deceive/decoys.yml`](../../../deceive/decoys.yml), planted with their audit entries by [`Deploy-RasdDecoys.ps1`](../../../deceive/Deploy-RasdDecoys.ps1), and `rasd deceive --check` fails the build when the inventory, this rule and its tests disagree.

## Telemetry required
Security **4663 (An attempt was made to access an object)** on the **file servers that hold the decoys**: *Audit File System* (success) in the advanced audit policy, and a **SACL on each decoy file** that audits ReadData, WriteData, AppendData and Delete for Everyone. Without the SACL the policy writes nothing; the deployment script sets both and `Test-RasdDecoys.ps1` checks they are still there. The rule reads `ObjectName` (the server's local path), `AccessList` (the `%%`-coded accesses), `SubjectUserName` and `ProcessName`.

## How the detection works
Attackers who land on a network search the shares for files that hold credentials - a spreadsheet of service accounts, a password-manager database, a note of VPN codes. RASD-Deceive plants exactly those files, with plausible names, in folders where such files would live, and the only thing that distinguishes them is that nobody needs them. The rule fires on **any data access** to one of them by a **user account**: a read (`%%4416`), a write or append (`%%4417`, `%%4418`) or a delete (`%%1537`), whatever process performed it and wherever the share is mounted (`endswith` on the three paths, so the drive letter and the share root may differ between servers).

Two things do not fire: attribute reads (`%%4423`), which Explorer makes for every file while listing a folder, so browsing past the decoy stays quiet; and two documented exceptions - the server's own machine account (backup and antivirus running as SYSTEM) and the Windows Search indexer - each recorded with its reason in [`tuning.yml`](tuning.yml) and each proven necessary by a true negative.

The honey files hold decoy credentials: plausible wrong passwords for `svc_backup_adm` and the other honey accounts, and the honey SPN account's name. Whoever tries them trips [T1078.002_honey_account_authentication](../T1078.002_honey_account_authentication/) next, which is the chain the DFIR playbook follows.

## Evasion & coverage gaps
- An attacker already running as **SYSTEM on the file server** reads the decoy under the backup filter. The filter is needed (nightly backups read every file) and the residual risk is accepted and recorded.
- A read through a path the SACL does not cover - a **shadow copy**, a **restored backup**, an **offline copy** of the disk - logs no 4663.
- Attackers who **recognise a decoy**: a passwords folder nobody else touches, a file whose modification date never moves. The deployment script refreshes timestamps; placing the decoys among ordinary files and giving them a history is operational work, not a rule change.
- Decoys that **drift from the inventory**: a moved or deleted file stops alerting silently. `rasd deceive --check` compares the inventory with the rule and the tests on every build; `Test-RasdDecoys.ps1` compares it with the servers in the lab.

## False positives & tuning
A data-classification or backup agent that runs under a user account instead of the machine account, and the curious employee who opens a file named passwords - the latter is a finding, not a false positive. Every tuning - applied, proposed or rejected - is recorded in [`tuning.yml`](tuning.yml), and `rasd tune --filter T1552.001` measures a proposal before it is applied: the accepted answer for a scanning agent is to exclude the decoy folders from its scope, not to filter its account.

## Offensive validation
[`red/windows/honey_file_access`](../../../red/windows/honey_file_access/) reads the decoy spreadsheet with `Get-Content` on the lab host that holds it, as a scripted search for password files would; the host's 4663 is one of this rule's true positives (CI proves it matches). Run it on the lab host, export its Security log and turn the run into evidence:

```powershell
.\deceive\Deploy-RasdDecoys.ps1 -LabConfirmed -Files            # once: the decoy files, their SACL and the audit policy
.\red\Invoke-RasdEmulation.ps1 -Test honey_file_access -LabConfirmed
.\red\Export-LabTelemetry.ps1 -LogName Security -EventId 4663 -Since (Get-Date).AddHours(-1) -OutFile .\lab-export.jsonl
```

```bash
rasd evidence --results <results>/emulation-results.json --logs lab-export.jsonl
```

## Test locally
```bash
rasd test --filter T1552.001
rasd prove --filter T1552.001
rasd certify --filter T1552.001 -v
rasd parity --filter T1552.001
rasd explain T1552.001_honey_file_access --tp 1
rasd deceive --check
```
