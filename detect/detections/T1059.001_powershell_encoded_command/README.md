# PowerShell Execution With Encoded Command

<!-- rasd:facts:start -->
| | |
|---|---|
| **ATT&CK** | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) Command and Scripting Interpreter: PowerShell (execution) · related: [T1027](https://attack.mitre.org/techniques/T1027/) Obfuscated Files or Information (stealth) |
| **Severity** | `medium` |
| **Maturity** | **SIEM-Ready** ([model](../../../docs/RASD_MATURITY_MODEL.md)) |
| **Engineering Score** | 100/100 · operational pending - [run the lab](../../../docs/OPERATIONAL_VALIDATION.md) |
| **Tests** | 13 true positive · 6 true negative · 8 technique mutations |
| **Proof** | 100% of rule mutants killed · fuzzer resistance 100% over 224 variants |
| **Behaviour proof** | 2 of 7 variants proven for every event · 4 known gaps, each with an engine-confirmed event · 1 exclusion proven quiet ([certificate](../../../docs/CERTIFICATES.md#t1059001-powershell-execution-with-encoded-command)) |
| **Parity** | KQL and SPL identical to the rule on 1874 events · Defender advanced hunting identical on the same events (RASD's offline KQL / SPL model, not yet a live SIEM) |
| **Public data** | fires on 8 of 13 public recordings of its behaviour · held-out: 6 of 6 · 15 alerts · 0 labelled false positives · [evidence](public_evidence.md) |
| **Rule** | [`rule.yml`](rule.yml) · [KQL](../../../queries/kql/T1059.001_powershell_encoded_command.kql) · [SPL](../../../queries/spl/T1059.001_powershell_encoded_command.spl) · [Defender](../../../queries/mde/T1059.001_powershell_encoded_command.kql) |
| **Operations** | [triage](triage.md) · [response](response.md) · [closure](closure.md) · [tuning](tuning.yml) · [contract](contract.yml) |
| **Chain** | red: [powershell_encoded_command](../../../red/windows/powershell_encoded_command/) · DFIR: [phishing_triage](../../../dfir/playbooks/phishing_triage.md) · DFIR: [suspicious_powershell](../../../dfir/playbooks/suspicious_powershell.md) · purple: [T1059.001_powershell_encoded](../../../purple/scenarios/T1059.001_powershell_encoded.md) |
<!-- rasd:facts:end -->

## Telemetry required
Sysmon **EID 1** - the generated KQL and SPL read Sysmon. Security **4688** (with command-line auditing) works after remapping `NewProcessName` / `ParentProcessName` in `tools/mappings.yml`; it has no `OriginalFileName`, so the renamed-binary branch goes blind. For full visibility also enable **PowerShell Script Block Logging (4104)**, which records the *decoded* script.

## How the detection works
PowerShell resolves prefixes of a parameter name: `-e`, `-enc`, `-encod` and `-EncodedCommand` all reach -EncodedCommand (`-e` would be ambiguous, but PowerShell maps it there), plus the separate `-ec` alias, and it also accepts `/` and Unicode dashes (`–`, `—`) as parameter prefixes. Rules matching the literal string `-enc` are trivially evaded.

This rule uses one regex: a dash-like prefix, then `e`, `ec` or `en*`, then whitespace and a Base64 blob of 16+ chars. Matching on `OriginalFileName` from the PE header catches a renamed `powershell.exe`. The tests prove that `-ExecutionPolicy` / `-ep` do **not** trigger it.

## Evasion & coverage gaps
- Proven by `rasd certify`, each with a replayed event ([certificate](../../../docs/CERTIFICATES.md#t1059001-powershell-execution-with-encoded-command)): quotes inside an argument, which the C runtime drops before PowerShell reads it (`-e"n"c`); blanks or line breaks inside the Base64 text, which `Convert.FromBase64String` ignores; Base64 text under 16 characters (a script of five characters or fewer); pwsh's trimmed `"-enc "`. Every unquoted spelling of `-EncodedCommand` is proven caught.
- Encoded content passed via environment variables or stdin (`powershell -` with piped input).
- Obfuscation inside a *non-encoded* command (`IEX`, string concatenation, tick marks) - cover with 4104 script-block rules.
- PowerShell hosted in another process (System.Management.Automation.dll loaded by a custom binary - Sysmon EID 7).

## False positives & tuning
Configuration management (SCCM `CcmExec.exe`, Intune, RMM tools) and automation bootstraps such as Ansible's over WinRM (the main noise in public data). Filter by the **full parent process path**, as shown with `filter_sccm` (`C:\Windows\CCM\CcmExec.exe` exactly: a copy named `CcmExec.exe` in any other folder still alerts).

Every tuning - applied, proposed or rejected - is recorded in [`tuning.yml`](tuning.yml). `rasd tune --filter T1059.001` measures each proposal before it is applied: how many attack variants it would hide against how many corpus alerts it would remove.

## Offensive validation
[`red/windows/powershell_encoded_command`](../../../red/windows/powershell_encoded_command/) is built to produce the telemetry this rule reads, and its expected event is one of this rule's true positives (CI proves it matches). Run it on a lab VM, export the logs and turn the run into evidence:

```powershell
.\red\Invoke-RasdEmulation.ps1 -Test powershell_encoded_command -LabConfirmed
.\red\Export-LabTelemetry.ps1 -Since (Get-Date).AddHours(-1) -OutFile .\lab-export.jsonl
```

```bash
rasd evidence --results <results>/emulation-results.json --logs lab-export.jsonl
```

## Test locally
```bash
rasd test --filter T1059.001
rasd prove --filter T1059.001
rasd parity --filter T1059.001
rasd explain T1059.001_powershell_encoded_command --tp 1
```
