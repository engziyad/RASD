# Suspicious Process Access to LSASS Memory

<!-- rasd:facts:start -->
| | |
|---|---|
| **ATT&CK** | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) OS Credential Dumping: LSASS Memory (credential-access) |
| **Severity** | `high` |
| **Maturity** | **SIEM-Ready** ([model](../../../docs/RASD_MATURITY_MODEL.md)) |
| **Engineering Score** | 100/100 · operational pending - [run the lab](../../../docs/OPERATIONAL_VALIDATION.md) |
| **Tests** | 27 true positive · 13 true negative · 5 technique mutations |
| **Proof** | 100% of rule mutants killed · fuzzer resistance 100% over 101 variants |
| **Parity** | KQL and SPL identical to the rule on 680 events (RASD's offline KQL / SPL model, not yet a live SIEM) |
| **Public data** | fires on 25 of 27 public recordings of its behaviour · held-out: 2 of 2 · 103 alerts · 1 labelled false positive · in-sample (changed after replaying them) · [evidence](public_evidence.md) |
| **Rule** | [`rule.yml`](rule.yml) · [KQL](../../../queries/kql/T1003.001_lsass_memory_access.kql) · [SPL](../../../queries/spl/T1003.001_lsass_memory_access.spl) |
| **Operations** | [triage](triage.md) · [response](response.md) · [closure](closure.md) · [tuning](tuning.yml) · [contract](contract.yml) |
| **Chain** | red: [lsass_memory_access](../../../red/windows/lsass_memory_access/) · DFIR: [lsass_access](../../../dfir/playbooks/lsass_access.md) · purple: [T1003.001_lsass_access](../../../purple/scenarios/T1003.001_lsass_access.md) |
<!-- rasd:facts:end -->

## Telemetry required
Sysmon **Event ID 10 (ProcessAccess)** with a rule that includes `TargetImage` = `lsass.exe`. Most baseline Sysmon configs exclude EID 10 for volume reasons, so add a targeted include for LSASS only.

### Signature fields
This rule does **not** use image signatures: Sysmon Event ID 10 has no signature field (signatures are reported in Event ID 7, ImageLoad). Signer-based allow-listing must happen in the SIEM by joining process metadata, not inside this rule.

### Pre-deployment check
Before enabling the rule, profile who already touches LSASS in your environment: [`queries/hunts/lsass_access_precheck.spl`](../../../queries/hunts/lsass_access_precheck.spl) / [`.kql`](../../../queries/hunts/lsass_access_precheck.kql).

## How the detection works
LSASS holds credential material (NTLM hashes, Kerberos tickets, sometimes cleartext). To dump it, a tool must open a handle with `PROCESS_VM_READ` (0x0010) plus query rights. The rule keys on the **access mask** rather than tool names, so renamed or custom tooling is still caught: any hex mask with the VM_READ bit set matches (the second-lowest hex digit is odd), so a larger mask such as `0x1f3fff` cannot slip past a fixed list. A regex cannot test a bit in a decimal number, so masks a pipeline stores in decimal are matched from a list of the known ones.

The interesting part is the filter design: no folder is excluded, only named components. An earlier version excluded `System32` except `rundll32.exe` and `taskmgr.exe`; replaying public attack data ([public evidence](public_evidence.md)) showed what that folder filter hid - Invoke-Mimikatz inside `powershell.exe`, a Meterpreter session migrated into `svchost.exe`, nanodump dropped into `System32`, and PPLdump starting a fresh `services.exe` that writes the dump through `dbgcore.dll`. The rule now excludes only `csrss.exe`, `wininit.exe` and the WMI provider host by full path, Windows PowerShell and its remoting host (`wsmprovhost.exe`) listing processes through .NET (`0x1410` with a `System.ni.dll` frame in `CallTrace`, which `Get-Process` produces and Invoke-Mimikatz does not), and the Defender scanner in its platform folder.

## Evasion & coverage gaps
- **Handle duplication / PPL bypass:** tools that duplicate an existing LSASS handle from another process (e.g. via `NtDuplicateObject`) never generate EID 10 against LSASS directly.
- **Code injected into a named Windows component** (`csrss.exe`, `wininit.exe`, the WMI provider host): the component is excluded by full path, so its access is not alerted; its `CallTrace` then shows a frame with no module (`UNKNOWN`), which a hunt can look for.
- **Credential Guard / RunAsPPL** is the real control: detection here is a backstop, not the primary defense.
- A mask a pipeline stores in **decimal** is matched only when it is on the list of known masks; hex masks are bit-tested.
- If ProcessAccess telemetry is disabled or filtered, this detection does not work.
- Complementary signal: file creation of `*.dmp` in unusual paths (Sysmon EID 11).

## False positives & tuning
Expect medium noise until the rule is tuned for an estate. Security agents (EDR sensors, AV, Defender running from `C:\Program Files\Windows Defender` on builds without platform updates), backup and management agents (VMware Tools, SCCM), and on some builds svchost-hosted services, Task Manager, WerFault and the Malicious Software Removal Tool open LSASS with the masks this rule reads; so does `Get-Process` in PowerShell 7, whose .NET runtime has no `System.ni.dll` frame for the process-listing filter to recognise. Tune by **full signed path**, never by filename alone, and use `SourceImage` + signer allow-listing in your SIEM. Public data cannot measure this: its labs run few agents.

Every tuning - applied, proposed or rejected - is recorded in [`tuning.yml`](tuning.yml). `rasd tune --filter T1003.001` measures each proposal before it is applied: how many attack variants it would hide against how many corpus alerts it would remove.

## Offensive validation
[`red/windows/lsass_memory_access`](../../../red/windows/lsass_memory_access/) is built to produce the telemetry this rule reads, and its expected event is one of this rule's true positives (CI proves it matches). Run it on a lab VM, export the logs and turn the run into evidence:

```powershell
.\red\Invoke-RasdEmulation.ps1 -Test lsass_memory_access -LabConfirmed -IncludeCredentialAccess
.\red\Export-LabTelemetry.ps1 -Since (Get-Date).AddHours(-1) -OutFile .\lab-export.jsonl
```

```bash
rasd evidence --results <results>/emulation-results.json --logs lab-export.jsonl
```

## Test locally
```bash
rasd test --filter T1003.001
rasd prove --filter T1003.001
rasd parity --filter T1003.001
rasd explain T1003.001_lsass_memory_access --tp 1
```
