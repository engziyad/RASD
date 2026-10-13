# Suspicious Process Access to LSASS Memory

<!-- rasd:facts:start -->
| | |
|---|---|
| **ATT&CK** | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) · credential-access |
| **Severity** | `high` |
| **Maturity** | **SIEM-Ready** ([model](../../../docs/RASD_MATURITY_MODEL.md)) |
| **Engineering score** | 100/100 · operational pending - [run the lab](../../../docs/OPERATIONAL_VALIDATION.md) |
| **Tests** | 9 true positive · 5 true negative · 5 technique mutations |
| **Proof** | 100% of rule mutants killed · fuzzer resistance 100% over 36 variants |
| **Parity** | KQL and SPL identical to the rule on 185 events |
| **Rule** | [`rule.yml`](rule.yml) · [KQL](../../../queries/kql/T1003.001_lsass_memory_access.kql) · [SPL](../../../queries/spl/T1003.001_lsass_memory_access.spl) |
| **Operations** | [triage](triage.md) · [response](response.md) · [tuning](tuning.yml) · [contract](contract.yml) |
| **Chain** | red: [lsass_memory_access](../../../red/windows/lsass_memory_access/) · DFIR: [lsass_access](../../../dfir/playbooks/lsass_access.md) · purple: [T1003.001_lsass_access](../../../purple/scenarios/T1003.001_lsass_access.md) |
<!-- rasd:facts:end -->

## Telemetry required
Sysmon **Event ID 10 (ProcessAccess)** with a rule that includes `TargetImage` = `lsass.exe`. Most baseline Sysmon configs exclude EID 10 for volume reasons, so add a targeted include for LSASS only.

### Signature fields
This rule does **not** use image signatures: Sysmon Event ID 10 has no signature field (signatures are reported in Event ID 7, ImageLoad). Signer-based allow-listing must happen in the SIEM by joining process metadata, not inside this rule.

### Pre-deployment check
Before enabling the rule, profile who already touches LSASS in your environment: [`queries/hunts/lsass_access_precheck.spl`](../../../queries/hunts/lsass_access_precheck.spl) / [`.kql`](../../../queries/hunts/lsass_access_precheck.kql).

## How the detection works
LSASS holds credential material (NTLM hashes, Kerberos tickets, sometimes cleartext). To dump it, a tool must open a handle with `PROCESS_VM_READ` (0x0010) plus query rights. The rule keys on the **access mask** rather than tool names, so renamed or custom tooling is still caught.

The interesting part is the filter design: binaries under `System32` are excluded **except** `rundll32.exe` and `taskmgr.exe`, because `rundll32 comsvcs.dll,MiniDump` is the most popular living-off-the-land dump technique. A naive "exclude System32" filter (seen in many public rules) silently misses it.

## Evasion & coverage gaps
- **Handle duplication / PPL bypass:** tools that duplicate an existing LSASS handle from another process (e.g. via `NtDuplicateObject`) never generate EID 10 against LSASS directly.
- **Direct syscalls with a minimal mask** (`0x1000`) followed by a later re-open.
- **Credential Guard / RunAsPPL** is the real control: detection here is a backstop, not the primary defense.
- Access masks outside the listed values may be missed.
- If ProcessAccess telemetry is disabled or filtered, this detection does not work.
- Complementary signal: file creation of `*.dmp` in unusual paths (Sysmon EID 11).

## False positives & tuning
EDR, AV and backup agents. Tune by **full signed path**, never by filename alone. Use `SourceImage` + signer allow-listing in your SIEM.

Every tuning - applied, proposed or rejected - is recorded in [`tuning.yml`](tuning.yml). `python rasd.py tune --filter T1003.001` measures each proposal before it is applied: how many attack variants it would hide against how many corpus alerts it would remove.

## Offensive validation
[`red/windows/lsass_memory_access`](../../../red/windows/lsass_memory_access/) produces exactly the telemetry this rule needs, and its expected event is one of this rule's true positives (CI proves it matches). Run it on a lab VM, export the logs and turn the run into evidence:

```powershell
.\red\Invoke-PurpleEmulation.ps1 -Test lsass_memory_access -LabConfirmed -IncludeCredentialAccess
.\red\Export-LabTelemetry.ps1 -Since (Get-Date).AddHours(-1)
```

```bash
python rasd.py evidence --results <results>/emulation-results.json --logs lab-export.jsonl
```

## Validate locally
```bash
python rasd.py test --filter T1003.001
python rasd.py prove --filter T1003.001
python rasd.py parity --filter T1003.001
python rasd.py explain T1003.001_lsass_memory_access --tp 1
```
