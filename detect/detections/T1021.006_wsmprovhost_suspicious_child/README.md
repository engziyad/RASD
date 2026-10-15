# Suspicious Child Process of a WinRM Session Host

<!-- rasd:facts:start -->
| | |
|---|---|
| **ATT&CK** | [T1021.006](https://attack.mitre.org/techniques/T1021/006/) Remote Services: Windows Remote Management (lateral-movement) |
| **Severity** | `medium` |
| **Maturity** | **SIEM-Ready** ([model](../../../docs/RASD_MATURITY_MODEL.md)) |
| **Engineering Score** | 100/100 · operational pending - [run the lab](../../../docs/OPERATIONAL_VALIDATION.md) |
| **Tests** | 18 true positive · 7 true negative · 7 technique mutations |
| **Proof** | 100% of rule mutants killed · fuzzer resistance 100% over 193 variants |
| **Parity** | KQL and SPL identical to the rule on 1900 events · Defender advanced hunting identical on the same events |
| **Public data** | fires on 5 of 8 public recordings of its behaviour · 37 alerts · 0 labelled false positive · [evidence](public_evidence.md) |
| **Rule** | [`rule.yml`](rule.yml) · [KQL](../../../queries/kql/T1021.006_wsmprovhost_suspicious_child.kql) · [SPL](../../../queries/spl/T1021.006_wsmprovhost_suspicious_child.spl) · [Defender](../../../queries/mde/T1021.006_wsmprovhost_suspicious_child.kql) |
| **Operations** | [triage](triage.md) · [response](response.md) · [closure](closure.md) · [tuning](tuning.yml) · [contract](contract.yml) |
| **Chain** | red: [winrm_access_validation](../../../red/active_directory/winrm_access_validation/) · DFIR: [lateral_movement](../../../dfir/playbooks/lateral_movement.md) · purple: [T1021.006_winrm](../../../purple/scenarios/T1021.006_winrm.md) |
<!-- rasd:facts:end -->

## Telemetry required
**Sysmon Event ID 1** (process creation) on the **WinRM target**, or Security **4688** with command lines through the `windows-security-4688` profile. The rule reads the parent (`ParentImage`), the child (`Image`, `OriginalFileName`) and its command line; 4688 has no `OriginalFileName`, so a renamed child is seen by its path only.

## How the detection works
Every PowerShell remoting session on a target runs inside `wsmprovhost.exe`, and every `winrs` command inside `winrshost.exe`. Cmdlets run in that process and start nothing. A native shell or a signed proxy binary started **from** it is how remote-execution tools run their commands over WinRM.

| Selection | What it catches under a WinRM host |
|---|---|
| `susp_shell` | `cmd.exe`, by path or by `OriginalFileName` (a renamed copy) |
| `powershell_image` and `encoded_command` | `powershell.exe` or `pwsh.exe` (also renamed) with an encoded command, using the same pattern as [`T1059.001_powershell_encoded_command`](../T1059.001_powershell_encoded_command/) |
| `susp_proxy` | `rundll32`, `regsvr32`, `mshta`, `certutil` or `bitsadmin`, by path or by `OriginalFileName` |

A WinRM logon alone (4624, WinRM 91) is everyday administration, so the rule keys on what the session **started**, not on the connection.

## Evasion & coverage gaps
- **Cmdlet-only sessions** - commands that stay inside PowerShell start no child process. Script block logging (4104) on the target covers them.
- **Custom binaries** - a tool copied to the target and started over WinRM is not in the lists. Hunt for any child of `wsmprovhost.exe` that is new to the host.
- **Other remote execution** - WMI (`WmiPrvSE.exe`) and DCOM use different hosts and need their own rules.

## False positives & tuning
Administrators who run `cmd.exe` commands or batch files over remoting. The [tuning guide](tuning.yml) proposes filtering an approved management share, and never an account: a stolen administrator account is what this rule exists to catch.

## Offensive validation
[`red/active_directory/winrm_access_validation`](../../../red/active_directory/winrm_access_validation/) runs one `cmd.exe /c echo` with the run marker on a lab target over WinRM. Its expected event is one of this rule's true positives (CI proves it matches). Export the target's logs and turn the run into evidence:

```powershell
.\red\Invoke-RasdEmulation.ps1 -Test winrm_access_validation -LabConfirmed -Target LAB-SRV01
.\red\Export-LabTelemetry.ps1 -Since (Get-Date).AddHours(-1)   # on the target
```

```bash
rasd evidence --results <results>/emulation-results.json --logs lab-export.jsonl
```

## Test locally
```bash
rasd test --filter T1021.006
rasd prove --filter T1021.006
rasd parity --filter T1021.006
rasd explain T1021.006_wsmprovhost_suspicious_child --tp 1
```
