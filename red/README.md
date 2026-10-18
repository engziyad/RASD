# RASD-Red: Offensive Validation

RASD-Red contains controlled offensive security labs used to validate detection coverage, generate telemetry, and connect adversary behavior to defensive outcomes.

Each offensive test (except one posture check, the HTTP security headers review) is mapped to MITRE ATT&CK, and every test includes expected telemetry, detection references, DFIR artifacts, cleanup steps, and validation criteria.

The goal is not to publish isolated offensive scripts.
The goal is to prove how offensive behavior becomes measurable defensive value.

## Mandatory contents of every test

Every offensive test inside RASD contains:

- Objective
- MITRE mapping: technique, name and tactics written exactly as ATT&CK writes them (`Parent: Sub-technique`), checked against the one ATT&CK reference in [`tools/common.py`](../tools/common.py); related techniques are listed as links for context and are not part of that check
- Execution steps
- Expected telemetry
- Detection link (or a documented, planned coverage gap)
- DFIR artifacts
- Cleanup steps
- Safety notes
- Sample output

They are written once, in the test's `test.yml`. `rasd red` validates the file and renders `README.md`, `expected_telemetry.md`, `detection_links.md`, `dfir_artifacts.md`, `sample_output.md` and `test.json`; CI fails when any of them is missing or stale. The sample event of every covered test **is** one of its detection's true positives (for a test a correlation covers, part of one of the correlation's scenarios), and CI proves it matches.

## Running tests

| Platform | Runner | Example |
|---|---|---|
| Windows, Active Directory | [`Invoke-RasdEmulation.ps1`](Invoke-RasdEmulation.ps1) | `.\red\Invoke-RasdEmulation.ps1 -Technique All -LabConfirmed -DryRun` |
| Web, Linux | [`run_red.py`](run_red.py) | `python3 red/run_red.py --platform web linux --lab-confirmed --target http://127.0.0.1:3000 --dry-run` |
| Full evidence run with Splunk | [`lab/`](lab/README.md) | `.\red\lab\Test-LabReadiness.ps1 -Fix` then `.\red\lab\Invoke-RasdLabRun.ps1 -LabConfirmed` |

Both runners give every run a random marker (`rasd_xxxxxxxx`) that names every object a test creates (file, task, service, Run value, test log, User-Agent); events that cannot carry it, such as the domain controller's Kerberos and logon events or LDAP queries, are bound to the run by host and time window instead. The runners record each step's UTC window and expected detections, collect DFIR artifacts with their SHA-256 before cleanup, record cleanup as verified / manual / failed, and write `emulation-results.json`. Then:

```powershell
.\red\Export-LabTelemetry.ps1 -Since '<start time printed by the runner>' -OutFile .\lab-export.jsonl
```
```bash
rasd evidence --results <results>/emulation-results.json --logs lab-export.jsonl
```

Safety is part of each test, not an afterthought: `-LabConfirmed` is mandatory and is not trusted on its own - the [lab guard](lab/README.md#lab-guard) refuses to run any test, web tests included, unless the machine itself is marked as a lab (on Windows `RASD_LAB_HOST`, plus a lab domain in `RASD_LAB_DOMAINS` for the PowerShell tests on a domain-joined host; a root-owned `/etc/rasd-lab-host` naming the host on Linux and macOS). Credential access and Security-log clearing are opt-in, checked by the runner and again by the step's own script. Every object a test creates carries the marker, so cleanup can only touch what the test created. Web tests refuse any target that resolves to a public address, connect only to the address they checked and never follow a redirect; a private address can still be a real intranet application, which is why the machine guard comes first. The password-spray simulation refuses to run when the domain lockout threshold is 1 or 2 and skips any account one more failure could lock; that check is complete only when the account running it can read fine-grained password policies (otherwise it warns and assumes the domain threshold).

## Catalogue

<!-- rasd:red-catalog:start -->
| Test | Platform | ATT&CK | Detect | Runner |
|---|---|---|---|---|
| [Kerberoasting - request an RC4 service ticket for a lab SPN](active_directory/kerberoasting/) | active directory | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | covered | powershell |
| [LDAP enumeration of users, groups and SPNs](active_directory/ldap_enumeration/) | active directory | [T1087.002](https://attack.mitre.org/techniques/T1087/002/) | gap | powershell |
| [Password spray simulation with a password that cannot be right](active_directory/password_spray_simulation/) | active directory | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | covered | powershell |
| [WinRM remote command on a lab host](active_directory/winrm_access_validation/) | active directory | [T1021.006](https://attack.mitre.org/techniques/T1021/006/) | covered | powershell |
| [User crontab persistence](linux/cron_persistence/) | linux | [T1053.003](https://attack.mitre.org/techniques/T1053/003/) | covered | bash |
| [Read-only privilege-escalation reconnaissance](linux/privilege_escalation_checks/) | linux | [T1083](https://attack.mitre.org/techniques/T1083/) | gap | bash |
| [Encoded shell command and execution from /tmp](linux/suspicious_shell_execution/) | linux | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | covered | bash |
| [API authentication enforcement](web/api_auth_testing/) | web | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) | covered | python |
| [File upload restrictions](web/file_upload_testing/) | web | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | gap | python |
| [Object-level authorization (IDOR / BOLA)](web/idor_testing/) | web | [T1190](https://attack.mitre.org/techniques/T1190/) | covered | python |
| [JWT validation (unsigned and tampered tokens)](web/jwt_testing/) | web | [T1606](https://attack.mitre.org/techniques/T1606/) | gap | python |
| [HTTP security headers and cookie flags](web/security_headers_testing/) | web | - | posture | python |
| [Event log clearing (dedicated test log, optional Security log)](windows/event_log_clearing/) | windows | [T1685.005](https://attack.mitre.org/techniques/T1685/005/) | covered | powershell |
| [LSASS memory dump with comsvcs.dll MiniDump](windows/lsass_memory_access/) | windows | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | covered | powershell |
| [PowerShell -EncodedCommand with a benign payload](windows/powershell_encoded_command/) | windows | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | covered | powershell |
| [HKCU Run value pointing into a user-writable folder](windows/run_key_persistence/) | windows | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | covered | powershell |
| [rundll32 javascript: proxy execution](windows/rundll32_execution/) | windows | [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | covered | powershell |
| [Scheduled task with a suspicious action (schtasks and PowerShell)](windows/scheduled_task_creation/) | windows | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | covered | powershell |
| [Service installed with a cmd.exe /c binary path](windows/service_creation/) | windows | [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | covered | powershell |
<!-- rasd:red-catalog:end -->

Templates for planning and reporting a run: [`templates/`](templates/).
