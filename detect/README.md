# RASD-Detect: Detection Engineering

The heart of RASD: adversary behaviour turned into detection rules that are tested, mutation-checked (`rasd prove`), deployable and measured.

| Folder | Contents |
|---|---|
| [`detections/`](detections/) | One folder per detection (see below) |
| [`correlations/`](correlations/) | One folder per Sigma correlation detection: correlation rule, base rule, scenarios ([format and proofs](../docs/CORRELATIONS.md)) |
| [`coverage/`](coverage/) | ATT&CK Navigator layer and coverage matrix (generated) |
| [`quality/`](quality/) | Engineering and Operational Scores (generated) |
| [`evasion/`](evasion/) | Fuzzer baseline: bypasses accepted with a documented blind spot (empty today) |
| [`risk_conditions.yml`](risk_conditions.yml) | The conditions a contract's risk model may use |

## Detection folder

```text
detect/detections/<Technique>_<name>/
├── rule.yml          Sigma rule - the single source of truth
├── contract.yml      telemetry contract, blind spots, coverage depth, risk model, triage, response, maturity
├── tuning.yml        applied, proposed and rejected tunings, and what must never be tuned
├── triage.md         SOC triage card (generated from the contract)
├── response.md       incident response card (generated from the contract)
├── closure.md        SOC L2 closure notes and the escalation note (generated from the contract and tuning)
├── public_evidence.md  public dataset replay: which public recordings it fires on, and why it stays quiet on the rest (generated from `datasets/results.json`)
├── evidence.md       lab evidence (written by `rasd evidence` from a real run; absent = pending)
├── README.md         logic, evasion gaps, tuning, offensive validation; facts block generated
└── tests/
    ├── true_positive.jsonl
    ├── true_negative.jsonl
    └── mutations.yml
```

Acceptance criteria: [docs/DETECTION_ACCEPTANCE_CRITERIA.md](../docs/DETECTION_ACCEPTANCE_CRITERIA.md). Writing guide: [docs/WRITING_DETECTIONS.md](../docs/WRITING_DETECTIONS.md).

<!-- rasd:detections:start -->
## Detections

| Detection | ATT&CK | Platform |
|---|---|---|
| [Deception - Authentication Attempt With a Honey Account](detections/T1078.002_honey_account_authentication/) | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Windows |
| [Crontab Installed From Standard Input or a File](detections/T1053.003_crontab_noninteractive_install/) | [T1053.003](https://attack.mitre.org/techniques/T1053/003/) | Linux |
| [Scheduled Task Registered via PowerShell ScheduledTasks Cmdlets](detections/T1053.005_powershell_scheduled_task_creation/) | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Windows |
| [Scheduled Task Created With Suspicious Action](detections/T1053.005_schtasks_suspicious_creation/) | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Windows |
| [PowerShell Execution With Encoded Command](detections/T1059.001_powershell_encoded_command/) | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Windows |
| [Linux Shell Executing Decoded Base64 or Code From a Temporary Directory](detections/T1059.004_linux_suspicious_shell_execution/) | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | Linux |
| [Suspicious Service Installation (PsExec-style / Command Services)](detections/T1569.002_suspicious_service_installation/) | [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | Windows |
| [Run Key Persistence Pointing to Suspicious Location](detections/T1547.001_registry_run_key_persistence/) | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Windows |
| [Rundll32 Proxy Execution From Suspicious Context](detections/T1218.011_rundll32_suspicious_execution/) | [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | Windows |
| [Windows Event Log Clearing via Command Line](detections/T1685.005_event_log_clearing/) | [T1685.005](https://attack.mitre.org/techniques/T1685/005/) | Windows |
| [Security Audit Log Cleared (Event 1102)](detections/T1685.005_security_log_cleared/) | [T1685.005](https://attack.mitre.org/techniques/T1685/005/) | Windows |
| [Windows Event Log Cleared (System Event 104)](detections/T1685.005_system_log_cleared/) | [T1685.005](https://attack.mitre.org/techniques/T1685/005/) | Windows |
| [Suspicious Process Access to LSASS Memory](detections/T1003.001_lsass_memory_access/) | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | Windows |
| [Deception - Honey Credentials File Opened](detections/T1552.001_honey_file_access/) | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Windows |
| [Deception - Service Ticket Requested for a Honey SPN Account](detections/T1558.003_honey_spn_ticket_request/) | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | Windows |
| [Kerberoasting - RC4 Service Ticket Requested for User Account](detections/T1558.003_kerberoasting_rc4_tgs/) | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | Windows |
| [Deception - Interaction With a Decoy Network Service](detections/T1046_decoy_service_interaction/) | [T1046](https://attack.mitre.org/techniques/T1046/) | opencanary |
| [Suspicious Child Process of a WinRM Session Host](detections/T1021.006_wsmprovhost_suspicious_child/) | [T1021.006](https://attack.mitre.org/techniques/T1021/006/) | Windows |

## Correlation detections

| Detection | ATT&CK | Platform | Condition |
|---|---|---|---|
| [API Probing - One Client Rejected on Many Distinct Paths](correlations/T1595.003_api_auth_probing/) | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) | Web access log | >= 5 distinct cs-uri-stem per c-ip in 5m windows |
| [Object ID Enumeration - One Client Walking Single-Owner Objects](correlations/T1190_object_id_enumeration/) | [T1190](https://attack.mitre.org/techniques/T1190/) | Web access log | >= 3 distinct cs-uri-stem per c-ip in 1m windows |
| [Password Spray - One Source Failing Authentication for Many Accounts](correlations/T1110.003_password_spray_burst/) | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Windows | >= 5 distinct TargetUserName per IpAddress in 10m windows |
| [Kerberoasting - One Client Requesting Tickets for Many Service Accounts](correlations/T1558.003_kerberoasting_volume/) | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | Windows | >= 5 distinct ServiceName per IpAddress in 10m windows |
<!-- rasd:detections:end -->

Live maturity, scores and evidence: [quality/QUALITY.md](quality/QUALITY.md) and the [validation matrix](../purple/validation_matrix.md).
