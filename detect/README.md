# RASD-Detect — Detection Engineering

The heart of RASD: adversary behaviour turned into detection rules that are tested, proven, deployable and measured.

| Folder | Contents |
|---|---|
| [`detections/`](detections/) | One folder per detection (see below) |
| [`correlations/`](correlations/) | One folder per Sigma correlation detection: correlation rule, base rule, scenarios ([format and proofs](../docs/CORRELATIONS.md)) |
| [`coverage/`](coverage/) | ATT&CK Navigator layer and coverage matrix (generated) |
| [`quality/`](quality/) | Engineering and Operational scores (generated) |
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
├── evidence.md       lab evidence (written by `rasd evidence` from a real run; absent = pending)
├── README.md         logic, evasion gaps, tuning, offensive validation; facts block generated
└── tests/
    ├── true_positive.jsonl
    ├── true_negative.jsonl
    └── mutations.yml
```

Acceptance criteria: [docs/DETECTION_ACCEPTANCE_CRITERIA.md](../docs/DETECTION_ACCEPTANCE_CRITERIA.md). Writing guide: [docs/WRITING_DETECTIONS.md](../docs/WRITING_DETECTIONS.md).

## Detections

| Detection | ATT&CK | Coverage |
|---|---|---|
| [PowerShell Execution With Encoded Command](detections/T1059.001_powershell_encoded_command/) | T1059.001 | [matrix](coverage/COVERAGE.md) |
| [Scheduled Task Created With Suspicious Action](detections/T1053.005_schtasks_suspicious_creation/) | T1053.005 | |
| [Scheduled Task Registered via PowerShell](detections/T1053.005_powershell_scheduled_task_creation/) | T1053.005 | |
| [Rundll32 Proxy Execution From Suspicious Context](detections/T1218.011_rundll32_suspicious_execution/) | T1218.011 | |
| [Run Key Persistence Pointing to Suspicious Location](detections/T1547.001_registry_run_key_persistence/) | T1547.001 | |
| [Suspicious Service Installation](detections/T1569.002_suspicious_service_installation/) | T1569.002 | |
| [Event Log Clearing via Command Line](detections/T1070.001_event_log_clearing/) | T1070.001 | |
| [Security Audit Log Cleared (1102)](detections/T1070.001_security_log_cleared/) | T1070.001 | |
| [Windows Event Log Cleared (System 104)](detections/T1070.001_system_log_cleared/) | T1070.001 | |
| [Suspicious Process Access to LSASS Memory](detections/T1003.001_lsass_memory_access/) | T1003.001 | |
| [Kerberoasting - RC4 Service Ticket](detections/T1558.003_kerberoasting_rc4_tgs/) | T1558.003 | |

## Correlation detections

| Detection | ATT&CK | Condition |
|---|---|---|
| [Password Spray - One Source Failing Authentication for Many Accounts](correlations/T1110.003_password_spray_burst/) | T1110.003 | 5+ distinct accounts per client address in 10 minutes |
| [Kerberoasting - One Client Requesting Tickets for Many Service Accounts](correlations/T1558.003_kerberoasting_volume/) | T1558.003 | 5+ distinct service accounts per client address in 10 minutes |

Live maturity, scores and evidence: [quality/QUALITY.md](quality/QUALITY.md) and the [validation matrix](../purple/validation_matrix.md).
