# Coverage and Layout

What the repository detects today, and what it only exercises. Detections are counted from `detect/detections` and `detect/correlations`; red tests without a detection are measured gaps, not coverage. The candidates of [RASD-Agent's lane](../detect/candidates/README.md) are not counted here: no person reviewed them and no lab run validated them.

| Area | Status | What exists |
|---|---|---|
| Windows process activity (Sysmon 1) | Covered | PowerShell encoded commands, scheduled tasks (schtasks and cmdlets), rundll32 proxy execution, wevtutil log clearing, shells and proxy binaries started by a WinRM session host |
| Windows process access (Sysmon 10) | Covered | LSASS memory access |
| Windows registry (Sysmon 13) | Covered | Run / RunOnce persistence |
| Windows Security log | Covered | Security log cleared (1102), RC4 Kerberos service tickets (4769); authentication failures for many accounts (4771, 4768, 4625) and service tickets of any encryption (4769) counted by the correlations |
| Windows System log | Covered | Other logs cleared (104), suspicious service installation (7045) |
| Deception (decoys) | Covered | Honey accounts used (4624, 4625, 4768, 4771, 4776), the honey SPN account requested (4769, any encryption), honey credential files opened (4663), the decoy host probed or logged on to (OpenCanary records); each a first-class detection with a red test, a playbook and a scenario ([RASD-Deceive](../deceive/)) |
| Active Directory | Partial | Kerberoasting (RC4 rule + encryption-agnostic volume correlation); password spray (correlation, tested on its red test's scenario; lab run pending); LDAP enumeration as a red test only |
| Web applications (access log) | Partial | API authentication probing and object-ID enumeration (correlations); JWT, file upload and security headers as red tests only |
| Linux (Sysmon for Linux 1) | Partial | Crontab installed from standard input or a file, Base64 decoded into a shell, execution from /tmp, /var/tmp and /dev/shm; privilege-escalation recon as a red test only |
| Cloud (Entra ID, AWS, Azure) | Not covered | Planned in the [roadmap](RELEASE_ROADMAP.md#after-v20-new-data-domains), after lab data exists |
| Email | Not covered | Planned, after lab data exists |
| WAF / NDR | Not covered | Planned, after lab data exists |

## Repository layout

```text
RASD
├── red/        → Offensive Validation      22 tests: Windows, Active Directory, web, Linux
├── detect/     → Detection Engineering     detections, correlations, coverage, quality, evasion baseline; candidates (RASD-Agent's lane)
├── deceive/    → Cyber Deception           decoy inventory, deployment and health-check scripts, decoy host configuration
├── agent/      → Counsel and growth        the ranked counsel page, the decisions taken on it, the ledger of the lane (proposals and your environment stay local)
├── dfir/       → Investigation & Response  playbooks, queries, templates, models
├── intel/      → CTI to Detection          templates, technique and actor maps, analyses
├── purple/     → Attack-to-Defense         scenarios, validation / evidence / latency matrices
├── profiles/   → Telemetry profiles: ECS, CIM, ASIM, Defender → rule field names
├── datasets/   → Public attack datasets: catalog, results, reduced extracts, licenses
├── samples/    → Replay corpus, telemetry profile and doctor samples
├── docs/       → Architecture, metrics, maturity, governance
├── tools/      → Automation, scoring, validation, generation
├── schemas/    → Contract, mutation and tuning schemas
├── queries/    → SPL / KQL / Defender advanced hunting / Hunts / Splunk app / health watchdogs
├── tests/      → Unit and framework tests
└── .github/    → CI, issue templates, PR template
```

<sub>RASD · Continuous Detection Assurance Framework</sub>
