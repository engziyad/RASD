# Red Test Plan

| | |
|---|---|
| **Test id** | `red/<platform>/<test>` |
| **ATT&CK** | |
| **Objective** | What this run must prove (for example: the encoded-command detection fires on our lab telemetry) |
| **Lab** | Hosts, domain, Sysmon version and configuration, SIEM |
| **Planned window (UTC)** | |
| **Operator / observer** | |

## Preconditions
- [ ] Lab host is isolated and disposable; no production credentials on it
- [ ] Lab guard marking set on the host (`RASD_LAB_HOST` / `RASD_LAB_DOMAINS` on Windows, `/etc/rasd-lab-host` on Linux and macOS - [red/lab/README.md](../lab/README.md#lab-guard))
- [ ] Logging required by the test's `expected_telemetry.md` is enabled
- [ ] Forwarding to the SIEM verified (if the SIEM result is in scope)
- [ ] Opt-in switches decided (`-IncludeCredentialAccess`, `-IncludeSecurityLogClear`) and approved

## Steps
| # | Step (from test.yml) | Expected detections | Go / no-go |
|---|---|---|---|
| 1 | | | |

## Success criteria
- Every expected detection reports FIRED in `rasd evidence`
- Cleanup recorded as verified
- Evidence files committed
