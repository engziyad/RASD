# Containment Plan

| | |
|---|---|
| **Incident ID** | |
| **Approved by** | |
| **Planned start (UTC)** | |

## Preserve before acting
- [ ] Volatile data captured where needed (memory, running processes, network connections)
- [ ] Persistence exported (task XML, service config, registry keys) before removal
- [ ] Forwarded logs confirmed in the SIEM for the full window

## Actions
| # | Action | Target | Owner | Business impact | Rollback | Done (UTC) |
|---|---|---|---|---|---|---|
| 1 | Isolate host | | | | Release isolation | |
| 2 | Disable / reset account | | | | Re-enable | |
| 3 | Block indicator (IP, domain, hash) | | | | Remove block | |
| 4 | Remove persistence | | | | Restore from export | |

## Credential scope
Accounts whose credentials must be considered exposed (for example everything logged on to a host where LSASS was accessed), and the reset order.

## Verification
How each action is confirmed effective (no new activity from the account, beacon traffic stopped, persistence absent after reboot).
