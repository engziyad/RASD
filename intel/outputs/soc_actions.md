# SOC Actions

Concrete actions from the intelligence work, for the SOC lead's backlog.

| Action | Owner | Done when |
|---|---|---|
| Run the Windows and AD red tests in the lab and commit evidence | Purple team | `python rasd.py evidence` writes evidence.md for each covered detection |
| Enable 4698 (task XML) and 4697 (service install) auditing | Platform / AD team | The persistence sweep returns task XML and installing accounts |
| Confirm DC auditing of Kerberos service tickets (4769) and pre-auth failures (4771) | AD team | Kerberoasting and spray hunts return data |
| Move RC4-only service accounts to AES (or gMSA) | AD team | `svc_legacy_scan`-style tuning proposals are no longer needed |
| Map a web / WAF log source in `tools/mappings.yml` | Detection engineering | Web red tests change from Gap to Detect |
| Map an auditd or Sysmon for Linux log source | Detection engineering | Linux red tests change from Gap to Detect |
| Re-check `intel/mappings/actors.yml` against the live ATT&CK site and set `last_checked` | CTI | The actor map shows a check date |
