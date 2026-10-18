# SOC Actions

Concrete actions from the intelligence work, for the SOC lead's backlog.

| Action | Owner | Done when |
|---|---|---|
| Run the Windows and AD red tests in the lab and commit evidence | Purple team | `rasd evidence` writes evidence.md for each covered detection |
| Enable 4698 (task XML) and 4697 (service install) auditing | Platform / AD team | The persistence sweep returns task XML and installing accounts |
| Confirm DC auditing of Kerberos service tickets (4769), pre-auth failures (4771) and refused TGTs (4768), and collect logon failures (4625) from member servers | AD team | The Kerberoasting and spray correlations and hunts return data |
| Move RC4-only service accounts to AES (or gMSA) | AD team | `svc_legacy_scan`-style tuning proposals are no longer needed |
| Collect a WAF log and the application's authentication log (token validation failures) | Detection engineering, application owners | `file_upload_testing` and `jwt_testing` change from gap to detected |
| Collect a Linux administration baseline (find, getcap and sudo -l run by admins and tools) | Detection engineering, Linux team | The planned T1083 correlation can be measured with `rasd nearmiss` before it alerts ([detection backlog](detection_backlog.md)) |
| Re-check `intel/mappings/actors.yml` against the live ATT&CK site and set `last_checked` | CTI | The actor map shows a check date |
