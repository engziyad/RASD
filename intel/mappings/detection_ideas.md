# Detection Ideas

Ideas that are not detections yet, each tied to the offensive test that already produces its telemetry. When an idea is built, it moves to `detect/detections/` or `detect/correlations/`, the red test's `gap` block is removed, and the idea moves to the table at the end.

| Idea | ATT&CK | Telemetry | Red test that validates it | Blocker today |
|---|---|---|---|---|
| Decoy service account read (4662 on a honeypot SPN user) | T1087.002 | DC Security 4662 with a SACL on the decoy | [ldap_enumeration](../../red/active_directory/ldap_enumeration/) | Needs a decoy account and SACL in the lab |
| `(servicePrincipalName=*)` LDAP searches from workstations | T1087.002 / T1558.003 | DC Directory Service 1644 | [ldap_enumeration](../../red/active_directory/ldap_enumeration/) | 1644 is verbose; enable on DCs only with thresholds |
| JWT with `alg: none` rejected by the application | T1606 | Application auth logs | [jwt_testing](../../red/web/jwt_testing/) | Application log source not mapped |
| Executable or double-extension upload | T1505.003 | WAF logs (multipart filename) | [file_upload_testing](../../red/web/file_upload_testing/) | WAF log source not mapped |
| SUID search + getcap + sudo -l in one session | T1083 / T1548.001 | Sysmon for Linux 1 | [privilege_escalation_checks](../../red/linux/privilege_escalation_checks/) | Needs a Linux administration baseline before it can alert |

## Built from this list

| Idea | Became | Note |
|---|---|---|
| Suspicious children of `wsmprovhost.exe` | [T1021.006_wsmprovhost_suspicious_child](../../detect/detections/T1021.006_wsmprovhost_suspicious_child/) | Shells, encoded PowerShell and proxy binaries under both WinRM hosts |
| Password spray as a correlation rule | [T1110.003_password_spray_burst](../../detect/correlations/T1110.003_password_spray_burst/) | Built once the engine gained Sigma correlations |
| One client receiving 401/403 on many API paths | [T1190_api_auth_probing](../../detect/correlations/T1190_api_auth_probing/) | Web access log mapped for Sentinel and Splunk |
| Sequential object IDs read by one session | [T1190_object_id_enumeration](../../detect/correlations/T1190_object_id_enumeration/) | Grouped by client address: access logs carry no session or owner field |
| Crontab written by an interactive user | [T1053.003_crontab_noninteractive_install](../../detect/detections/T1053.003_crontab_noninteractive_install/) | Keys on non-interactive installs (`crontab -`, `crontab <file>`), which scripts and intruders use |
| `base64 -d` piped into a shell; execution from /tmp | [T1059.004_linux_suspicious_shell_execution](../../detect/detections/T1059.004_linux_suspicious_shell_execution/) | Sysmon for Linux instead of auditd: the same field names as on Windows |
