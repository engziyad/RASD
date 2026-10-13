# Detection Ideas

Ideas that are not detections yet, each tied to the offensive test that already produces its telemetry. When an idea is built, it moves to `detect/detections/` and the red test's `gap` block is removed.

| Idea | ATT&CK | Telemetry | Red test that validates it | Blocker today |
|---|---|---|---|---|
| Decoy service account read (4662 on a honeypot SPN user) | T1087.002 | DC Security 4662 with a SACL on the decoy | [ldap_enumeration](../../red/active_directory/ldap_enumeration/) | Needs a decoy account and SACL in the lab |
| `(servicePrincipalName=*)` LDAP searches from workstations | T1087.002 / T1558.003 | DC Directory Service 1644 | [ldap_enumeration](../../red/active_directory/ldap_enumeration/) | 1644 is verbose; enable on DCs only with thresholds |
| Suspicious children of `wsmprovhost.exe` | T1021.006 | Sysmon 1 on the target | [winrm_access_validation](../../red/active_directory/winrm_access_validation/) | Baseline of normal admin commands needed |
| Password spray as a correlation rule | T1110.003 | DC 4771 / 4776 | [password_spray_simulation](../../red/active_directory/password_spray_simulation/) | Engine evaluates single events; hunt exists |
| One client receiving 401/403 on many API paths | T1190 | Web access logs | [api_auth_testing](../../red/web/api_auth_testing/) | No web log source mapped yet |
| Sequential object IDs read by one session | T1190 (API1 BOLA) | Web access logs with session id | [idor_testing](../../red/web/idor_testing/) | Access logs lack the session / owner field |
| JWT with `alg: none` rejected by the application | T1606 | Application auth logs | [jwt_testing](../../red/web/jwt_testing/) | Application log source not mapped |
| Executable or double-extension upload | T1505.003 | WAF logs (multipart filename) | [file_upload_testing](../../red/web/file_upload_testing/) | WAF log source not mapped |
| Crontab written by an interactive user | T1053.003 | auditd / Sysmon for Linux | [cron_persistence](../../red/linux/cron_persistence/) | No Linux log source mapped |
| `base64 -d` piped into a shell; execution from /tmp | T1059.004 | auditd EXECVE | [suspicious_shell_execution](../../red/linux/suspicious_shell_execution/) | No Linux log source mapped |
| SUID search + getcap + sudo -l in one session | T1083 / T1548.001 | auditd EXECVE | [privilege_escalation_checks](../../red/linux/privilege_escalation_checks/) | Needs Linux telemetry and correlation |
