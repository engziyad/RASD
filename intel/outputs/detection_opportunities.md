# Detection Opportunities

Prioritised output of the analyses in [`reports/`](../reports/) and the coverage gaps reported by the red tests. Status is the state in this repository.

| # | Opportunity | ATT&CK | Status | Next step |
|---|---|---|---|---|
| 1 | Encoded PowerShell from Office | T1059.001 | Detected | Lab evidence |
| 2 | Scheduled task / Run key into user-writable paths | T1053.005, T1547.001 | Detected | Lab evidence |
| 3 | comsvcs MiniDump by name or ordinal | T1218.011, T1003.001 | Detected | Lab evidence |
| 4 | RC4 Kerberoasting from workstations | T1558.003 | Detected + hunt | Lab evidence with an RC4-enabled lab SPN |
| 5 | Log clearing (process and record) | T1070.001 | Detected | Lab evidence (Security clear is opt-in) |
| 6 | Remote command services | T1569.002 | Detected | Lab evidence |
| 7 | Password spray burst | T1110.003 | Detected (correlation) | Lab evidence with 9 or more lab accounts |
| 8 | Domain account and SPN enumeration | T1087.002 | Gap | A process-creation correlation for `net ... /domain` and AD cmdlets; a decoy account and 1644 for in-process LDAP |
| 9 | WinRM lateral movement | T1021.006 | Detected | Lab evidence; list the administration hosts that use WinRM |
| 10 | Web API probing and object-ID enumeration (IDOR) | T1190 | Detected (correlations) | Lab evidence from the application's access log |
| 11 | Web shells, forged JWT and unsafe uploads | T1505.003, T1606 | Gap | A web server process starting a shell (process creation); an application log source for token failures |
| 12 | Linux cron and shell execution | T1053.003, T1059.004 | Detected | Lab evidence with Sysmon for Linux |
| 13 | Linux privilege-escalation reconnaissance | T1083 | Gap | A burst rule on find / getcap / sudo -l executions |

The gaps (8, 11, 13) are ranked, with the groups documented using each technique, in the [detection backlog](detection_backlog.md).
