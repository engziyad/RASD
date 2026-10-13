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
| 7 | Password spray burst | T1110.003 | Hunt only | Correlation support in the engine |
| 8 | LDAP SPN enumeration | T1087.002 | Gap | Decoy account + 1644 in the lab |
| 9 | WinRM lateral movement | T1021.006 | Gap | Baseline admin use, then a wsmprovhost child-process rule |
| 10 | Web API probing, IDOR, forged JWT, unsafe uploads | T1190, T1606, T1505.003 | Gap | Map a web / WAF log source |
| 11 | Linux cron, encoded shell, privesc recon | T1053.003, T1059.004, T1083 | Gap | Map an auditd / Sysmon for Linux log source |
