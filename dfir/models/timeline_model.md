# Timeline Model

Every RASD investigation builds its timeline in this order. Each phase names the telemetry that fills it, so a missing phase is visibly a telemetry gap, not an assumption.

```text
Alert Time
   ↓
Initial Process Execution
   ↓
Child Process Activity
   ↓
File / Registry Changes
   ↓
Network Connections
   ↓
Authentication Events
   ↓
Persistence Events
   ↓
Containment Action
   ↓
Recovery / Closure
```

| Phase | Windows telemetry | Linux telemetry |
|---|---|---|
| Alert time | The detection's triggering event | The triggering event |
| Initial process execution | Sysmon 1, Security 4688 | auditd EXECVE, Sysmon for Linux 1 |
| Child process activity | Sysmon 1 by ParentProcessGuid | auditd ppid, Sysmon for Linux 1 |
| File / registry changes | Sysmon 11, 12, 13 | auditd PATH, Sysmon for Linux 11 |
| Network connections | Sysmon 3, 22; proxy; firewall | Sysmon for Linux 3; netflow |
| Authentication events | Security 4624, 4648, 4768, 4769, 4771, 4776 | auth.log, journald (sshd, sudo) |
| Persistence events | 4698, 7045, 4697, Sysmon 13 (Run keys) | crontab, systemd units, authorized_keys |
| Containment action | Ticket / EDR action log | Ticket / EDR action log |
| Recovery / closure | Ticket | Ticket |

The [timeline template](../templates/timeline_template.md) uses these phases as its rows.
