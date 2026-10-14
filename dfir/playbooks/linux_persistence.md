---
playbook: linux_persistence
techniques: [T1053.003, T1059.004, T1083, T1548.001]
detections: [T1053.003_crontab_noninteractive_install, T1059.004_linux_suspicious_shell_execution]
red_tests: [cron_persistence, suspicious_shell_execution, privilege_escalation_checks]
---

# DFIR Playbook: Linux Persistence and Execution

## Trigger
A crontab changed outside configuration management, a Base64-decoded command was piped into a shell, a file executed from /tmp, /var/tmp or /dev/shm, or a session ran privilege-escalation enumeration (SUID search, getcap, sudo -l).

## Required Data
- auditd records (EXECVE, SYSCALL, PATH) or Sysmon for Linux events
- syslog / journald (cron, sudo, sshd)
- Cron locations, systemd units, shell profiles and authorized_keys files
- Network connections of the host (ss, netflow)

## First 15 Minutes
1. Identify the user and session (sshd login, web server process, cron job) behind the activity.
2. Read the crontab or the decoded command - what does it run and where does it reach out to?
3. List files executed from world-writable directories in the window.
4. Check sudo usage and privilege changes by the same session.

## Deep Investigation
- All persistence locations: `/etc/crontab`, `/etc/cron.*`, user crontabs, systemd units (`/etc/systemd/system`, `~/.config/systemd/user`), `~/.bashrc` and `/etc/profile.d`, `~/.ssh/authorized_keys`
- The entry point: SSH with which key, a vulnerable web application, a stolen credential
- Outbound connections and downloaded tools
- SUID changes or new capabilities set on binaries

## Evidence to Collect
| Evidence | Source | Purpose |
|---|---|---|
| Crontabs and systemd units | Disk | Persistence entries and what they run |
| EXECVE records | auditd / Sysmon for Linux | Commands executed and their parents |
| Files in /tmp, /var/tmp, /dev/shm | Disk | Dropped payloads |
| Authentication logs | /var/log/auth.log, journald | How the attacker logged in, sudo use |
| authorized_keys | ~/.ssh | Keys added for re-entry |

## Escalate If
- A crontab or systemd unit that downloads or runs code from a writable path
- A shell started by a web server or database process
- Enumeration followed by a successful privilege change
- An unknown SSH key in authorized_keys

## Closure Guidance
Close as benign only for configuration management or a documented administrator task (named owner, change record). Preserve the crontab and unit files in the ticket before removing anything.
