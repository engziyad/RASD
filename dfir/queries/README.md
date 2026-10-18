# DFIR investigation queries

Pivot queries the playbooks call during an investigation. Unlike `queries/kql` and `queries/spl`, they are not generated from Sigma and do not alert: an analyst fills in the values from the alert and runs them.

| Query | Used in | Values to set |
|---|---|---|
| `process_tree` | suspicious PowerShell | host, process GUID, alert time (KQL) / `<HOST>`, `<GUID>` (SPL) |
| `user_host_window` | suspicious PowerShell | host, user, alert time (KQL) / `<HOST>`, `<USER>` and a ±30 minute time range (SPL) |
| `persistence_sweep` | suspicious PowerShell, scheduled task, Run key | host and window (KQL) / `<HOST>` and the time range (SPL) |
| `kerberos_client_activity` | Kerberoasting | client IP and window (KQL) / `<CLIENT_IP>` and the time range (SPL) |

"Used in" lists the playbooks that link the query today. `process_tree` and `user_host_window` fit any endpoint alert (rundll32, Run key, service installation, LSASS access) with the alert's host, user and time, and `kerberos_client_activity` fits a password spray's source address too.

Field and table names follow `tools/mappings.yml`: a `Sysmon` parser function, `SecurityEvent` and `Event` in Sentinel; the Splunk Add-ons for Windows and Sysmon with XML event logs. Adjust them once there and in these files if your environment differs.
