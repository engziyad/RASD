# Hunting queries

Hand-written hunts that complement the single-event detections. They are **not** generated from Sigma, so CI does not overwrite them. Thresholds are starting points: baseline your environment before alerting on them.

| Hunt | Complements | Logic |
|---|---|---|
| `kerberoasting_volume` | [T1558.003](../../detect/detections/T1558.003_kerberoasting_rc4_tgs/) | One client requesting service tickets for distinct user-based SPNs within 10 minutes, any encryption type: 3+ when any ticket is RC4, 5+ when all are AES. The alerting, tested version is the [Kerberoasting volume correlation](../../detect/correlations/T1558.003_kerberoasting_volume/); keep this hunt for its lower RC4 threshold and per-user split |
| `kerberoasting_contextual_hunt` | [T1558.003](../../detect/detections/T1558.003_kerberoasting_rc4_tgs/) | Volume hunt plus asset type and account type enrichment, producing a risk score (RC4 adds 10) |
| `lsass_access_precheck` | [T1003.001](../../detect/detections/T1003.001_lsass_memory_access/) | Pre-deployment profile of every process that opens LSASS, to build the allow-list from your own estate |
| `password_spray_burst` | [password spray correlation](../../detect/correlations/T1110.003_password_spray_burst/) | One source failing Kerberos pre-auth (4771 0x18) or NTLM validation (4776 0xc000006a) for 5+ distinct accounts within 10 minutes. The alerting, tested version is the correlation (4771 and 4625 per client address); this hunt adds 4776 grouped by the workstation name the client claims |
| `powershell_encoded_with_network_or_child` | [T1059.001](../../detect/detections/T1059.001_powershell_encoded_command/) | Encoded PowerShell escalated from medium to high when it makes network connections or spawns children |

Every hunt ships as `.spl` (Splunk) and `.kql` (Sentinel / Defender).

## Optional enrichment

The contextual Kerberoasting hunt uses two lookups. Keys are normalised on both sides before the join: 4769 logs the client as `::ffff:10.0.0.5` and the user as `user@DOMAIN`, while inventories usually hold `10.0.0.5` and `user`.

- **Sentinel:** the hunt runs without the watchlists (`column_ifexists`); risk then falls back to volume.
- **Splunk:** `lookup` fails when the lookup definition does not exist. Create both lookups (a CSV with only the header row is enough) or delete the two `lookup` lines. Lookups match case-sensitively by default and the hunt lowercases the user, so define `privileged_accounts` with `case_sensitive_match = false` (transforms.conf) or keep its `user` column in lowercase.

The Kerberoasting hunts and the DFIR Kerberos query read `TicketEncryptionType`, `ServiceName` and `Status` from `EventData` when the `SecurityEvent` table has no such column, like the generated detections.

| Lookup | Splunk | Sentinel | Fields |
|---|---|---|---|
| Asset inventory | lookup `asset_inventory` | watchlist `asset_inventory` | `ip`, `asset_type` (workstation / server), `owner`, `criticality` |
| Privileged accounts | lookup `privileged_accounts` | watchlist `privileged_accounts` | `user`, `account_type` (service / admin / user) |

The correlation hunt uses `join`, which Splunk caps by subsearch limits. On large estates, schedule it over short windows or rewrite it with `stats` on `ProcessGuid`.
