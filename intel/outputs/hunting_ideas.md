# Hunting Ideas

Hypotheses for proactive hunts. Each names the data it needs and where an existing query helps.

| Hypothesis | Data | Start from |
|---|---|---|
| An Office document launched PowerShell that then talked to the internet | Sysmon 1 + 3 | [`powershell_encoded_with_network_or_child`](../../queries/hunts/) |
| A workstation Kerberoasted several service accounts | DC 4769 | [`kerberoasting_volume_hunt`](../../queries/hunts/kerberoasting_volume_hunt.kql), [`kerberoasting_contextual_hunt`](../../queries/hunts/kerberoasting_contextual_hunt.kql) |
| Something other than the EDR reads LSASS | Sysmon 10 | [`lsass_access_precheck`](../../queries/hunts/lsass_access_precheck.kql) |
| One source failed authentication for many accounts | DC 4768 / 4771 / 4776 | [`password_spray_hunt`](../../queries/hunts/password_spray_hunt.kql) |
| The same binary is referenced by a task and a Run key | Security 4698, Sysmon 13 | [`persistence_sweep`](../../dfir/queries/kql/persistence_sweep.kql) |
| A server received a 7045 right after a network logon from a workstation | System 7045, Security 4624 | [lateral movement playbook](../../dfir/playbooks/lateral_movement.md) |
| A host replayed through `rasd replay` shows a storyline nobody alerted on | Any exported logs | `rasd replay <export> --assets <assets.csv>` |
