# Deception - Interaction With a Decoy Network Service

<!-- rasd:facts:start -->
| | |
|---|---|
| **ATT&CK** | [T1046](https://attack.mitre.org/techniques/T1046/) Network Service Discovery (discovery) · related: [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Brute Force: Password Guessing (credential-access) |
| **Severity** | `high` |
| **Maturity** | **SIEM-Ready** ([model](../../../docs/RASD_MATURITY_MODEL.md)) |
| **Engineering Score** | 100/100 · operational pending - [run the lab](../../../docs/OPERATIONAL_VALIDATION.md) |
| **Tests** | 23 true positive · 12 true negative · 11 technique mutations |
| **Proof** | 100% of rule mutants killed · fuzzer resistance 100% over 0 variants |
| **Behaviour proof** | 3 of 7 variants proven for every event · no known gap · 4 exclusions proven quiet ([certificate](../../../docs/CERTIFICATES.md#t1046-deception---interaction-with-a-decoy-network-service)) |
| **Parity** | KQL and SPL identical to the rule on 274 events (RASD's offline KQL / SPL model, not yet a live SIEM) |
| **Public data** | no public dataset records it yet · [why](public_evidence.md) |
| **Rule** | [`rule.yml`](rule.yml) · [KQL](../../../queries/kql/T1046_decoy_service_interaction.kql) · [SPL](../../../queries/spl/T1046_decoy_service_interaction.spl) |
| **Operations** | [triage](triage.md) · [response](response.md) · [closure](closure.md) · [tuning](tuning.yml) · [contract](contract.yml) |
| **Chain** | red: [decoy_service_probe](../../../red/linux/decoy_service_probe/) · DFIR: [decoy_service_interaction](../../../dfir/playbooks/decoy_service_interaction.md) · purple: [T1046_decoy_service](../../../purple/scenarios/T1046_decoy_service.md) |
<!-- rasd:facts:end -->

Part of [RASD-Deceive](../../../deceive/): the decoy host this rule watches is defined once in [`deceive/decoys.yml`](../../../deceive/decoys.yml), configured from [`deceive/opencanary/settings.json`](../../../deceive/opencanary/settings.json), and `rasd deceive --check` fails the build when the inventory, this rule and its tests disagree - including when the inventory enables a module whose event codes the rule does not list.

## Telemetry required
The decoy host's **OpenCanary log** (`/var/tmp/opencanary.log` in the shipped configuration: one JSON record per line) forwarded to the SIEM as the `opencanary/honeypot` log source - index `deception`, sourcetype `opencanary` in Splunk; a parser function `OpenCanary` over the ingested records in Sentinel ([mappings](../../../tools/mappings.yml)). The rule reads `node_id`, `logtype` and `src_host`, which OpenCanary writes into every record. The port scan module needs the kernel's SYN log (`iptables -j LOG`, as the OpenCanary documentation describes); without it, only connections to enabled services are recorded.

## How the detection works
A decoy host runs services nobody on the network needs: an SSH daemon with an old banner, a NAS login page, an FTP server, a database port, RDP and VNC, an SMB share named `Backups`. There is no reason to talk to it, so the first packet that reaches it is reconnaissance - a sweep, a port scan, a connection to see what answers - and a login attempt is password guessing. OpenCanary writes a JSON record for each, and the rule fires on **any** record of the inventory's decoy whose `logtype` is one of the event codes of the modules enabled on it, from any client except two: the lab's authorised vulnerability scanner and the decoy's own loopback health check, each a documented tuning proven necessary by a true negative.

Not selected by design: the decoy's own housekeeping records (start-up, heartbeat, configuration saves, codes 1000-1006), the LLMNR responder's records (Windows hosts resolving names, code 19001), and the codes of modules the inventory does not enable. The inventory names the modules; `rasd deceive --check` derives their codes from OpenCanary's logger and fails when the rule lists more or fewer.

## Evasion & coverage gaps
- A scan that **skips the decoy's address**, or probes only ports the decoy does not listen on when the port scan module has no kernel log to read.
- An attacker who **fingerprints the decoy** - an SSH banner of a 2008 Debian, a NAS login page on a host with no other role - and moves on. The configuration sets banners and skins; making them fit the network, and giving the host a DNS name and a place in the asset list, is operational work.
- **Passive reconnaissance** that never touches the network (a host list from a share, a CMDB, DNS zone transfers) produces no decoy record.
- A **decoy that is down**, or whose log is not forwarded, records nothing and nothing says so: `Test-RasdDecoys.ps1` checks the decoy's ports from the lab, and the SIEM should alert when the decoy's heartbeat (code 1004, written every few minutes) stops.

## False positives & tuning
Network management and asset discovery tools that sweep every address behave exactly like the attacker. One scanner is filtered by address; for a second one, the accepted answer is to exclude the decoy from the tool's inventory rather than to filter the tool, so nothing on that host is hidden. A new administrator who connects to the decoy because it looks real is a finding about the asset list, not a false positive. Every tuning - applied, proposed or rejected - is recorded in [`tuning.yml`](tuning.yml), and `rasd tune --filter T1046` measures a proposal before it is applied.

## Offensive validation
[`red/linux/decoy_service_probe`](../../../red/linux/decoy_service_probe/) connects to the decoy's SSH port and posts one login attempt to the decoy web portal with the run marker as the user name, from a lab Linux host; the decoy's record of the login attempt is one of this rule's true positives (CI proves it matches) and carries the marker, so evidence binds it to the run. Run it from the lab host, export the decoy's log and turn the run into evidence:

```bash
python red/run_red.py --platform linux --test decoy_service_probe --lab-confirmed --target http://10.0.0.40
scp lab-canary-01:/var/tmp/opencanary.log ./canary-export.jsonl
rasd evidence --results <results>/emulation-results.json --logs canary-export.jsonl
```

## Test locally
```bash
rasd test --filter T1046
rasd prove --filter T1046
rasd certify --filter T1046 -v
rasd parity --filter T1046
rasd explain T1046_decoy_service_interaction --tp 1
rasd deceive --check
```
