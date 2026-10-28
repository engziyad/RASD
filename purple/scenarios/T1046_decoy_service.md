---
scenario: T1046_decoy_service
technique: T1046
detections: [T1046_decoy_service_interaction]
red_test: decoy_service_probe
dfir_playbook: decoy_service_interaction
---

# Purple Scenario: Decoy Service Probe (T1046 Network Service Discovery)

## Objective
Validate that touching the decoy host - a connection to its SSH port and one credential guess on its web portal - is recorded by OpenCanary with the client address and fires the decoy service detection, and that the record of the guess carries the run marker so evidence binds it to the run.

## Red
Run `decoy_service_probe --target http://10.0.0.40` from a Linux lab host: one TCP connection to the decoy's port 22, then one POST to its login page with the marker as the user name.

Test folder: [`red/linux/decoy_service_probe`](../../red/linux/decoy_service_probe/) · expected telemetry: [expected_telemetry.md](../../red/linux/decoy_service_probe/expected_telemetry.md)

The decoy host must run OpenCanary with [`deceive/opencanary/settings.json`](../../deceive/opencanary/settings.json) ([inventory](../../deceive/decoys.yml)).

## Telemetry
- OpenCanary 4000 - node_id `lab-canary-01`, src_host the lab host, dst_port 22
- OpenCanary 3001 - node_id `lab-canary-01`, src_host the lab host, dst_port 80, logdata.USERNAME the run marker

## Detect
- [`T1046_decoy_service_interaction`](../../detect/detections/T1046_decoy_service_interaction/) - rule, tests, mutation tests, behaviour proof, KQL and SPL

Run the full gate for this detection:

```bash
rasd test --filter T1046
rasd prove --filter T1046
rasd certify --filter T1046
rasd parity --filter T1046
rasd deceive --check
```

## DFIR
Playbook: [decoy_service_interaction.md](../../dfir/playbooks/decoy_service_interaction.md). Collect:
- The decoy's records from the client, in order
- The client's process and network telemetry around the first record
- The decoy's configuration at run time

## Intel
Network service discovery is documented for most of the groups RASD tracks - APT39 (G0087), APT41 (G0096), Fox Kitten (G0117), Lazarus Group (G0032), OilRig (G0049), Rocke (G0106), Volt Typhoon (G1017) - [actor tradecraft map](../../intel/mappings/actor_tradecraft_map.md). A decoy host is found by the same sweep that finds the real ones.

## Success Criteria
- Required telemetry exists (every event in expected_telemetry.md arrived with its fields)
- Detection triggers (`rasd evidence` reports FIRED for every detection above, on a record that carries the marker)
- Triage steps are actionable (the triage card answered the analyst's first questions)
- Response guidance is available (the response card and the DFIR playbook were usable)
- Cleanup is complete (the runner recorded cleanup: verified)
- Evidence is documented (evidence.md committed for every detection above)
- The decoy's log was copied out and passed to `rasd evidence`

## Status
Live status for this scenario is in the [validation matrix](../validation_matrix.md).
