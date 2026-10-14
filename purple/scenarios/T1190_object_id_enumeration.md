---
scenario: T1190_object_id_enumeration
technique: T1190
detections: [T1190_object_id_enumeration]
red_test: idor_testing
dfir_playbook: web_application_attack
---

# Purple Scenario: Object ID Enumeration, IDOR / BOLA (T1190 Exploit Public-Facing Application)

## Objective
Validate that one account reading other users' objects by walking their IDs reaches the access log and fires the object-ID enumeration correlation.

## Red
Run `idor_testing` against a lab copy of the application: one lab account logs in and reads baskets 1 to 5. All requests are read-only and carry the run marker in the User-Agent.

Test folder: [`red/web/idor_testing`](../../red/web/idor_testing/) · expected telemetry: [expected_telemetry.md](../../red/web/idor_testing/expected_telemetry.md)

## Telemetry
- Access log - `GET /rest/basket/<n>` for consecutive IDs from one client within seconds, with the status of each

## Detect
- [`T1190_object_id_enumeration`](../../detect/correlations/T1190_object_id_enumeration/) - correlation rule, base rule, scenarios, parameter mutants, SPL and KQL

Run the full gate for this detection:

```bash
rasd correlate --filter T1190_object -v
```

## DFIR
Playbook: [web_application_attack.md](../../dfir/playbooks/web_application_attack.md). Collect:
- Access-log lines of the client for the window, with status codes
- Application records of who owns each object requested
- Authentication records of the account used

## Intel
Broken object-level authorization is the top risk of the OWASP API Security Top 10 (2023). Groups exploiting internet-facing applications: HAFNIUM (G0125) - [actor tradecraft map](../../intel/mappings/actor_tradecraft_map.md).

## Success Criteria
- Required telemetry exists (every event in expected_telemetry.md arrived with its fields)
- Detection triggers (`rasd evidence` reports FIRED for the detection above)
- Triage steps are actionable (the triage card answered the analyst's first questions)
- Response guidance is available (the response card and the DFIR playbook were usable)
- Cleanup is complete (the runner recorded cleanup: verified)
- Evidence is documented (evidence.md committed for the detection above)

## Status
Live status for this scenario is in the [validation matrix](../validation_matrix.md).
