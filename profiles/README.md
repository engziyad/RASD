# Telemetry profiles

The rules, their tests and the evidence step use Sysmon / Windows native field names: `Image`, `CommandLine`, `TargetObject`, `TicketEncryptionType`. Exports from a SIEM or an EDR usually rename them - Elastic writes `process.command_line`, Defender writes `ProcessCommandLine`, Splunk's CIM writes `process`. A profile tells RASD where each rule field lives in such an export and how to recognise the event type, so the same rules run on it unchanged.

```bash
rasd doctor export.jsonl --profile auto            # which profile fits, and is the export ready?
rasd doctor export.jsonl --profile elastic-ecs
rasd replay export.jsonl --profile mde-advanced-hunting
rasd evidence --results emulation-results.json --logs export.jsonl --profile splunk-ta-windows
rasd benchmark export.jsonl --profile sentinel-asim
```

A profile only fills fields the event is missing and keeps the original ones, so a native export is never changed. `rasd profiles --detect export.jsonl` scores every profile on a sample of the export.

<!-- rasd:profiles:start -->
| Profile | Reads exports from | `process_creation` | `process_access` | `registry_set` | `windows/security` | `windows/system` | `linux/process_creation` | `webserver` | `opencanary/honeypot` |
|---|---|---|---|---|---|---|---|---|---|
| [`elastic-ecs`](elastic-ecs.yml) | Elasticsearch / Kibana export (JSON) of logs-windows.*, winlogbeat-* or logs-endpoint.events.* | ✓ | ✓ | ✓ | ✓ | ✓ | - | - | - |
| [`mde-advanced-hunting`](mde-advanced-hunting.yml) | Defender XDR / Sentinel export (JSON) of DeviceProcessEvents and DeviceRegistryEvents | ✓ | - | ✓ | - | - | - | - | - |
| [`nxlog-windows`](nxlog-windows.yml) | NXLog im_msvistalog with to_json(), Windows Event Collector exports, OTRF Security-Datasets | ✓ | ✓ | ✓ | ✓ | ✓ | - | - | - |
| [`sentinel-asim`](sentinel-asim.yml) | Sentinel query export (JSON) of imProcessCreate / imRegistry | ✓ | - | ✓ | - | - | - | - | - |
| [`splunk-cim`](splunk-cim.yml) | Splunk CIM Endpoint data model export (JSON) | ✓ | - | ✓ | - | - | - | - | - |
| [`splunk-ta-windows`](splunk-ta-windows.yml) | Splunk search export (JSON) of the sysmon and wineventlog indexes | ✓ | ✓ | ✓ | ✓ | ✓ | - | - | - |
| [`sysmon-native`](sysmon-native.yml) | RASD lab export (red/Export-LabTelemetry.ps1), Windows Event Forwarding, any export that keeps the EventData names | ✓ | ✓ | ✓ | ✓ | ✓ | - | - | - |
| [`windows-security-4688`](windows-security-4688.yml) | Security log export (Export-LabTelemetry.ps1 -LogName Security -EventId 4688,4769,1102, Windows Event Forwarding, Sentinel SecurityEvent, Splunk WinEventLog) | ✓ | - | - | ✓ | ✓ | - | - | - |
<!-- rasd:profiles:end -->

`windows-security-4688` is for estates without Sysmon: Security event 4688 stands in for Sysmon event 1. Export it explicitly (`Export-LabTelemetry.ps1 -LogName Security -EventId 4688,4769,1102`; the default event list is for Sysmon labs). It has no `OriginalFileName`, so `rasd doctor` reports the six rules with a renamed-binary branch as DEGRADED (each contract rates that field `medium`), and the other process rules as READY.

A dash means the profile's schema has no record the rules for that log source can use - Defender has no Sysmon-style lsass-access record, CIM and ASIM have no 4769 ticket-encryption or 7045 service-install fields. `rasd doctor` reports those detections as BLIND with that reason; collect the native Windows / Sysmon events for them.

## Not the same as `tools/mappings.yml`

| File | Direction | Used by |
|---|---|---|
| `profiles/*.yml` (this folder) | export field names → rule field names, when reading logs | `doctor`, `replay`, `evidence`, `benchmark`, `correlate`, `nearmiss` |
| [`tools/mappings.yml`](../tools/mappings.yml) | rule field names → SIEM table and column names, when writing queries | `convert`, `parity`, the Splunk app |

## Adding a profile

Copy the closest profile, rename it, and set for each log source the field (or `join` / `path` of fields) that holds each rule field, and the `infer` rule that recognises the event type when the export has no Windows channel. Add a few events of that export to [`samples/profiles/`](../samples/profiles/) with the detections each one must trigger (`_expect`); the unit tests then prove the profile end to end. EDR schemas whose field references are not public are not shipped; a profile for one follows the same format.
