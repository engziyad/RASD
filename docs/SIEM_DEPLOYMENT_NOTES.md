# SIEM Deployment Notes

The generated queries in [`queries/`](../queries/) are proven equivalent to the tested rules by `rasd parity`. What parity cannot know is how your environment names tables and fields; that lives in one file, [`tools/mappings.yml`](../tools/mappings.yml).

## Microsoft Sentinel / Defender (KQL)
- Process, process-access and registry rules read a function named `Sysmon` (the common community parser). If your parser has another name, change the `kql.logsources` entries in `mappings.yml`.
- Security events come from `SecurityEvent`, System events from `Event | where EventLog == "System"`. The provider field is mapped from Sigma's `Provider_Name` to `Source`.
- The stock `Event` table has no `ServiceName` or `ImagePath` column, and `TicketEncryptionType` is not a `SecurityEvent` column in every workspace. For these two tables the converter extends every field a rule reads (except the native columns listed under `kql.eventdata` in `mappings.yml`) from the `EventData` XML before the filter:
  `| extend ImagePath = coalesce(tostring(column_ifexists("ImagePath", "")), extract(@'Name="ImagePath">([^<]*)<', 1, EventData))`.
  A real column wins when it exists; otherwise the value comes from the XML. `rasd parity` fails if a query reads such a field without extracting it. Values are XML-escaped in `EventData` (`&amp;`, `&lt;`), so a rule value containing `&` or `<` would need the escaped form.
- Process-creation rules read Sysmon EID 1. To run them on Security 4688 instead, point `process_creation` at `SecurityEvent | where EventID == 4688` and map `Image` to `NewProcessName` and `ParentImage` to `ParentProcessName` under `kql.fields`; 4688 has no `OriginalFileName`, so renamed-binary branches go blind.
- String columns in Kusto are never null, so negations need no special handling; regular expressions use RE2, which is why `validate.py` rejects lookarounds, backreferences, atomic groups and possessive quantifiers.
- Deploy each query as an analytics rule. Map entities (host, account, process) for the incident graph, and use the contract's `detection_logic.severity` as the rule severity.
- Correlation queries (`queries/kql/correlations/`) count exactly with `array_length(make_set())` - `dcount()` is an estimate - and bin on `window_start = bin(TimeGenerated, 600s)`. Schedule them every 10 minutes with a 20-minute lookback and group alerts on `window_start` and the group-by fields ([CORRELATIONS.md](CORRELATIONS.md#in-the-siem)).

## Splunk (SPL)
- **Splunk app:** [`queries/splunk_app`](../queries/splunk_app/README.md) is generated on every build. `rasd/` holds the indexes, a `Provider_Name` extraction from the event XML, one scheduled alert per detection (`RASD - <detection id>`, every 5 minutes over the last 10, each also logging an event with the alerting host to `rasd_alerts`), one per correlation (once per window length over the last two windows plus 3 minutes, keeping only the most recent complete window, so each window is reported by exactly one run with the search head in UTC or a fixed-offset time zone; one alert per window and group, the group written as the alerting host) and three reports - **RASD - alert export** and its `(audit)` and `(scheduler)` fallbacks - whose CSV is the `--siem-alerts` input of `rasd evidence`. `rasd_forwarder/` holds the Universal Forwarder inputs (`renderXml = true`, so the sources match the queries). It needs the Splunk Add-on for Microsoft Windows and the Splunk Add-on for Sysmon for field extractions.
- Sysmon events: `index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`; Windows events: `index=wineventlog` with the XML sources. `EventID` is mapped to `EventCode`.
- Every query is a raw search that starts with `index=`, so it pastes into a saved search or the REST API unchanged.
- Inside a `NOT`, fields are read as `coalesce('F', "")`: in Splunk, `NOT` over a missing field is NULL and `where` would drop the event. Parity tests this on events with each rule field removed and emptied.
- Schedule each saved search with a window that matches its latency target (see the Detection Latency weights in [QUALITY_MODEL.md](QUALITY_MODEL.md)).

## Before going live
1. `python rasd.py doctor <export from your SIEM> --profile auto` - the [telemetry profile](../mappings/README.md) that fits the export (ECS, CIM, ASIM, Defender), fields present, command lines not truncated.
2. `python rasd.py replay <export> --profile auto --assets assets.csv` - alert volume forecast per rule and the risk ranking; `python rasd.py benchmark <export>` - rule cost on your data volume.
3. `python rasd.py tune` - measure every tuning proposal before adding it; never add a filter that hides an attack variant.
4. Record each rule's deployment (SIEM, rule name, schedule) in your change system; name SIEM rules after the detection id so `rasd evidence --siem-alerts` can match their alerts.
