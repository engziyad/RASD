#!/usr/bin/env python3
"""
splunk_app.py - every detection as a Splunk app, ready to install in the lab's Splunk.

Real operational evidence needs the SIEM to raise the alert, not only the offline engine.
This writes two Splunk apps under queries/splunk_app/ (generated, drift-checked like
queries/spl):

  rasd/                       install on Splunk Enterprise (or the free trial)
    default/app.conf
    default/indexes.conf      every index the queries read (sysmon, wineventlog, linux, web), and rasd_alerts
    default/props.conf        Provider_Name read from the event XML (the System rules need it)
    default/savedsearches.conf
                              one scheduled alert per detection and per correlation, named
                              "RASD - <id>", so `rasd evidence --siem-alerts` matches the
                              alerts it raises. A correlation alert runs once per window and
                              keeps only the most recent complete window, so every window is
                              reported by exactly one run (search head in UTC or a fixed offset).
                              Each alert also writes one event to the rasd_alerts index (Log
                              Event action) with the alerting host. Three reports export the
                              alerts as the --siem-alerts CSV, from three independent sources:
                                RASD - alert export              index=rasd_alerts (with host)
                                RASD - alert export (audit)      index=_audit action=alert_fired
                                RASD - alert export (scheduler)  index=_internal scheduler log
    metadata/default.meta     shares the searches and the field extraction app-wide
  rasd_fields/                install on a Splunk that does NOT have the Splunk add-ons for Windows,
                              Sysmon and Sysmon for Linux (a fresh lab Splunk): never beside them
    default/props.conf        the fields of the event XML under the names those add-ons give them
    default/transforms.conf   (EventCode / EventID, Computer, one field per <Data Name=...>), XML
                              entities decoded in the fields the rules read, and one event per
                              line with its own time for Sysmon for Linux
  rasd_forwarder/             install on the Universal Forwarder of every lab VM (and the DC)
    default/app.conf
    default/inputs.conf       Sysmon, Security, System and PowerShell logs, as XML, into
                              the two indexes
  rasd_forwarder_linux/       install on the Universal Forwarder of a Linux lab host
    default/app.conf
    default/inputs.conf       Sysmon for Linux (the add-on's journald input) into the linux
                              index; the lab web application's access log into the web index

The search of each alert is the generated SPL in queries/spl - the query `rasd parity`
proves equivalent to the tested rule (or, for a correlation, queries/spl/correlations, proven
by `rasd correlate`) - joined onto one line.

Usage
  rasd splunk            # write queries/splunk_app/
  rasd splunk --check    # fail if the committed app is stale (CI)
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BOLD, GREEN, RED, RESET, ROOT, VERSION, legacy_technique, load_detections
from convert import MAPPINGS, convert, logsource_key, referenced_fields
from correlation import load_correlations, to_spl

OUT = ROOT / "queries" / "splunk_app"
ALERT_PREFIX = "RASD - "
EXPORT_NAME = "RASD - alert export"
ALERT_INDEX = "rasd_alerts"
EXPORTS = {   # report name -> search; each yields _time, ss_name (carries the detection id), host when known
    # host comes from the alert's own results only: the rasd_alerts event's metadata host is the
    # search head, and a search-head name would make evidence reject a genuine alert
    EXPORT_NAME: f'index={ALERT_INDEX} sourcetype="rasd:alert" | eval ss_name=rasd_alert, host=alert_host '
                 '| table _time ss_name host alert_hosts result_count first_event last_event | sort 0 _time',
    f"{EXPORT_NAME} (audit)": f'index=_audit action=alert_fired ss_name="{ALERT_PREFIX}T*" '
                              '| table _time ss_name severity | sort 0 _time',
    f"{EXPORT_NAME} (scheduler)": f'index=_internal sourcetype=scheduler savedsearch_name="{ALERT_PREFIX}T*" '
                                  'status=success result_count>0 | rename savedsearch_name AS ss_name '
                                  '| table _time ss_name result_count | sort 0 _time',
}
SEVERITY = {"informational": 2, "low": 3, "medium": 4, "high": 5, "critical": 6}   # Splunk alert.severity
SCHEDULE = "*/5 * * * *"
WINDOW = "-10m@m"                     # each run reads one 5-minute slice that closed 5 minutes ago:
WINDOW_END = "-5m@m"                  # consecutive runs tile time (no event is alerted twice) and 5 minutes of indexing delay never drop one
# every index a generated query reads (from spl.logsources in tools/mappings.yml), then the alert index
INDEXES = tuple(dict.fromkeys(re.findall(r"\bindex=([A-Za-z0-9_]+)", " ".join(
    str(v) for v in (MAPPINGS["spl"].get("logsources") or {}).values())))) + (ALERT_INDEX,)
CORRELATION_LAG = 3                   # minutes a correlation alert waits after its window closes (indexing delay)
HEADER = "# Generated by tools/splunk_app.py from detect/detections and detect/correlations - do not edit; run: rasd build\n"

INPUTS = """\
# Lab inputs for RASD: a Universal Forwarder, or a Splunk Enterprise that runs on the lab host.
# renderXml = true sends each event as its XML, and source names it the way the queries read it:
# XmlWinEventLog:<channel>, the name such events are known by where the Windows add-on is
# installed. Left to itself Splunk calls the source WinEventLog:<channel>. That was seen on the
# lab's own Splunk, which has no add-on: no RASD search found an event there until these lines
# named the source.

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = sysmon
renderXml = true
source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

[WinEventLog://Security]
disabled = 0
index = wineventlog
renderXml = true
source = XmlWinEventLog:Security
evt_resolve_ad_obj = 0

[WinEventLog://System]
disabled = 0
index = wineventlog
renderXml = true
source = XmlWinEventLog:System

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = wineventlog
renderXml = true
source = XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
"""

INPUTS_LINUX = """\
# Lab Universal Forwarder inputs for RASD on a Linux lab host.
#
# Sysmon for Linux: install the Splunk Add-on for Sysmon for Linux on this forwarder. Its
# journald://sysmon input (enabled by default) reads Sysmon from journald as sourcetype
# sysmon:linux; this stanza only sends it to the linux index the queries read. If the add-on
# already sets an index, the add-on wins: check with
#   splunk btool inputs list journald://sysmon --debug
[journald://sysmon]
index = linux

# Access log of the lab web application, combined format (nginx, Apache; OWASP Juice Shop
# writes <install folder>/logs/access.log.<date>). Set the path, then disabled = 0.
[monitor:///var/log/nginx/access.log]
disabled = 1
index = web
sourcetype = access_combined
"""

PROPS = """\
# The System rules read Provider_Name (the event's <Provider Name='...'>). The Windows
# add-on names that field differently across versions, so read it from the XML directly.
[source::XmlWinEventLog:System]
EXTRACT-rasd_provider_name = <Provider Name=['"](?<Provider_Name>[^'"]+)

[source::XmlWinEventLog:Security]
EXTRACT-rasd_provider_name = <Provider Name=['"](?<Provider_Name>[^'"]+)

# The decoy's records: one JSON object per line. OpenCanary writes three times into each; the
# first one Splunk would find is the decoy host's local time, so read the UTC one by name.
[{decoy}]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\\r\\n]+)
TIME_PREFIX = "utc_time":\\s*"
TIME_FORMAT = %Y-%m-%d %H:%M:%S.%6N
MAX_TIMESTAMP_LOOKAHEAD = 32
TZ = UTC
KV_MODE = json

# What the alerts and the health watchdogs write to {alerts}: the time of such a record is the moment
# it was written, never one of the event times it quotes.
[rasd:alert]
SHOULD_LINEMERGE = false
DATETIME_CONFIG = CURRENT

[rasd:health]
SHOULD_LINEMERGE = false
DATETIME_CONFIG = CURRENT
"""

FIELDS_APP = "rasd_fields"
EVENT_XML = tuple(MAPPINGS["spl"].get("event_xml") or ())
# the text of an XML element as it was written: &amp; last, because "&amp;lt;" is the text "&lt;"
XML_ENTITIES = (("&lt;", "<"), ("&gt;", ">"), ("&quot;", '\\"'), ("&apos;", "'"), ("&amp;", "&"))
FIELDS_REPORT = "rasd_fields_event_code, rasd_fields_event_id, rasd_fields_computer, rasd_fields_data"
FIELDS_INTRO = """\
# For a Splunk WITHOUT the Splunk Add-on for Microsoft Windows, the Splunk Add-on for Sysmon and the
# Splunk Add-on for Sysmon for Linux (a fresh lab Splunk). Those add-ons read the fields out of the
# event XML; this app does the same under the same names, so the RASD searches find EventCode,
# Computer and every <Data Name='...'> as a field. Do not install it beside the add-ons.
#
# A field read by a regular expression holds the XML text as written (&amp; for &). The EVAL lines
# decode the five XML entities in the fields the rules read, so a rule sees the value Windows logged.
# KV_MODE = none: only the extractions named here read these records. Left on, Splunk would also make
# a field of every name=value it finds in the text, and a command line is text an intruder writes.
"""
FIELDS_LINES = """\
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\\r\\n]+)
TIME_PREFIX = <TimeCreated SystemTime=['"]
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%9N
MAX_TIMESTAMP_LOOKAHEAD = 40
TZ = UTC
TRUNCATE = 65536
"""
TRANSFORMS = """\
# One field per <Data Name='...'> of the event (Windows writes the attribute in single quotes,
# Sysmon for Linux in double quotes), the event id under both names the add-ons use, and the
# computer that logged the event.
[rasd_fields_data]
REGEX = <Data Name=['"]([^'"]+)['"]>([^<]*)</Data>
FORMAT = $1::$2

[rasd_fields_event_code]
REGEX = <EventID[^>]*>(\\d+)</EventID>
FORMAT = EventCode::$1

[rasd_fields_event_id]
REGEX = <EventID[^>]*>(\\d+)</EventID>
FORMAT = EventID::$1

[rasd_fields_computer]
REGEX = <Computer>([^<]+)</Computer>
FORMAT = Computer::$1
"""

META = """\
[]
access = read : [ * ], write : [ admin ]
export = system
"""


def one_line(spl: str) -> str:
    return " ".join(part.strip() for part in spl.splitlines() if part.strip())


def severity(det) -> int:
    level = (det.contract.get("detection_logic") or {}).get("severity") or det.level
    return SEVERITY.get(str(level).lower(), 4)


def alert_search(det) -> str:
    """The proven detection query, followed by a tiny lab-only summary row.

    The base query stays byte-for-byte generated from the tested rule; the appended
    fields make Splunk's Log Event action deterministic. Without this, `$result.host$`
    can be blank on some deployments because the result token depends on the first raw
    event. The summary keeps one row per host and scheduled run, and the alert fires once
    per row (digest mode off), so two hosts hit in the same slice are two alerts, each with
    its own host. An event with no host field is kept, with an empty alert_host.
    """
    base = one_line(convert(det.rule, 'spl'))
    return (base + f' | eval rasd_detection="{det.id}" '
            '| eval alert_host=coalesce(host, Computer, ComputerName, dvc, dest, TargetComputerName, WorkstationName, ClientAddress, "") '
            '| stats count as result_count earliest(_time) as first_event latest(_time) as last_event by rasd_detection, alert_host '
            '| eval alert_host=if(alert_host=="", null(), alert_host), alert_hosts=alert_host')


def correlation_schedule(seconds: int) -> tuple[str, str, str]:
    """(cron, earliest, latest) for a correlation: one run per window length, over the last two
    windows plus CORRELATION_LAG minutes of indexing delay. correlation_search keeps only the
    most recent complete window, so the runs tile time and each window is reported once - in
    UTC or any fixed-offset time zone, even when cron fires at local times that are not window
    boundaries (a daylight-saving transition can drop or repeat one window)."""
    minutes = seconds // 60
    if seconds % 60 or minutes < 1:
        raise ValueError(f"a {seconds}s correlation window cannot be scheduled by minute in Splunk")
    if 60 % minutes == 0:
        cron = "0 * * * *" if minutes == 60 else f"*/{minutes} * * * *"
    elif minutes % 60 == 0 and 24 % (minutes // 60) == 0:
        cron = "0 0 * * *" if minutes == 1440 else f"0 */{minutes // 60} * * *"
    else:
        raise ValueError(f"a {minutes}-minute correlation window cannot be expressed as a cron schedule")
    return cron, f"-{2 * minutes + CORRELATION_LAG}m@m", f"-{CORRELATION_LAG}m@m"


def correlation_search(corr) -> str:
    """The proven correlation query, then two lines of scheduling glue: keep only the windows that
    are complete inside this run's range and end in its last window length (consecutive runs
    tile time, so each window is reported by exactly one run), and name the detection and the
    alerting group for the Log Event action."""
    p = corr.params
    spl_fields = MAPPINGS["spl"].get("fields") or {}
    host = spl_fields.get(p.group_by[0], p.group_by[0]) if p.group_by else None   # the SPL column, e.g. c-ip -> clientip
    span = p.timespan
    return (one_line(to_spl(corr))
            + f" | addinfo | where window_start>=info_min_time AND window_start+{span}<=info_max_time"
              f" AND window_start+{span}>info_max_time-{span}"
            + f' | eval rasd_detection="{corr.id}"' + (f", alert_host='{host}'" if host else "")
            + ", result_count=event_count")


def saved_searches(dets, corrs=()) -> str:
    out = [HEADER]
    for det in dets:
        out += [f"[{ALERT_PREFIX}{det.id}]",
                f"description = {det.title} ({det.technique}"
                + (f"; ATT&CK v18: {legacy_technique(det.technique)}" if legacy_technique(det.technique) else "")
                + f"). Generated by RASD from rule {det.rule.get('id', '')}.",
                f"search = {alert_search(det)}",
                "disabled = 0",
                "enableSched = 1",
                f"cron_schedule = {SCHEDULE}",
                "realtime_schedule = 0",
                f"dispatch.earliest_time = {WINDOW}",
                f"dispatch.latest_time = {WINDOW_END}",
                "counttype = number of events",
                "relation = greater than",
                "quantity = 0",
                "alert.track = 1",
                "alert.digest_mode = 0",
                f"alert.severity = {severity(det)}",
                "alert.expires = 7d",
                "action.logevent = 1",
                f"action.logevent.param.index = {ALERT_INDEX}",
                "action.logevent.param.sourcetype = rasd:alert",
                "action.logevent.param.source = rasd",
                f'action.logevent.param.event = rasd_alert="$name$" detection="{det.id}" alert_host="$result.alert_host$" '
                'alert_hosts="$result.alert_hosts$" result_count="$result.result_count$" '
                'first_event="$result.first_event$" last_event="$result.last_event$" trigger_time="$trigger_time$"' ,
                ""]
    for corr in corrs:
        cron, earliest, latest = correlation_schedule(corr.params.timespan)
        out += [f"[{ALERT_PREFIX}{corr.id}]",
                f"description = {corr.title} ({corr.technique}). Sigma correlation: {corr.params.describe()}. "
                f"Generated by RASD from rule {corr.rule.get('id', '')}.",
                f"search = {correlation_search(corr)}",
                "disabled = 0",
                "enableSched = 1",
                f"cron_schedule = {cron}",
                "realtime_schedule = 0",
                f"dispatch.earliest_time = {earliest}",
                f"dispatch.latest_time = {latest}",
                "counttype = number of events",
                "relation = greater than",
                "quantity = 0",
                "alert.track = 1",
                "alert.digest_mode = 0",
                f"alert.severity = {severity(corr)}",
                "alert.expires = 7d",
                "action.logevent = 1",
                f"action.logevent.param.index = {ALERT_INDEX}",
                "action.logevent.param.sourcetype = rasd:alert",
                "action.logevent.param.source = rasd",
                f'action.logevent.param.event = rasd_alert="$name$" detection="{corr.id}" alert_host="$result.alert_host$" '
                'alert_hosts="$result.alert_host$" result_count="$result.event_count$" '
                f'{corr.params.metric}="$result.{corr.params.metric}$" window_start="$result.window_start$" '
                'first_event="$result.first_event$" last_event="$result.last_event$" trigger_time="$trigger_time$"',
                ""]
    for name, search in EXPORTS.items():
        out += [f"[{name}]",
                "description = RASD alerts that fired. Run it over the lab window and export the result as CSV: "
                "that file is the --siem-alerts input of rasd evidence.",
                f"search = {search}",
                "disabled = 0",
                "enableSched = 0",
                "dispatch.earliest_time = -24h",
                "dispatch.latest_time = now",
                ""]
    import health                                          # imported here: health reads this module's schedule
    out += health.app_stanzas()
    return "\n".join(out)


def props_stanza(source: str) -> str:
    """The props.conf stanza the records of a log source fall under, read from the search that finds them."""
    base = MAPPINGS["spl"]["logsources"][source]
    by_source = re.search(r'\bsource="([^"]+)"', base)
    if by_source:
        return f"source::{by_source.group(1)}"
    by_type = re.search(r'\bsourcetype="?([^"\s]+)"?', base)
    if not by_type:
        raise SystemExit(f"[!] spl.logsources.{source} names neither a source nor a sourcetype")
    return by_type.group(1)


def decoded_fields(dets, corrs=()) -> dict[str, list[str]]:
    """props stanza -> the fields the rules read in the event XML held there, in first-seen order."""
    fieldmap = MAPPINGS["spl"].get("fields") or {}
    out: dict[str, list[str]] = {props_stanza(s): [] for s in EVENT_XML}
    read = [(d.rule, ()) for d in dets]
    read += [(c.base, (*c.params.group_by, *([c.params.counted] if c.params.counted else []))) for c in corrs]
    for rule, grouped in read:
        source = logsource_key(rule)
        if source not in EVENT_XML:
            continue
        bucket = out[props_stanza(source)]
        for field in (*referenced_fields(rule.get("detection") or {}), *grouped):
            name = fieldmap.get(field, field)
            if name in ("EventCode", "EventID", "Provider_Name") or name in bucket:
                continue                # a number, and an attribute the rasd app reads itself
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                raise SystemExit(f"[!] {name}: not a field name an EVAL line can carry")
            bucket.append(name)
    return out


def decode_entities(field: str) -> str:
    """The eval expression that gives a field read out of event XML the text that was logged."""
    expr = f"'{field}'"
    for entity, char in XML_ENTITIES:
        expr = f'replace({expr}, "{entity}", "{char}")'
    return expr


def fields_props(dets, corrs=()) -> str:
    out = [FIELDS_INTRO]
    for stanza, fields in decoded_fields(dets, corrs).items():
        out.append(f"[{stanza}]")
        if not stanza.startswith("source::"):               # a sourcetype RASD's lab feeds as one event XML per line
            out.append(FIELDS_LINES.rstrip("\n"))
        out.append("KV_MODE = none")
        out.append(f"REPORT-rasd_fields = {FIELDS_REPORT}")
        out += [f"EVAL-{f} = {decode_entities(f)}" for f in fields]
        out.append("")
    return "\n".join(out)


def indexes() -> str:
    out = [HEADER]
    for name in INDEXES:
        out += [f"[{name}]", f"homePath = $SPLUNK_DB/{name}/db", f"coldPath = $SPLUNK_DB/{name}/colddb",
                f"thawedPath = $SPLUNK_DB/{name}/thaweddb", ""]
    return "\n".join(out)


def app_conf(app_id: str, label: str, description: str) -> str:
    return (HEADER + f"[install]\nis_configured = 1\n\n[ui]\nis_visible = 0\nlabel = {label}\n\n"
            f"[launcher]\nauthor = Ziyad (github.com/engziyad)\ndescription = {description}\nversion = {VERSION}\n\n"
            f"[package]\nid = {app_id}\n")


def live_section(store: Path | None = None, entries: list | None = None) -> str:
    """What the kept lab runs say these apps did on a live Splunk, and what no run has shown."""
    import evidence                                     # imported here: the kept runs are evidence's to read
    live = evidence.live_siem(store or evidence.STORE, entries)
    if not live["hosts"]:
        return ("**Not yet run on a live Splunk.** The searches are proven against the tested rules by `rasd parity`, on RASD's "
                "own model of SPL; no kept lab run has a Splunk in it yet ([how to make one](../../red/lab/README.md)).")
    hosts = f"{live['hosts']} lab host{'' if live['hosts'] == 1 else 's'}"
    fields = ("`rasd_fields` and no vendor add-on" if "rasd_fields" in live["apps"] and not live["addons"] else
              "the vendor add-ons " + ", ".join(f"`{a}`" for a in live["addons"]))
    text = (f"**Run on a live Splunk, in the lab.** In the kept lab run{'' if len(live['runs']) == 1 else 's'} "
            f"{', '.join(f'`{r}`' for r in live['runs'])} ([what is kept](../../purple/lab_runs/README.md)) these apps ran on "
            f"{' and '.join(live['platforms'])} beside {hosts}, with {fields}. Splunk's own scheduler raised the alert of "
            f"{live['alerted']} of the {live['evidence']} detections whose attack step ran there, from the events of that step")
    if live["searches"]:
        if all(ok == total for ok, total in live["searches"]):
            text += f", and every saved search of the `rasd` app ({live['searches'][0][1]} of them) ran to the end on each host"
        else:
            text += f", and {sum(total - ok for ok, total in live['searches'])} saved search run(s) did not reach the end"
    text += "."
    if live["unasked"]:
        text += (" It also raised alerts that no step of the run asked for: "
                 + ", ".join(f"`{det}` ({n})" for det, n in live["unasked"].items())
                 + ". On a host where nobody ran that attack, each is a false positive to explain or a rule to tune.")
    return (text + " Not shown by a kept run: the same searches over the fields of the vendor add-ons, the detections that "
            "need a domain controller (their searches ran, over no event), a forwarder between host and Splunk, and Splunk "
            "Cloud or a cluster.")


def readme(dets, corrs=()) -> str:
    from health import HEALTH_PREFIX                       # imported here: health reads this module's schedule
    rows = "\n".join(f"| `{ALERT_PREFIX}{d.id}` | {d.title} | {severity(d)} |" for d in dets)
    crow = "\n".join(f"| `{ALERT_PREFIX}{c.id}` | {c.title} | {c.params.describe()} | "
                     f"`{correlation_schedule(c.params.timespan)[0]}` | {severity(c)} |" for c in corrs)
    return f"""# RASD Splunk apps

Generated by `tools/splunk_app.py` on every build; do not edit by hand.

| App | Install on | What it does |
|---|---|---|
| [`rasd/`](rasd/) | Splunk Enterprise / trial (search head and indexer) | {', '.join(f'`{i}`' for i in INDEXES)} indexes, `Provider_Name` extraction, one scheduled alert per detection and per correlation, three alert export reports |
| [`rasd_fields/`](rasd_fields/) | The same Splunk, **only where the add-ons below are not installed** (a fresh lab Splunk) | `EventCode`, `Computer` and every `<Data Name='...'>` of the event XML as a field, under the names the add-ons give them; XML entities decoded in the fields the rules read; one event per line with its own time for Sysmon for Linux |
| [`rasd_forwarder/`](rasd_forwarder/) | Universal Forwarder on each Windows lab VM and the lab DC, or the Splunk Enterprise that runs on a lab host itself | Sysmon, Security, System and PowerShell logs as XML into those indexes, each under the source the searches read (`XmlWinEventLog:<channel>`) |
| [`rasd_forwarder_linux/`](rasd_forwarder_linux/) | Universal Forwarder on a Linux lab host | Sysmon for Linux into `linux`; the lab web application's access log into `web` (disabled until you set its path) |

The searches read the fields of an event by the names the vendor add-ons give them (`EventCode`, `CommandLine`, `TicketEncryptionType` ...). Give Splunk those fields one of two ways, never both: the **Splunk Add-on for Microsoft Windows**, the **Splunk Add-on for Sysmon** and, for Linux hosts, the **Splunk Add-on for Sysmon for Linux** (on the search head and the Linux forwarder); or `rasd_fields/`, which reads the same fields out of the event XML itself and needs nothing from Splunkbase. Where forwarders send, receiving has to be enabled on port 9997. The web access log uses Splunk's built-in `access_combined` extractions (`clientip`, `method`, `uri_path`, `status`).

{live_section()}

Install: copy each folder into `$SPLUNK_HOME/etc/apps/` (on a Windows forwarder: `C:\\Program Files\\SplunkUniversalForwarder\\etc\\apps\\`; on a Linux forwarder: `/opt/splunkforwarder/etc/apps/`) and restart Splunk. The full lab procedure is in [red/lab](../../red/lab/README.md).

## Alerts

Each alert runs every 5 minutes over one 5-minute slice that closed 5 minutes earlier (`-10m@m` to `-5m@m`): consecutive runs tile time and `realtime_schedule = 0` makes Splunk catch up a run it skipped, so an event is alerted exactly once, and up to 5 minutes of indexing delay never drop one (events indexed later than that are missed by the alert, not by `rasd replay`). It fires once per host in the slice (digest mode off), so two hosts are two alerts. Its base search is the generated query in [`queries/spl`](../spl/), proven equivalent to the tested rule by `rasd parity`; the saved search appends a per-host summary row only for reliable alert export.

| Saved search | Detection | Severity |
|---|---|---:|
{rows}

## Correlation alerts

A correlation alert counts per window. It runs once per window length over the last two windows plus {CORRELATION_LAG} minutes (indexing delay) and keeps only the most recent window that is complete inside that range (`addinfo` and one `where`): consecutive runs tile time, so every window is reported whole by exactly one run, with the search head in UTC or any fixed-offset time zone (where it observes daylight saving, a window can be dropped or repeated at the transitions). `realtime_schedule = 0` makes Splunk catch up a run it skipped. Events indexed more than {CORRELATION_LAG} minutes late are missed by the alert (not by `rasd correlate --logs`). It alerts once per result row - one window and one group (for example one spraying source) - and its search starts with the generated query in [`queries/spl/correlations`](../spl/correlations/), proven by `rasd correlate` to return exactly the engine's alerts.

| Saved search | Correlation | Condition | Schedule | Severity |
|---|---|---|---|---:|
{crow}

Every alert also writes one event to the `{ALERT_INDEX}` index (Log Event alert action). A detection's alert search is the proven rule query plus a lab-only summary per host (`stats count`, first and last event time `by` detection and host), so the export gets a deterministic host even when Splunk result tokens differ between deployments. A correlation's search is its proven query plus the window filter and three `eval` fields (detection id, alerting group, event count): its rows already carry the window, the counts and the first and last event.

## Health watchdogs

Five scheduled searches, `{HEALTH_PREFIX}silent`, `volume`, `fields`, `delay` and `schedule`, watch what feeds the alerts above: the hosts and channels the rules read, the fields they need, the indexing delay against the 5-minute wait, and the scheduler's record of the alerts' own runs. Each row names the detections it blinds and is written to `{ALERT_INDEX}` as `sourcetype=rasd:health`. They are generated by `rasd health` ([what they check](../health/README.md)); `schedule` reads `index=_internal` and the saved-searches REST endpoint, so its owner needs a role that can.

## Alert export for `rasd evidence`

Run one of these reports over the lab window, export the result as CSV and pass it to `rasd evidence --siem-alerts`. Each row is one alert: `_time` (when it fired) and `ss_name` (which carries the detection id). They read three independent sources, so a Splunk where one of them is restricted still has the others.

| Report | Source | Use | Notes |
|---|---|---|---|
| **{EXPORT_NAME}** | `index={ALERT_INDEX}` | **Preferred** | Carries the alerting `host`, which evidence checks against the lab host |
| **{EXPORT_NAME} (audit)** | `index=_audit action=alert_fired` | Acceptable fallback | No host: the alert is matched by name and time only; needs a role that can search `_audit` |
| **{EXPORT_NAME} (scheduler)** | `index=_internal sourcetype=scheduler` | Acceptable fallback | Scheduled runs that returned results, no host; needs a role that can search `_internal` |

On the first lab run, check that the host really reaches `{ALERT_INDEX}`: `index={ALERT_INDEX} | table _time rasd_alert alert_host alert_hosts first_event last_event`. An empty `alert_host` means the alert's results had no usable host field; the export still works, matched by name and time like the fallbacks. For a correlation, `alert_host` is its first group-by value - the client address for every correlation in this repository.

Each alert reads a slice that closed 5 minutes earlier and runs every 5 minutes, so the SIEM latency `rasd evidence` reports includes 5 to 10 minutes of schedule wait on top of the indexing delay; the evidence file shows both parts. A correlation alert waits for its window to close, so its latency includes up to two window lengths plus {CORRELATION_LAG} minutes.
"""


def render(dets, corrs=()) -> dict[Path, str]:
    return {
        OUT / "README.md": readme(dets, corrs),
        OUT / "rasd" / "default" / "app.conf": app_conf("rasd", "RASD Detections",
                                                         "RASD detections as scheduled alerts"),
        OUT / "rasd" / "default" / "savedsearches.conf": saved_searches(dets, corrs),
        OUT / "rasd" / "default" / "indexes.conf": indexes(),
        OUT / "rasd" / "default" / "props.conf": HEADER + PROPS.format(decoy=props_stanza("opencanary/honeypot"), alerts=ALERT_INDEX),
        OUT / FIELDS_APP / "default" / "app.conf": app_conf(FIELDS_APP, "RASD Field Extractions",
                                                             "The event XML fields the RASD searches read, for a Splunk without the vendor add-ons"),
        OUT / FIELDS_APP / "default" / "props.conf": HEADER + fields_props(dets, corrs),
        OUT / FIELDS_APP / "default" / "transforms.conf": HEADER + TRANSFORMS,
        OUT / FIELDS_APP / "metadata" / "default.meta": HEADER + META,
        OUT / "rasd" / "metadata" / "default.meta": HEADER + META,
        OUT / "rasd_forwarder" / "default" / "app.conf": app_conf("rasd_forwarder", "RASD Forwarder Inputs",
                                                                   "Windows and Sysmon inputs for the RASD lab"),
        OUT / "rasd_forwarder" / "default" / "inputs.conf": HEADER + INPUTS,
        OUT / "rasd_forwarder_linux" / "default" / "app.conf": app_conf("rasd_forwarder_linux", "RASD Linux Forwarder Inputs",
                                                                         "Sysmon for Linux and web access log inputs for the RASD lab"),
        OUT / "rasd_forwarder_linux" / "default" / "inputs.conf": HEADER + INPUTS_LINUX,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="fail if the committed app differs from the rules")
    args = ap.parse_args()
    files = render(load_detections(), load_correlations())
    stale = [p for p, body in files.items() if not p.exists() or p.read_text(encoding="utf-8") != body]
    if args.check:
        for p in stale:
            print(f"  {RED}✗{RESET} {p.relative_to(ROOT)} is stale (run: rasd build)")
        print(f"{BOLD}Splunk app · {len(files)} files · {len(stale)} stale{RESET}" if stale else
              f"{GREEN}Splunk app · {len(files)} files up to date{RESET}")
        return 1 if stale else 0
    for p, body in files.items():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8", newline="\n")
    print(f"[+] Splunk app: {len(files)} files in {OUT.relative_to(ROOT)} ({len(files) - len(stale)} unchanged)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
