#!/usr/bin/env python3
"""
evidence.py - turn a real lab run into committed, verifiable detection evidence.

Synthetic samples prove the rule logic. Only a real run proves the whole loop: the
technique runs, Windows writes the event, the collector exports it, the parser keeps the
fields, the rule fires, the SIEM raises the alert, the analyst has the artifacts, and the
host is clean afterwards. evidence.py joins the pieces of a lab run:

  emulation-results.json   from red/Invoke-PurpleEmulation.ps1 or red/run_red.py
                           (each step: expected detections, host, UTC window, cleanup
                           status, collected artifacts with SHA-256)
  lab-export.jsonl         from red/Export-LabTelemetry.ps1 on the same VM
                           (plus the domain controller's export for Kerberos)
  siem-alerts.csv|jsonl    optional: the alerts your SIEM raised in the same window
                           (a Splunk or Sentinel export; see --siem-alerts)

For every executed step it replays the exported events through each detection the step
is expected to trigger, inside the step's time window plus a grace period. An event counts
only when it is bound to the run: logged on the emulation host (or, for a network event a
DC logged, with the host's own IP or name as the client) and - where the test declares a
`bind` token - carrying this run's marker. Then it writes
detect/detections/<id>/evidence.md ONLY when the rule really fired. The file's front
matter carries everything the Operational Validation Score is computed from:

  Lab evidence        35  the rule fired on telemetry exported from the lab
  SIEM result         25  the SIEM raised a matching alert in the window
  Detection latency   15  step start -> SIEM alert (<=60 s: 15, <=5 min: 10, <=15 min: 5)
  DFIR evidence       15  the runner collected and hashed the test's artifacts
  Cleanup             10  the cleanup script verified the host is clean

plus the SHA-256 of every input file, so anyone holding the raw exports can verify it.
A detection whose step ran but did not fire is reported as MISSED and the command fails -
a miss is never written down as evidence.

Correlation detections (a step's `correlations`) are evaluated the same way over the base
rule's events bound to the run - inside the step window, logged on the emulation host or
naming it as the client - and fire only when those events alone reach the correlation's
threshold. Their evidence goes to detect/correlations/<id>/evidence.md, with the alerting
window, group and count; latency runs to the event that reached the threshold.

Usage
  python tools/evidence.py --results emulation-results.json --logs lab-export.jsonl
  python tools/evidence.py --results r.json --logs ws.jsonl dc.jsonl --siem-alerts alerts.csv
  python tools/evidence.py --results r.json --logs ws.jsonl --dry-run
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BOLD, DIM, GREEN, RED, RESET, YELLOW, carries_token, expand_token, load_detections, load_jsonl  # noqa: E402
from correlation import (CorrelationError, evaluate as evaluate_correlation, group_label, iso,  # noqa: E402
                         load_correlations, value_reader)
from convert import logsource_key  # noqa: E402
import profiles  # noqa: E402
from replay import HOST_FIELDS, NETWORK_EVENTS, USER_FIELDS, first, parse_time, route  # noqa: E402
from sigma_engine import SigmaError, compile_rule, matches  # noqa: E402
from validate import rule_fields  # noqa: E402

FORMAT_VERSION = 1
EARLY_SECONDS = 5                 # clock skew allowance before a step starts
SIEM_TIME = ("_time", "TimeGenerated", "time", "timestamp", "StartTime", "trigger_time", "@timestamp")
SIEM_NAME = ("search_name", "savedsearch_name", "ss_name", "AlertName", "alert_name", "rule", "rule_name",
             "title", "name", "DisplayName")
SIEM_HOST = ("host", "alert_host", "dest", "Computer", "CompromisedEntity", "hostname", "DeviceName")
SIEM_EVENT_SPAN = ("first_event", "last_event")    # time range of the events the alert summarised (RASD Splunk app)
OPERATIONAL_WEIGHTS = {"Lab evidence": 35, "SIEM result": 25, "Detection latency": 15, "DFIR evidence": 15,
                       "Cleanup": 10}


MANIFEST = "lab-run-manifest.json"     # written by red/lab/Invoke-RasdLabRun.ps1 next to the results


def verify_manifest(path: Path | None, inputs: list[Path]) -> tuple[dict | None, list[str]]:
    """Every input the lab run's manifest lists must still have the SHA-256 recorded at the
    end of the run: a results file from one run and an export from another, or an edited
    export, is refused before anything is written."""
    if path is None or not path.exists():
        return None, []
    doc = json.loads(path.read_text(encoding="utf-8-sig"))
    recorded = {re.split(r"[\\/]", str(f.get("path", "")))[-1].lower(): str(f.get("sha256", "")).lower()
                for f in doc.get("files") or [] if isinstance(f, dict)}
    errors, verified = [], []
    for p in inputs:
        want = recorded.get(p.name.lower())
        if want is None:
            continue
        if want != sha256(p):
            errors.append(f"{p.name}: SHA-256 differs from the one {path.name} recorded for this run")
        else:
            verified.append(p.name)
    return {"file": path.name, "sha256": sha256(path), "verified": verified}, errors


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_results(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))   # Windows PowerShell may add a BOM
    return data if isinstance(data, list) else [data]


def load_siem(path: Path) -> list[dict]:
    """A Splunk / Sentinel alert export: CSV with a header row, JSON lines, or a JSON array."""
    text = path.read_text(encoding="utf-8-sig")
    if path.suffix.lower() == ".csv":
        return list(csv.DictReader(text.splitlines()))
    stripped = text.lstrip()
    if stripped.startswith("["):
        return json.loads(stripped)
    return load_jsonl(path)


def short(host: str) -> str:
    return str(host or "").split(".")[0].lower()


def step_time(step: dict, key: str) -> datetime | None:
    return parse_time({"TimeCreated": step.get(key)}) if step.get(key) else None


def expected_detections(step: dict, dets) -> list:
    wanted = step.get("detections") or []
    if isinstance(wanted, str):
        wanted = [wanted]
    if wanted:
        return [d for d in dets if d.id in wanted]
    return [d for d in dets if d.technique == step.get("technique")]   # results without a detections list


CLIENT_FIELDS = ("IpAddress", "ClientAddress", "SourceAddress", "SourceNetworkAddress")
WORKSTATION_FIELDS = ("WorkstationName", "Workstation")


def norm_ip(value) -> str:
    text = str(value or "").strip().lower()
    text = text[7:] if text.startswith("::ffff:") else text
    return "" if text in ("", "-") else text.split("%")[0]


def host_names(step: dict) -> set[str]:
    """The emulation host's names: DNS host name and NetBIOS name (cut at 15 characters,
    which is what Workstation fields and many forwarders use)."""
    return {short(n) for n in (step.get("host"), step.get("host_netbios")) if n}


def on_host(ev: dict, step: dict) -> tuple[bool, str]:
    """The event was logged on the emulation host, or it is a network event (4769, 4624 ...)
    logged by a DC or target whose client address or workstation IS the emulation host.
    Anything else - including a Kerberos ticket another machine requested in the same
    minute - is not evidence of this run."""
    names = host_names(step)
    logged_on = first(ev, HOST_FIELDS)
    if not names or short(logged_on) in names:
        return True, ""
    try:
        eid = int(ev.get("EventID", 0))
    except (TypeError, ValueError):
        eid = 0
    if eid not in NETWORK_EVENTS:
        return False, ""
    client = norm_ip(first(ev, CLIENT_FIELDS))
    if client and client in {norm_ip(i) for i in step.get("host_ips") or []}:
        return True, f"logged on {logged_on}; client address {client} is the emulation host"
    ws = first(ev, WORKSTATION_FIELDS)
    if ws != "-" and short(ws) in names:
        return True, f"logged on {logged_on}; workstation {ws} is the emulation host"
    return False, ""


def expected_correlations(step: dict, corrs) -> list:
    """Only the correlations the step names: a single-ticket Kerberoasting step must not be
    expected to raise a volume correlation of the same technique."""
    wanted = step.get("correlations") or []
    if isinstance(wanted, str):
        wanted = [wanted]
    return [c for c in corrs if c.id in wanted]


def is_host(value, step: dict) -> bool:
    """A group value names the emulation host: one of its addresses, or one of its names."""
    return bool(value) and (norm_ip(value) in {norm_ip(i) for i in step.get("host_ips") or []}
                            or short(value) in host_names(step))


def from_host(ev: dict, step: dict) -> bool:
    """The activity came FROM the emulation host: a network event (4625, 4771 ...) whose client is
    the host, or a local event logged on it. Unlike on_host, a network event logged on the host
    about another client - someone spraying AT the host - does not count."""
    try:
        eid = int(ev.get("EventID", 0))
    except (TypeError, ValueError):
        eid = 0
    client, ws = norm_ip(first(ev, CLIENT_FIELDS)), first(ev, WORKSTATION_FIELDS)
    if eid in NETWORK_EVENTS and (client or ws != "-"):
        return is_host(client, step) or (ws != "-" and is_host(ws, step))
    names = host_names(step)
    return not names or short(first(ev, HOST_FIELDS)) in names


def correlation_hits(corr, step: dict, events: list[dict], grace: int) -> tuple[list[dict], list[dict]]:
    """The correlation's alerts that belong to this run, and the base events each one counted.

    A correlation grouped by the client (an address or workstation field) binds through its own
    group: every client value of the alert's group must name the emulation host, so a spray from
    another client - even one aimed AT the emulation host, which logs the failures - never counts.
    Any other correlation (no group-by, or grouped by the target) counts only events whose
    activity came from the host (from_host), and then alerts as usual."""
    start, end = step_time(step, "utc_start"), step_time(step, "utc_end")
    if not start:
        return [], []
    lo, hi = start - timedelta(seconds=EARLY_SECONDS), (end or start) + timedelta(seconds=grace)
    try:
        base, p = compile_rule(corr.base), corr.params
    except (SigmaError, CorrelationError):
        return [], []
    src = logsource_key(corr.base)
    window = [ev for ev in events if (t := parse_time(ev)) and lo <= t <= hi and route(ev) == src and base(ev)]
    clients = [g for g in p.group_by if g in CLIENT_FIELDS + WORKSTATION_FIELDS]
    if not clients:
        window = [ev for ev in window if from_host(ev, step)]
    fired = [a for a in evaluate_correlation(corr, window, base_fn=base)
             if all(is_host(a["group"][g], step) for g in clients)]
    return window, sorted(fired, key=lambda a: a["crossed_at"])


def counted_events(corr, alert: dict, events: list[dict]) -> list[dict]:
    """The events an alert counted: its window and group, read the way the engine reads them."""
    p = corr.params
    read = value_reader(p)
    lo = alert["window_start"]
    hi = lo + timedelta(seconds=p.timespan)
    group = tuple(alert["group"].values())
    return [ev for ev in events if (t := parse_time(ev)) and lo <= t < hi
            and tuple(read(ev, g) for g in p.group_by) == group and (not p.counted or read(ev, p.counted))]


def find_correlation_alerts(corr, step: dict, alerts: list[dict], grace: int) -> list[tuple[datetime, dict]]:
    """SIEM alerts of the correlation inside the window whose group is the emulation host
    (the RASD Splunk app writes the client address as alert_host)."""
    start, end = step_time(step, "utc_start"), step_time(step, "utc_end")
    if not start:
        return []
    lo, hi = start - timedelta(seconds=EARLY_SECONDS), (end or start) + timedelta(seconds=grace)
    keys = [k.lower() for k in (corr.id, corr.title, str(corr.rule.get("id", ""))) if k]
    ips = {norm_ip(i) for i in step.get("host_ips") or []}
    out = []
    for a in alerts:
        name = first(a, SIEM_NAME).lower()
        if name == "-" or not any(k in name for k in keys):
            continue
        t = siem_time(next((a[f] for f in SIEM_TIME if a.get(f)), None))
        if not t or not lo <= t <= hi:
            continue
        host = first(a, SIEM_HOST)
        if host != "-" and (ips or host_names(step)) and not is_host(host, step):
            continue                    # another client's spray in the same window
        span = [siem_time(a.get(f)) if a.get(f) not in (None, "") else None for f in SIEM_EVENT_SPAN]
        if span[0] and span[1] and (span[0] > hi or span[1] < lo):
            continue
        out.append((t, a))
    return sorted(out, key=lambda x: x[0])


def run_token(det, step: dict) -> str | None:
    """The step's bind template for this detection, if the test declares one."""
    return (step.get("bind") or {}).get(det.id)


def find_hits(det, step: dict, events: list[dict], grace: int) -> list[tuple[datetime, dict, str]]:
    start, end = step_time(step, "utc_start"), step_time(step, "utc_end")
    if not start:
        return []
    lo, hi = start - timedelta(seconds=EARLY_SECONDS), (end or start) + timedelta(seconds=grace)
    src = logsource_key(det.rule)
    token = run_token(det, step)
    try:
        rule_matches = compile_rule(det.rule)                 # same verdicts as matches(), read once
    except SigmaError:
        return []
    hits = []
    for ev in events:
        t = parse_time(ev)
        if not t or not lo <= t <= hi or route(ev) != src:
            continue
        same, note = on_host(ev, step)
        if not same:
            continue
        if not rule_matches(ev):
            continue
        if token and not carries_token(ev, token, step.get("marker", "")):
            continue                                      # fired, but on something this run did not create
        if token:
            note = "; ".join(x for x in (note, f"carries this run's token {expand_token(token, step.get('marker', ''))}") if x)
        hits.append((t, ev, note))
    return sorted(hits, key=lambda h: h[0])


def find_alerts(det, step: dict, alerts: list[dict], grace: int) -> list[tuple[datetime, dict]]:
    """SIEM alerts whose name carries the detection id, title or rule UUID, inside the window."""
    start, end = step_time(step, "utc_start"), step_time(step, "utc_end")
    if not start:
        return []
    lo, hi = start - timedelta(seconds=EARLY_SECONDS), (end or start) + timedelta(seconds=grace)
    keys = [k.lower() for k in (det.id, det.title, str(det.rule.get("id", ""))) if k]
    out = []
    for a in alerts:
        name = first(a, SIEM_NAME).lower()
        if name == "-" or not any(k in name for k in keys):
            continue
        t = siem_time(next((a[f] for f in SIEM_TIME if a.get(f)), None))
        if not t or not lo <= t <= hi:
            continue
        host = first(a, SIEM_HOST)
        dc_logged = logsource_key(det.rule) == "windows/security"       # 4769 alerts name the DC, not the client
        if host != "-" and host_names(step) and not dc_logged and short(host) not in host_names(step):
            continue
        span = [siem_time(a.get(f)) if a.get(f) not in (None, "") else None for f in SIEM_EVENT_SPAN]
        if span[0] and span[1] and (span[0] > hi or span[1] < lo):
            continue                    # the alert summarised events from outside this step: another run
        out.append((t, a))
    return sorted(out, key=lambda x: x[0])


def siem_time(raw) -> datetime | None:
    """ISO 8601 (with or without a colon in the offset) or epoch seconds, as naive UTC."""
    if raw is None:
        return None
    text = str(raw).strip()
    try:
        return datetime.fromtimestamp(float(text), timezone.utc).replace(tzinfo=None)
    except ValueError:
        pass
    m = re.match(r"^(.*[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)([+-]\d{2})(\d{2})$", text)
    if m:
        text = f"{m.group(1)}{m.group(2)}:{m.group(3)}"
    return parse_time({"TimeCreated": text})


def latency_points(seconds: float | None) -> int:
    if seconds is None:
        return 0
    return 15 if seconds <= 60 else 10 if seconds <= 300 else 5 if seconds <= 900 else 0


def operational_score(front: dict) -> dict[str, int]:
    """Operational Validation Score from an evidence.md front matter (see module docstring)."""
    fired = front.get("result") == "fired" and int(front.get("matched_events") or 0) >= 1
    siem = front.get("siem") or {}
    arts = [a for a in front.get("artifacts") or [] if isinstance(a, dict) and len(str(a.get("sha256", ""))) == 64]
    return {
        "Lab evidence": 35 if fired else 0,
        "SIEM result": 25 if fired and int(siem.get("alerts") or 0) >= 1 else 0,
        "Detection latency": latency_points(siem.get("latency_seconds")) if fired else 0,
        "DFIR evidence": 15 if fired and arts else 0,
        "Cleanup": 10 if fired and front.get("cleanup") == "verified" else 0,
    }


def render(det, step: dict, hits, alerts, files: dict[str, str], results_name: str, results_sha: str,
           siem_files: dict[str, str], profile: str = profiles.NATIVE, manifest: dict | None = None) -> str:
    t0, ev, note = hits[0]
    start = step_time(step, "utc_start")
    latency = max(0.0, (t0 - start).total_seconds())
    keep = sorted(rule_fields(det.rule["detection"]) | {"EventID", "Channel", "Provider_Name"})
    excerpt = {k: ev[k] for k in ev if k in keep or k in HOST_FIELDS or k in ("UtcTime", "TimeCreated", "User")}
    artifacts = [{"file": Path(str(a.get("path", ""))).name, "sha256": str(a.get("sha256", "")).lower()}
                 for a in step.get("artifacts") or [] if isinstance(a, dict)]
    front = {
        "rasd_evidence": FORMAT_VERSION,
        "detection": det.id,
        "technique": det.technique,
        "result": "fired",
        "run_utc": start.isoformat() + "Z",
        "host": step.get("host", ""),
        "test": step.get("test", ""),
        "step": step.get("step", ""),
        "marker": step.get("marker", ""),
        "bound_by": ("run token" if run_token(det, step) else "host and time window") + (
            "; client address" if note and "client address" in note else ""),
        "latency_seconds": round(latency, 3),
        "matched_events": len(hits),
        "cleanup": step.get("cleanup", "not-run"),
        "artifacts": artifacts,
        "siem": None,
        "inputs": {"results": {"file": results_name, "sha256": results_sha},
                   "telemetry": [{"file": n, "sha256": h} for n, h in files.items()],
                   "profile": profile},
    }
    if manifest:
        front["inputs"]["manifest"] = manifest
    if alerts:
        a_time, a = alerts[0]
        front["siem"] = {"alerts": len(alerts), "first_alert_utc": a_time.isoformat() + "Z",
                         "alert_name": first(a, SIEM_NAME),
                         "latency_seconds": round(max(0.0, (a_time - start).total_seconds()), 3),
                         # event logged -> alert: forwarding, indexing and the wait for the scheduled search
                         "pipeline_seconds": round(max(0.0, (a_time - t0).total_seconds()), 3)}
        front["inputs"]["siem"] = [{"file": n, "sha256": h} for n, h in siem_files.items()]
    score = operational_score(front)
    front["operational_score"] = sum(score.values())
    lines = ["---", yaml.safe_dump(front, sort_keys=False, allow_unicode=True).rstrip(), "---", "",
             f"# Lab evidence · {det.title}", "",
             "| | |", "|---|---|",
             f"| Emulation step | {step.get('name', '-')} |",
             f"| Host · user | {step.get('host', '-')} · {step.get('user', '-')} |",
             f"| Step window (UTC) | {step.get('utc_start', '-')} → {step.get('utc_end', '-')} |",
             f"| First matching event (UTC) | {t0.isoformat()} |",
             f"| Matching events | {len(hits)} |",
             f"| SIEM alert | " + (f"{front['siem']['alert_name']} at {front['siem']['first_alert_utc']}"
                                   if alerts else "not provided") + " |",
             f"| Telemetry latency | {latency:.1f} s - step start → the event is logged on the host |",
             f"| SIEM alert latency | " + (f"{front['siem']['latency_seconds']:.0f} s - step start → the SIEM alert "
                                           "(scored)" if alerts else "-") + " |",
             f"| SIEM pipeline delay | " + (f"{front['siem']['pipeline_seconds']:.0f} s - event → alert: forwarding, "
                                            "indexing and the wait for the scheduled search" if alerts else "-") + " |",
             f"| DFIR artifacts | {len(artifacts)} collected and hashed |",
             f"| Cleanup | {front['cleanup']} |",
             f"| Alert user | {first(ev, USER_FIELDS)} |"]
    if note:
        lines.append(f"| Note | {note} |")
    lines += ["", "## Operational Validation Score", "",
              "| Area | Points |", "|---|---:|"]
    lines += [f"| {k} | {v} / {OPERATIONAL_WEIGHTS[k]} |" for k, v in score.items()]
    lines += [f"| **Total** | **{front['operational_score']} / 100** |", "",
              "## Matching event (fields the rule reads)", "", "```json",
              json.dumps(excerpt, indent=2, ensure_ascii=False), "```", "",
              "## Verify", "",
              "Hash the raw files and compare them with `inputs` above, then re-run:", "",
              "```bash",
              f"python rasd.py evidence --results {results_name} --logs {' '.join(files)}"
              + (f" --siem-alerts {' '.join(siem_files)}" if siem_files else "")
              + (f" --profile {profile}" if profile != profiles.NATIVE else "") + " --dry-run",
              f"python rasd.py explain {det.id} --event '{json.dumps(excerpt, ensure_ascii=False)}'",
              "```", "",
              "<sub>Generated by RASD · Attack-to-Defense Validation Framework</sub>", ""]
    return "\n".join(lines)


def render_correlation(corr, step: dict, bound: list[dict], alert: dict, siem_alerts, files: dict[str, str],
                       results_name: str, results_sha: str, siem_files: dict[str, str], profile: str = profiles.NATIVE,
                       manifest: dict | None = None) -> str:
    p = corr.params
    start = step_time(step, "utc_start")
    crossed = alert["crossed_at"]
    latency = max(0.0, (crossed - start).total_seconds())
    artifacts = [{"file": Path(str(a.get("path", ""))).name, "sha256": str(a.get("sha256", "")).lower()}
                 for a in step.get("artifacts") or [] if isinstance(a, dict)]
    front = {
        "rasd_evidence": FORMAT_VERSION,
        "detection": corr.id,
        "technique": corr.technique,
        "result": "fired",
        "run_utc": start.isoformat() + "Z",
        "host": step.get("host", ""),
        "test": step.get("test", ""),
        "step": step.get("step", ""),
        "marker": step.get("marker", ""),
        "bound_by": "host and time window; client address",
        "latency_seconds": round(latency, 3),
        "matched_events": alert["event_count"],
        "correlation": {"condition": p.describe(), "window_start": iso(alert["window_start"]),
                        "group": alert["group"], p.metric: alert["metric"], "event_count": alert["event_count"],
                        "first_event": iso(alert["first_event"]), "last_event": iso(alert["last_event"]),
                        "threshold_reached": iso(crossed), "values": alert["values"]},
        "cleanup": step.get("cleanup", "not-run"),
        "artifacts": artifacts,
        "siem": None,
        "inputs": {"results": {"file": results_name, "sha256": results_sha},
                   "telemetry": [{"file": n, "sha256": h} for n, h in files.items()],
                   "profile": profile},
    }
    if manifest:
        front["inputs"]["manifest"] = manifest
    if siem_alerts:
        a_time, a = siem_alerts[0]
        front["siem"] = {"alerts": len(siem_alerts), "first_alert_utc": a_time.isoformat() + "Z",
                         "alert_name": first(a, SIEM_NAME),
                         "latency_seconds": round(max(0.0, (a_time - start).total_seconds()), 3),
                         # threshold reached -> alert: forwarding, indexing and the wait for the window to close
                         "pipeline_seconds": round(max(0.0, (a_time - crossed).total_seconds()), 3)}
        front["inputs"]["siem"] = [{"file": n, "sha256": h} for n, h in siem_files.items()]
    score = operational_score(front)
    front["operational_score"] = sum(score.values())
    keep = sorted(set(p.reads()) | {"EventID", "Status", "SubStatus", "TimeCreated", "Computer"})
    counted = counted_events(corr, alert, bound)
    excerpt = [{k: ev[k] for k in ev if k in keep} for ev in counted[:10]]
    what = f"{alert['metric']} distinct {p.field}" if p.counted else f"{alert['metric']} events"
    lines = ["---", yaml.safe_dump(front, sort_keys=False, allow_unicode=True).rstrip(), "---", "",
             f"# Lab evidence · {corr.title}", "",
             "| | |", "|---|---|",
             f"| Emulation step | {step.get('name', '-')} |",
             f"| Host · user | {step.get('host', '-')} · {step.get('user', '-')} |",
             f"| Step window (UTC) | {step.get('utc_start', '-')} → {step.get('utc_end', '-')} |",
             f"| Correlation | {p.describe()} |",
             f"| Alert | {what} from {group_label(alert)} in the window from {iso(alert['window_start'])} |",
             f"| Events counted | {alert['event_count']} ({iso(alert['first_event'])} → {iso(alert['last_event'])}) |",
             f"| Threshold reached (UTC) | {iso(crossed)} |",
             f"| SIEM alert | " + (f"{front['siem']['alert_name']} at {front['siem']['first_alert_utc']}"
                                   if siem_alerts else "not provided") + " |",
             f"| Telemetry latency | {latency:.1f} s - step start → the event that reached the threshold |",
             f"| SIEM alert latency | " + (f"{front['siem']['latency_seconds']:.0f} s - step start → the SIEM alert "
                                           "(scored)" if siem_alerts else "-") + " |",
             f"| SIEM pipeline delay | " + (f"{front['siem']['pipeline_seconds']:.0f} s - threshold reached → alert: "
                                            "forwarding, indexing and the wait for the window to close" if siem_alerts
                                            else "-") + " |",
             f"| DFIR artifacts | {len(artifacts)} collected and hashed |",
             f"| Cleanup | {front['cleanup']} |",
             "", "## Operational Validation Score", "", "| Area | Points |", "|---|---:|"]
    lines += [f"| {k} | {v} / {OPERATIONAL_WEIGHTS[k]} |" for k, v in score.items()]
    lines += [f"| **Total** | **{front['operational_score']} / 100** |", "",
              f"## Events counted (first {len(excerpt)} of {len(counted)}, fields the correlation reads)", "", "```json",
              json.dumps(excerpt, indent=2, ensure_ascii=False), "```", "",
              "## Verify", "",
              "Hash the raw files and compare them with `inputs` above, then re-run:", "",
              "```bash",
              f"python rasd.py evidence --results {results_name} --logs {' '.join(files)}"
              + (f" --siem-alerts {' '.join(siem_files)}" if siem_files else "")
              + (f" --profile {profile}" if profile != profiles.NATIVE else "") + " --dry-run",
              f"python rasd.py correlate --filter {corr.id} --logs {' '.join(files)}",
              "```", "",
              "<sub>Generated by RASD · Attack-to-Defense Validation Framework</sub>", ""]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", required=True, help="emulation-results.json from a RASD-Red runner")
    ap.add_argument("--logs", nargs="+", required=True, help="JSONL exports (Export-LabTelemetry.ps1)")
    ap.add_argument("--siem-alerts", nargs="*", default=[], help="alert exports from the SIEM (CSV or JSON)")
    ap.add_argument("--grace", type=int, default=120, help="seconds after a step for log delivery (default 120)")
    ap.add_argument("--siem-grace", type=int, default=900,
                    help="seconds after a step for the SIEM's scheduled search to alert (default 900)")
    ap.add_argument("--dry-run", action="store_true", help="report only, do not write evidence.md")
    ap.add_argument("--profile", help="telemetry profile from mappings/ (or 'auto') the --logs exports are written in")
    ap.add_argument("--manifest", help=f"the lab run's {MANIFEST} (default: next to --results, when present)")
    args = ap.parse_args()

    results_path = Path(args.results)
    manifest, manifest_errors = verify_manifest(Path(args.manifest) if args.manifest else results_path.parent / MANIFEST,
                                                [results_path, *map(Path, args.logs)])
    if manifest_errors:
        for e in manifest_errors:
            print(f"  {RED}✗{RESET} {e}")
        print(f"\n{RED}The inputs do not belong to the run the manifest describes - nothing written.{RESET}")
        return 1
    steps = load_results(results_path)
    events, files = [], {}
    for p in map(Path, args.logs):
        events += load_jsonl(p)
        files[p.name] = sha256(p)
    events, profile = profiles.apply(events, args.profile)
    alerts, siem_files = [], {}
    for p in map(Path, args.siem_alerts):
        alerts += load_siem(p)
        siem_files[p.name] = sha256(p)
    dets = load_detections()
    corrs = load_correlations()

    print(f"{BOLD}Lab evidence · {len(steps)} step(s) · {len(events)} exported event(s) · profile {profile}"
          + (f" · {len(alerts)} SIEM alert(s)" if args.siem_alerts else "") + f"{RESET}")
    if manifest:
        print(f"{DIM}manifest {manifest['file']}: {', '.join(manifest['verified']) or 'no listed input'} verified{RESET}")
    print()
    best: dict[str, tuple] = {}
    best_corr: dict[str, tuple] = {}
    expected: dict[str, list[str]] = {}
    for step in steps:
        label = f"[{step.get('technique', '?')}] {step.get('name', '')}"
        if step.get("status") != "executed":
            print(f"  {DIM}skipped  {label} ({step.get('status')}: {step.get('reason') or step.get('error') or '-'}){RESET}")
            continue
        for det in expected_detections(step, dets):
            expected.setdefault(det.id, []).append(label)
            hits = find_hits(det, step, events, args.grace)
            if hits and (det.id not in best or hits[0][0] < best[det.id][2][0][0]):
                best[det.id] = (det, step, hits, find_alerts(det, step, alerts, args.siem_grace))
        for corr in expected_correlations(step, corrs):
            expected.setdefault(corr.id, []).append(label)
            bound, fired = correlation_hits(corr, step, events, args.grace)
            if fired and (corr.id not in best_corr or fired[0]["crossed_at"] < best_corr[corr.id][3]["crossed_at"]):
                # a correlation alert comes after its window closes: up to two windows plus the schedule lag
                siem_grace = max(args.siem_grace, 2 * corr.params.timespan + 600)
                best_corr[corr.id] = (corr, step, bound, fired[0],
                                      find_correlation_alerts(corr, step, alerts, siem_grace))

    missed = sorted(set(expected) - set(best) - set(best_corr))
    for det_id in sorted(expected):
        if det_id in best_corr:
            corr, step, bound, alert, al = best_corr[det_id]
            latency = (alert["crossed_at"] - step_time(step, "utc_start")).total_seconds()
            siem = f", SIEM alert after {(al[0][0] - step_time(step, 'utc_start')).total_seconds():.0f}s" if al else ""
            print(f"  {GREEN}FIRED{RESET}   {det_id:<48} {alert['metric']} from {group_label(alert)} "
                  f"({alert['event_count']} events), threshold after {max(0, latency):.1f}s{siem}"
                  f" · cleanup {step.get('cleanup', 'not-run')}")
        elif det_id in best:
            det, step, hits, al = best[det_id]
            latency = (hits[0][0] - step_time(step, "utc_start")).total_seconds()
            siem = f", SIEM alert after {(al[0][0] - step_time(step, 'utc_start')).total_seconds():.0f}s" if al else ""
            print(f"  {GREEN}FIRED{RESET}   {det_id:<48} {len(hits)} event(s), {max(0, latency):.1f}s{siem}"
                  f" · cleanup {step.get('cleanup', 'not-run')}")
        else:
            print(f"  {RED}MISSED{RESET}  {det_id:<48} {DIM}expected from: {'; '.join(expected[det_id])}{RESET}")

    if not args.dry_run:
        for det, step, hits, al in best.values():
            body = render(det, step, hits, al, files, results_path.name, sha256(results_path), siem_files, profile,
                          manifest)
            (det.folder / "evidence.md").write_text(body, encoding="utf-8")
        for corr, step, bound, alert, al in best_corr.values():
            body = render_correlation(corr, step, bound, alert, al, files, results_path.name, sha256(results_path),
                                      siem_files, profile, manifest)
            (corr.folder / "evidence.md").write_text(body, encoding="utf-8")
        if best or best_corr:
            print(f"\n{GREEN}[+] wrote evidence.md for {len(best) + len(best_corr)} detection(s){RESET}")

    if missed:
        print(f"\n{YELLOW}{len(missed)} detection(s) did not fire on their own emulation step.{RESET}")
        print("  Check in order: the event was logged (audit policy / Sysmon config); it was exported")
        print("  from every machine that logs it (the DC for Kerberos) with -Since covering the run; the")
        print("  results come from the current runner (host_ips recorded); the event carries the run's")
        print("  marker where the test binds one; and its fields arrived intact:")
        print(f"  python rasd.py doctor {' '.join(args.logs)}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
