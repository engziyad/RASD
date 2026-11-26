#!/usr/bin/env python3
"""
replay.py - run every detection over real (or lab) logs, offline, before deploying anything.

What it answers
  1. What would have fired?           every alert, with the rule, host, user and time - including
                                      the correlation detections (a password spray, a burst of
                                      service tickets), timed at the event that reached the threshold
  2. How noisy will each rule be?     alerts per rule, and per day when the logs span a day
                                      or more: a shorter capture is never stretched to a day
  3. What actually happened?          alerts are correlated per entity into attack
                                      storylines, ordered along the ATT&CK kill chain,
                                      scored, and narrated in one sentence an analyst
                                      can paste into a ticket
  4. Which alert first?               every alert gets a risk score from its detection's
                                      contract risk_model: the base score plus every
                                      condition replay can resolve from the event, the
                                      assets file and the users file (critical host,
                                      privileged user, off-hours, writable path, Office
                                      parent, remote execution); conditions only a human
                                      can answer are listed as questions
  5. What goes in the ticket?         --case-dir writes one folder per storyline:
                                      case_summary.md, timeline.json (every alert with
                                      the event fields its rule read), observables.csv
                                      (hosts, accounts, processes, command lines, keys,
                                      services, addresses), analyst_closure.md (the
                                      escalation, benign and false positive notes,
                                      pre-filled with what the logs show) and
                                      evidence_request.md (what to collect, in order,
                                      and what a log clear in the storyline took). Observed
                                      facts only: the replay never sets a disposition

Input   JSONL, one event per line (Sysmon / Security / System as exported from a SIEM).
        Events are routed to rules by log source, so a Security event is never tested
        against a process-creation rule.
Assets  Optional CSV (ip,host,role) to resolve network events (e.g. Kerberos 4769 on a
        DC, service installs) back to the client host, joining them to its storyline.
        Roles domain-controller, server and critical make a host critical for risk.
Users   Optional CSV (user,privileged) marking privileged accounts for risk.

Usage
  rasd replay samples/replay/lab-day.jsonl --assets samples/replay/assets.csv
  rasd replay logs.jsonl --html report.html --json alerts.json --window 60
  rasd replay logs.jsonl --assets assets.csv --users users.csv --hours 7-19 --utc-offset 3
  rasd replay elastic-export.jsonl --profile elastic-ecs
  rasd replay logs.jsonl --assets assets.csv --case-dir reports/cases

Event times are compared in UTC; --hours are local business hours, so pass --utc-offset
for the off-hours risk condition to use the right clock.

The HTML report prints to paper or PDF as it stands: it writes its own footer on every page,
so a browser adds no file address or date of its own.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from itertools import pairwise
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import yaml

from common import ATTACK_TACTICS, BOLD, DIM, GOLD, GREEN, RED, RESET, YELLOW, load_detections, load_jsonl, write_output
from convert import logsource_key
from sigma_engine import SigmaError, compile_rule

TACTIC_ORDER = list(ATTACK_TACTICS)
LEVEL_WEIGHT = {"informational": 1, "low": 2, "medium": 4, "high": 7, "critical": 10}
# the record time first: TimeCreated is the clock every channel of a host shares. Sysmon writes its own
# UtcTime too, and public captures show it hours away from TimeCreated when a pipeline re-renders one
# of them, which would put a Sysmon event and the Security event beside it hours apart
TIME_FIELDS = ("TimeCreated", "UtcTime", "@timestamp", "_time", "timestamp", "TimeGenerated", "utc_time")
HOST_FIELDS = ("Computer", "host", "Hostname", "DeviceName", "node_id")   # node_id: the OpenCanary decoy that logged the record
USER_FIELDS = ("User", "SubjectUserName", "TargetUserName", "AccountName", "SourceUser")
NETWORK_EVENTS = {4768, 4769, 4771, 4776, 4624, 4625}   # logged by a DC / target about a client: entity = client


def is_network(ev: dict) -> bool:
    """The record was logged by a server about a client: a Security logon or Kerberos event, or an OpenCanary
    record (logged on the decoy, about src_host). The client, not the logging host, is the entity."""
    try:
        eid = int(ev.get("EventID", 0))
    except (TypeError, ValueError):
        eid = 0
    return eid in NETWORK_EVENTS or ("logtype" in ev and "src_host" in ev)

CRITICAL_ROLES = {"domain-controller", "server", "critical"}
WRITABLE_PATH = re.compile(r"(?i)[\\/](AppData|ProgramData|Users[\\/]Public|Windows[\\/]Temp|Downloads)[\\/]"
                           r"|(?:^|[\s'\"=(])/(?:tmp|var/tmp|dev/shm)/")      # Linux: the world-writable temp folders
RISKY_PARENTS = ("\\winword.exe", "\\excel.exe", "\\powerpnt.exe", "\\outlook.exe", "\\mshta.exe",
                 "\\wscript.exe", "\\cscript.exe", "\\chrome.exe", "\\msedge.exe", "\\firefox.exe")
RISK_CONDITIONS = yaml.safe_load((Path(__file__).resolve().parent.parent / "detect" / "risk_conditions.yml")
                                 .read_text(encoding="utf-8"))["conditions"]


# --------------------------------------------------------------------------- #
# routing & entity resolution
# --------------------------------------------------------------------------- #
def route(ev: dict) -> str | None:
    """Map an event to the Sigma logsource key used by rules."""
    ch = str(ev.get("Channel") or ev.get("channel") or ev.get("source") or "").lower()
    eid = str(ev.get("EventID") or ev.get("EventCode") or ev.get("event_id") or ev.get("code") or "")
    if not ch and ("cs-uri-stem" in ev or "sc-status" in ev):
        return "webserver"
    if "linux" in ch and "sysmon" in ch:
        return {"1": "linux/process_creation"}.get(eid)
    if not ch and str(ev.get("Image") or "").startswith("/"):
        return "linux/process_creation" if eid in ("", "1") else None
    if "sysmon" in ch or (not ch and ("Image" in ev or "TargetImage" in ev or "TargetObject" in ev)):
        return {"1": "process_creation", "10": "process_access", "13": "registry_set"}.get(eid)
    if ch.endswith("security") or (not ch and eid in {"4769", "4768", "4771", "4776", "4624", "4625", "4648", "4663",
                                                      "1102", "4698", "4688"}):
        return "process_creation" if eid == "4688" else "windows/security"
    if ch.endswith("system") or (not ch and eid in {"7045", "104", "7036"}):
        return "windows/system"
    if not ch and "logtype" in ev and ("node_id" in ev or "src_host" in ev):     # an OpenCanary JSON record
        return "opencanary/honeypot"
    return None


_FRACTION = re.compile(r"\.(\d+)")


def parse_time(ev: dict) -> datetime | None:
    """First parseable timestamp field in TIME_FIELDS order, returned as naive UTC.

    Accepts Windows SystemTime with 7 fractional digits ('...01.1234567Z'), Sysmon UtcTime
    ('2026-10-12 06:00:01.120') and any ISO 8601 offset, which is converted to UTC.
    """
    for f in TIME_FIELDS:
        v = ev.get(f)
        if not isinstance(v, str) or not v.strip():
            continue
        text = _FRACTION.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), v.strip().replace("Z", "+00:00"), count=1)
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            continue
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    return None


def first(ev: dict, fields) -> str:
    for f in fields:
        if ev.get(f):
            return str(ev[f])
    return "-"


def summary(ev: dict) -> str:
    s = first(ev, ("CommandLine", "ImagePath", "Details", "ServiceName", "SourceImage", "ObjectName"))
    if s == "-" and "logtype" in ev:
        return f"decoy {first(ev, ('node_id', 'dst_host'))} port {ev.get('dst_port', '-')} event {ev.get('logtype')}"
    return "" if s == "-" else s


def load_assets(path: str | None) -> dict:
    if not path:
        return {}
    with open(path, encoding="utf-8") as fh:
        return {row["ip"].strip(): row for row in csv.DictReader(fh)}


def entity(ev: dict, assets: dict) -> str:
    ip = str(ev.get("IpAddress") or ev.get("src_host") or "").replace("::ffff:", "")
    if ip and ip not in ("-", "::1", "127.0.0.1") and is_network(ev):
        return assets.get(ip, {}).get("host", ip)
    return first(ev, HOST_FIELDS)


def load_users(path: str | None) -> dict:
    if not path:
        return {}
    with open(path, encoding="utf-8") as fh:
        return {row["user"].strip().lower(): row for row in csv.DictReader(fh)}


class RiskContext:
    def __init__(self, assets: dict | None = None, users: dict | None = None, hours: tuple[int, int] = (7, 19),
                 utc_offset: float = 0.0):
        """hours are LOCAL business hours; event times are UTC, so utc_offset (e.g. 3 for UTC+3)
        converts them before the off-hours check."""
        self.assets, self.users, self.hours = assets or {}, users or {}, hours
        self.utc_offset = timedelta(hours=utc_offset)
        self.roles = {row.get("host", "").lower(): row.get("role", "").lower() for row in self.assets.values()}

    def _short(self, name: str) -> str:
        return str(name or "").split("\\")[-1].split("@")[0].lower()

    def resolve(self, condition: str, ev: dict, ent: str) -> bool | None:
        """True / False when the data answers it, None when only an analyst can."""
        if condition == "host_is_critical":
            return self.roles.get(str(ent).lower()) in CRITICAL_ROLES or self.roles.get(first(ev, HOST_FIELDS).lower()) in CRITICAL_ROLES
        if condition == "user_is_privileged":
            user = self._short(first(ev, USER_FIELDS))
            row = self.users.get(user)
            if row is not None:
                return str(row.get("privileged", "")).strip().lower() in ("1", "true", "yes")
            return user in ("administrator", "admin", "root")
        if condition == "outside_business_hours":
            t = parse_time(ev)
            return None if t is None else not (self.hours[0] <= (t + self.utc_offset).hour < self.hours[1])
        if condition == "payload_in_user_writable_path":
            # SourceImage: the process that opened another one (Sysmon 10), e.g. a dumper run from a temp folder
            return any(WRITABLE_PATH.search(str(ev.get(f) or "")) for f in ("CommandLine", "Details", "ImagePath", "SourceImage"))
        if condition == "suspicious_parent":
            # a registry write (Sysmon 13) has no parent: the process that wrote the value stands in for it
            parent = ev.get("ParentImage") or (ev.get("Image") if "TargetObject" in ev else "")
            return str(parent or "").lower().endswith(RISKY_PARENTS)
        if condition == "remote_execution":
            cmd = str(ev.get("CommandLine") or "")
            image_path = str(ev.get("ImagePath") or "")
            remote_task = re.search(r"(?i)(^|\s)[/-]s\s+\S+", cmd) is not None and "schtasks" in cmd.lower()
            share = re.search(r"(?i)\\\\[^\\]+\\(ADMIN\$|C\$|IPC\$)", image_path) is not None
            other_host = ent != first(ev, HOST_FIELDS) and ent != "-"
            return remote_task or share or other_host
        return None

    def score(self, det, ev: dict, ent: str) -> tuple[int | None, list[str], list[str]]:
        model = (det.contract or {}).get("risk_model") or {}
        if "base_score" not in model:
            return None, [], []
        score, factors, questions = int(model["base_score"]), [], []
        for kind, sign in (("increase_if", 1), ("decrease_if", -1)):
            for item in model.get(kind) or []:
                cond = item["condition"]
                amount = int(item.get("add") or item.get("subtract") or 0)
                if RISK_CONDITIONS.get(cond, {}).get("resolve") != "auto":
                    questions.append(f"{'+' if sign > 0 else '-'}{amount} if {cond.replace('_', ' ')}?")
                    continue
                if self.resolve(cond, ev, ent):
                    score += sign * amount
                    factors.append(f"{'+' if sign > 0 else '-'}{amount} {cond.replace('_', ' ')}")
        return max(0, min(100, score)), factors, questions


# --------------------------------------------------------------------------- #
# replay
# --------------------------------------------------------------------------- #
def correlation_alerts(events: list[dict], corrs, assets: dict, risk: RiskContext | None = None) -> list[dict]:
    """One alert per correlation window and group, at the event that made it reach its threshold.
    The entity is the group's client address resolved through the assets file, so a spray joins
    the storyline of the host it came from."""
    from correlation import (  # imported here: correlation imports replay
        evaluate,
        group_label,
        human,
        iso,
        value_reader,
    )
    out = []
    for corr in corrs:
        p = corr.params
        read = value_reader(p)
        try:
            base, src = compile_rule(corr.base), logsource_key(corr.base)
            counted = [ev for ev in events if route(ev) == src and base(ev)] if p.counted else []
        except SigmaError:
            counted = []
        for a in evaluate(corr, events):
            label = group_label(a)
            ent = assets.get(label, {}).get("host", label) if p.group_by else "-"
            ev = {"TimeCreated": iso(a["crossed_at"]), "IpAddress": label}
            score, factors, questions = (risk or RiskContext(assets)).score(corr, ev, ent)
            what = f"{a['value_count']} distinct {p.field}" if p.counted else f"{a['event_count']} events"
            values = ", ".join(a["values"][:6]) + ("…" if len(a["values"]) > 6 else "")
            seen: dict[str, list[datetime]] = {}
            lo, group = a["window_start"], tuple(a["group"].values())
            for ev in counted:
                t = parse_time(ev)
                if t and lo <= t < lo + timedelta(seconds=p.timespan) and tuple(read(ev, g) for g in p.group_by) == group:
                    v = read(ev, p.counted)
                    if v:
                        seen.setdefault(v, []).append(t)
            out.append({
                "_value_times": {v: (min(ts), max(ts)) for v, ts in seen.items()},
                "time": a["crossed_at"], "entity": ent, "host": "-", "user": "-", "rule": corr.id,
                "title": corr.title, "level": corr.level, "technique": corr.technique, "tactics": corr.tactics,
                "summary": f"{what} from {label} in the {human(p.timespan)} window from {a['window_start']:%H:%M}"
                           + (f": {values}" if values else ""),
                "risk": score, "risk_factors": factors, "risk_questions": questions,
                "correlation": {"window_start": a["window_start"], "group": a["group"], "metric": a["metric"],
                                "event_count": a["event_count"], "first_event": a["first_event"],
                                "last_event": a["last_event"], "values": a["values"]},
            })
    return out


def replay(events: list[dict], dets, assets: dict, risk: RiskContext | None = None,
           corrs=()) -> tuple[list[dict], dict]:
    by_source = defaultdict(list)
    alerts: list[dict] = []
    stats: dict[str, Any] = {"events": len(events), "routed": 0, "unrouted": 0, "errors": 0}
    compiled = {}
    for d in dets:
        try:
            compiled[d.id] = compile_rule(d.rule)          # same verdicts as matches(), read once
        except SigmaError:
            stats["errors"] += 1
            continue
        by_source[logsource_key(d.rule)].append(d)
    for ev in events:
        src = route(ev)
        if not src:
            stats["unrouted"] += 1
            continue
        stats["routed"] += 1
        for d in by_source.get(src, []):
            if compiled[d.id](ev):
                ent = entity(ev, assets)
                score, factors, questions = (risk or RiskContext(assets)).score(d, ev, ent)
                alerts.append({
                    "time": parse_time(ev), "entity": ent, "host": first(ev, HOST_FIELDS),
                    "user": first(ev, USER_FIELDS), "rule": d.id, "title": d.title, "level": d.level,
                    "technique": d.technique, "tactics": d.tactics,
                    "summary": summary(ev), "risk": score, "risk_factors": factors, "risk_questions": questions,
                    "_event": ev,
                })
    alerts += correlation_alerts(events, corrs, assets, risk)
    alerts.sort(key=lambda a: (a["time"] or datetime.min, a["rule"]))
    times = [t for t in (parse_time(e) for e in events) if t]
    stats["start"], stats["end"] = (min(times), max(times)) if times else (None, None)
    return alerts, stats


DAY = 86400.0
NOISY = "noisy - tune before deploying"


def replayed_days(stats: dict) -> float | None:
    """The days the replayed events span when they span one or more, else None: a per-day figure is an
    average over the logs, never a short capture stretched to a day."""
    if not (stats.get("start") and stats.get("end")):
        return None
    seconds = (stats["end"] - stats["start"]).total_seconds()
    return seconds / DAY if seconds >= DAY else None


def span_text(stats: dict) -> str:
    """How long the replayed events span, in words: '8 minutes', '11 h 57 min', '3.2 days'."""
    if not (stats.get("start") and stats.get("end")):
        return "no time"
    seconds = (stats["end"] - stats["start"]).total_seconds()
    if seconds >= DAY:
        return f"{seconds / DAY:.1f} days"
    minutes = round(seconds / 60)
    if minutes >= 60:
        return f"{minutes // 60} h {minutes % 60:02d} min"
    if minutes >= 1:
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    return "under a minute"


def volume_note(stats: dict, noisy_per_day: float) -> str:
    """One sentence on what the volume table can and cannot say for these logs."""
    if replayed_days(stats) is not None:
        return f"Per-day figures are averages over the {span_text(stats)} replayed."
    limit = f"{noisy_per_day:g}"
    if not (stats.get("start") and stats.get("end")):
        return (f"The events carry no time, so no per-day figure is given; a rule is called noisy here only when "
                f"its alerts already pass {limit}.")
    return (f"The replayed events span {span_text(stats)}: too short for a per-day figure, which takes a day or more "
            f"of logs. A rule is called noisy here only when its alerts already pass {limit}.")


def forecast(alerts: list[dict], stats: dict, dets, noisy_per_day: float) -> list[dict]:
    """Alert volume per rule. per_day is the average over logs of a day or more and None for anything
    shorter. The verdict is silent, ok or noisy when a day was replayed; on a shorter capture a rule that
    alerted is 'fired', and noisy only when the alerts counted already pass the daily limit."""
    days = replayed_days(stats)
    counts = Counter(a["rule"] for a in alerts)
    entities = defaultdict(set)
    for a in alerts:
        entities[a["rule"]].add(a["entity"])
    rows = []
    for d in dets:
        n = counts.get(d.id, 0)
        per_day = round(n / days, 1) if days else None
        if n == 0:
            verdict = "silent"
        elif (n / days if days else n) > noisy_per_day:
            verdict = NOISY
        else:
            verdict = "ok" if days else "fired"
        rows.append({"rule": d.id, "title": d.title, "level": d.level, "alerts": n,
                     "per_day": per_day, "entities": len(entities[d.id]), "verdict": verdict})
    return sorted(rows, key=lambda r: -r["alerts"])


def storylines(alerts: list[dict], window_min: int) -> list[dict]:
    per_entity = defaultdict(list)
    for a in alerts:
        if a["time"]:
            per_entity[a["entity"]].append(a)
    stories = []
    for ent, items in per_entity.items():
        items.sort(key=lambda a: a["time"])
        group = [items[0]]
        for a in items[1:]:
            if (a["time"] - group[-1]["time"]).total_seconds() <= window_min * 60:
                group.append(a)
            else:
                stories.append(_story(ent, group))
                group = [a]
        stories.append(_story(ent, group))
    stories = sorted([s for s in stories if s["techniques"] >= 2], key=lambda s: -s["score"])
    # Possible pivots: lateral-movement alerts on OTHER entities shortly after a storyline starts
    for s in stories:
        s["pivots"] = [a for a in alerts if a["time"] and a["entity"] != s["entity"]
                       and "lateral-movement" in a["tactics"]
                       and s["start"] <= a["time"] <= s["end"] + (s["end"] - s["start"]) + _minutes(window_min)]
        if s["pivots"]:
            s["narrative"] += " Possible pivot: " + ", ".join(
                f"{a['title']} on {a['entity']} at {a['time']:%H:%M}" for a in s["pivots"]) + "."
    return stories


def _minutes(m: int):
    from datetime import timedelta
    return timedelta(minutes=m)


def _story(ent: str, group: list[dict]) -> dict:
    tactic_seq = []
    for a in group:
        ranks = [TACTIC_ORDER.index(t) for t in a["tactics"] if t in TACTIC_ORDER]
        a["_rank"] = min(ranks) if ranks else 99
        tactic_seq.append(a["_rank"])
    techniques = sorted({a["technique"] for a in group})
    tactics = sorted({t for a in group for t in a["tactics"] if t in TACTIC_ORDER}, key=TACTIC_ORDER.index)
    progression = sum(1 for x, y in pairwise(tactic_seq) if y > x)
    base = sum(LEVEL_WEIGHT.get(a["level"], 4) for a in {a["rule"]: a for a in group}.values())
    score = min(100, round(base * (1 + 0.15 * len(tactics)) + 4 * progression))
    minutes = (group[-1]["time"] - group[0]["time"]).total_seconds() / 60
    steps, seen = [], set()
    for a in group:
        if a["rule"] not in seen:
            seen.add(a["rule"])
            steps.append(a)
    span = "a minute" if minutes < 1 else (f"{minutes:.0f} minutes" if round(minutes) != 1 else "1 minute")
    narrative = (f"On {ent}, within {span}: "
                 + " → ".join(f"{s['title']} ({s['technique']})" for s in steps) + ".")
    return {"entity": ent, "start": group[0]["time"], "end": group[-1]["time"], "minutes": round(minutes, 1),
            "alerts": len(group), "techniques": len(techniques), "tactics": tactics, "score": score,
            "kill_chain_progression": progression, "narrative": narrative, "steps": group}


# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #
def when_text(stats: dict) -> str:
    """The replayed span as a reader wants it: to the second, the date once when both ends share it, in UTC."""
    start, end = stats.get("start"), stats.get("end")
    if not (start and end):
        return "no timestamps"
    last = f"{end:%H:%M:%S}" if start.date() == end.date() else f"{end:%Y-%m-%d %H:%M:%S}"
    return f"{start:%Y-%m-%d %H:%M:%S} → {last} UTC"


def print_report(alerts, stats, fc, stories, noisy_per_day: float = 20):
    span = when_text(stats)
    print(f"{BOLD}Replayed {stats['events']} events{RESET} ({stats['routed']} routed, {stats['unrouted']} unrouted)  {DIM}{span}{RESET}")
    print(f"{BOLD}{len(alerts)} alerts{RESET} from {sum(1 for r in fc if r['alerts'])} of {len(fc)} detections\n")
    print(f"{BOLD}Attack storylines{RESET}")
    if not stories:
        print(f"  {DIM}none (no entity triggered two or more techniques inside the window){RESET}")
    for s in stories:
        colour = RED if s["score"] >= 70 else YELLOW
        print(f"  {colour}{s['score']:3d}{RESET}  {GOLD}{s['entity']}{RESET}  {s['start']:%H:%M}–{s['end']:%H:%M}  "
              f"{s['techniques']} techniques · {len(s['tactics'])} tactics · {s['alerts']} alerts")
        print(f"       {s['narrative']}")
    ranked = sorted((a for a in alerts if a.get("risk") is not None), key=lambda a: -a["risk"])[:5]
    if ranked:
        print(f"\n{BOLD}Highest-risk alerts{RESET} {DIM}(contract risk_model + resolved conditions){RESET}")
        for a in ranked:
            colour = RED if a["risk"] >= 70 else (YELLOW if a["risk"] >= 50 else DIM)
            when = f"{a['time']:%H:%M}" if a["time"] else "--:--"
            why = ", ".join(a["risk_factors"]) or "base score"
            print(f"  {colour}{a['risk']:3d}{RESET}  {when}  {a['entity']:<20} {a['technique']:<10} {DIM}{why}{RESET}")
    print(f"\n{BOLD}Alert volume{RESET}")
    for r in fc:
        colour = RED if r["verdict"].startswith("noisy") else (DIM if r["verdict"] == "silent" else GREEN)
        per_day = "" if r["per_day"] is None else f"{r['per_day']:6.1f}/day  "
        print(f"  {r['alerts']:4d} alerts  {per_day}{r['entities']:3d} entities  "
              f"{colour}{r['verdict']:<32}{RESET} {r['rule']}")
    print(f"  {DIM}{volume_note(stats, noisy_per_day)}{RESET}")


REPORT_CSS = """
:root{--bg:#fff;--fg:#111;--dim:#666;--line:#d0d0d0;--soft:#f2f2f2}
@media (prefers-color-scheme:dark){:root{--bg:#0f0f0f;--fg:#e9e9e9;--dim:#9c9c9c;--line:#343434;--soft:#1c1c1c}}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
header,main,footer,nav{max-width:1360px;margin:0 auto;padding:0 22px}
header{padding-top:26px;padding-bottom:12px}
nav{position:sticky;top:0;z-index:2;background:var(--bg);padding-top:9px;padding-bottom:9px;border-bottom:2px solid var(--fg)}
section{scroll-margin-top:56px}details.alert{scroll-margin-top:43px}
h1{font-size:21px;margin:0}h2{font-size:15px;margin:34px 0 10px;text-transform:uppercase;letter-spacing:.08em}
h3{font-size:16px;margin:0}a{color:inherit}
.src,.note,.meta,time,small{color:var(--dim)}.src{margin:2px 0 12px}
.counts{margin:0;font-size:16px}.counts b{font-size:19px}.counts i{font-style:normal;color:var(--dim);margin:0 9px}
nav a{margin-right:18px}
.story{border-left:3px solid var(--fg);padding:2px 0 2px 16px;margin-bottom:22px}.meta{font-weight:400;font-size:14px;margin-left:10px}
.narrative{margin:8px 0 10px;max-width:1000px}.steps{margin:0;padding-left:22px}.steps li{margin:3px 0}
.steps a{text-decoration:none}.steps a:hover b,.steps a:focus b{text-decoration:underline}
time,.n,.fields,code{font-family:ui-monospace,"Cascadia Mono",Menlo,Consolas,"DejaVu Sans Mono",monospace;font-size:13px}
time{margin-right:10px}code{display:block;color:var(--dim);overflow-wrap:anywhere}
.tools{display:flex;gap:12px;align-items:center;margin:0 0 10px}
#q{flex:0 1 420px;font:inherit;color:inherit;background:var(--bg);border:1px solid var(--dim);padding:6px 9px}
#all{font:inherit;color:inherit;background:var(--soft);border:1px solid var(--dim);padding:6px 12px;cursor:pointer}
.row{display:grid;grid-template-columns:16px 78px 44px 70px 140px 230px 100px 1fr;gap:12px;padding:7px 8px;border-bottom:1px solid var(--line);align-items:baseline}
.head{font-size:13px;color:var(--dim);border-bottom:1px solid var(--fg)}
summary.row{cursor:pointer;list-style:none}summary.row::-webkit-details-marker{display:none}
summary.row::before{content:"+";font-family:ui-monospace,Menlo,Consolas,monospace;color:var(--dim)}
details[open]>summary.row::before{content:"\\2212"}details[open]>summary.row,summary.row:hover{background:var(--soft)}
.row span,.row b{overflow-wrap:anywhere;min-width:0}.n{text-align:right}
.body{padding:10px 8px 14px 36px;border-bottom:1px solid var(--line)}
.fields{border-collapse:collapse}.fields th{text-align:right;font-weight:400;color:var(--dim);padding:1px 14px 1px 0;vertical-align:top;white-space:nowrap}
.fields td{padding:1px 0;overflow-wrap:anywhere}.body p{margin:8px 0 0;font-size:14px}
.vol{width:100%;border-collapse:collapse}.vol th,.vol td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);font-size:14px}
.vol th{color:var(--dim);font-weight:400;border-bottom:1px solid var(--fg);white-space:nowrap}.vol .n{text-align:right;white-space:nowrap}
.quiet{color:var(--dim)}.loud{font-weight:700}
footer{margin-top:40px;padding-top:10px;padding-bottom:40px;border-top:1px solid var(--line);color:var(--dim);font-size:13px}
@page{margin:14mm 12mm 16mm;@top-left{content:""}@top-center{content:""}@top-right{content:""}@bottom-center{content:""}
@bottom-left{content:"RASD replay report";font:9pt system-ui,sans-serif;color:#666}@bottom-right{content:counter(page) " / " counter(pages);font:9pt system-ui,sans-serif;color:#666}}
@media print{:root{--bg:#fff;--fg:#000;--dim:#555;--line:#bbb;--soft:#fff}body{font-size:11pt}header,main,footer{max-width:none;padding:0}
nav,.tools{display:none}h2{break-after:avoid}.story,.row,.body,tr{break-inside:avoid}.vol th,.vol td{font-size:9.5pt;padding:4px 6px}thead{display:table-header-group}}
"""

REPORT_JS = """
(function(){
var q=document.getElementById('q'),all=document.getElementById('all'),count=document.getElementById('count');
var rows=[].slice.call(document.querySelectorAll('details.alert'));
function filter(){var s=q.value.trim().toLowerCase(),n=0;
rows.forEach(function(r){var hit=!s||r.textContent.toLowerCase().indexOf(s)>-1;r.hidden=!hit;if(hit)n++;});
count.textContent=s?n+' of '+rows.length+' alerts':'';}
function toggle(open){rows.forEach(function(r){if(!r.hidden)r.open=open;});all.textContent=open?'Close all':'Open all';}
function jump(){var t=document.getElementById(location.hash.slice(1));
if(t&&t.tagName==='DETAILS'){t.hidden=false;t.open=true;t.scrollIntoView({block:'start'});}}
q.addEventListener('input',filter);
all.addEventListener('click',function(){toggle(all.textContent==='Open all');});
window.addEventListener('hashchange',jump);window.addEventListener('beforeprint',function(){toggle(true);});
jump();
})();
"""


def _alert_fields(alert: dict, rules: dict) -> list[tuple[str, str]]:
    """What an alert's details show: the event fields its rule read, or a correlation's window and counts."""
    rec = _alert_record(alert, rules)
    if "event" in rec:
        return [(k, _one_line(v)) for k, v in rec["event"].items() if v not in (None, "")]
    rows = []
    for k, v in (rec.get("correlation") or {}).items():
        if isinstance(v, dict):
            v = ", ".join(f"{a}={b}" for a, b in v.items())
        elif isinstance(v, (list, tuple, set)):
            v = ", ".join(str(x) for x in v)
        if v not in (None, ""):
            rows.append((k, _one_line(v)))
    return rows


def write_html(path: str, alerts, stats, fc, stories, source: str, noisy_per_day: float = 20, rules: dict | None = None):
    e = lambda x: html.escape(str(x))
    daily = any(r["per_day"] is not None for r in fc)
    rules = rules or {}
    shown = [a for a in alerts if a["time"]]
    anchor = {id(a): f"a{n}" for n, a in enumerate(shown, 1)}
    by_key = {(a["time"], a["rule"], a["entity"]): f"a{n}" for n, a in enumerate(shown, 1)}

    def link(a) -> str:
        return anchor.get(id(a)) or by_key.get((a["time"], a["rule"], a["entity"]), "alerts")

    story_html = "".join(
        f"""<article class="story"><h3>{e(s['entity'])}<span class="meta">risk {s['score']} · {s['start']:%Y-%m-%d %H:%M} – {s['end']:%H:%M} · """
        f"""{s['techniques']} techniques · {len(s['tactics'])} tactics · {s['alerts']} alerts</span></h3>
<p class="narrative">{e(s['narrative'])}</p>
<ol class="steps">"""
        + "".join(f"""<li><a href="#{link(a)}"><time>{a['time']:%H:%M:%S}</time><b>{e(a['technique'])}</b> {e(a['title'])}</a>"""
                  f"""<code>{e(a['summary'][:140])}</code></li>""" for a in s["steps"])
        + "</ol></article>" for s in stories) or '<p class="note">No multi-technique storylines in this window.</p>'
    fc_rows = "".join(f"<tr><td>{e(r['rule'])}</td><td>{e(r['level'])}</td><td class='n'>{r['alerts']}</td>"
                      + (f"<td class='n'>{r['per_day']}</td>" if daily else "") + f"<td class='n'>{r['entities']}</td>"
                      f"<td class='{'loud' if r['verdict'].startswith('noisy') else ('quiet' if r['verdict'] == 'silent' else '')}'>{e(r['verdict'])}</td></tr>" for r in fc)

    def alert_html(a) -> str:
        fields = "".join(f"<tr><th>{e(k)}</th><td>{e(v)}</td></tr>" for k, v in _alert_fields(a, rules))
        factors = ", ".join(a.get("risk_factors") or [])
        asks = "; ".join(a.get("risk_questions") or [])
        return (f"""<details class="alert" id="{link(a)}"><summary class="row"><time>{a['time']:%H:%M:%S}</time>"""
                f"""<span class="n">{'' if a.get('risk') is None else a['risk']}</span><span>{e(a['level'])}</span><span>{e(a['entity'])}</span>"""
                f"""<span>{e(a['user'])}</span><b>{e(a['technique'])}</b><span>{e(a['title'])}</span></summary>"""
                f"""<div class="body"><table class="fields">{fields}</table>"""
                + (f"<p>Risk: {e(factors)}</p>" if factors else "")
                + (f"<p>To answer: {e(asks)}</p>" if asks else "") + "</div></details>")

    alerts_html = "".join(alert_html(a) for a in shown)
    fired = sum(1 for r in fc if r["alerts"])
    count = lambda n, noun: f"<b>{n}</b> {noun}{'' if n == 1 else 's'}"
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RASD replay</title><style>{REPORT_CSS}</style></head><body>
<header><h1>RASD replay</h1><p class="src">{e(", ".join(Path(x).name for x in source.split(", ")))} · {e(when_text(stats))}</p>
<p class="counts">{count(stats['events'], 'event')}<i>·</i>{count(len(alerts), 'alert')}<i>·</i>{count(len(stories), 'storyline')}<i>·</i><b>{fired}</b> of {len(fc)} rules fired</p>
</header>
<nav><a href="#storylines">Storylines</a><a href="#alerts">Alerts</a><a href="#volume">Alert volume</a></nav>
<main>
<section id="storylines"><h2>Storylines</h2>{story_html}</section>
<section id="alerts"><h2>Alerts</h2>
<p class="tools"><input id="q" type="search" placeholder="Filter: host, user, technique, detection, field value" aria-label="Filter alerts">
<button id="all" type="button">Open all</button><span id="count" class="note"></span></p>
<div class="row head"><span></span><span>Time</span><span class="n">Risk</span><span>Level</span><span>Host</span><span>User</span><span>Technique</span><span>Detection</span></div>
{alerts_html}</section>
<section id="volume"><h2>Alert volume</h2><p class="note">{e(volume_note(stats, noisy_per_day))}</p>
<table class="vol"><thead><tr><th>Detection</th><th>Level</th><th class="n">Alerts</th>{'<th class="n">Per day</th>' if daily else ''}<th class="n">Entities</th><th>Verdict</th></tr></thead><tbody>{fc_rows}</tbody></table></section>
</main>
<footer>Generated by RASD</footer>
<script>{REPORT_JS}</script></body></html>"""
    write_output(path, doc)


# --------------------------------------------------------------------------- #
# case files (--case-dir)
# --------------------------------------------------------------------------- #
CASE_FORMAT = 1
OBSERVABLES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("host", HOST_FIELDS),
    ("account", USER_FIELDS),
    ("process", ("Image", "NewProcessName")),
    ("parent_process", ("ParentImage", "ParentProcessName")),
    ("command_line", ("CommandLine",)),
    ("parent_command_line", ("ParentCommandLine",)),
    ("source_process", ("SourceImage",)),
    ("target_process", ("TargetImage",)),
    ("registry_key", ("TargetObject",)),
    ("registry_data", ("Details",)),
    ("service_name", ("ServiceName",)),
    ("service_path", ("ImagePath",)),
    ("task_name", ("TaskName",)),
    ("address", ("IpAddress", "SourceAddress", "ClientAddress", "c-ip")),
    ("url", ("cs-uri-stem",)),
    ("user_agent", ("cs(User-Agent)",)),
)
OBSERVABLE_TYPE = {f: kind for kind, fields in OBSERVABLES for f in fields}
NOT_OBSERVABLE = {"", "-", "null", "none", "n/a", "::1", "127.0.0.1", "0.0.0.0"}  # noqa: S104 (values, not a bind)
CONTEXT_FIELDS = ("EventID", "Channel", "Provider_Name", *TIME_FIELDS, *HOST_FIELDS)


def _utc(t: datetime | None) -> str | None:
    return None if t is None else t.isoformat(timespec="milliseconds") + "Z"


def _slug(text: str) -> str:
    slug = re.sub(r"[^a-z0-9.-]+", "-", str(text).lower()).strip("-.")
    return slug[:48] or "unknown"


def _cell(text) -> str:
    """Text in Markdown, read from logs or not: one line, HTML escaped, and every character that
    could start a link, an image, emphasis or a table cell escaped, so a logged value is shown
    and never rendered."""
    text = re.sub(r"([\\`*_\[\]|~])", r"\\\1", html.escape(" ".join(str(text).split()), quote=False))
    return re.sub(r"(?i)\bwww\.", "www\\.", text.replace("://", "\\://"))      # no bare-URL autolinks


def _one_line(text) -> str:
    return " ".join(str(text).split())


def _code(text, limit: int = 160) -> str:
    """Logged text in a Markdown table cell, shown as written: a code span whose fence is longer
    than any backtick run inside it (PowerShell escapes with backticks), pipes escaped."""
    text = " ".join(str(text).split())
    if len(text) > limit:
        text = text[:limit - 1] + "…"
    if not text:
        return ""
    fence = "`" * (max((len(m) for m in re.findall(r"`+", text)), default=0) + 1)
    pad = " " if text[0] == "`" or text[-1] == "`" else ""
    return f"{fence}{pad}{text.replace('|', chr(92) + '|')}{pad}{fence}"


def _spreadsheet_safe(value: str) -> str:
    """A spreadsheet runs a cell that starts with = + - @ as a formula; logged command lines are
    attacker-controlled, so such values get a leading apostrophe in the CSV (timeline.json keeps
    them exact)."""
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


def _observed(kind: str, field: str, value) -> list[tuple[str, str, str]]:
    text = str(value).strip()
    if kind == "address":
        text = text.removeprefix("::ffff:")
    if text.lower() in NOT_OBSERVABLE:
        return []
    return [(kind, text, field)]


Observable = tuple[str, str, str, datetime, datetime]          # type, value, field, first seen, last seen


def alert_observables(alert: dict, rules: dict) -> list[Observable]:
    """Every observable an alert's event carries, at the event's time; for a correlation, its group
    over the counted window and each counted value at the times it was seen in that window."""
    out: list[Observable] = []
    t = alert["time"]
    ev = alert.get("_event")
    if ev is not None:
        for kind, fields in OBSERVABLES:
            for f in fields:
                if ev.get(f) not in (None, ""):
                    out += [(k, v, fl, t, t) for k, v, fl in _observed(kind, f, ev[f])]
        for part in str(ev.get("Hashes") or "").split(","):
            alg, sep, digest = part.partition("=")
            if sep and digest.strip():
                out.append((alg.strip().lower(), digest.strip().lower(), "Hashes", t, t))
        return out
    corr = alert.get("correlation") or {}
    first, last = corr.get("first_event") or t, corr.get("last_event") or t
    for f, v in (corr.get("group") or {}).items():
        out += [(k, val, fl, first, last) for k, val, fl in _observed(OBSERVABLE_TYPE.get(f, "value"), f, v)]
    rule = rules.get(alert["rule"])
    counted = getattr(getattr(rule, "params", None), "field", None) or "value"
    times = alert.get("_value_times") or {}
    for v in corr.get("values") or []:
        lo, hi = times.get(v, (first, last))
        out += [(k, val, fl, lo, hi) for k, val, fl in _observed(OBSERVABLE_TYPE.get(counted, "value"), counted, v)]
    return out


def _alert_record(alert: dict, rules: dict) -> dict:
    """An alert as the case timeline keeps it: the event fields its rule read, plus where and
    when it was logged; for a correlation, its window, group, counts and values."""
    rec = {"time_utc": _utc(alert["time"]), "rule": alert["rule"], "title": alert["title"],
           "technique": alert["technique"], "tactics": alert["tactics"], "level": alert["level"],
           "entity": alert["entity"], "host": alert["host"], "user": alert["user"],
           "risk": alert.get("risk"), "risk_factors": alert.get("risk_factors") or [],
           "risk_questions": alert.get("risk_questions") or [], "summary": alert["summary"]}
    ev = alert.get("_event")
    if ev is not None:
        from validate import rule_fields
        rule = rules.get(alert["rule"])
        reads = rule_fields(rule.rule["detection"]) if rule is not None else set(ev)
        rec["event"] = {k: v for k, v in ev.items() if k in reads or k in CONTEXT_FIELDS or k in USER_FIELDS}
    elif alert.get("correlation"):
        corr = alert["correlation"]
        rec["correlation"] = {**corr, **{k: _utc(corr.get(k)) for k in ("window_start", "first_event", "last_event")}}
    return rec


def _card_folder(rule) -> str:
    folder = getattr(rule, "folder", None)
    if folder is None:
        return ""
    try:
        return Path(folder).resolve().relative_to(Path(__file__).resolve().parent.parent).as_posix() + "/"
    except ValueError:
        return str(folder)


def closure_draft(n: int, name: str, story: dict, rules: dict) -> str:
    """analyst_closure.md: the three notes a case can end with, pre-filled only with what the logs
    show. The analyst picks one and fills in what they checked; the replay never picks."""
    steps, pivots = story["steps"], story.get("pivots") or []
    entity = _one_line(story["entity"])
    case = f"{name} · {entity} · {story['start']:%Y-%m-%d %H:%M:%S} → {story['end']:%H:%M:%S} UTC"
    accounts = list(dict.fromkeys(_one_line(a["user"]) for a in steps if a["user"] != "-"))
    sources = list(dict.fromkeys(_one_line(o[1]) for a in steps for o in alert_observables(a, rules) if o[0] == "address"))
    who = f"{', '.join(accounts) or '-'} on {entity}" + (f"; source {', '.join(sources)}" if sources else "")
    pad = " " * 14
    observed = [f"{a['time']:%H:%M:%S} {a['technique']} {a['title']}" for a in steps]
    risks = [a for a in steps if a.get("risk") is not None]
    top = max(risks, key=lambda a: a["risk"]) if risks else None
    alerts = (f"{len(steps)} alerts, {story['techniques']} techniques on {entity} "
              f"({story['start']:%H:%M:%S} → {story['end']:%H:%M:%S} UTC)")
    escalation = [f"Case:         {case}", f"Observed:     {observed[0]}", *(pad + o for o in observed[1:])]
    if pivots:
        other = [f"{a['time']:%H:%M:%S} {_one_line(a['entity'])} {a['technique']} {a['title']}" for a in pivots]
        escalation += [f"Other hosts:  {other[0]}", *(pad + o for o in other[1:])]
    escalation += [f"Who / where:  {who}",
                   f"Risk:         storyline {story['score']}/100"
                   + (f" · highest alert {top['risk']} ({top['technique']})" if top else ""),
                   "Escalated:    <the condition met, from the detection cards>",
                   "Preserved:    <what is saved, and where>",
                   "Containment:  none yet | <action taken, time UTC>"]
    benign = [f"Case:         {case}", f"Alerts:       {alerts}",
              "Checked:      <the triage step from each detection card> -> <result>",
              "Benign:       <the approved activity> - confirmed by <change record, owner or ticket>",
              "Disposition:  Benign Positive"]
    false_positive = [f"Case:         {case}", f"Alerts:       {alerts}",
                      "Why not:      <the field that matched, and what it really was>",
                      "Disposition:  False Positive",
                      "Follow-up:    <events sent to detection engineering as true negatives | not yet>"]

    def block(rows: list[str]) -> list[str]:
        """A text block whose fence is longer than any backtick run inside it, so no logged value closes it."""
        fence = "`" * max(3, max((len(m) for r in rows for m in re.findall(r"`+", r)), default=0) + 1)
        return [fence + "text", *rows, fence]

    lines = [f"# Analyst notes · Case {n:02d} · {_cell(entity)}", "",
             "Drafted by `rasd replay` from the logs only. Fill in only what you checked. A storyline is escalated, "
             "not closed from the queue, unless every alert in it is explained.", "",
             "## Escalation to incident response", "", *block(escalation), "",
             "## Benign Positive", "", *block(benign), "",
             "## False Positive", "", *block(false_positive), ""]
    return "\n".join(lines)


def write_cases(case_dir: str | Path, stories: list[dict], rules: dict, sources: list[str]) -> list[Path]:
    """One folder per storyline: case_summary.md, timeline.json, observables.csv, analyst_closure.md and
    evidence_request.md.
    Only what the logs show is written; the disposition is left to the analyst."""
    out = Path(case_dir)
    out.mkdir(parents=True, exist_ok=True)
    inputs = [{"file": Path(p).name, "sha256": hashlib.sha256(Path(p).read_bytes()).hexdigest()} for p in sources]
    written = []
    for n, s in enumerate(stories, 1):
        name = f"case-{n:02d}-{_slug(s['entity'])}"
        folder = out / name
        folder.mkdir(exist_ok=True)
        steps, pivots = s["steps"], s.get("pivots") or []
        observed: dict[tuple[str, str], dict] = {}
        for a in [*steps, *pivots]:
            for kind, value, field, first_seen, last_seen in alert_observables(a, rules):
                o = observed.setdefault((kind, value), {"first": first_seen, "last": last_seen, "alerts": 0,
                                                         "rules": set(), "fields": set()})
                o["first"], o["last"] = min(o["first"], first_seen), max(o["last"], last_seen)
                o["alerts"] += 1
                o["rules"].add(a["rule"])
                o["fields"].add(field)
        order = {kind: i for i, (kind, _) in enumerate(OBSERVABLES)}
        with open(folder / "observables.csv", "w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["type", "value", "first_seen_utc", "last_seen_utc", "alerts", "detections", "fields"])
            for (kind, value), o in sorted(observed.items(), key=lambda kv: (order.get(kv[0][0], 99), kv[0][0],
                                                                              kv[1]["first"], kv[0][1])):
                w.writerow([kind, _spreadsheet_safe(value), _utc(o["first"]), _utc(o["last"]), o["alerts"],
                            " ".join(sorted(o["rules"])), " ".join(sorted(o["fields"]))])
        narrative = s["narrative"].split(" Possible pivot: ")[0]
        timeline = {"rasd_case": CASE_FORMAT, "case": name, "entity": s["entity"], "start_utc": _utc(s["start"]),
                    "end_utc": _utc(s["end"]), "minutes": s["minutes"], "score": s["score"],
                    "techniques": sorted({a["technique"] for a in steps}), "tactics": s["tactics"],
                    "narrative": narrative, "disposition": None, "sources": inputs,
                    "alerts": [_alert_record(a, rules) for a in steps],
                    "other_hosts": [_alert_record(a, rules) for a in pivots]}
        (folder / "timeline.json").write_text(json.dumps(timeline, indent=2, ensure_ascii=False, default=str) + "\n",
                                              encoding="utf-8", newline="\n")
        risks = [a for a in steps if a.get("risk") is not None]
        top = max(risks, key=lambda a: a["risk"]) if risks else None
        questions: dict[str, dict[str, str]] = {}
        for a in steps:
            for q in a.get("risk_questions") or []:
                m = re.fullmatch(r"([+-]\d+) if (.+)\?", q)
                if m:
                    questions.setdefault(m.group(2), {}).setdefault(a["rule"], m.group(1))
        lines = [f"# Case {n:02d} · {_cell(s['entity'])}", "",
                 "| | |", "|---|---|",
                 f"| Window (UTC) | {s['start']:%Y-%m-%d %H:%M:%S} → {s['end']:%H:%M:%S} ({s['minutes']:.0f} min) |",
                 f"| Storyline | score {s['score']}/100 · {s['techniques']} techniques · {len(s['tactics'])} tactics · "
                 f"{s['alerts']} alerts |",
                 f"| Tactics | {' → '.join(s['tactics']) or '-'} |",
                 "| Highest alert risk | " + (f"{top['risk']} · {top['technique']} at {top['time']:%H:%M:%S}" if top else "-")
                 + " |",
                 "| Disposition | not set: the replay reports what the logs show; the analyst sets it after triage |",
                 "| Built from | " + " · ".join(f"{_cell(i['file'])} (SHA-256 {i['sha256'][:12]}…)" for i in inputs) + " |",
                 "", "## What the logs show", "", _cell(narrative), "",
                 "## Timeline", "",
                 "| Time (UTC) | Technique | Detection | Host | Account | Risk | Observed |",
                 "|---|---|---|---|---|---:|---|"]
        lines += [f"| {a['time']:%H:%M:%S} | {a['technique']} | {_cell(a['title'])} | {_cell(a['host'])} | "
                  f"{_cell(a['user'])} | {'' if a.get('risk') is None else a['risk']} | {_code(a['summary'])} |"
                  for a in steps]
        if pivots:
            lines += ["", "## Other hosts in the same window", "",
                      "| Time (UTC) | Host | Detection | Observed |", "|---|---|---|---|"]
            lines += [f"| {a['time']:%H:%M:%S} | {_cell(a['entity'])} | {_cell(a['title'])} | {_code(a['summary'])} |"
                      for a in pivots]
        if questions:
            lines += ["", "## Open questions", "",
                      "The detections' risk models score these only after an analyst answers them.", "",
                      "| Question | Risk change if yes |", "|---|---|"]
            lines += [f"| {_cell(q.capitalize())}? | " + " · ".join(f"{r} {v}" for r, v in changes.items()) + " |"
                      for q, changes in questions.items()]
        lines += ["", "## Detection cards", ""]
        for rule_id in dict.fromkeys(a["rule"] for a in [*steps, *pivots]):
            card = _card_folder(rules.get(rule_id))
            lines.append(f"- {rule_id}" + (f": `{card}` triage.md · response.md · closure.md" if card else ""))
        lines += ["", "## Files", "",
                  "- `timeline.json`: every alert in order, with the event fields its rule read",
                  f"- `observables.csv`: {len(observed)} values seen in these alerts (hosts, accounts, processes, "
                  "command lines, registry keys, services, addresses, hashes); seen in the logs, not judged",
                  "- `analyst_closure.md`: the escalation, benign positive and false positive notes, pre-filled with "
                  "what the logs show; the analyst picks one",
                  "- `evidence_request.md`: what to collect for these detections, in order, and what a log clear in this "
                  "storyline took",
                  "", "<sub>Generated by RASD · Continuous Detection Assurance Framework</sub>", ""]
        (folder / "case_summary.md").write_text("\n".join(lines), encoding="utf-8", newline="\n")
        (folder / "analyst_closure.md").write_text(closure_draft(n, name, s, rules), encoding="utf-8", newline="\n")
        from survivability import evidence_request, load_model     # imported here: survivability reads route() from this module
        (folder / "evidence_request.md").write_text(evidence_request(load_model(), name, steps), encoding="utf-8", newline="\n")
        written.append(folder)
    return written


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logs", nargs="+", help="JSONL log files")
    ap.add_argument("--assets", help="CSV with ip,host[,role] to resolve network events and critical hosts")
    ap.add_argument("--users", help="CSV with user,privileged to mark privileged accounts")
    ap.add_argument("--hours", default="7-19", help="local business hours for the off-hours risk condition (default 7-19)")
    ap.add_argument("--utc-offset", type=float, default=0.0,
                    help="hours between UTC and the business hours' local time, e.g. 3 for UTC+3 (default 0)")
    ap.add_argument("--window", type=int, default=60, help="storyline correlation window in minutes (default 60)")
    ap.add_argument("--noisy", type=float, default=20,
                    help="alerts a day above which a rule is called noisy; judged per day on logs of a day or more, "
                         "on a shorter capture only by the alerts it already holds (default 20)")
    ap.add_argument("--filter", help="only replay detections matching this text")
    ap.add_argument("--html", help="write a self-contained HTML report")
    ap.add_argument("--json", help="write alerts, forecast and storylines as JSON")
    ap.add_argument("--profile", help="telemetry profile from profiles/ (or 'auto') the logs are written in")
    ap.add_argument("--case-dir", help="write one case folder per storyline: case_summary.md, timeline.json, "
                                       "observables.csv, analyst_closure.md")
    args = ap.parse_args()

    import profiles  # imported here: profiles itself imports replay
    events, used = profiles.apply([ev for p in args.logs for ev in load_jsonl(Path(p))], args.profile)
    if used != profiles.NATIVE:
        print(f"telemetry profile: {used}")
    from correlation import (
        load_correlations,  # imported here: correlation imports replay
    )
    dets = load_detections(args.filter)
    corrs = load_correlations(args.filter)
    assets = load_assets(args.assets)
    start, end = (int(x) for x in args.hours.split("-"))
    alerts, stats = replay(events, dets, assets,
                           RiskContext(assets, load_users(args.users), (start, end), args.utc_offset), corrs)
    fc = forecast(alerts, stats, [*dets, *corrs], args.noisy)
    stories = storylines(alerts, args.window)
    print_report(alerts, stats, fc, stories, args.noisy)
    if args.html:
        write_html(args.html, alerts, stats, fc, stories, ", ".join(args.logs), args.noisy,
                   {**{d.id: d for d in dets}, **{c.id: c for c in corrs}})
        print(f"\n[+] HTML report: {args.html}")
    if args.json:
        clean = lambda o: o.isoformat() if isinstance(o, datetime) else str(o)
        public = lambda a: {k: v for k, v in a.items() if not k.startswith("_")}
        out = {"stats": stats, "forecast": fc,
               "storylines": [{**{k: v for k, v in s.items() if k not in ("steps", "pivots")},
                               "pivots": [public(a) for a in s.get("pivots") or []]} for s in stories],
               "alerts": [public(a) for a in alerts]}
        write_output(args.json, json.dumps(out, indent=2, default=clean, ensure_ascii=False) + "\n")
        print(f"[+] JSON: {args.json}")
    if args.case_dir:
        if not stories:
            print(f"\nno storyline, so no case folder written to {args.case_dir}")
        else:
            rules: dict[str, Any] = {d.id: d for d in dets}
            rules.update({c.id: c for c in corrs})
            cases = write_cases(args.case_dir, stories, rules, args.logs)
            print(f"\n[+] {len(cases)} case folder(s) in {args.case_dir}: " + ", ".join(c.name for c in cases))
    return 0


if __name__ == "__main__":
    sys.exit(main())
