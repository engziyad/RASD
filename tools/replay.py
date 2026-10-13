#!/usr/bin/env python3
"""
replay.py - run every detection over real (or lab) logs, offline, before deploying anything.

What it answers
  1. What would have fired?           every alert, with the rule, host, user and time - including
                                      the correlation detections (a password spray, a burst of
                                      service tickets), timed at the event that reached the threshold
  2. How noisy will each rule be?     alert volume forecast per rule and per day
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

Input   JSONL, one event per line (Sysmon / Security / System as exported from a SIEM).
        Events are routed to rules by log source, so a Security event is never tested
        against a process-creation rule.
Assets  Optional CSV (ip,host,role) to resolve network events (e.g. Kerberos 4769 on a
        DC, service installs) back to the client host, joining them to its storyline.
        Roles domain-controller, server and critical make a host critical for risk.
Users   Optional CSV (user,privileged) marking privileged accounts for risk.

Usage
  python tools/replay.py samples/replay/lab-day.jsonl --assets samples/replay/assets.csv
  python tools/replay.py logs.jsonl --html report.html --json alerts.json --window 60
  python tools/replay.py logs.jsonl --assets assets.csv --users users.csv --hours 7-19 --utc-offset 3
  python tools/replay.py elastic-export.jsonl --profile elastic-ecs

Event times are compared in UTC; --hours are local business hours, so pass --utc-offset
for the off-hours risk condition to use the right clock.
"""
from __future__ import annotations

import argparse
import csv
import html
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import yaml  # noqa: E402

from common import BOLD, DIM, GOLD, GREEN, RED, RESET, YELLOW, load_detections, load_jsonl  # noqa: E402
from convert import logsource_key  # noqa: E402
from sigma_engine import SigmaError, compile_rule, matches  # noqa: E402

TACTIC_ORDER = ["initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion",
                "credential-access", "discovery", "lateral-movement", "collection", "command-and-control",
                "exfiltration", "impact"]
LEVEL_WEIGHT = {"informational": 1, "low": 2, "medium": 4, "high": 7, "critical": 10}
TIME_FIELDS = ("UtcTime", "TimeCreated", "@timestamp", "_time", "timestamp", "TimeGenerated")
HOST_FIELDS = ("Computer", "host", "Hostname", "DeviceName")
USER_FIELDS = ("User", "SubjectUserName", "TargetUserName", "AccountName")
NETWORK_EVENTS = {4768, 4769, 4771, 4776, 4624, 4625}   # logged by a DC / target about a client: entity = client
CRITICAL_ROLES = {"domain-controller", "server", "critical"}
WRITABLE_PATH = re.compile(r"(?i)[\\/](AppData|ProgramData|Users[\\/]Public|Windows[\\/]Temp|Downloads)[\\/]")
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
    if "sysmon" in ch or (not ch and ("Image" in ev or "TargetImage" in ev or "TargetObject" in ev)):
        return {"1": "process_creation", "10": "process_access", "13": "registry_set"}.get(eid)
    if ch.endswith("security") or (not ch and eid in {"4769", "4768", "4624", "4625", "1102", "4698", "4688"}):
        return "process_creation" if eid == "4688" else "windows/security"
    if ch.endswith("system") or (not ch and eid in {"7045", "104", "7036"}):
        return "windows/system"
    return None


_FRACTION = re.compile(r"\.(\d+)")


def parse_time(ev: dict) -> datetime | None:
    """First parseable timestamp field, returned as naive UTC.

    Accepts Sysmon UtcTime ('2026-10-12 06:00:01.120'), Windows SystemTime with 7
    fractional digits ('...01.1234567Z') and any ISO 8601 offset, which is converted to UTC.
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
    s = first(ev, ("CommandLine", "ImagePath", "Details", "ServiceName", "SourceImage"))
    return "" if s == "-" else s


def load_assets(path: str | None) -> dict:
    if not path:
        return {}
    with open(path, encoding="utf-8") as fh:
        return {row["ip"].strip(): row for row in csv.DictReader(fh)}


def entity(ev: dict, assets: dict) -> str:
    ip = str(ev.get("IpAddress") or "").replace("::ffff:", "")
    try:
        eid = int(ev.get("EventID", 0))
    except (TypeError, ValueError):
        eid = 0
    if ip and ip not in ("-", "::1", "127.0.0.1") and eid in NETWORK_EVENTS:
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
            return user in ("administrator", "admin")
        if condition == "outside_business_hours":
            t = parse_time(ev)
            return None if t is None else not (self.hours[0] <= (t + self.utc_offset).hour < self.hours[1])
        if condition == "payload_in_user_writable_path":
            return any(WRITABLE_PATH.search(str(ev.get(f) or "")) for f in ("CommandLine", "Details", "ImagePath"))
        if condition == "suspicious_parent":
            return str(ev.get("ParentImage") or "").lower().endswith(RISKY_PARENTS)
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
    from correlation import evaluate, group_label, human, iso   # imported here: correlation imports replay
    out = []
    for corr in corrs:
        p = corr.params
        for a in evaluate(corr, events):
            label = group_label(a)
            ent = assets.get(label, {}).get("host", label) if p.group_by else "-"
            ev = {"TimeCreated": iso(a["crossed_at"]), "IpAddress": label}
            score, factors, questions = (risk or RiskContext(assets)).score(corr, ev, ent)
            what = f"{a['value_count']} distinct {p.field}" if p.counted else f"{a['event_count']} events"
            values = ", ".join(a["values"][:6]) + ("…" if len(a["values"]) > 6 else "")
            out.append({
                "time": a["crossed_at"], "entity": ent, "host": "-", "user": "-", "rule": corr.id,
                "title": corr.title, "level": corr.level, "technique": corr.technique, "tactics": corr.tactics,
                "summary": f"{what} from {label} in the {human(p.timespan)} window from {a['window_start']:%H:%M}"
                           + (f": {values}" if values else ""),
                "risk": score, "risk_factors": factors, "risk_questions": questions,
                "correlation": {"window_start": a["window_start"], "group": a["group"], "metric": a["metric"],
                                "event_count": a["event_count"], "first_event": a["first_event"],
                                "last_event": a["last_event"]},
            })
    return out


def replay(events: list[dict], dets, assets: dict, risk: RiskContext | None = None,
           corrs=()) -> tuple[list[dict], dict]:
    by_source = defaultdict(list)
    alerts, stats = [], {"events": len(events), "routed": 0, "unrouted": 0, "errors": 0}
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
                })
    alerts += correlation_alerts(events, corrs, assets, risk)
    alerts.sort(key=lambda a: (a["time"] or datetime.min, a["rule"]))
    times = [t for t in (parse_time(e) for e in events) if t]
    stats["start"], stats["end"] = (min(times), max(times)) if times else (None, None)
    return alerts, stats


def forecast(alerts: list[dict], stats: dict, dets, noisy_per_day: float) -> list[dict]:
    span_days = 1.0
    if stats["start"] and stats["end"]:
        span_days = max((stats["end"] - stats["start"]).total_seconds() / 86400, 1 / 24)
    counts = Counter(a["rule"] for a in alerts)
    entities = defaultdict(set)
    for a in alerts:
        entities[a["rule"]].add(a["entity"])
    rows = []
    for d in dets:
        n = counts.get(d.id, 0)
        per_day = n / span_days
        verdict = "silent" if n == 0 else ("noisy - tune before deploying" if per_day > noisy_per_day else "ok")
        rows.append({"rule": d.id, "title": d.title, "level": d.level, "alerts": n,
                     "per_day": round(per_day, 1), "entities": len(entities[d.id]), "verdict": verdict})
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
                stories.append(_story(ent, group)); group = [a]
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
    progression = sum(1 for x, y in zip(tactic_seq, tactic_seq[1:]) if y > x)
    base = sum(LEVEL_WEIGHT.get(a["level"], 4) for a in {a["rule"]: a for a in group}.values())
    score = min(100, round(base * (1 + 0.15 * len(tactics)) + 4 * progression))
    minutes = (group[-1]["time"] - group[0]["time"]).total_seconds() / 60
    steps, seen = [], set()
    for a in group:
        if a["rule"] not in seen:
            seen.add(a["rule"]); steps.append(a)
    narrative = (f"On {ent}, within {minutes:.0f} minutes: "
                 + " → ".join(f"{s['title']} ({s['technique']})" for s in steps) + ".")
    return {"entity": ent, "start": group[0]["time"], "end": group[-1]["time"], "minutes": round(minutes, 1),
            "alerts": len(group), "techniques": len(techniques), "tactics": tactics, "score": score,
            "kill_chain_progression": progression, "narrative": narrative, "steps": group}


# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #
def print_report(alerts, stats, fc, stories):
    span = f"{stats['start']} → {stats['end']}" if stats["start"] else "no timestamps"
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
    print(f"\n{BOLD}Alert volume forecast{RESET}")
    for r in fc:
        colour = RED if r["verdict"].startswith("noisy") else (DIM if r["verdict"] == "silent" else GREEN)
        print(f"  {r['alerts']:4d} alerts  {r['per_day']:6.1f}/day  {r['entities']:3d} entities  "
              f"{colour}{r['verdict']:<32}{RESET} {r['rule']}")
    print(f"  {DIM}per-day figures are projected from the replayed time span{RESET}")


def write_html(path: str, alerts, stats, fc, stories, source: str):
    e = lambda x: html.escape(str(x))
    lvl = {"high": "var(--high)", "critical": "var(--high)", "medium": "var(--med)", "low": "var(--low)"}
    story_html = "".join(f"""
      <article class="story"><header><span class="score" style="--s:{s['score']}">{s['score']}</span>
        <div><h3>{e(s['entity'])}</h3><p class="muted">{s['start']:%Y-%m-%d %H:%M} – {s['end']:%H:%M} · {s['techniques']} techniques ·
        {len(s['tactics'])} tactics · {s['alerts']} alerts</p></div></header>
        <p class="narrative">{e(s['narrative'])}</p>
        <ol class="timeline">{''.join(f"<li><time>{a['time']:%H:%M:%S}</time><b style='color:{lvl.get(a['level'],'inherit')}'>{e(a['technique'])}</b> {e(a['title'])}<code>{e(a['summary'][:140])}</code></li>" for a in s['steps'])}</ol>
      </article>""" for s in stories) or "<p class='muted'>No multi-technique storylines in this window.</p>"
    fc_rows = "".join(f"<tr><td>{e(r['rule'])}</td><td>{e(r['level'])}</td><td class='n'>{r['alerts']}</td>"
                      f"<td class='n'>{r['per_day']}</td><td class='n'>{r['entities']}</td>"
                      f"<td class='{ 'bad' if r['verdict'].startswith('noisy') else ('muted' if r['verdict']=='silent' else 'ok') }'>{e(r['verdict'])}</td></tr>" for r in fc)
    alert_rows = "".join(f"<tr><td>{a['time']:%H:%M:%S}</td><td class='n'>{'' if a.get('risk') is None else a['risk']}</td>"
                         f"<td>{e(a['entity'])}</td><td>{e(a['user'])}</td>"
                         f"<td><b style='color:{lvl.get(a['level'],'inherit')}'>{e(a['technique'])}</b></td><td>{e(a['title'])}"
                         f"<code>{e(', '.join(a.get('risk_factors') or []))}</code></td></tr>" for a in alerts if a['time'])
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RASD Replay Report</title><style>
:root{{--bg:#fbfaf7;--fg:#1d1c1a;--muted:#6b6862;--card:#fff;--line:#e6e2da;--gold:#9a7a45;--sage:#4f7a4f;--high:#b3412e;--med:#a8741a;--low:#4f7a4f}}
@media (prefers-color-scheme:dark){{:root{{--bg:#111214;--fg:#e9e5dc;--muted:#9a968d;--card:#1a1b1e;--line:#2c2d31;--gold:#d7af87;--sage:#87af87;--high:#ef7b66;--med:#e3b25b;--low:#87af87}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}}
main{{max-width:1080px;margin:0 auto;padding:32px 16px 64px}}h1{{font-size:26px;margin:0}}h2{{font-size:18px;margin:36px 0 12px;color:var(--gold)}}h3{{margin:0;font-size:16px}}
.muted{{color:var(--muted)}}.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:20px}}
.kpi{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px}}.kpi b{{display:block;font-size:24px}}
.story{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:14px}}
.story header{{display:flex;gap:14px;align-items:center}}.score{{width:52px;height:52px;border-radius:50%;display:grid;place-items:center;font-weight:700;
background:conic-gradient(var(--high) calc(var(--s)*1%),var(--line) 0)}}.narrative{{margin:12px 0;font-weight:500}}
.timeline{{margin:0;padding-left:18px}}.timeline li{{margin:6px 0}}time{{color:var(--muted);font-variant-numeric:tabular-nums;margin-right:8px}}
code{{display:block;color:var(--muted);font-size:12px;overflow-wrap:anywhere}}.table-wrap{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}}
th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);font-size:14px}}th{{color:var(--muted);font-weight:500}}.n{{text-align:right;font-variant-numeric:tabular-nums}}
.bad{{color:var(--high)}}.ok{{color:var(--sage)}}footer{{margin-top:40px;color:var(--muted);font-size:13px}}
</style></head><body><main>
<h1>RASD Replay Report</h1><p class="muted">{e(", ".join(Path(x).name for x in source.split(", ")))} · {e(stats['start'])} → {e(stats['end'])}</p>
<div class="kpis"><div class="kpi"><span class="muted">Events</span><b>{stats['events']}</b></div>
<div class="kpi"><span class="muted">Alerts</span><b>{len(alerts)}</b></div>
<div class="kpi"><span class="muted">Storylines</span><b>{len(stories)}</b></div>
<div class="kpi"><span class="muted">Rules fired</span><b>{sum(1 for r in fc if r['alerts'])}/{len(fc)}</b></div></div>
<h2>Attack storylines</h2>{story_html}
<h2>Alert volume forecast</h2><div class="table-wrap"><table><tr><th>Detection</th><th>Level</th><th class="n">Alerts</th><th class="n">Projected / day</th><th class="n">Entities</th><th>Verdict</th></tr>{fc_rows}</table></div>
<h2>All alerts</h2><div class="table-wrap"><table><tr><th>Time</th><th class="n">Risk</th><th>Entity</th><th>User</th><th>Technique</th><th>Detection · risk factors</th></tr>{alert_rows}</table></div>
<footer>Generated by RASD · Attack-to-Defense Validation Framework</footer></main></body></html>"""
    Path(path).write_text(doc, encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logs", nargs="+", help="JSONL log files")
    ap.add_argument("--assets", help="CSV with ip,host[,role] to resolve network events and critical hosts")
    ap.add_argument("--users", help="CSV with user,privileged to mark privileged accounts")
    ap.add_argument("--hours", default="7-19", help="local business hours for the off-hours risk condition (default 7-19)")
    ap.add_argument("--utc-offset", type=float, default=0.0,
                    help="hours between UTC and the business hours' local time, e.g. 3 for UTC+3 (default 0)")
    ap.add_argument("--window", type=int, default=60, help="storyline correlation window in minutes (default 60)")
    ap.add_argument("--noisy", type=float, default=20, help="alerts/day above which a rule is flagged noisy")
    ap.add_argument("--filter", help="only replay detections matching this text")
    ap.add_argument("--html", help="write a self-contained HTML report")
    ap.add_argument("--json", help="write alerts, forecast and storylines as JSON")
    ap.add_argument("--profile", help="telemetry profile from mappings/ (or 'auto') the logs are written in")
    args = ap.parse_args()

    import profiles                                     # imported here: profiles itself imports replay
    events, used = profiles.apply([ev for p in args.logs for ev in load_jsonl(Path(p))], args.profile)
    if used != profiles.NATIVE:
        print(f"telemetry profile: {used}")
    from correlation import load_correlations           # imported here: correlation imports replay
    dets = load_detections(args.filter)
    corrs = load_correlations(args.filter)
    assets = load_assets(args.assets)
    start, end = (int(x) for x in args.hours.split("-"))
    alerts, stats = replay(events, dets, assets,
                           RiskContext(assets, load_users(args.users), (start, end), args.utc_offset), corrs)
    fc = forecast(alerts, stats, [*dets, *corrs], args.noisy)
    stories = storylines(alerts, args.window)
    print_report(alerts, stats, fc, stories)
    if args.html:
        write_html(args.html, alerts, stats, fc, stories, ", ".join(args.logs))
        print(f"\n[+] HTML report: {args.html}")
    if args.json:
        clean = lambda o: o.isoformat() if isinstance(o, datetime) else str(o)
        out = {"stats": stats, "forecast": fc, "storylines": [{k: v for k, v in s.items() if k != "steps"} for s in stories],
               "alerts": [{k: v for k, v in a.items() if not k.startswith("_")} for a in alerts]}
        Path(args.json).write_text(json.dumps(out, indent=2, default=clean, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"[+] JSON: {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
