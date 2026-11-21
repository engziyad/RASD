#!/usr/bin/env python3
"""
health.py - RASD-Health: is every detection still being fed?

A detection is the last link of a chain: the sensor writes the event, the forwarder ships it, the
index receives it in time, the fields keep their names, the scheduled search runs. Every link fails
without a sound, and a rule whose chain is broken answers the way it answers on a quiet day: no alert.

doctor asks once, before deployment: will the rules work on this telemetry? silence asks afterwards,
host by host: what does a month without an alert prove? health asks every day in between: is each
detection fed today the way it was when it was last known to work - and it gives every failure the
names of the detections it blinds.

  the watch       rasd health CURRENT --baseline BASELINE
                  compares an export of today's telemetry with a baseline (an earlier export, or the
                  small profile --save-baseline writes from one) and gives each detection a verdict
  the watchdogs   rasd health --write
                  generates the searches that keep the same watch inside the SIEM (queries/health, SPL
                  and KQL) from the log sources, event ids and fields the library's own rules read;
                  the Splunk app schedules them

Verdicts
  healthy    fed as in the baseline
  degraded   fed, but less than it was
  blind      not fed: the rule cannot fire, whatever happens on the hosts
  unknown    nothing to compare: the baseline has no event of the kind the rule reads

Checks
  silent      a host that fed the rule in the baseline has sent nothing over a stretch in which the
              baseline, at the same hours, saw at least 20 events: a workstation asleep at night is not
              silent, one that stops at half past ten on a working day is. A baseline of a week or more
              is read by hour of the week, a shorter one by hour of the day. An event too rare to be
              judged by its own volume (a cleared log) is judged by the channel that carries it
  volume      what the rule reads arrives at less than a quarter of what the baseline saw at those hours
  fields      a field the rule reads is filled in fewer events (20 points less), or in none; a name that
              appeared in its place is given as the rename to map
  truncation  command lines pile up at one length the baseline did not show
  delay       a host's events on a channel reach the index later than the scheduled search waits: the
              Splunk app reads each slice 5 minutes after it closes, and an event indexed after that is
              never read
  schedule    --scheduler FILE, the SIEM's own record of scheduled runs: a search that did not run, or
              was skipped, is a rule that did not look

Usage
  rasd health --sample
  rasd health last-week.jsonl --save-baseline health-baseline.json
  rasd health today.jsonl --baseline health-baseline.json
  rasd health today.jsonl --baseline last-week.jsonl --profile auto --scheduler scheduler.jsonl --json health.json
  rasd health today.jsonl --baseline health-baseline.json --until 2026-11-09T06:00:00Z --strict
  rasd health --write          regenerate the watchdogs and their page (part of rasd build)
  rasd health --check          the generated files match the library (CI)
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BOLD, DIM, GREEN, RED, RESET, ROOT, YELLOW, load_detections, load_jsonl, read_text, write_output
from convert import MAPPINGS, kql_eventdata, logsource_key
import doctor
import profiles
from replay import HOST_FIELDS, TIME_FIELDS, parse_time, route

FORMAT = 1
OUT = ROOT / "queries" / "health"
PAGE = OUT / "README.md"
SAMPLE = ROOT / "samples" / "health"
SAMPLE_BASELINE, SAMPLE_TODAY, SAMPLE_SCHEDULER = SAMPLE / "baseline.json", SAMPLE / "today.jsonl", SAMPLE / "scheduler.jsonl"

INGEST_FIELDS = ("_indextime", "event.ingested", "_TimeReceived", "IngestionTime", "ingest_time")
WEEK = 168                       # hours: the rhythm a baseline of a week or more is read by
MIN_EXPECTED = 20                # events the baseline saw at those hours before an empty stretch means anything
MIN_VOLUME = 50                  # events the baseline saw at those hours before a drop is judged
DROP = 0.25                      # volume: below this share of what the baseline saw at those hours
FIELD_DROP = 20.0                # points of coverage a field may lose
LOST_FROM = 50.0                 # a field counts as lost when the baseline filled it at least this often and now nothing does
MIN_LAGS = 20                    # events with an arrival time before the delay is judged
LATE = (0.01, 0.5)               # share of events arriving too late: degraded from, blind from
SKIPPED = (0.05, 0.5)            # share of scheduled runs that did not complete: degraded from, blind from
RUN_OK = {"success", "succeeded", "completed", "continued", "delegated_remote", "delegated_remote_completion"}
RUN_BAD = {"skipped", "failed", "failure", "error", "delegated_remote_error"}
RUN_NAME = ("savedsearch_name", "search_name", "ss_name", "SentinelResourceName", "name")
RUN_STATUS = ("status", "Status")
RUN_REASON = ("reason", "Reason", "Description")
ORDER = {"blind": 0, "degraded": 1, "unknown": 2, "healthy": 3}
CHECKS = ("silent", "volume", "fields", "truncation", "delay", "schedule")
NAMES_KEPT = 300                 # field names remembered per feed, to name a rename


class HealthError(SystemExit):
    """An input that cannot be read as what it was given as."""

    def __init__(self, message: str):
        super().__init__(f"rasd health: {message}")


# --------------------------------------------------------------------------- #
# what each detection reads
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Need:
    detection: str
    title: str
    source: str                          # log source key (tools/mappings.yml)
    ids: tuple[str, ...]                 # event ids of the rule's positive selections; none: every event of the source
    fields: tuple[str, ...]              # the contract's required fields
    scopes: dict                         # field -> the event ids it is read with
    critical: frozenset                  # fields the rule cannot work without (the contract's telemetry risk)
    allowance: int                       # seconds the scheduled search waits before it reads a slice
    search: str                          # the saved search that runs it
    period: int = 300                    # seconds between two scheduled runs of it

    @property
    def feeds(self) -> tuple[str, ...]:
        return tuple(f"{self.source}#{i}" for i in self.ids) or (self.source,)

    def reads(self, feed: str, name: str) -> bool:
        """The rule reads this field on the events of this feed."""
        eid = feed.partition("#")[2]
        scope = self.scopes.get(name)
        return not scope or not eid or eid in scope


def _minutes(offset: str) -> int:
    m = re.fullmatch(r"-(\d+)m@m", offset)
    if not m:
        raise ValueError(f"cannot read {offset} as a number of minutes")
    return int(m.group(1))


def needs(filter_: str | None = None) -> list[Need]:
    import splunk_app                                   # imported here: splunk_app schedules the watchdogs
    from correlation import load_correlations           # imported here: correlation imports replay
    single = _minutes(splunk_app.WINDOW_END) * 60
    every = re.fullmatch(r"\*/(\d+) \* \* \* \*", splunk_app.SCHEDULE)
    if not every:
        raise ValueError(f"cannot read {splunk_app.SCHEDULE} as a number of minutes between two runs")
    out: list[Need] = []
    entries = [(d.id, d.title, d.rule, d.contract, single, int(every.group(1)) * 60) for d in load_detections(filter_)]
    entries += [(c.id, c.title, c.base, c.contract, splunk_app.CORRELATION_LAG * 60, c.params.timespan)
                for c in load_correlations(filter_)]
    for det_id, title, rule, contract, allowance, period in entries:
        dc = contract.get("data_contract") or {}
        required = tuple(str(f) for f in dc.get("required_fields") or [])
        risk = dc.get("telemetry_risk") or {}
        critical = frozenset(f for f in required if str(risk.get(f"missing_{f.lower()}", "critical")).lower() == "critical")
        ids = tuple(sorted(doctor.rule_event_ids(rule), key=lambda i: (len(i), i)))
        scopes = {k: frozenset(v) for k, v in doctor.field_event_ids(rule).items()}
        out.append(Need(det_id, title, logsource_key(rule), ids, required, scopes, critical, allowance,
                        f"{splunk_app.ALERT_PREFIX}{det_id}", period))
    return out


def feed_fields(wanted: list[Need]) -> dict[str, list[str]]:
    """feed -> the fields the library reads on it, in first-seen order."""
    out: dict[str, list[str]] = {}
    for n in wanted:
        for feed in n.feeds:
            bucket = out.setdefault(feed, [])
            bucket += [f for f in n.fields if n.reads(feed, f) and f not in bucket]
    return out


def feed_detections(wanted: list[Need]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for n in wanted:
        for feed in n.feeds:
            out.setdefault(feed, []).append(n.detection)
    return out


# --------------------------------------------------------------------------- #
# measuring an export
# --------------------------------------------------------------------------- #
@dataclass
class Flow:
    """What one host sent of one kind of event."""
    events: int = 0
    first: datetime | None = None
    last: datetime | None = None
    hours: dict = field(default_factory=dict)       # hour of the week (Monday 00:00 is 0) -> events


@dataclass
class Feed:
    events: int = 0
    hosts: dict[str, Flow] = field(default_factory=dict)
    present: Counter = field(default_factory=Counter)      # field -> events that carry it
    names: set = field(default_factory=set)                 # field names seen on these events
    carriers: Counter = field(default_factory=Counter)      # channel -> events it carried
    cut: int | None = None               # the length command lines pile up at, when they do


@dataclass
class Measure:
    start: datetime | None = None
    end: datetime | None = None
    events: int = 0
    undated: int = 0
    profile: str = profiles.NATIVE
    feeds: dict[str, Feed] = field(default_factory=dict)
    carriers: dict[str, dict[str, Flow]] = field(default_factory=dict)
    hosts: set = field(default_factory=set)
    lags: dict[str, list] = field(default_factory=dict)     # "channel|host" -> seconds from each event to its arrival
    lag: dict[str, dict] = field(default_factory=dict)      # their summary: n, p50, p95 (all a saved baseline keeps)
    _occurrences: list | None = None

    @property
    def hours(self) -> float:
        if not self.start or not self.end:
            return 0.0
        return max((self.end - self.start).total_seconds() / 3600, 1 / 60)

    @property
    def occurrences(self) -> list[float]:
        if self._occurrences is None:
            self._occurrences = occurrences(self.start, self.end) if self.start and self.end else [0.0] * WEEK
        return self._occurrences


def occurrences(start: datetime, end: datetime) -> list[float]:
    """How often each hour of the week occurs between two moments, the part hours at both ends counted as parts."""
    out = [0.0] * WEEK
    t = start
    while t < end:
        nxt = min(end, t.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1))
        out[t.weekday() * 24 + t.hour] += (nxt - t).total_seconds() / 3600
        t = nxt
    return out


def rates(flow: Flow, base: Measure) -> list[float]:
    """Events per hour the baseline shows at each hour of the week: read by hour of the week when the
    baseline spans one, by hour of the day when it is shorter."""
    occ = base.occurrences
    if base.hours >= WEEK:
        return [flow.hours.get(b, 0) / occ[b] if occ[b] else 0.0 for b in range(WEEK)]
    by_day = []
    for hour in range(24):
        span = sum(occ[day * 24 + hour] for day in range(7))
        by_day.append(sum(flow.hours.get(day * 24 + hour, 0) for day in range(7)) / span if span else 0.0)
    return [by_day[b % 24] for b in range(WEEK)]


def expected(flow: Flow, base: Measure, start: datetime, end: datetime) -> float:
    """Events the baseline saw of this flow over the same hours as the stretch from start to end."""
    if end <= start:
        return 0.0
    per_hour = rates(flow, base)
    return sum(r * o for r, o in zip(per_hour, occurrences(start, end), strict=True))


def short(host: object) -> str:
    text = str(host or "").strip()
    return text.lower() if re.fullmatch(r"[0-9a-fA-F:.]+", text) else text.split(".")[0].lower()


def to_time(value: object) -> datetime | None:
    """A timestamp as naive UTC: ISO 8601 text, or seconds since 1970 (Splunk's _time and _indextime)."""
    epoch = isinstance(value, (int, float)) and not isinstance(value, bool)
    if isinstance(value, str):
        if not value.strip():
            return None
        if not re.fullmatch(r"\d{9,11}(\.\d+)?", value.strip()):
            return parse_time({"TimeCreated": value})
        epoch = True
    if not epoch:
        return None
    number = float(value)      # type: ignore[arg-type]
    try:
        return datetime.fromtimestamp(number, tz=timezone.utc).replace(tzinfo=None)
    except (OverflowError, OSError, ValueError):
        return None


def event_time(flat: dict) -> datetime | None:
    for name in TIME_FIELDS:
        when = to_time(flat.get(name))
        if when:
            return when
    return None


def _quantile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, round(q * (len(ordered) - 1))))]


def lag_summary(lags: list[float]) -> dict | None:
    if not lags:
        return None
    return {"n": len(lags), "p50": round(_quantile(lags, 0.5), 1), "p95": round(_quantile(lags, 0.95), 1)}


def _flows(times: dict[str, list[datetime]]) -> dict[str, Flow]:
    out = {}
    for host, stamps in times.items():
        by_hour = Counter(t.weekday() * 24 + t.hour for t in stamps)
        out[host] = Flow(len(stamps), min(stamps), max(stamps), dict(sorted(by_hour.items())))
    return out


def measure(events: list[dict], wanted: list[Need], profile: str = profiles.NATIVE, until: datetime | None = None) -> Measure:
    """Count what an export holds of everything the library reads. until: when the export was taken, if
    later than its newest event (a pipeline that stopped an hour before is silent for that hour)."""
    by_id: dict[str, set[str]] = {}
    whole: set[str] = set()
    for n in wanted:
        if n.ids:
            by_id.setdefault(n.source, set()).update(n.ids)
        else:
            whole.add(n.source)
    fields = feed_fields(wanted)
    m = Measure(profile=profile)
    feed_times: dict[str, dict[str, list[datetime]]] = {}
    carrier_times: dict[str, dict[str, list[datetime]]] = {}
    lengths: dict[str, Counter] = {}
    for ev in events:
        flat = doctor.flatten(ev)
        when = event_time(flat)
        if when is None:
            m.undated += 1
            continue
        m.events += 1
        m.start = when if m.start is None or when < m.start else m.start
        m.end = when if m.end is None or when > m.end else m.end
        host = short(next((flat[f] for f in HOST_FIELDS if flat.get(f)), "")) or "-"
        m.hosts.add(host)
        src = route(ev) or route({k.split(".")[-1]: v for k, v in flat.items()})
        channel = str(flat.get("Channel") or "").strip().lower() or (src or "")
        if channel:
            carrier_times.setdefault(channel, {}).setdefault(host, []).append(when)
        if not src:
            continue
        eid = str(flat.get("EventID", flat.get("event.code", "")))
        keys = ([src] if src in whole else []) + ([f"{src}#{eid}"] if eid in by_id.get(src, ()) else [])
        arrived = next((to_time(flat[f]) for f in INGEST_FIELDS if flat.get(f) is not None), None) if keys else None
        if arrived:
            m.lags.setdefault(f"{channel}|{host}", []).append((arrived - when).total_seconds())
        for key in keys:
            feed = m.feeds.setdefault(key, Feed())
            feed.events += 1
            feed.carriers[channel] += 1
            feed_times.setdefault(key, {}).setdefault(host, []).append(when)
            for name in fields.get(key, []):
                if doctor.present(flat.get(name)):
                    feed.present[name] += 1
            if len(feed.names) < NAMES_KEPT:
                feed.names.update(k for k in flat if doctor.present(flat[k]))
            command = flat.get("CommandLine")
            if isinstance(command, str):
                lengths.setdefault(key, Counter())[len(command)] += 1
    if m.start is None or m.end is None:
        return m
    if until and until > m.end:
        m.end = until
    for key, per_host in feed_times.items():
        feed = m.feeds[key]
        feed.hosts = _flows(per_host)
        seen = lengths.get(key)
        if seen:
            total = sum(seen.values())
            piled = [(seen[length], length) for length in doctor.TRUNCATION_LENGTHS if seen.get(length, 0) >= max(3, 0.02 * total)]
            feed.cut = max(piled)[1] if piled else None
    m.carriers = {channel: _flows(per_host) for channel, per_host in carrier_times.items()}
    m.lag = {key: summary for key, summary in ((k, lag_summary(v)) for k, v in sorted(m.lags.items())) if summary}
    return m


# --------------------------------------------------------------------------- #
# the baseline profile: what a week looked like, without its events
# --------------------------------------------------------------------------- #
def _iso(t: datetime | None) -> str | None:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ") if t else None


def _flow_out(flows: dict[str, Flow]) -> dict:
    return {h: {"events": f.events, "first": _iso(f.first), "last": _iso(f.last), "hours": {str(b): n for b, n in f.hours.items()}}
            for h, f in sorted(flows.items())}


def _flow_in(doc: dict) -> dict[str, Flow]:
    return {h: Flow(int(f["events"]), to_time(f.get("first")), to_time(f.get("last")),
                    {int(b): int(n) for b, n in (f.get("hours") or {}).items()})
            for h, f in doc.items()}


def to_baseline(m: Measure) -> dict:
    return {"rasd_health_baseline": FORMAT, "start": _iso(m.start), "end": _iso(m.end), "events": m.events,
            "profile": m.profile, "hosts": sorted(m.hosts),
            "feeds": {key: {"events": f.events, "hosts": _flow_out(f.hosts), "present": dict(sorted(f.present.items())),
                            "names": sorted(f.names), "carriers": dict(sorted(f.carriers.items())), "cut": f.cut}
                      for key, f in sorted(m.feeds.items())},
            "carriers": {channel: _flow_out(flows) for channel, flows in sorted(m.carriers.items())},
            "lag": m.lag}


def from_baseline(doc: dict) -> Measure:
    try:
        if doc.get("rasd_health_baseline") != FORMAT:
            raise KeyError("rasd_health_baseline")
        m = Measure(to_time(doc["start"]), to_time(doc["end"]), int(doc["events"]), 0, str(doc.get("profile") or profiles.NATIVE))
        m.hosts = set(doc.get("hosts") or [])
        for key, f in (doc.get("feeds") or {}).items():
            m.feeds[key] = Feed(int(f["events"]), _flow_in(f.get("hosts") or {}), Counter(f.get("present") or {}),
                                set(f.get("names") or []), Counter(f.get("carriers") or {}), f.get("cut"))
            if any(not 0 <= b < WEEK for flow in m.feeds[key].hosts.values() for b in flow.hours):
                raise ValueError("an hour of the week outside 0-167")
        m.carriers = {channel: _flow_in(flows) for channel, flows in (doc.get("carriers") or {}).items()}
        m.lag = {str(key): {"n": int(x["n"]), "p50": float(x["p50"]), "p95": float(x["p95"])}
                 for key, x in (doc.get("lag") or {}).items()}
    except (KeyError, TypeError, ValueError, AttributeError) as e:
        raise HealthError(f"not a baseline written by --save-baseline ({e})") from e
    if m.start is None or m.end is None:
        raise HealthError("the baseline has no time span")
    return m


def is_baseline(path: Path) -> bool:
    if path.suffix.lower() != ".json":
        return False
    try:
        doc = json.loads(read_text(path))
    except (OSError, ValueError):
        return False
    return isinstance(doc, dict) and "rasd_health_baseline" in doc


def load(paths: list[Path], wanted: list[Need], profile: str | None, until: datetime | None = None) -> Measure:
    """A baseline profile, or one or more exports measured now."""
    for p in paths:
        if not p.exists():
            raise HealthError(f"{p}: not found")
    saved = [p for p in paths if is_baseline(p)]
    if saved:
        if len(paths) > 1:
            raise HealthError("a saved baseline stands alone: give one, or the exports to measure")
        return from_baseline(json.loads(read_text(saved[0])))
    raw = [e for p in paths for e in load_jsonl(p)]
    events, used = profiles.apply(raw, profile)
    return measure(events, wanted, used, until)


# --------------------------------------------------------------------------- #
# the SIEM's own record of scheduled runs
# --------------------------------------------------------------------------- #
def read_scheduler(path: Path) -> dict[str, dict]:
    """search name -> runs, the ones that did not complete, and the commonest reason."""
    if not path.exists():
        raise HealthError(f"{path}: not found")
    if path.suffix.lower() == ".csv":
        with path.open(encoding="utf-8-sig", newline="") as fh:
            rows: list[dict] = list(csv.DictReader(fh))
    else:
        rows = load_jsonl(path)
    out: dict[str, dict] = {}
    for row in rows:
        name = next((str(row[f]) for f in RUN_NAME if row.get(f)), "")
        status = next((str(row[f]).strip().lower() for f in RUN_STATUS if row.get(f)), "")
        if not name or not status:
            continue
        entry = out.setdefault(name, {"runs": 0, "bad": 0, "reasons": Counter()})
        entry["runs"] += 1
        if status in RUN_BAD:
            entry["bad"] += 1
            reason = next((str(row[f]) for f in RUN_REASON if row.get(f)), status)
            entry["reasons"][reason] += 1
    return out


# --------------------------------------------------------------------------- #
# the verdict
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    check: str
    level: str                           # blind | degraded | note
    text: str
    fix: str | None = None


@dataclass
class Verdict:
    detection: str
    verdict: str
    feeds: tuple[str, ...]
    findings: list[Finding] = field(default_factory=list)


def human(seconds: float) -> str:
    seconds = abs(seconds)
    if seconds < 90:
        return f"{seconds:.0f} s"
    if seconds < 5400:
        return f"{seconds / 60:.0f} min"
    if seconds < 172800:
        return f"{seconds / 3600:.1f} h"
    return f"{seconds / 86400:.1f} d"


def listed(names: list[str], limit: int = 4) -> str:
    names = sorted(names)
    return ", ".join(names[:limit]) + (f" and {len(names) - limit} more" if len(names) > limit else "")


def label(feed: str) -> str:
    source, _, eid = feed.partition("#")
    return f"{source} event {eid}" if eid else source


def quiet_hosts(flows: dict[str, Flow], seen: dict[str, Flow], base: Measure, cur: Measure,
                only: set[str] | None = None) -> dict[str, tuple[datetime | None, float]]:
    """Hosts of the baseline that have sent nothing over a stretch in which the baseline, at the same hours,
    saw enough events for the emptiness to mean something: host -> (its last event in the export, the events
    the baseline saw over those hours)."""
    out: dict[str, tuple[datetime | None, float]] = {}
    if cur.start is None or cur.end is None:
        return out
    for host, flow in flows.items():
        if only is not None and host not in only:
            continue
        now = seen.get(host)
        since = now.last if now and now.last else cur.start
        missing = expected(flow, base, since, cur.end)
        if missing >= MIN_EXPECTED:
            out[host] = (now.last if now else None, missing)
    return out


def channel_of(feed: str, base: Measure) -> str | None:
    """The channel that carries a feed in the baseline: its own events' when it has any, else the one its
    log source's other events came through (a cleared Security log is carried by the Security channel)."""
    own = base.feeds.get(feed)
    if own and own.carriers:
        return own.carriers.most_common(1)[0][0]
    source = feed.partition("#")[0]
    siblings: Counter = Counter()
    for key, other in base.feeds.items():
        if key.partition("#")[0] == source:
            siblings.update(other.carriers)
    return siblings.most_common(1)[0][0] if siblings else None


def _silence(feed: str, quiet: dict, total: int, cur: Measure) -> Finding:
    gone = sorted(h for h in quiet if h not in cur.hosts)
    there = sorted(h for h in quiet if h in cur.hosts)
    everywhere = len(quiet) == total
    parts = []
    if gone:
        parts.append(f"{listed(gone)} send{'s' if len(gone) == 1 else ''} nothing at all")
    if there:
        stamp = quiet[there[0]][0] if len(there) == 1 else None
        parts.append(f"{listed(there)} still send{'s' if len(there) == 1 else ''} other events, and none of this kind"
                     + (f" since {stamp:%Y-%m-%d %H:%M}" if stamp else ""))
    missing = sum(m for _last, m in quiet.values())
    return Finding(
        "silent", "blind" if everywhere else "degraded",
        f"{label(feed)}: {'every host that sent it is silent' if everywhere else f'{len(quiet)} of {total} hosts silent'} "
        f"({'; '.join(parts)}); the baseline saw about {missing:.0f} events over the same hours",
        "the host is down or its forwarder stopped" if gone and not there else
        "the log is no longer written or no longer shipped: the sensor's service and configuration, then the forwarder's inputs")


def judge(n: Need, base: Measure, cur: Measure, scheduler: dict[str, dict] | None = None) -> Verdict:
    v = Verdict(n.detection, "healthy", n.feeds)
    if cur.start is None or cur.end is None or base.start is None:
        v.verdict = "unknown"
        v.findings.append(Finding("note", "note", "the export has no dated event"))
        return v
    known = [f for f in n.feeds if base.feeds.get(f) and base.feeds[f].events]
    empty = Feed()
    comparable = 0                       # feeds the baseline lets us judge, by their own events or their channel's
    blind_feeds = 0
    for feed in n.feeds:
        channel = channel_of(feed, base)
        carried = base.carriers.get(channel or "", {})
        if feed not in known:
            if not carried:
                continue
            comparable += 1
            quiet = quiet_hosts(carried, cur.carriers.get(channel or "", {}), base, cur)
            v.findings.append(Finding("note", "note", f"{label(feed)}: never seen in the baseline; judged by its channel, "
                                                      f"{channel} ({len(carried)} hosts)"))
            if quiet:
                v.findings.append(_silence(feed, quiet, len(carried), cur))
                blind_feeds += len(quiet) == len(carried)
            continue
        comparable += 1
        b, c = base.feeds[feed], cur.feeds.get(feed, empty)
        # hosts whose own events are frequent enough to be judged by; the others are judged by their channel
        judged = {h for h, flow in b.hosts.items() if expected(flow, base, cur.start, cur.end) >= MIN_EXPECTED}
        thin = set(b.hosts) - judged
        quiet = quiet_hosts(b.hosts, c.hosts, base, cur, judged)
        if thin and carried:
            quiet.update(quiet_hosts(carried, cur.carriers.get(channel or "", {}), base, cur, thin))
        if quiet:
            v.findings.append(_silence(feed, quiet, len(b.hosts), cur))
            blind_feeds += len(quiet) == len(b.hosts)
        elif thin and not judged:
            v.findings.append(Finding("note", "note", f"{label(feed)}: too rare to judge by its own volume ({b.events} in the "
                                                      f"baseline); judged by its channel, {channel or 'which the baseline does not name'}"))
        steady = [h for h in b.hosts if h not in quiet]
        saw = sum(expected(b.hosts[h], base, cur.start, cur.end) for h in steady)
        now = sum(c.hosts[h].events for h in steady if h in c.hosts)
        if steady and saw >= MIN_VOLUME and now < DROP * saw:
            v.findings.append(Finding(
                "volume", "degraded",
                f"{label(feed)}: {now} events where the baseline saw about {saw:.0f} over the same hours "
                f"({100 * now / saw:.0f}%), on the hosts still sending",
                "a filter, a sampling rule or a license limit upstream: compare the sensor's configuration with the baseline's"))
    for name in n.fields:
        pool = [f for f in known if n.reads(f, name)]
        base_total = sum(base.feeds[f].events for f in pool)
        cur_total = sum(cur.feeds[f].events for f in pool if f in cur.feeds)
        if not base_total or not cur_total:
            continue
        was = 100 * sum(base.feeds[f].present.get(name, 0) for f in pool) / base_total
        filled = 100 * sum(cur.feeds[f].present.get(name, 0) for f in pool if f in cur.feeds) / cur_total
        if was >= LOST_FROM and filled == 0:
            new = (set().union(*(cur.feeds[f].names for f in pool if f in cur.feeds))
                   - set().union(*(base.feeds[f].names for f in pool)))
            alias = next((a for a in doctor.ALIASES.get(name, []) if a in new), None)
            v.findings.append(Finding(
                "fields", "blind" if name in n.critical else "degraded",
                f"field {name} is in none of {cur_total} events (the baseline filled it in {was:.0f}%)"
                + (f": the same events now carry {alias}" if alias else
                   f"; names that appeared since the baseline: {listed(sorted(new), 3)}" if new else ""),
                f"map {alias} to {name} (a profile in profiles/, or a field alias in the SIEM)" if alias else
                "the parser or the add-on changed: restore the extraction of this field"))
        elif was - filled >= FIELD_DROP:
            v.findings.append(Finding("fields", "degraded",
                                      f"field {name} is filled in {filled:.0f}% of events (the baseline: {was:.0f}%)",
                                      "some hosts or one pipeline stopped sending it: rasd doctor names the events without it"))
    if "CommandLine" in n.fields:
        for feed in known:
            cut = cur.feeds[feed].cut if feed in cur.feeds else None
            if cut and cut != base.feeds[feed].cut:
                v.findings.append(Finding("truncation", "degraded",
                                          f"{label(feed)}: command lines are cut at {cut} characters, which the baseline's were not: "
                                          "whatever the rule matches after that length is gone",
                                          "raise the truncation limit of the collector or the index (TRUNCATE in props.conf)"))
    # delay is a property of what ships the events: one host's channel, whatever the event ids on it
    senders = sorted({f"{cur.feeds[f].carriers.most_common(1)[0][0]}|{host}" for f in n.feeds if f in cur.feeds
                      for host in cur.feeds[f].hosts if cur.feeds[f].carriers})
    shares = {key: sum(1 for lag in cur.lags[key] if lag > n.allowance) / len(cur.lags[key])
              for key in senders if len(cur.lags.get(key, [])) >= MIN_LAGS}
    for key, late in shares.items():
        if late < LATE[0]:
            continue
        channel, _, host = key.partition("|")
        before = base.lag.get(key)
        v.findings.append(Finding(
            "delay", "blind" if all(share >= LATE[1] for share in shares.values()) else "degraded",
            f"{channel} from {host}: {100 * late:.0f}% of its events reach the index more than {human(n.allowance)} after they "
            f"happen (95% within {human(_quantile(cur.lags[key], 0.95))}" + (f"; the baseline: {human(before['p95'])}" if before else "")
            + f"): the scheduled search reads each slice {human(n.allowance)} after it closes and never sees them",
            "a forwarder backlog or a clock that is off: fix it, or give the searches a longer wait"))
    if scheduler is not None:
        runs = scheduler.get(n.search)
        if runs is None:
            v.findings.append(Finding("schedule", "blind", f"no run of '{n.search}' in the scheduler's record",
                                      "the search is disabled or missing: reinstall the app's saved searches"))
        elif runs["bad"] / runs["runs"] >= SKIPPED[0]:
            reason = runs["reasons"].most_common(1)[0][0] if runs["reasons"] else ""
            v.findings.append(Finding(
                "schedule", "blind" if runs["bad"] / runs["runs"] >= SKIPPED[1] else "degraded",
                f"{runs['bad']} of {runs['runs']} scheduled runs did not complete" + (f" ({reason})" if reason else "")
                + ": the slices they were to read were never searched",
                "the scheduler is over its concurrency limit: stagger the schedules or raise the limit"))
    hard = [f for f in v.findings if f.level == "blind" and f.check != "silent"]
    if hard or (comparable and blind_feeds == comparable):
        v.verdict = "blind"                  # a silent feed blinds the rule only when every feed it reads is silent
    elif any(f.level in ("blind", "degraded") for f in v.findings):
        v.verdict = "degraded"
    elif not comparable:
        v.verdict = "unknown"
        v.findings.append(Finding("note", "note", f"the baseline has no {' or '.join(label(f) for f in n.feeds)}: nothing to compare "
                                                  "(rasd doctor says whether it is collected at all)"))
    return v


def assess(base: Measure, cur: Measure, wanted: list[Need], scheduler: dict[str, dict] | None = None) -> list[Verdict]:
    return sorted((judge(n, base, cur, scheduler) for n in wanted), key=lambda v: (ORDER[v.verdict], v.detection))


def to_json(base: Measure, cur: Measure, verdicts: list[Verdict]) -> dict:
    return {"rasd_health": FORMAT,
            "baseline": {"start": _iso(base.start), "end": _iso(base.end), "events": base.events, "hosts": len(base.hosts)},
            "current": {"start": _iso(cur.start), "end": _iso(cur.end), "events": cur.events, "hosts": len(cur.hosts),
                        "profile": cur.profile},
            "summary": dict(Counter(v.verdict for v in verdicts)),
            "detections": [{"detection": v.detection, "verdict": v.verdict, "feeds": list(v.feeds),
                            "findings": [{"check": f.check, "level": f.level, "text": f.text, "fix": f.fix} for f in v.findings]}
                           for v in verdicts]}


def causes(verdicts: list[Verdict]) -> list[tuple[Finding, list[tuple[str, str]]]]:
    """Each thing that broke, once, with the detections it takes with it and how far: the worst first."""
    seen: dict[tuple[str, str], tuple[Finding, list[tuple[str, str]]]] = {}
    for v in verdicts:
        for f in v.findings:
            if f.level != "note":
                seen.setdefault((f.check, f.text), (f, []))[1].append((v.detection, f.level))
    return sorted(seen.values(), key=lambda entry: (min(ORDER[level] for _d, level in entry[1]), CHECKS.index(entry[0].check),
                                                    entry[0].text))


def show(base: Measure, cur: Measure, verdicts: list[Verdict], detail: bool = False) -> None:
    colour = {"healthy": GREEN, "degraded": YELLOW, "blind": RED, "unknown": DIM}
    print(f"{BOLD}RASD-Health · baseline {human(base.hours * 3600)} ({base.events} events, {len(base.hosts)} hosts) → "
          f"current {human(cur.hours * 3600)} ({cur.events} events, {len(cur.hosts)} hosts) · profile {cur.profile}{RESET}\n")
    broke = causes(verdicts)
    if broke:
        print(f"{BOLD}What broke, and what it takes with it{RESET}")
        for f, touched in broke:
            worst = min((level for _d, level in touched), key=ORDER.__getitem__)
            print(f"  {colour[worst]}{f.check:<10}{RESET} {f.text}")
            if f.fix:
                print(f"  {'':<10} {DIM}→ {f.fix}{RESET}")
            for level in ("blind", "degraded"):
                names = [d for d, lv in touched if lv == level]
                if names:
                    print(f"  {'':<10} {colour[level]}{level.upper()}{RESET} {', '.join(names)}")
        print()
    print(f"{BOLD}Verdicts{RESET}")
    for v in verdicts:
        checks = list(dict.fromkeys(f.check for f in v.findings if f.level != "note"))
        print(f"  {colour[v.verdict]}{v.verdict.upper():<9}{RESET} {v.detection:<48} {DIM}{', '.join(checks)}{RESET}")
        if detail or v.verdict == "unknown":
            for f in v.findings:
                if f.level == "note":
                    print(f"            {DIM}{f.text}{RESET}")
    tally = Counter(v.verdict for v in verdicts)
    print(f"\n{BOLD}{tally.get('blind', 0)} blind · {tally.get('degraded', 0)} degraded · {tally.get('healthy', 0)} healthy · "
          f"{tally.get('unknown', 0)} unknown{RESET}")
    if cur.undated:
        print(f"{DIM}{cur.undated} events without a readable time were left out{RESET}")


# --------------------------------------------------------------------------- #
# the watchdogs: the same watch, kept inside the SIEM
# --------------------------------------------------------------------------- #
SPL_SAFE = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*")
WATCHDOGS = {
    "silent": ("hourly", "7 * * * *",
               "A host that reported in most hours of the past week has sent nothing on a channel for four hours."),
    "volume": ("daily", "13 6 * * *",
               "A host sent, in the last day, none or under a quarter of what it sent on the same day a week earlier, "
               "of an event the rules read."),
    "fields": ("daily", "23 6 * * *", "A field the rules read is filled in under 95% of the events that should carry it."),
    "delay": ("hourly", "17 * * * *",
              "Events indexed in the last hour arrived later than the scheduled searches wait."),
    # two minutes after the half hour: every search has had a slot since the app was loaded, unless that was two minutes ago
    "schedule": ("hourly", "32 * * * *", "A scheduled detection search did not run, or was skipped."),
}
HEALTH_PREFIX = "RASD Health - "


def _spl_field(name: str) -> str:
    mapped = str((MAPPINGS["spl"].get("fields") or {}).get(name, name))
    if not SPL_SAFE.fullmatch(mapped) or mapped in ("events", "reads", "low", "feed", "blinds"):
        raise ValueError(f"field {name} maps to {mapped}, which a watchdog cannot name as it is")
    return mapped


def _kql_field(name: str) -> str:
    return str((MAPPINGS["kql"].get("fields") or {}).get(name, name))


def _sources(wanted: list[Need]) -> dict[str, dict]:
    """log source -> the event ids read there, whether some rule reads every event, its detections."""
    out: dict[str, dict] = {}
    for n in wanted:
        entry = out.setdefault(n.source, {"ids": set(), "whole": False, "detections": []})
        entry["ids"].update(n.ids)
        entry["whole"] = entry["whole"] or not n.ids
        entry["detections"].append(n.detection)
    return dict(sorted(out.items()))


def _numeric(ids: set[str]) -> list[str]:
    return sorted(ids, key=lambda i: (len(i), i))


def _plain(text: str) -> str:
    """A literal as a regular expression: itself when it holds nothing a pattern reads."""
    return text if re.fullmatch(r"[A-Za-z0-9 _-]*", text) else re.escape(text)


def _spl_case(pairs: list[tuple[str, str]], subject: str) -> str:
    return "case(" + ", ".join(f'{subject}=="{key}", "{value}"' for key, value in pairs) + ")"


def spl_carriers(wanted: list[Need]) -> list[tuple[str, str, list[str]]]:
    """(name, the indexed terms that select the channel, detections): the channel under each log source."""
    carriers: dict[str, tuple[str, list[str]]] = {}
    names = (MAPPINGS.get("health") or {}).get("carriers") or {}
    for source, info in _sources(wanted).items():
        base = " ".join(str(MAPPINGS["spl"]["logsources"][source]).split())
        clause = re.sub(r"\s+Event(?:Code|ID)=\d+", "", base)
        name = str(names.get(source, source))
        known = carriers.setdefault(clause, (name, []))
        known[1].extend(d for d in info["detections"] if d not in known[1])
    return [(name, clause, sorted(dets)) for clause, (name, dets) in carriers.items()]


def _carrier_test(clause: str) -> str:
    terms = re.findall(r'(\w+)=("[^"]*"|\S+)', clause)
    return " AND ".join(f'{key}=="{value.strip(chr(34))}"' for key, value in terms)


def spl_feeds(wanted: list[Need], window: str, mark: str = "") -> list[str]:
    """One streaming subsearch per log source, each event labelled with the feed it belongs to."""
    eid = _spl_field("EventID")
    legs = []
    for source, info in _sources(wanted).items():
        base = " ".join(str(MAPPINGS["spl"]["logsources"][source]).split())
        if info["whole"] or not info["ids"]:
            legs.append(f'[search {base} {window} | eval feed="{source}"{mark}]')
        if info["ids"]:
            legs.append(f'[search {base} {eid} IN ({", ".join(_numeric(info["ids"]))}) {window} | eval feed="{source}#".{eid}{mark}]')
    return legs


def spl_watchdogs(wanted: list[Need]) -> dict[str, str]:
    import splunk_app
    carriers = spl_carriers(wanted)
    where = " OR ".join(f"({clause})" for _name, clause, _dets in carriers)
    carrier = "case(" + ", ".join(f'{_carrier_test(clause)}, "{name}"' for name, clause, _dets in carriers) + ")"
    carrier_blinds = _spl_case([(name, ", ".join(dets)) for name, _clause, dets in carriers], "carrier")
    feed_blinds = _spl_case([(feed, ", ".join(dets)) for feed, dets in sorted(feed_detections(wanted).items())], "feed")
    fields = feed_fields(wanted)
    every = sorted({_spl_field(f) for names in fields.values() for f in names})
    reads = _spl_case([(feed, ",".join(_spl_field(f) for f in names)) for feed, names in sorted(fields.items())], "feed")
    allowance = _minutes(splunk_app.WINDOW_END) * 60
    settle = max((n.period for n in wanted), default=300) + allowance      # every search has had a slot, and its wait
    out = {}
    out["silent"] = "\n".join([
        f"| tstats count where ({where}) earliest=-7d@h latest=@h by index, sourcetype, source, host, _time span=1h",
        f"| eval carrier={carrier}",
        "| where isnotnull(carrier)",
        "| stats sum(count) as events by carrier, host, _time",
        "| stats count as active_hours, max(_time) as last_hour, sum(events) as events_7d by carrier, host",
        '| eval quiet_hours=round((relative_time(now(), "@h") - last_hour) / 3600) - 1',
        "| where active_hours >= 84 AND quiet_hours >= 4",
        f'| eval last_seen=strftime(last_hour, "%Y-%m-%d %H:%M"), blinds={carrier_blinds}',
        "| table carrier, host, quiet_hours, last_seen, active_hours, events_7d, blinds"])
    out["volume"] = "\n".join([
        "| multisearch",
        *(f"    {leg}" for leg in spl_feeds(wanted, "earliest=-24h@h latest=@h", ', period="now"')),
        *(f"    {leg}" for leg in spl_feeds(wanted, "earliest=-8d@h latest=-7d@h", ', period="week_ago"')),
        '| stats count(eval(period=="now")) as last_24h, count(eval(period=="week_ago")) as week_ago by feed, host',
        f'| eval state=case(week_ago >= {MIN_EXPECTED} AND last_24h == 0, "silent", '
        f'week_ago >= {MIN_VOLUME} AND last_24h < {DROP} * week_ago, "volume fell")',
        "| where isnotnull(state)",
        f"| eval blinds={feed_blinds}",
        "| table feed, host, state, last_24h, week_ago, blinds"])
    out["fields"] = "\n".join([
        "| multisearch",
        *(f"    {leg}" for leg in spl_feeds(wanted, "earliest=-24h latest=now")),
        "| stats count as events, " + ", ".join(f"count({f}) as {f}" for f in every) + " by feed",
        f"| eval reads={reads}",
        "| foreach " + " ".join(every) + " [eval low=if(like(\",\" . reads . \",\", \"%,<<FIELD>>,%\") AND '<<FIELD>>' < 0.95 * events, "
        "mvappend(low, \"<<FIELD>> \" . round(100 * '<<FIELD>>' / events) . \"%\"), low)]",
        "| where isnotnull(low)",
        f"| eval blinds={feed_blinds}",
        "| table feed, events, low, blinds"])
    out["delay"] = "\n".join([
        f"({where}) _index_earliest=-60m@m _index_latest=@m earliest=-7d@d latest=+1d@d",
        f"| eval lag=_indextime - _time, carrier={carrier}",
        "| where isnotnull(carrier)",
        f"| stats count as events, count(eval(lag > {allowance})) as late, perc95(lag) as p95_lag by carrier, host",
        # A channel Splunk first heard from within the hour brings its backlog first, days old on a host that was
        # logging before Splunk read it: true of every new host, and no fault of the pipeline. It is judged from
        # the next hour on. The lab's own Splunk named the Security and System logs of its host this way.
        f"| append [| tstats min(_indextime) as first_heard where ({where}) earliest=-7d@d latest=+1d@d "
        f"by index, sourcetype, source, host | eval carrier={carrier} | where isnotnull(carrier) "
        "| stats min(first_heard) as first_heard by carrier, host]",
        "| stats max(events) as events, max(late) as late, max(p95_lag) as p95_lag, min(first_heard) as first_heard by carrier, host",
        '| where isnotnull(events) AND (isnull(first_heard) OR first_heard < relative_time(now(), "-60m@m"))',
        "| eval late_pct=round(100 * late / events, 1), p95_lag=round(p95_lag)",
        f"| where late_pct >= {100 * LATE[0]:g}",
        f"| eval blinds={carrier_blinds}",
        "| table carrier, host, events, late, late_pct, p95_lag, blinds"])
    out["schedule"] = "\n".join([
        # Read up to now, not to the last full hour, and do not name a search that has no run yet while Splunk has
        # been up for less than the longest schedule: on a Splunk started within the hour, the first form of this
        # search named every detection as one that did not run. The lab's own Splunk showed it.
        f'index=_internal sourcetype=scheduler savedsearch_name="{splunk_app.ALERT_PREFIX}T*" earliest=-24h latest=now',
        '| stats count as runs, count(eval(status=="success")) as succeeded, count(eval(status=="skipped")) as skipped, '
        'max(eval(if(status=="success", _time, null()))) as last_success by savedsearch_name',
        f'| append [| rest /servicesNS/-/-/saved/searches splunk_server=local | search title="{splunk_app.ALERT_PREFIX}T*" '
        "is_scheduled=1 disabled=0 | rename title as savedsearch_name | fields savedsearch_name | eval listed=1]",
        "| stats max(runs) as runs, max(succeeded) as succeeded, max(skipped) as skipped, max(last_success) as last_success, "
        "max(listed) as listed by savedsearch_name",
        "| fillnull value=0 runs succeeded skipped listed",
        "| appendcols [| rest /services/server/info splunk_server=local | eval uptime=now() - startup_time | fields uptime]",
        "| eventstats max(uptime) as uptime",
        f"| where listed == 1 AND ((succeeded == 0 AND (runs > 0 OR coalesce(uptime, 86400) >= {settle})) "
        f"OR skipped > {SKIPPED[0]} * runs)",
        f'| eval detection=replace(savedsearch_name, "^{_plain(splunk_app.ALERT_PREFIX)}", ""), '
        'last_success=if(isnull(last_success), "none in 24 h", strftime(last_success, "%Y-%m-%d %H:%M"))',
        "| table savedsearch_name, detection, runs, succeeded, skipped, last_success"])
    return out


def _kql_case(pairs: list[tuple[str, str]], subject: str) -> str:
    return "case(" + ", ".join(f'{subject} == "{key}", "{value}"' for key, value in pairs) + ', "")'


def kql_carriers(wanted: list[Need]) -> list[dict]:
    used = set(_sources(wanted))
    out = []
    for name, spec in ((MAPPINGS.get("health") or {}).get("kql_carriers") or {}).items():
        sources = [s for s in spec.get("logsources") or [] if s in used]
        if sources:
            dets = sorted({d for n in wanted if n.source in sources for d in [n.detection]})
            out.append({"name": name, "table": " ".join(str(spec["table"]).split()), "host": spec.get("host", "Computer"),
                        "arrival": spec.get("arrival", True), "detections": dets})
    return out


def kql_feeds(wanted: list[Need], when: str, tail: str) -> list[str]:
    legs = []
    for source, info in _sources(wanted).items():
        base = " ".join(str(MAPPINGS["kql"]["logsources"][source]).split())
        host = (((MAPPINGS.get("health") or {}).get("kql_hosts")) or {}).get(source, "Computer")
        if info["whole"] or not info["ids"]:
            legs.append(f'({base} | where {when} | extend feed = "{source}", host_ = tostring({host}){tail})')
        if info["ids"]:
            legs.append(f'({base} | where ({when}) and EventID in ({", ".join(_numeric(info["ids"]))}) '
                        f'| extend feed = strcat("{source}#", tostring(EventID)), host_ = tostring({host}){tail})')
    return legs


def kql_watchdogs(wanted: list[Need]) -> dict[str, str]:
    import splunk_app
    carriers = kql_carriers(wanted)
    carrier_blinds = _kql_case([(c["name"], ", ".join(c["detections"])) for c in carriers], "carrier")
    feed_blinds = _kql_case([(feed, ", ".join(dets)) for feed, dets in sorted(feed_detections(wanted).items())], "feed")
    fields = feed_fields(wanted)
    allowance = _minutes(splunk_app.WINDOW_END)
    out = {}
    out["silent"] = "\n".join([
        "union",
        ",\n".join(f'  ({c["table"]} | where TimeGenerated > ago(7d) | project TimeGenerated, carrier = "{c["name"]}", '
                   f'host_ = tostring({c["host"]}))' for c in carriers),
        "| summarize active_hours = dcount(bin(TimeGenerated, 1h)), last_seen = max(TimeGenerated), events_7d = count() by carrier, host_",
        '| extend quiet_hours = datetime_diff("hour", now(), last_seen)',
        "| where active_hours >= 84 and quiet_hours >= 4",
        f"| extend blinds = {carrier_blinds}",
        "| project carrier, host = host_, quiet_hours, last_seen, active_hours, events_7d, blinds"])
    out["volume"] = "\n".join([
        "union",
        ",\n".join(f"  {leg}" for leg in kql_feeds(wanted, "TimeGenerated > ago(24h) or TimeGenerated between (ago(8d) .. ago(7d))",
                                                  " | project TimeGenerated, feed, host_")),
        "| summarize last_24h = countif(TimeGenerated > ago(24h)), week_ago = countif(TimeGenerated <= ago(7d)) by feed, host_",
        f'| extend state = case(week_ago >= {MIN_EXPECTED} and last_24h == 0, "silent", '
        f'week_ago >= {MIN_VOLUME} and last_24h < {DROP} * week_ago, "volume fell", "")',
        "| where isnotempty(state)",
        f"| extend blinds = {feed_blinds}",
        "| project feed, host = host_, state, last_24h, week_ago, blinds"])
    legs = []
    for source, info in _sources(wanted).items():
        names = sorted({f for feed, fs in fields.items() if feed.partition("#")[0] == source for f in fs})
        if not names:
            continue
        columns = [_kql_field(f) for f in names]
        base = " ".join(str(MAPPINGS["kql"]["logsources"][source]).split())
        extend = " ".join(kql_eventdata({"detection": {"selection": dict.fromkeys(names, "x")}}, source,
                                        MAPPINGS["kql"].get("fields") or {}).split())
        counts = ", ".join(f"{c}_ = countif(isnotempty({c}))" for c in columns)
        arrays = (f'field = pack_array({", ".join(chr(34) + f + chr(34) for f in names)}), '
                  f'filled = pack_array({", ".join(c + "_" for c in columns)})')
        if info["ids"]:
            legs.append(f'({base} | where TimeGenerated > ago(24h) and EventID in ({", ".join(_numeric(info["ids"]))})'
                        f'{" " + extend if extend else ""} | summarize events = count(), {counts} by EventID '
                        f'| project feed = strcat("{source}#", tostring(EventID)), events, {arrays})')
        if info["whole"] or not info["ids"]:
            legs.append(f'({base} | where TimeGenerated > ago(24h){" " + extend if extend else ""} '
                        f'| summarize events = count(), {counts} | project feed = "{source}", events, {arrays})')
    reads = _kql_case([(feed, "," + ",".join(names) + ",") for feed, names in sorted(fields.items())], "feed")
    out["fields"] = "\n".join([
        "union",
        ",\n".join(f"  {leg}" for leg in legs),
        "| mv-expand field to typeof(string), filled to typeof(long)",
        f"| extend reads = {reads}",
        '| where events > 0 and reads contains strcat(",", field, ",")',
        "| extend coverage = round(100.0 * filled / events, 1)",
        "| where coverage < 95",
        f"| extend blinds = {feed_blinds}",
        "| project feed, field, coverage, events, blinds"])
    arriving = [c for c in carriers if c["arrival"]]
    out["delay"] = "\n".join([
        "union",
        ",\n".join(f'  ({c["table"]} | where TimeGenerated > ago(8d) and ingestion_time() > ago(1h) '
                   f'| project carrier = "{c["name"]}", host_ = tostring({c["host"]}), lag = ingestion_time() - TimeGenerated)'
                   for c in arriving),
        f"| summarize events = count(), late = countif(lag > {allowance}m), p95_lag = percentile(lag, 95) by carrier, host_",
        "| extend late_pct = round(100.0 * late / events, 1)",
        f"| where late_pct >= {100 * LATE[0]:g}",
        f"| extend blinds = {carrier_blinds}",
        "| project carrier, host = host_, events, late, late_pct, p95_lag, blinds"])
    out["schedule"] = "\n".join([
        "SentinelHealth",
        "| where TimeGenerated > ago(24h)",
        f'| where SentinelResourceType == "Analytics Rule" and SentinelResourceName startswith "{splunk_app.ALERT_PREFIX}T"',
        '| summarize runs = count(), failed = countif(Status != "Success"), last_success = maxif(TimeGenerated, Status == "Success") '
        "by SentinelResourceName",
        f"| where isnull(last_success) or failed > {SKIPPED[0]} * runs",
        f'| extend detection = replace_string(SentinelResourceName, "{splunk_app.ALERT_PREFIX}", "")',
        "| project SentinelResourceName, detection, runs, failed, last_success"])
    return out


def live_line(store: Path | None = None, entries: list | None = None) -> str:
    """What the kept lab runs hold of the watchdogs on a live SIEM, as one clause for a table cell."""
    import evidence                                     # imported here: the kept runs are evidence's to read
    live = evidence.live_siem(store or evidence.STORE, entries)
    ran = live["health"]
    if not ran:
        return "generated, not yet run on a live SIEM"
    where = f"{' and '.join(live['platforms'])} beside {len(ran)} lab host{'' if len(ran) == 1 else 's'} in the kept lab run"
    if all(ok == total for ok, total in ran):
        return f"generated, and the SPL ones ran to the end on {where}"
    return f"generated; on {where}, {sum(total - ok for ok, total in ran)} SPL run(s) did not reach the end"


def live_block(store: Path | None = None, entries: list | None = None) -> list[str]:
    """The page's own account of a live SIEM: what the records kept with the lab runs say, and what they do not."""
    import evidence
    live = evidence.live_siem(store or evidence.STORE, entries)
    records = {label: [r for r in rows if str(r["name"]).startswith(HEALTH_PREFIX)]
               for label, rows in evidence.siem_records(store or evidence.STORE).items()}
    records = {label: rows for label, rows in records.items() if rows}
    if not records:
        return ["> **Not yet run on a live SIEM.** The searches are generated and checked for structure on every build, but "
                "they wait for a lab run with a live SIEM in it ([how](../../red/lab/README.md)). The same checks, as "
                "`rasd health` runs them on exports, are exercised by the tests and by the sample below."]
    labels = sorted(records)
    lines = [f"> **Run on a live Splunk, in the lab.** The table is what {' and '.join(live['platforms'])} answered when each "
             f"SPL search was run once beside {len(labels)} lab host{'' if len(labels) == 1 else 's'}, after the attack steps "
             "([kept runs](../../purple/lab_runs/README.md); the record is each part's `siem-searches.json`). It shows that "
             "Splunk accepts the searches as generated, and what they return over a lab that is in order: a row there would "
             "be a false alarm. It does not show a watchdog catching its fault. No feed was broken on purpose, and `silent` "
             "and `volume` compare with a week that a host made for one run has not lived. The KQL searches have not run "
             "on a live Sentinel.", "",
             "| Watchdog | " + " | ".join(f"`{label}`" for label in labels) + " |", "|---|" + "---|" * len(labels)]
    for check in WATCHDOGS:
        cells = []
        for label in labels:
            row = next((r for r in records[label] if r["name"] == f"{HEALTH_PREFIX}{check}"), None)
            if row is None:
                cells.append("not run")
            elif not row.get("ok"):
                cells.append("**refused**")
            else:
                n = int(row.get("results") or 0)
                cells.append(f"ran: {n} row{'' if n == 1 else 's'}")
        lines.append(f"| **{check}** | " + " | ".join(cells) + " |")
    return lines


def app_stanzas(wanted: list[Need] | None = None) -> list[str]:
    """The watchdogs as saved searches of the Splunk app: scheduled, and written to the alert index."""
    import splunk_app
    searches = spl_watchdogs(wanted if wanted is not None else needs())
    out = []
    for check, (_every, cron, what) in WATCHDOGS.items():
        out += [f"[{HEALTH_PREFIX}{check}]",
                f"description = {what} Each row names the detections it blinds. Generated by RASD-Health from the log sources, "
                "event ids and fields the library's rules read.",
                f"search = {splunk_app.one_line(searches[check])}",
                "disabled = 0",
                "enableSched = 1",
                f"cron_schedule = {cron}",
                "realtime_schedule = 0",
                "dispatch.earliest_time = -8d@h",
                "dispatch.latest_time = now",
                "counttype = number of events",
                "relation = greater than",
                "quantity = 0",
                "alert.track = 1",
                "alert.digest_mode = 0",
                "alert.severity = 4",
                "alert.expires = 7d",
                "action.logevent = 1",
                f"action.logevent.param.index = {splunk_app.ALERT_INDEX}",
                "action.logevent.param.sourcetype = rasd:health",
                "action.logevent.param.source = rasd",
                f'action.logevent.param.event = rasd_health="{check}" subject="$result.{_subject(check)}$" host="$result.host$" '
                'blinds="$result.blinds$" trigger_time="$trigger_time$"',
                ""]
    return out


def _subject(check: str) -> str:
    return {"silent": "carrier", "delay": "carrier", "schedule": "savedsearch_name"}.get(check, "feed")


def page(wanted: list[Need]) -> str:
    feeds = feed_detections(wanted)
    fields = feed_fields(wanted)
    sample = sample_summary()
    lines = ["<!-- Generated by tools/health.py --write - do not edit by hand. -->", "",
             "# RASD-Health: the watchdogs", "",
             "A rule that is not fed looks exactly like a rule on a quiet day. These searches keep watch over the chain "
             "under every detection - sensor, forwarder, index, fields, schedule - and each row they return names the "
             "detections it blinds. They are generated from what the library's own rules read, so a new detection is "
             "watched from the build that adds it. [How it works](../../docs/HEALTH.md).", "",
             "| Watchdog | Runs | Fires when | Splunk | Sentinel |", "|---|---|---|---|---|"]
    for check, (every, _cron, what) in WATCHDOGS.items():
        lines.append(f"| **{check}** | {every} | {what} | [`{check}.spl`](spl/{check}.spl) | [`{check}.kql`](kql/{check}.kql) |")
    lines += ["", "The Splunk app schedules the five SPL searches as `" + HEALTH_PREFIX + "<name>` and writes each row to the "
              "alert index as `sourcetype=rasd:health`. The KQL searches are for Sentinel analytics rules or a workbook; "
              "`schedule.kql` reads the `SentinelHealth` table, which health monitoring has to be turned on for.", "",
              *live_block(), "",
              "## What is watched", "",
              f"{len(feeds)} kinds of event, read by {len(wanted)} detections. A watchdog row for one of them means the "
              "detections beside it cannot be trusted until it clears.", "",
              "| Events | Fields the rules read on them | Detections they feed |", "|---|---|---|"]
    for feed in sorted(feeds):
        lines.append(f"| `{feed}` | {', '.join(f'`{f}`' for f in fields.get(feed, [])) or '-'} | "
                     + ", ".join(f"`{d}`" for d in sorted(feeds[feed])) + " |")
    lines += ["", "## The same watch, on an export", "",
              "No SIEM is needed to ask the question: `rasd health` compares an export of today's telemetry with a baseline "
              "and gives every detection a verdict.", "", "```bash",
              "rasd health --sample                                         # three ordinary days, then the day the pipeline breaks",
              "rasd health last-week.jsonl --save-baseline health-baseline.json",
              "rasd health today.jsonl --baseline health-baseline.json --scheduler scheduler.jsonl", "```", ""]
    if sample:
        lines += [sample, ""]
    lines += ["<sub>Generated by RASD · Attack-to-Defense Validation Framework</sub>", ""]
    return "\n".join(lines)


def sample_verdicts() -> tuple[Measure, Measure, list[Verdict]] | None:
    if not (SAMPLE_BASELINE.exists() and SAMPLE_TODAY.exists()):
        return None
    wanted = needs()
    base = load([SAMPLE_BASELINE], wanted, None)
    cur = load([SAMPLE_TODAY], wanted, None)
    scheduler = read_scheduler(SAMPLE_SCHEDULER) if SAMPLE_SCHEDULER.exists() else None
    return base, cur, assess(base, cur, wanted, scheduler)


def sample_counts() -> dict | None:
    """Numbers of the bundled sample, for the pages that quote them."""
    got = sample_verdicts()
    if not got:
        return None
    base, cur, verdicts = got
    tally = Counter(v.verdict for v in verdicts)
    return {"detections": len(verdicts), "blind": tally.get("blind", 0), "degraded": tally.get("degraded", 0),
            "healthy": tally.get("healthy", 0), "unknown": tally.get("unknown", 0),
            "checks": sorted({f.check for v in verdicts for f in v.findings if f.level != "note"}, key=CHECKS.index),
            "baseline_events": base.events, "current_events": cur.events, "hosts": len(base.hosts),
            "feeds": len(feed_detections(needs())), "watchdogs": len(WATCHDOGS)}


def sample_summary() -> str:
    got = sample_verdicts()
    if not got:
        return ""
    base, _cur, verdicts = got
    tally = Counter(v.verdict for v in verdicts)
    rows = ["On the bundled sample (`samples/health`: a baseline of "
            f"{human(base.hours * 3600)} from {len(base.hosts)} hosts, then a day in which the pipeline breaks in several "
            "places without a sound), "
            f"**{tally.get('blind', 0)} detections are blind and {tally.get('degraded', 0)} degraded**, "
            f"{tally.get('healthy', 0)} healthy, {tally.get('unknown', 0)} with nothing to compare:", "",
            "| Check | What broke | Blind | Degraded |", "|---|---|---|---|"]
    for f, touched in causes(verdicts):
        cells = ["<br>".join(f"`{d}`" for d, lv in touched if lv == level) or "-" for level in ("blind", "degraded")]
        rows.append(f"| **{f.check}** | {f.text.replace('|', chr(92) + '|')} | {cells[0]} | {cells[1]} |")
    return "\n".join(rows)


def render(wanted: list[Need]) -> dict[Path, str]:
    files = {PAGE: page(wanted)}
    for check, text in spl_watchdogs(wanted).items():
        files[OUT / "spl" / f"{check}.spl"] = text + "\n"
    for check, text in kql_watchdogs(wanted).items():
        what = WATCHDOGS[check][2]
        files[OUT / "kql" / f"{check}.kql"] = f"// RASD-Health · {check}: {what}\n{text}\n"
    return files


def check(wanted: list[Need]) -> list[str]:
    problems = []
    files = render(wanted)
    for path, text in files.items():
        if not path.exists() or read_text(path) != text:
            problems.append(f"{path.relative_to(ROOT).as_posix()} is out of date - run: rasd health --write")
    for folder in (OUT / "spl", OUT / "kql"):
        for extra in sorted(p for p in folder.glob("*") if p not in files) if folder.is_dir() else []:
            problems.append(f"{extra.relative_to(ROOT).as_posix()} is not a generated watchdog - remove it")
    watched = set(feed_detections(wanted))
    for n in wanted:
        if not set(n.feeds) <= watched:
            problems.append(f"{n.detection}: reads events no watchdog covers")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logs", nargs="*", help="exports of the telemetry to judge (JSON lines)")
    ap.add_argument("--baseline", nargs="+", metavar="PATH", help="what healthy looked like: an earlier export, or a saved profile")
    ap.add_argument("--save-baseline", metavar="FILE", help="measure the exports and keep the result as a baseline profile")
    ap.add_argument("--scheduler", metavar="FILE", help="the SIEM's record of scheduled runs (JSON lines or CSV)")
    ap.add_argument("--until", metavar="TIME", help="when the export was taken, if later than its newest event (UTC)")
    ap.add_argument("--profile", help="telemetry profile from profiles/ (or 'auto') the exports are written in")
    ap.add_argument("--filter", help="only the detections whose id contains this text")
    ap.add_argument("--json", metavar="FILE", help="also write the verdicts as JSON")
    ap.add_argument("--strict", action="store_true", help="exit 1 when a detection is blind or degraded")
    ap.add_argument("--detail", action="store_true", help="also print, per detection, how each kind of event was judged")
    ap.add_argument("--sample", action="store_true", help="judge the bundled sample (samples/health)")
    ap.add_argument("--write", action="store_true", help="regenerate the watchdogs and their page")
    ap.add_argument("--check", action="store_true", help="fail when the generated files are out of date (CI)")
    args = ap.parse_args()
    wanted = needs(args.filter)
    if args.write or args.check:
        if args.logs or args.baseline:
            ap.error("--write and --check take no export")
        if args.write:
            for path, text in render(needs()).items():
                write_output(path, text)
            print(f"{GREEN}✓{RESET} RASD-Health · {len(WATCHDOGS)} watchdogs in SPL and KQL over {len(feed_detections(needs()))} "
                  f"kinds of event, {len(needs())} detections")
            return 0
        problems = check(needs())
        for p in problems:
            print(f"{RED}✗{RESET} {p}")
        if not problems:
            print(f"{GREEN}✓{RESET} RASD-Health · the watchdogs match the library: every detection is watched")
        return 1 if problems else 0
    until = to_time(args.until) if args.until else None
    if args.until and until is None:
        ap.error(f"--until {args.until}: not a time")
    if args.sample:
        if args.logs or args.baseline:
            ap.error("--sample reads the bundled files: give it alone")
        logs, baseline = [SAMPLE_TODAY], [SAMPLE_BASELINE]
        scheduler_path: Path | None = SAMPLE_SCHEDULER if not args.scheduler else Path(args.scheduler)
    else:
        logs, baseline = [Path(p) for p in args.logs], [Path(p) for p in args.baseline or []]
        scheduler_path = Path(args.scheduler) if args.scheduler else None
    if not logs:
        ap.error("give an export to judge, or --sample")
    if args.save_baseline:
        m = load(logs, wanted, args.profile, until)
        if m.start is None:
            raise HealthError("the exports hold no dated event: nothing to keep as a baseline")
        write_output(args.save_baseline, json.dumps(to_baseline(m), indent=1) + "\n")
        print(f"{GREEN}✓{RESET} baseline of {human(m.hours * 3600)}: {m.events} events from {len(m.hosts)} hosts, "
              f"{len(m.feeds)} kinds of event the rules read → {args.save_baseline}")
        return 0
    if not baseline:
        ap.error("give --baseline (an earlier export, or a profile written by --save-baseline)")
    if any(is_baseline(p) for p in logs):
        ap.error("the export to judge has to be events: a saved baseline goes after --baseline")
    base = load(baseline, wanted, args.profile)
    cur = load(logs, wanted, args.profile, until)
    scheduler = read_scheduler(scheduler_path) if scheduler_path else None
    verdicts = assess(base, cur, wanted, scheduler)
    show(base, cur, verdicts, args.detail)
    if args.json:
        write_output(args.json, json.dumps(to_json(base, cur, verdicts), indent=2) + "\n")
    bad = any(v.verdict in ("blind", "degraded") for v in verdicts)
    return 1 if args.strict and bad else 0


if __name__ == "__main__":
    sys.exit(main())
