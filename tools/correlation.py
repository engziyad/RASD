#!/usr/bin/env python3
"""
correlation.py - Sigma correlation rules: detections no single event can express.

One failed logon is noise. One failed logon for each of many accounts, from one source,
within minutes, is a password spray. Sigma v2 correlation rules describe exactly that: count
the events of a base rule, or the distinct values of a field, per group and time window.
This module is the core RASD uses for them - loading, the offline engine, the SPL / KQL
conversion and the burst guarantee. `rasd correlate` (tools/correlate.py) proves them.

A correlation detection lives in detect/correlations/<id>/:
  correlation.yml   the Sigma correlation rule: type, rules, group-by, timespan, condition
  base.yml          the base rule it counts - a normal Sigma rule that never alerts alone
  contract.yml      data contract, triage, response and risk, like every detection
  tuning.yml        tuning guidance: thresholds, known benign sources, what never to tune
  tests/true_positive.jsonl, tests/true_negative.jsonl   single events for the base rule
  tests/scenarios.yml   event sequences that must fire, or stay silent
  README.md

Semantics - identical in the engine, the generated SPL and the generated KQL
  * windows are tumbling and aligned to the clock (bin span=<n>s _time / bin(TimeGenerated, <n>s));
    a timespan is whole minutes dividing an hour or whole hours dividing a day, so every SIEM
    cuts the windows at the same instants and a scheduler can run once per window
  * an event without a group-by value - or, for value_count, without the counted value - is
    ignored; an empty value counts as missing
  * values are compared exactly (case-sensitive), as stats dc() and make_set() do, after the
    normalisations in tools/mappings.yml `correlation.normalize` (for example ::ffff:10.0.0.5
    and 10.0.0.5 are one client)
  * types: event_count and value_count over one base rule; anything else is rejected
"""
from __future__ import annotations

import math
import operator
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from common import CORRELATIONS, Detection, load_jsonl, selected
from convert import KQL, MAPPINGS, SPL, convert, kql_eventdata, logsource_key, referenced_fields
from replay import TIME_FIELDS, parse_time, route
from sigma_engine import _get_field, compile_rule

SUPPORTED = ("event_count", "value_count")
OPS = {"gte": operator.ge, "gt": operator.gt, "lte": operator.le, "lt": operator.lt, "eq": operator.eq}
SYMBOL = {"gte": ">=", "gt": ">", "lte": "<=", "lt": "<", "eq": "="}
KQL_SYMBOL = {**SYMBOL, "eq": "=="}
UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
EPOCH = datetime(1970, 1, 1)
VALUES_KEPT = 50                     # distinct values listed per alert; counting is never capped
FIELD_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
NORMALIZE: dict[str, str] = dict((MAPPINGS.get("correlation") or {}).get("normalize") or {})


class CorrelationError(Exception):
    pass


def valid_timespan(seconds: int) -> bool:
    """Whole minutes dividing an hour (1, 2, 3, 4, 5, 6, 10, 12, 15, 20, 30, 60) or whole hours dividing
    a day (1, 2, 3, 4, 6, 8, 12, 24): every SIEM aligns such windows identically, and a cron schedule
    can run once per window."""
    if seconds <= 0 or seconds % 60:
        return False
    minutes = seconds // 60
    return 60 % minutes == 0 or (minutes % 60 == 0 and 24 % (minutes // 60) == 0)


def timespan_seconds(text: Any) -> int:
    m = re.fullmatch(r"\s*(\d+)\s*([smhd])\s*", str(text))
    if not m:
        raise CorrelationError(f"timespan {text!r} must look like 10m, 1h or 1d")
    seconds = int(m.group(1)) * UNITS[m.group(2)]
    if not valid_timespan(seconds):
        raise CorrelationError(f"timespan {text!r} must be whole minutes dividing an hour or whole hours dividing "
                               "a day, so every SIEM aligns the windows identically and can schedule one run per window")
    return seconds


def human(seconds: int) -> str:
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds % size == 0:
            return f"{seconds // size}{unit}"
    return f"{seconds}s"


@dataclass(frozen=True)
class Params:
    """Everything that decides a correlation's verdict - and what its mutants change."""
    type: str
    group_by: tuple[str, ...]
    timespan: int
    field: str | None
    op: str
    threshold: int
    normalize: tuple[tuple[str, str], ...] = ()

    @property
    def metric(self) -> str:
        return "value_count" if self.type == "value_count" else "event_count"

    @property
    def counted(self) -> str | None:
        return self.field if self.type == "value_count" else None

    def reads(self) -> list[str]:
        """Fields the correlation itself reads, beyond the base rule: group-by, then the counted field."""
        return list(dict.fromkeys(list(self.group_by) + ([self.counted] if self.counted else [])))

    def describe(self) -> str:
        what = f"distinct {self.field}" if self.type == "value_count" else "events"
        by = f" per {', '.join(self.group_by)}" if self.group_by else " in total"
        return f"{SYMBOL[self.op]} {self.threshold} {what}{by} in {human(self.timespan)} windows"


def normalizations(fields: list[str]) -> tuple[tuple[str, str], ...]:
    return tuple((f, NORMALIZE[f]) for f in fields if f in NORMALIZE)


@dataclass
class Correlation:
    folder: Path
    rule: dict
    base: dict
    contract: dict = field(default_factory=dict)

    @property
    def id(self) -> str:
        return self.folder.name

    @property
    def technique(self) -> str:
        return self.folder.name.split("_")[0]

    @property
    def title(self) -> str:
        return self.rule.get("title", self.id)

    @property
    def level(self) -> str:
        return self.rule.get("level", "medium")

    @property
    def tactics(self) -> list[str]:
        return [t.split(".", 1)[1] for t in self.rule.get("tags", [])
                if t.startswith("attack.") and not re.match(r"^attack\.t\d{4}", t)]

    @property
    def params(self) -> Params:
        spec = self.rule.get("correlation") or {}
        cond = spec.get("condition") or {}
        ops = [k for k in cond if k in OPS]
        if spec.get("type") not in SUPPORTED:
            raise CorrelationError(f"correlation type {spec.get('type')!r} is not supported (use {' or '.join(SUPPORTED)})")
        if len(ops) != 1 or not isinstance(cond[ops[0]], int) or isinstance(cond[ops[0]], bool) or cond[ops[0]] < 0:
            raise CorrelationError("condition needs exactly one of gte / gt / lte / lt / eq with a non-negative integer")
        if spec["type"] == "value_count" and not cond.get("field"):
            raise CorrelationError("a value_count correlation needs condition.field")
        group_by = tuple(spec.get("group-by") or ())
        counted = cond.get("field") if spec["type"] == "value_count" else None
        for name in group_by + ((counted,) if counted else ()):
            # the generated queries name the field: it must be a plain identifier in every backend,
            # as written or as tools/mappings.yml renames it (c-ip -> clientip / cIP)
            columns = [str((MAPPINGS[b].get("fields") or {}).get(name, name)) for b in ("spl", "kql")]
            if not all(FIELD_NAME.match(c) for c in columns):
                raise CorrelationError(f"field {name!r} must be a plain field name (letters, digits, _) "
                                       "or be renamed to one for every backend in tools/mappings.yml")
        reads = list(dict.fromkeys(list(group_by) + ([counted] if counted else [])))
        return Params(type=spec["type"], group_by=group_by, timespan=timespan_seconds(spec.get("timespan")),
                      field=counted, op=ops[0], threshold=int(cond[ops[0]]), normalize=normalizations(reads))

    def tests(self, kind: str) -> list[dict]:
        return load_jsonl(self.folder / "tests" / f"{kind}.jsonl")

    def base_detection(self) -> Detection:
        """The base rule as a Detection: every single-event proof applies to it unchanged."""
        return Detection(self.folder, self.base, self.contract)

    def scenario_doc(self) -> dict:
        path = self.folder / "tests" / "scenarios.yml"
        return (yaml.safe_load(path.read_text(encoding="utf-8")) or {}) if path.exists() else {}

    def scenarios(self) -> list[dict]:
        return expand_scenarios(self.scenario_doc())

    def accepted_mutants(self) -> dict[str, str]:
        return {a["id"]: a["reason"] for a in self.scenario_doc().get("accepted_mutants") or []}


def load_correlations(filter_: str | None = None) -> list[Correlation]:
    out: list[Correlation] = []
    if not CORRELATIONS.exists():
        return out
    for folder in sorted(p for p in CORRELATIONS.iterdir() if p.is_dir()):
        if not selected(folder.name, filter_):
            continue
        rule = yaml.safe_load((folder / "correlation.yml").read_text(encoding="utf-8")) or {}
        base = yaml.safe_load((folder / "base.yml").read_text(encoding="utf-8")) or {}
        cpath = folder / "contract.yml"
        contract = yaml.safe_load(cpath.read_text(encoding="utf-8")) if cpath.exists() else {}
        out.append(Correlation(folder, rule, base, contract or {}))
    return out


# --------------------------------------------------------------------------- #
# Scenarios: compact, readable event sequences
# --------------------------------------------------------------------------- #
def iso(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def expand_scenarios(doc: dict) -> list[dict]:
    """tests/scenarios.yml -> [{name, expect, groups, alerts, known_limit, events}].

    Every event is `defaults` (file, then scenario) + its own fields, timed `at` seconds
    after the scenario's `start`. One entry can write several events:
      - {at: 0, every: 20, count: 6, set: {TargetUserName: "lab.user{n:02d}"}}
    gives six events 20 s apart, TargetUserName lab.user01 ... lab.user06.
    """
    out = []
    for sc in doc.get("scenarios") or []:
        start = datetime.fromisoformat(str(sc["start"]).replace("Z", "+00:00"))
        start = start.astimezone(timezone.utc).replace(tzinfo=None) if start.tzinfo else start
        defaults = {**(doc.get("defaults") or {}), **(sc.get("defaults") or {})}
        events = []
        for item in sc.get("events") or []:
            item = dict(item)
            count, every = int(item.pop("count", 1)), float(item.pop("every", 0))
            at = float(item.pop("at", 0))
            template = item.pop("set", None) or {}
            for i in range(count):
                ev = {**defaults, **item}
                for k, v in template.items():
                    ev[k] = v.format(n=i + 1) if isinstance(v, str) else v
                ev = {k: v for k, v in ev.items() if v is not None and k not in TIME_FIELDS}   # `Field: null` removes a default
                ev["TimeCreated"] = iso(start + timedelta(seconds=at + i * every))          # the only time it carries
                events.append(ev)
        out.append({"name": sc["name"], "expect": sc.get("expect"), "groups": sc.get("groups"),
                    "alerts": sc.get("alerts"), "known_limit": sc.get("known_limit"), "events": events})
    return out


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #
def epoch(t: datetime) -> float:
    return (t - EPOCH).total_seconds()


def value_reader(p: Params):
    """field -> normalised, non-empty string value (or None) - the one definition of 'a value'."""
    norm = {f: re.compile(rx) for f, rx in p.normalize}

    def read(ev: dict, name: str) -> str | None:
        v = _get_field(ev, name)
        if v is None:
            return None
        text = str(v)
        if name in norm:
            text = norm[name].sub("", text)
        return text or None
    return read


def evaluate(corr: Correlation, events: list[dict], params: Params | None = None, base_fn=None) -> list[dict]:
    """The correlation's alerts over `events` (any order): one per window and group that meets
    the condition. `crossed_at` is the event that made the group meet it - the earliest moment
    any SIEM could have alerted - which evidence uses for latency."""
    p = params or corr.params
    fn = base_fn or compile_rule(corr.base)
    source = logsource_key(corr.base)
    read = value_reader(p)
    buckets: dict[tuple, list[tuple[datetime, str | None]]] = {}
    for ev in events:
        if route(ev) != source or not fn(ev):
            continue
        t = parse_time(ev)
        if t is None:
            continue
        group = tuple(read(ev, g) for g in p.group_by)
        if None in group:
            continue
        value = read(ev, p.field) if p.counted else None
        if p.counted and value is None:
            continue
        start = math.floor(epoch(t) / p.timespan) * p.timespan
        buckets.setdefault((start, group), []).append((t, value))
    compare = OPS[p.op]
    monotonic = p.op in ("gte", "gt")          # only an at-least condition can be met before the window closes
    alerts = []
    for (start, group), items in buckets.items():
        items.sort(key=lambda x: x[0])
        seen: set[str] = set()
        crossed = None
        for n, (t, value) in enumerate(items, 1):
            if value is not None:
                seen.add(value)
            if monotonic and crossed is None and compare(len(seen) if p.counted else n, p.threshold):
                crossed = t
        metric = len(seen) if p.counted else len(items)
        if not compare(metric, p.threshold):
            continue
        if not monotonic:                       # lt / lte / eq: decided when the window closes
            crossed = EPOCH + timedelta(seconds=start + p.timespan)
        alerts.append({"window_start": EPOCH + timedelta(seconds=start), "group": dict(zip(p.group_by, group, strict=True)),
                       "value_count": len(seen) if p.counted else None, "event_count": len(items),
                       "metric": metric, "values": sorted(seen)[:VALUES_KEPT],
                       "first_event": items[0][0], "last_event": items[-1][0], "crossed_at": crossed or items[-1][0]})
    return sorted(alerts, key=lambda a: (a["window_start"], tuple(a["group"].values())))


def group_label(alert: dict) -> str:
    return "|".join(alert["group"].values()) if alert["group"] else "*"


def alert_signature(alert: dict) -> tuple:
    """What two implementations must agree on for one alert."""
    return (epoch(alert["window_start"]), tuple(alert["group"].values()), alert["metric"], alert["event_count"],
            epoch(alert["first_event"]), epoch(alert["last_event"]))


# --------------------------------------------------------------------------- #
# Parameter mutants: the edits that would break the correlation without breaking the base rule
# --------------------------------------------------------------------------- #
def param_mutants(p: Params):
    """Yield (id, description, mutated Params)."""
    yield "threshold:+1", f"threshold {p.threshold} -> {p.threshold + 1}", replace(p, threshold=p.threshold + 1)
    if p.threshold > 0:
        yield "threshold:-1", f"threshold {p.threshold} -> {p.threshold - 1}", replace(p, threshold=p.threshold - 1)
    if valid_timespan(p.timespan * 2):
        yield "timespan:x2", f"timespan {human(p.timespan)} -> {human(p.timespan * 2)}", replace(p, timespan=p.timespan * 2)
    if p.timespan % 2 == 0 and valid_timespan(p.timespan // 2):
        yield "timespan:/2", f"timespan {human(p.timespan)} -> {human(p.timespan // 2)}", replace(p, timespan=p.timespan // 2)
    for g in p.group_by:
        rest = tuple(x for x in p.group_by if x != g)
        keep = rest + ((p.counted,) if p.counted else ())
        yield f"group-by:-{g}", f"stop grouping by {g}", replace(p, group_by=rest,
                                                              normalize=tuple(n for n in p.normalize if n[0] in keep))
    if p.type == "value_count":
        yield "type:event_count", f"count events instead of distinct {p.field}", \
            replace(p, type="event_count", field=None,
                    normalize=tuple(n for n in p.normalize if n[0] in p.group_by))
    for f, _rx in p.normalize:
        yield f"normalize:-{f}", f"compare {f} without normalisation", \
            replace(p, normalize=tuple(n for n in p.normalize if n[0] != f))


# --------------------------------------------------------------------------- #
# Burst guarantee: the smallest burst that alerts whatever the window alignment
# --------------------------------------------------------------------------- #
def guaranteed_burst(p: Params) -> int | None:
    """Tumbling windows cut a burst at a boundary. A burst of n events (or distinct values) inside
    one window length always leaves ceil(n/2) on one side, so 2T-1 always reaches a threshold T
    and 2T-2 can be split T-1 / T-1. None when the condition is not 'at least'."""
    if p.op not in ("gte", "gt"):
        return None
    need = p.threshold + (1 if p.op == "gt" else 0)
    return max(1, 2 * need - 1)


def burst_values(p: Params, template: dict, fn=None):
    """The counted values of a burst: the template's own value with a numeric suffix when the base
    rule still matches it (a base rule can constrain the counted field itself - an object path
    that must end in digits), otherwise neutral values."""
    if not p.counted:
        return None
    own = str(template.get(p.counted) or "")
    schemes = ([lambda i: f"{own}{i:03d}"] if own else []) + [lambda i: f"burst.value{i:03d}"]
    if fn is None:
        return schemes[-1]
    return next((s for s in schemes if all(fn({**template, p.counted: s(i)}) for i in range(3))), schemes[-1])


def burst_events(p: Params, template: dict, times: list[float], start: datetime, values=None) -> list[dict]:
    """`len(times)` copies of one base event for one group, each with its own counted value."""
    values = values or burst_values(p, template)
    out = []
    for i, offset in enumerate(times):
        ev = {k: v for k, v in template.items() if k not in TIME_FIELDS}   # the burst time is the only time
        if p.counted:
            ev[p.counted] = values(i)
        ev["TimeCreated"] = iso(start + timedelta(seconds=offset))
        out.append(ev)
    return out


def check_guarantee(corr: Correlation, template: dict, params: Params | None = None, alignments: int = 120) -> dict | None:
    """Verify guaranteed_burst() with the engine: the burst alerts at every alignment and spread,
    and one fewer can be split by a boundary so that nothing alerts (the bound is tight)."""
    p = params or corr.params
    g = guaranteed_burst(p)
    if g is None:
        return None
    w = p.timespan
    day = datetime(2026, 1, 5)                                   # any midnight: windows divide a day
    fn = compile_rule(corr.base)
    values = burst_values(p, template, fn)
    failures = []
    for k in range(alignments):
        offset = w * k / alignments
        for spread in (0.0, w / 3, w - 1.0):
            times = [offset + (spread * i / max(1, g - 1)) for i in range(g)]
            if not evaluate(corr, burst_events(p, template, times, day, values), p, fn):
                failures.append({"offset": offset, "spread": spread})
    need = (g + 1) // 2
    split = [w - 1.0 - i * 0.5 for i in range(need - 1)] + [w + i * 0.5 for i in range(need - 1)]
    tight = not evaluate(corr, burst_events(p, template, split, day, values), p, fn) if need > 1 else True
    return {"burst": g, "alignments": alignments, "spreads": 3, "checked": alignments * 3, "failures": failures,
            "tight": tight}


# --------------------------------------------------------------------------- #
# SIEM conversion
# --------------------------------------------------------------------------- #
def _column(backend: str):
    fmap = MAPPINGS[backend].get("fields") or {}
    return lambda f: fmap.get(f, f)


def to_spl(corr: Correlation, params: Params | None = None) -> str:
    p = params or corr.params
    col = _column("spl")
    groups, counted = [col(g) for g in p.group_by], (col(p.counted) if p.counted else None)
    lines = [convert(corr.base, "spl")]
    for f, rx in p.normalize:
        lines.append(f"| eval {col(f)}=replace('{col(f)}', {SPL.s(rx)}, \"\")")
    needed = [col(f) for f in p.reads()]
    if needed:
        lines.append("| where " + " AND ".join(f"isnotnull('{c}') AND '{c}'!=\"\"" for c in needed))
    lines.append(f"| bin span={p.timespan}s _time AS window_start")      # AS: _time keeps each event's own time
    aggs = ([f"dc({counted}) as value_count"] if counted else []) + ["count as event_count"]
    aggs += ([f"values({counted}) as distinct_values"] if counted else []) + ["min(_time) as first_event",
                                                                              "max(_time) as last_event"]
    lines.append(f"| stats {' '.join(aggs)} by window_start" + "".join(f" {g}" for g in groups))
    lines.append(f"| where {p.metric}{SYMBOL[p.op]}{p.threshold}")
    return "\n".join(lines)


def to_kql(corr: Correlation, params: Params | None = None) -> str:
    p = params or corr.params
    col = _column("kql")
    groups, counted = [col(g) for g in p.group_by], (col(p.counted) if p.counted else None)
    body = convert(corr.base, "kql").split("\n", 1)[1]               # the base rule's own title comment goes
    head, where = body.rsplit("\n| where ", 1)
    read = referenced_fields(corr.base["detection"])
    extra = [f for f in p.reads() if f not in read]
    if extra:                                                        # fields only the correlation reads
        head += kql_eventdata({"detection": {"fields": dict.fromkeys(extra), "condition": "fields"}},
                              logsource_key(corr.base), MAPPINGS["kql"].get("fields") or {})
    lines = [f"// {corr.title} | {corr.rule.get('id')}",
             f"// counts: {corr.base.get('title')} | {corr.base.get('id')}", head, f"| where {where}"]
    for f, rx in p.normalize:
        lines.append(f"| extend {col(f)} = replace_regex({col(f)}, {KQL.s(rx)}, \"\")")
    needed = [col(f) for f in p.reads()]
    if needed:
        lines.append("| where " + " and ".join(f"isnotempty({c})" for c in needed))
    # array_length(make_set()) is exact; dcount() is a HyperLogLog estimate and could miss a threshold
    aggs = ([f"value_count = array_length(make_set({counted}))"] if counted else []) + ["event_count = count()"]
    aggs += ([f"distinct_values = make_set({counted}, {VALUES_KEPT})"] if counted else [])
    aggs += ["first_event = min(TimeGenerated)", "last_event = max(TimeGenerated)"]
    lines.append(f"| summarize {', '.join(aggs)} by window_start = bin(TimeGenerated, {p.timespan}s)"
                 + "".join(f", {g}" for g in groups))
    lines.append(f"| where {p.metric} {KQL_SYMBOL[p.op]} {p.threshold}")
    return "\n".join(lines)
