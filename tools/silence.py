#!/usr/bin/env python3
"""
silence.py - RASD-Silence: what a rule that stayed quiet proves.

Every other tool answers for an alert. This one answers for its absence. A detection that raised nothing
over a month of logs is read, everywhere, as "nothing happened". It says that only if the sensor was
recording the whole time, no record is missing, and nothing emptied or stopped the log in between.
Otherwise the quiet is a blind spot that looks exactly like safety.

`rasd silence` reads an export and decides, for every detection and every host:

  fired        the rule raised an alert: the quiet is broken, and replay has the storyline
  attested     quiet, and the quiet is evidence. Between two records that show the sensor recording,
               every record is present and none says the sensor stopped, changed or was emptied
  unattested   quiet, and the quiet proves nothing here: no record shows the sensor was recording what
               the rule reads, or the field the rule reads is not in the events. The reason is printed
               with what to turn on

An attested verdict carries its share of the watched time, and its grade:

  sequence     the channel's record numbers are consecutive: no record between the first and the last
               can have been removed without leaving a hole in the count
  rhythm       the export has no usable record numbers: the channel never went quiet for longer than
               its own gaps allow, which is weaker and is said so

and every stretch it does not cover is listed as a break in the record: record numbers missing, a
channel emptied, a logging service stopped or started with no stop before it, a channel that went
quiet while another host kept recording the same machine.

  rasd silence                               this Windows host: its own event logs, read only
  rasd silence EXPORT [EXPORT ...]           one or more JSONL exports (--profile for ECS, CIM ...)
  --assets FILE      ip,host,role: lets a logon recorded by a domain controller count as a sign that
                     the client was up
  --from T --to T    the window to answer for (default: from the first record to the last)
  --quiet MINUTES    the longest gap a channel may have (default: three times the gap each channel
                     exceeds once in a hundred, at least 15 minutes)
  --filter TEXT      only the detections whose id contains TEXT
  --host NAME        only this host
  --days N           with no export: how far back to read this host's logs (default 7)
  --certificate FILE the certificate as Markdown: the claim, every verdict with its proof, the breaks,
                     the limits, the SHA-256 of every input (with no export it is written beside the
                     answer as rasd-silence-<host>-<time>.md, with the page as .html)
  --html FILE        the same as one page, with the map of every sensor over the window: where its proof
                     holds, where the host was off, where the record breaks
  --json FILE        the same as JSON
  --check            the model is in step with dfir/trace/model.yml, the rules and the engine, and the
                     results page of the sample fleet is current
  --write            render the results block of dfir/silence/README.md from the sample fleet

What it rests on is written once in dfir/silence/model.yml: what proves each sensor was recording, the
records that end that proof, and the limits printed with every certificate. A verdict holds for the
behaviours the rule is proven to catch (rasd certify) and for the anti-forensic actions RASD-Trace
catalogues; both are listed beside it. Entries are documented behaviour, not lab evidence.
"""
from __future__ import annotations

import argparse
import bisect
import codecs
import functools
import hashlib
import html
import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from itertools import pairwise
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (BOLD, DFIR, DIM, GREEN, RED, RESET, ROOT, VERSION, YELLOW, load_detections, load_jsonl, md_text,
                    selected, write_output)
from convert import logsource_key
from correlation import load_correlations
import doctor
import profiles
from replay import HOST_FIELDS, first, load_assets, parse_time, replay as run_replay, route
from sigma_engine import SigmaError, matches
import survivability

SILENCE = DFIR / "silence"
MODEL = SILENCE / "model.yml"
README = SILENCE / "README.md"
SAMPLE = ROOT / "samples" / "silence"
SAMPLE_EXPORT = SAMPLE / "fleet.jsonl"
SAMPLE_ASSETS = SAMPLE / "assets.csv"
BLOCK_START, BLOCK_END = "<!-- rasd:silence:start -->", "<!-- rasd:silence:end -->"
FORMAT = 1
PROOFS = ("channel", "event")
EDGES = ("stop", "start", "change", "clear")
BASES = ("vendor", "practitioner")
DENSE = 0.9                                  # share of consecutive record numbers above which an export is taken as complete
MIN_GAPS = 30                                # gaps a channel needs before its rhythm is known
QUIET_FLOOR = timedelta(minutes=15)
QUIET_CEILING = timedelta(hours=24)
QUIET_FACTOR = 3
SKEW = timedelta(seconds=2)                  # how far two clocks, or two renderings of one time, may disagree
MARGIN = timedelta(minutes=5)                # how far from the ends of a stretch a shutdown or start record may sit
LIFE_MARGIN = timedelta(minutes=2)           # a record this close to the ends of a stretch belongs to its ends
MINOR_RUN = timedelta(seconds=60)            # a shorter run between two breaks is part of one break (a restart's own records)
BACK = timedelta(minutes=5)                  # a clock this far behind for three records in a row was set back
DOWN_MIN = timedelta(seconds=30)             # a shorter pause after a shutdown or sleep record is not time off
CLOSE = timedelta(seconds=20)                # how far a shutdown or wake record sits from the pause it belongs to
BOOT = timedelta(minutes=2)                  # how long after the pause a start writes its own records (the kernel's come first)
HEAD = 20                                    # records at the head of a stream among which a time filter may have left one out
KIND_ORDER = ("restarted", "cleared", "missing", "stopped", "quiet")
SEVERITY_ORDER = ("high", "medium", "low")
LIVE_CHANNELS = ("Microsoft-Windows-Sysmon/Operational", "Security", "System")
LIVE_LIMIT = 400_000                         # records read per channel from this host
Span = tuple[datetime, datetime]


class SilenceError(SystemExit):
    pass


# --------------------------------------------------------------------------- #
# The model
# --------------------------------------------------------------------------- #
@dataclass
class Witness:
    artifact: str
    proof: str
    why: str
    enable: str
    basis: str


@dataclass
class Cut:
    id: str
    name: str
    record: dict                    # the values that recognise the record
    cuts: Any                       # a tuple of channel names in lowercase, "named" or "all"
    edge: str
    detection: str | None
    erasures: tuple[str, ...]
    event: dict | None
    basis: str
    source: str | None
    note: str | None

    def targets(self, ev: dict, channels: list[str]) -> list[str]:
        """The channels of a host this record ends, as lowercase names."""
        if self.cuts == "all":
            return list(channels)
        if self.cuts == "named":
            return [str(ev.get("Channel_Cleared") or ev.get("Channel") or "").lower()]
        return list(self.cuts)


@dataclass
class Down:
    id: str
    name: str
    start: dict
    end: dict
    basis: str


@dataclass
class Model:
    claim: str
    fields: tuple[str, ...]
    witnesses: dict[str, Witness]
    cuts: list[Cut]
    down: list[Down]
    limits: list[str]
    sequence: dict = field(default_factory=dict)


def build_model(doc: dict) -> Model:
    witnesses = {str(k): Witness(str(k), str(w.get("proof", "")), str(w.get("why", "")), str(w.get("enable", "")),
                                 str(w.get("basis", "")))
                 for k, w in (doc.get("witnesses") or {}).items()}
    cuts = []
    for c in doc.get("cuts") or []:
        scope = c.get("cuts")
        cuts.append(Cut(str(c.get("id", "")), str(c.get("name", "")), dict(c.get("record") or {}),
                        tuple(str(x).lower() for x in scope) if isinstance(scope, list) else scope, str(c.get("edge", "")),
                        c.get("detection"), tuple(c.get("erasures") or ()), c.get("event"), str(c.get("basis", "")),
                        c.get("source"), c.get("note")))
    down = [Down(str(d.get("id", "")), str(d.get("name", "")), dict(d.get("from") or {}), dict(d.get("to") or {}),
                 str(d.get("basis", ""))) for d in doc.get("down") or []]
    seq = dict(doc.get("sequence") or {})
    return Model(" ".join(str(doc.get("claim", "")).split()), tuple(str(f) for f in seq.get("fields") or ()), witnesses, cuts,
                 down, [str(x) for x in doc.get("limits") or []], seq)


def load_model(path: Path = MODEL) -> Model:
    if not path.exists():
        raise SilenceError(f"{path.relative_to(ROOT)} is missing")
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(doc, dict):
        raise SilenceError(f"{path.relative_to(ROOT)}: a mapping is expected at the top level")
    return build_model(doc)


def holds(ev: dict, values: dict) -> bool:
    """The record carries every value named (text without case, numbers as written)."""
    return bool(values) and all(str(ev.get(k, "")).strip().lower() == str(v).strip().lower() for k, v in values.items())


# --------------------------------------------------------------------------- #
# What silence asks of each detection
# --------------------------------------------------------------------------- #
@dataclass
class Target:
    """A detection or a correlation as this tool reads it: the record its rule reads and what proves a sensor wrote it."""
    id: str
    title: str
    kind: str                       # rule | correlation
    rule: dict                      # the rule, or the correlation's base rule
    contract: dict
    logsource: str
    ids: frozenset[str]
    artifact: str | None            # the artifact of dfir/trace/model.yml its rule reads; None when RASD-Trace does not model it
    reads: str                      # that artifact's name, or the log source
    proof: str
    channel: str | None             # the channel the record is written to, in lowercase, when the model names one
    channel_name: str | None        # the same channel as Windows writes it
    reach: str                      # host: the technique runs where the record is written; remote: an observer records it
    why: str
    enable: str


def targets(sm: Model, trace: survivability.Model, filter_: str | None = None) -> list[Target]:
    rules: list[tuple[str, str, str, dict, dict]] = [(d.id, d.title, "rule", d.rule, d.contract) for d in load_detections()]
    rules += [(c.id, c.title, "correlation", c.base, c.contract) for c in load_correlations()]
    out = []
    for ident, title, kind, rule, contract in rules:
        if not selected(ident, filter_):
            continue
        src, ids = logsource_key(rule), frozenset(doctor.rule_event_ids(rule))
        fp = trace.footprints.get(ident)
        art = trace.artifacts.get(fp.reads) if fp else None
        wit = sm.witnesses.get(art.id) if art else None
        if art is None or wit is None:
            out.append(Target(ident, title, kind, rule, contract, src, ids, None, f"{src} records", "event", None, None, "remote",
                              "RASD-Trace does not model this log source yet: its quiet is judged on its own records alone",
                              f"Export the {src} records"))
            continue
        store = trace.stores.get(art.store) or {}
        name = str(store.get("channel") or "") or None
        channel = name.lower() if name else None
        proof = wit.proof if (wit.proof == "event" or channel) else "event"
        out.append(Target(ident, title, kind, rule, contract, src, ids, art.id, art.name, proof, channel, name,
                          str(store.get("reach", "remote")), wit.why, wit.enable))
    return out


def behaviour(folder: Path | None) -> dict:
    """What the rule is proven to catch, as its behaviour spec states it (rasd certify --check holds the spec true)."""
    out: dict[str, Any] = {"spec": False, "fires": 0, "gaps": [], "exclusions": 0}
    path = None if folder is None else folder / "behavior.yml"
    if path is None or not path.exists():
        return out
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    out["spec"] = True
    for v in doc.get("variants") or []:
        expect = str(v.get("expect", "fires"))
        if expect == "fires":
            out["fires"] += 1
        elif expect == "bypass":
            out["gaps"].append(str(v.get("name", "")))
        else:
            out["exclusions"] += 1
    return out


# --------------------------------------------------------------------------- #
# The export, arranged by host and channel
# --------------------------------------------------------------------------- #
@dataclass
class Rec:
    time: datetime
    rid: int | None
    ev: dict
    src: str | None


def record_id(ev: dict, fields: tuple[str, ...]) -> int | None:
    for f in fields:
        v = ev.get(f)
        if isinstance(v, bool) or v is None:
            continue
        try:
            return int(str(v).strip())
        except ValueError:
            continue
    nested = ev.get("winlog")
    if isinstance(nested, dict) and str(nested.get("record_id", "")).isdigit():
        return int(nested["record_id"])
    return None


def short(host: str) -> str:
    return host.split(".")[0].lower()


def plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def listed(names: list[str]) -> str:
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


class Fleet:
    """An export arranged for the questions silence asks: the records of every host and channel, the records
    that end a proof, the records that mark a shutdown, and which host named which."""

    def __init__(self, events: list[dict], sm: Model, assets: dict | None = None):
        self.sm = sm
        self.assets = assets or {}
        self.hosts: dict[str, str] = {}                               # key -> the name as the export writes it
        self.channels: dict[str, str] = {}                            # key -> the channel as the export writes it
        self.streams: dict[tuple[str, str], list[Rec]] = defaultdict(list)
        self.windows: set[str] = set()                                # hosts that write a Windows event channel
        self.undated = 0
        self.total = len(events)
        named: dict[str, list[tuple[datetime, str]]] = defaultdict(list)
        cuts: dict[tuple[str, str], list[tuple[datetime, Cut, dict]]] = defaultdict(list)
        pending: list[tuple[str, datetime, Cut, dict]] = []
        marks: dict[str, list[tuple[datetime, str, str]]] = defaultdict(list)
        spoken: dict[tuple[str, str], list[tuple[dict, Cut | None, str, str]]] = defaultdict(list)     # by channel and event id
        for cut in sm.cuts:
            spoken[(str(cut.record.get("Channel", "")).lower(), str(cut.record.get("EventID", "")))].append((cut.record, cut, "", ""))
        for d in sm.down:
            for values, side in ((d.start, "from"), (d.end, "to")):
                spoken[(str(values.get("Channel", "")).lower(), str(values.get("EventID", "")))].append((values, None, d.id, side))
        for ev in events:
            t = parse_time(ev)
            if t is None:
                self.undated += 1
                continue
            name = first(ev, HOST_FIELDS).strip()
            host = name.lower()
            self.hosts.setdefault(host, name)
            src = route(ev)
            raw = str(ev.get("Channel") or ev.get("channel") or "").strip()
            label = raw or (src or "other records")
            key = label.lower()
            self.channels.setdefault(key, label)
            if raw and "linux" not in key:
                self.windows.add(host)
            self.streams[(host, key)].append(Rec(t, record_id(ev, sm.fields), ev, src))
            for values, which, ident, side in spoken.get((key, str(ev.get("EventID", "")).strip()), ()):
                if not holds(ev, values):
                    continue
                if which is not None:
                    pending.append((host, t, which, ev))
                else:
                    marks[host].append((t, ident, side))
            callers = {short(str(ev[f])) for f in ("WorkstationName", "Workstation") if ev.get(f)}
            ip = str(ev.get("IpAddress") or ev.get("src_host") or "").replace("::ffff:", "")
            if ip in self.assets and self.assets[ip].get("host"):
                callers.add(short(str(self.assets[ip]["host"])))
            for who in callers:                                       # one record names a client once, by name or by address
                named[who].append((t, name))
        per_host: dict[str, list[str]] = defaultdict(list)
        for host, key in self.streams:
            per_host[host].append(key)
        self.per_host = {h: sorted(ks) for h, ks in per_host.items()}
        for host, t, cut, ev in pending:
            for key in cut.targets(ev, self.per_host.get(host, [])):
                cuts[(host, key)].append((t, cut, ev))
        self.cuts = {k: sorted(v, key=lambda x: x[0]) for k, v in cuts.items()}
        self.marks = {h: sorted(v) for h, v in marks.items()}
        self.named = {h: sorted((t, by) for t, by in v if short(by) != h) for h, v in named.items()}
        self.ordered = {k: order(v) for k, v in self.streams.items()}
        self.times = {k: sorted(r.time for r in o[0]) for k, o in self.ordered.items()}
        every = [t for ts in self.times.values() for t in (ts[0], ts[-1])]
        self.start: datetime | None = min(every) if every else None
        self.end: datetime | None = max(every) if every else None

    def seen_by_others(self, host: str, lo: datetime, hi: datetime) -> str:
        """Who recorded the host inside a stretch its own channels have no record for."""
        calls = self.named.get(short(host), [])
        a, b = bisect.bisect_right(calls, (lo, "￿")), bisect.bisect_left(calls, (hi, ""))
        if b <= a:
            return ""
        by = Counter(who for _t, who in calls[a:b])
        top, n = by.most_common(1)[0]
        more = f" (and {plural(len(by) - 1, 'other host')})" if len(by) > 1 else ""
        return f"{top} recorded {plural(n, 'event')} naming it meanwhile{more}"

    def down(self, host: str, start: datetime, end: datetime, edge: str) -> str:
        """The name of the shutdown or sleep whose records bracket a stretch, if one does."""
        marks = self.marks.get(host, [])
        for d in self.sm.down:
            began = any(k == d.id and side == "from" and start - MARGIN <= t <= start + CLOSE for t, k, side in marks)
            ended = any(k == d.id and side == "to" and end - CLOSE <= t <= end + MARGIN for t, k, side in marks)
            if (began or edge == "lead") and (ended or edge == "trail") and (began or ended):
                return d.name
        return ""


# --------------------------------------------------------------------------- #
# One sensor: the records of one channel of one host, and where its proof holds
# --------------------------------------------------------------------------- #
@dataclass
class Hole:
    """A stretch a sensor's proof does not cover."""
    start: datetime
    end: datetime
    kind: str                       # down | restarted | cleared | missing | stopped | quiet
    missing: int = 0
    found: list[tuple[datetime, Cut]] = field(default_factory=list)
    shutdown: bool = False          # a shutdown or sleep record opens it
    opened: str = ""                # stop | start: what the first record that speaks of it says
    numbers: str = ""
    edge: str = ""                  # lead | trail: before the first record or after the last
    index: int = HEAD               # how many records of the stream come before it
    detail: str = ""
    life: str = ""
    severity: str = "medium"

    @property
    def seconds(self) -> float:
        return max(0.0, (self.end - self.start).total_seconds())

    @property
    def cuts(self) -> list[str]:
        return list(dict.fromkeys(c.id for _t, c in self.found))


@dataclass
class Run:
    """A stretch of consecutive records with nothing between them that ends the proof."""
    i0: int
    i1: int
    start: datetime
    end: datetime


@dataclass
class Sensor:
    host: str
    key: str
    channel: str
    recs: list[Rec]
    mode: str                       # sequence | rhythm
    note: str
    bound: timedelta | None
    runs: list[Run]
    holes: list[Hole]
    splits: set[int]                # record indexes where the sensor's settings changed
    carriers: dict[str, list[int]]
    watched: Span | None = None     # the part of the window this sensor can answer for at all

    def spans(self) -> list[Run]:
        """The runs, cut again where the sensor's settings changed. The record of a change shows the sensor up
        on both sides of it."""
        out = []
        for run in self.runs:
            at, since = run.i0, run.start
            for s in sorted(x for x in self.splits if run.i0 < x <= run.i1):
                out.append(Run(at, s, since, self.recs[s].time))
                at, since = s, self.recs[s].time
            out.append(Run(at, run.i1, since, run.end))
        return out


def human(seconds: float) -> str:
    s = round(seconds)
    if s < 90:
        return f"{s} s"
    m = s // 60
    if m < 90:
        return f"{m} min"
    h, m = divmod(m, 60)
    if h < 48:
        return f"{h} h {m:02d} min" if m else f"{h} h"
    d, h = divmod(h, 24)
    return f"{d} d {h} h" if h else f"{d} d"


def clock(t: datetime) -> str:
    return t.strftime("%m-%d %H:%M")


def stamp(t: datetime | None) -> str:
    return "" if t is None else t.strftime("%Y-%m-%d %H:%M:%S")


def order(recs: list[Rec]) -> tuple[list[Rec], str, str, set[int]]:
    """The records in the order they were written, the grade of proof that order allows, why not the better one, and
    the places where the clock was set back.

    With record numbers the order is the numbers', whatever each record's own clock says: Windows stamps a resume
    record with the clock of the moment the host fell asleep and writes boot records after later ones, so a time
    that runs backwards for a record or two is ordinary. Each record then takes the latest time written so far."""
    with_id = [r for r in recs if r.rid is not None]
    if len(recs) >= 2 and len(with_id) >= 0.99 * len(recs):
        kept: list[Rec] = []
        again: list[datetime] = []                                   # the later of two different records under one number
        for r in sorted(with_id, key=lambda r: (r.rid, r.time)):
            if kept and kept[-1].rid == r.rid:
                if abs(r.time - kept[-1].time) > SKEW:
                    again.append(max(r.time, kept[-1].time))
                continue                                            # the same record exported twice
            kept.append(r)
        steps = [(b.rid or 0) - (a.rid or 0) for a, b in pairwise(kept)]
        consecutive = sum(1 for s in steps if s == 1)
        if again:
            note = "one record number is carried by two different records: the log was recreated, or two logs share this host name"
            by_time = sorted(recs, key=lambda r: (r.time, r.rid or 0))
            first = bisect.bisect_left([r.time for r in by_time], min(again))
            return by_time, "rhythm", note, {first} if first else set()      # the numbers start again at that record
        elif steps and consecutive / len(steps) < DENSE:
            note = (f"the export skips records ({consecutive} of {len(steps)} steps between record numbers are consecutive), "
                    "so the numbers cannot show whether one is missing")
        else:
            out: list[Rec] = []
            setbacks: set[int] = set()
            behind, at = 0, kept[0].time
            for i, r in enumerate(kept):
                behind = behind + 1 if r.time < at - BACK else 0
                if behind == 3:
                    setbacks.add(i - 2)
                at = max(at, r.time)
                out.append(Rec(at, r.rid, r.ev, r.src))
            return out, "sequence", "", setbacks
        return sorted(recs, key=lambda r: (r.time, r.rid or 0)), "rhythm", note, set()
    note = "the export carries no record numbers" if not with_id else "some records carry no record number"
    return sorted(recs, key=lambda r: (r.time, r.rid or 0)), "rhythm", note if len(recs) >= 2 else "", set()


def _quantile(gaps: list[timedelta], q: float) -> timedelta:
    return gaps[min(len(gaps) - 1, math.ceil(q * len(gaps)) - 1)]


def rhythm(gaps: list[timedelta]) -> timedelta | None:
    """The longest gap a channel may have before it counts as quiet: three times the gap it exceeds once in a hundred.
    A gap that is itself quiet against the others is left out of that count, or one long quiet would hide itself."""
    kept = sorted(g for g in gaps if g >= timedelta(0))
    while len(kept) > MIN_GAPS and kept[-1] > max(QUIET_FLOOR, QUIET_FACTOR * _quantile(kept[:-1], 0.99)):
        kept.pop()
    if len(kept) < MIN_GAPS:
        return None
    return min(max(QUIET_FLOOR, QUIET_FACTOR * _quantile(kept, 0.99)), QUIET_CEILING)


def sense(fleet: Fleet, host: str, key: str, by_source: dict[str, list[Target]], quiet: timedelta | None = None) -> Sensor:
    """The records of one channel of one host in order, cut into the runs its proof holds for."""
    recs, mode, note, setbacks = fleet.ordered[(host, key)]
    marks = fleet.marks.get(host, [])
    n = len(recs) - 1                                  # pairs of consecutive records
    times = [r.time for r in recs]
    where = {id(r.ev): i for i, r in enumerate(recs)}
    found: list[list[tuple[datetime, Cut]]] = [[] for _ in range(n)]
    head: list[tuple[datetime, Cut]] = []              # cuts before the first record
    tail: list[tuple[datetime, Cut]] = []              # cuts after the last
    stops: list[list[datetime]] = [[] for _ in range(n)]
    starts: list[list[datetime]] = [[] for _ in range(n)]

    def place(i: int, at: datetime, cut: Cut) -> None:
        (found[i] if 0 <= i < n else head if i < 0 else tail).append((at, cut))

    def pause(i: int) -> bool:
        return times[i + 1] - times[i] > DOWN_MIN

    # Windows does not write a stop or a start beside the pause it speaks of: more records follow a stop before the
    # host halts, and the kernel's boot records are written before the Event Log service says it started. A record of
    # this channel is therefore tied to the pause next to it; a record of another channel is placed by its time
    mine = [(t, cut, where.get(id(ev))) for t, cut, ev in fleet.cuts.get((host, key), [])]
    answers = {j for _t, cut, j in mine if cut.edge == "start" and j is not None}
    for t, cut, j in mine:
        if cut.edge != "stop":
            continue
        i = bisect.bisect_right(times, t) - 1 if j is None else j
        if j is not None:
            k = j
            while k < n and times[k] <= times[j] + CLOSE:
                if pause(k) or (k + 1) in answers:               # the pause, or the start that answers the stop
                    i = k
                    break
                k += 1
        place(i, t, cut)
    # a shutdown or sleep record opens the pause that follows it, looked for close after it and before the host is next
    # seen waking. A start or wake record opens nothing: it closes the pause its time falls in
    wakes = sorted(t for t, _k, side in marks if side == "to")
    for t, _k, side in marks if n > 0 else []:
        if side == "from":
            later = bisect.bisect_left(wakes, t)
            woke = wakes[later] if later < len(wakes) else None
            i = max(0, bisect.bisect_right(times, t) - 1)
            while i < n and times[i] <= t + CLOSE and (woke is None or times[i] < woke):
                if times[i + 1] - max(times[i], t) > DOWN_MIN:
                    stops[i].append(max(times[i], t))
                    break
                i += 1
        else:
            i = bisect.bisect_left(times, t) - 1
            if 0 <= i < n and times[i] < t <= times[i + 1]:
                starts[i].append(t)
    for t, cut, j in mine:
        if cut.edge == "stop":
            continue
        i = bisect.bisect_left(times, t) - 1 if j is None else j - 1
        if j is not None and cut.edge == "start":
            k = j - 1
            while k >= 0 and times[k + 1] >= times[j] - BOOT:         # back to the pause, or to the stop that explains it
                if pause(k) or stops[k] or any(c.edge == "stop" for _t, c in found[k]):
                    i = k
                    break
                k -= 1
        place(i, t, cut)
    plain = [times[i + 1] - times[i] for i in range(n)
             if not stops[i] and not starts[i] and not any(c.edge in ("stop", "start") for _t, c in found[i])]
    bound = quiet or rhythm(plain)

    breaks: dict[int, Hole] = {}
    splits: set[int] = set()
    for i in range(n):
        a, b = recs[i], recs[i + 1]
        gap = b.time - a.time
        edges = Counter(c.edge for _t, c in found[i])
        if edges["change"]:
            splits.add(i + 1)
        missing = max(0, (b.rid or 0) - (a.rid or 0) - 1) if mode == "sequence" else 0
        restarted = (i + 1) in setbacks
        kinds = ["restarted"] * restarted
        if edges["clear"] and (mode == "rhythm" or missing or restarted):
            kinds.append("cleared")
        elif missing:
            kinds.append("missing")
        if edges["stop"] or edges["start"] or stops[i]:
            kinds.append("stopped")
        if mode == "rhythm" and bound is not None and gap > bound:
            kinds.append("quiet")              # with whole record numbers a long quiet is not a break: nothing was taken out
        if not kinds:
            continue
        # the sensor is shown up until the first record of a stop and from the last record of a start, when nothing
        # is missing in between (by number) or the wait is one the channel ordinarily has (by rhythm)
        whole = mode == "sequence" and not missing and not restarted
        ends = [t for t, c in found[i] if c.edge == "stop"] + stops[i]
        begins = [t for t, c in found[i] if c.edge == "start"] + starts[i]
        lo, hi = min(a.time, b.time), max(a.time, b.time)
        start, end = lo, hi
        if ends and (whole or (bound is not None and min(ends) - lo <= bound)):
            start = min(hi, max(lo, min(ends)))
        if begins and (whole or (bound is not None and hi - max(begins) <= bound)):
            end = max(lo, min(hi, max(begins)))
        if end < start:
            start, end = lo, hi
        said = sorted([(t, 0, "stop") for t in ends] + [(t, 1, "start") for t in begins])
        numbers = f"between #{a.rid} and #{b.rid}" if a.rid is not None and b.rid is not None else ""
        breaks[i] = Hole(start, end, min(kinds, key=KIND_ORDER.index), missing, list(found[i]), bool(stops[i]),
                         said[0][2] if said else "", numbers, index=i)

    runs: list[Run] = []
    gaps: list[Hole] = []
    at = 0
    for i in sorted(breaks):
        runs.append(Run(at, i, recs[at].time, breaks[i].start))
        gaps.append(breaks[i])
        at = i + 1
    if recs:
        runs.append(Run(at, len(recs) - 1, recs[at].time, recs[-1].time))
    for k in range(1, len(runs)):
        runs[k].start = gaps[k - 1].end
    k = 1
    while k < len(runs) - 1:                                       # a restart writes a few records of its own between two breaks
        if runs[k].end - runs[k].start < MINOR_RUN:
            a_, b_ = gaps[k - 1], gaps[k]
            gaps[k - 1] = Hole(a_.start, b_.end, min((a_.kind, b_.kind), key=KIND_ORDER.index), a_.missing + b_.missing,
                               a_.found + b_.found, a_.shutdown or b_.shutdown, a_.opened or b_.opened, a_.numbers or b_.numbers,
                               index=a_.index)
            del gaps[k], runs[k]
        else:
            k += 1

    sensor = Sensor(host, key, fleet.channels[key], recs, mode, note, bound, runs, gaps, splits, defaultdict(list))
    for i, r in enumerate(recs):
        eid = str(r.ev.get("EventID", r.ev.get("EventCode", "")))
        for target in by_source.get(r.src or "", []):
            if not target.ids or eid in target.ids:
                sensor.carriers[target.id].append(i)
    if recs and fleet.start is not None and fleet.end is not None:
        since, until = runs[0].start, runs[-1].end
        opening = [(t, c) for t, c in head if c.edge in ("clear", "start")]
        closing = [(t, c) for t, c in tail if c.edge == "stop"]
        lead, trail = since - fleet.start, fleet.end - until
        if since >= fleet.end or until <= fleet.start:              # no record of the channel inside the window at all
            sensor.holes.insert(0, Hole(fleet.start, fleet.end, "quiet", edge="lead"))
            since, until = fleet.start, fleet.end
        elif lead > SKEW and (opening or (bound is not None and lead > bound)):
            kind = "cleared" if any(c.edge == "clear" for _t, c in opening) else ("stopped" if opening else "quiet")
            sensor.holes.insert(0, Hole(fleet.start, since, kind, 0, opening, opened="start" if opening else "", edge="lead"))
            since = fleet.start
        if until < fleet.end and trail > SKEW and (closing or (bound is not None and trail > bound)):
            shut = any(side == "from" and abs(t - until) <= MARGIN for t, _k, side in marks)
            sensor.holes.append(Hole(until, fleet.end, "stopped" if closing or shut else "quiet", 0, closing, shut,
                                     "stop" if closing or shut else "", edge="trail"))
            until = fleet.end
        sensor.watched = (max(since, fleet.start), min(until, fleet.end))
    return sensor


def settle(fleet: Fleet, sensors: dict[tuple[str, str], Sensor]) -> None:
    """Every hole said the way an analyst would say it, once the other channels of its host are known: was the host
    off, and did anything show it up meanwhile."""
    by_host: dict[str, list[Sensor]] = defaultdict(list)
    for (host, _key), s in sensors.items():
        by_host[host].append(s)
    for host, mine in by_host.items():
        for s in mine:
            for h in s.holes:
                margin = max(LIFE_MARGIN, (h.end - h.start) / 10)
                lo, hi = h.start + margin, h.end - margin
                life = []
                if hi > lo and h.kind in ("quiet", "stopped"):
                    for other in mine:                      # a channel that kept its own rhythm through the stretch
                        if other is s or any(o.start < hi and o.end > lo for o in other.holes):
                            continue
                        ts = fleet.times[(host, other.key)]
                        n = bisect.bisect_left(ts, hi) - bisect.bisect_right(ts, lo)
                        if n > 0:
                            life.append(f"the host wrote {plural(n, 'record')} to {other.channel} meanwhile")
                    seen = fleet.seen_by_others(host, lo, hi)
                    if seen:
                        life.append(seen)
                h.life = "; ".join(life)
                describe(fleet, s, h)


def describe(fleet: Fleet, s: Sensor, h: Hole) -> None:
    took = human(h.seconds)
    spoke = sorted(h.found, key=lambda x: x[0])
    names = list(dict.fromkeys(c.name for _t, c in spoke))
    stops = list(dict.fromkeys(c.name for _t, c in spoke if c.edge == "stop"))
    begins = list(dict.fromkeys(c.name for _t, c in spoke if c.edge == "start"))
    down = fleet.down(s.host, h.start, h.end, h.edge) if h.kind in ("quiet", "stopped") and not h.life else ""
    if down:
        h.kind, h.detail, h.severity = "down", f"{down} for {took}", "low"
    elif h.kind == "restarted":
        h.detail = f"the record order and the clock disagree {h.numbers}: the log was replaced or recreated, or the clock was set back"
        h.severity = "high"
    elif h.kind == "cleared":
        at = clock(next(t for t, c in h.found if c.edge == "clear"))
        if h.edge == "lead":
            h.detail, h.severity = f"cleared at {at}: nothing written before it is in this export", "high"
        elif h.missing:
            h.detail, h.severity = f"{plural(h.missing, 'record')} gone {h.numbers}: the channel was cleared at {at}", "high"
        else:
            h.detail = f"cleared at {at}; without record numbers nothing shows what was lost"
    elif h.kind == "missing" and h.index < HEAD and h.missing <= 3:
        h.detail = (f"{plural(h.missing, 'record')} missing {h.numbers}, at the head of the export: a time filter leaves out a record "
                    "stamped before the window, as the record of a wake is")
        h.severity = "low"
    elif h.kind == "missing":
        h.detail, h.severity = f"{plural(h.missing, 'record')} missing {h.numbers}, and no record says why", "high"
    elif h.kind == "stopped" and h.edge == "lead":
        h.detail, h.severity = f"{listed(begins or names)} at {clock(h.end)}: nothing before it is in this export", "low"
    elif h.kind == "stopped":
        if h.opened == "stop" or h.edge == "trail":
            said = listed(stops) if stops else "the host recorded that it was shutting down or going to sleep"
            h.detail = f"{said}; no record for {took}" + (f", then {listed(begins)}" if begins else "")
        else:
            h.detail = f"no record for {took}, then {listed(begins or names)}, and no record of a stop before it"
        h.severity = "high" if h.life else "medium"
    else:
        limit = f", against gaps of at most {human(s.bound.total_seconds())}" if s.bound else ""
        if h.edge == "lead" and fleet.end is not None and h.end >= fleet.end:
            h.detail, h.severity = "no record of the channel inside the window", "medium"
        elif h.edge == "lead":
            h.detail, h.severity = f"no record until {clock(h.end)}, {took} into the window{limit}", "low"
        elif h.edge == "trail":
            h.detail = f"no record after {clock(h.start)}, for the last {took} of the window{limit}"
        else:
            h.detail = f"no record for {took}{limit}"
        if h.life:
            h.severity = "high"


# --------------------------------------------------------------------------- #
# The verdicts
# --------------------------------------------------------------------------- #
def union(intervals: list[Span]) -> list[Span]:
    out: list[Span] = []
    for a, b in sorted(intervals):
        if out and a <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], b))
        else:
            out.append((a, b))
    return out


def clip(intervals: list[Span], start: datetime, end: datetime) -> list[Span]:
    return [(max(a, start), min(b, end)) for a, b in intervals if min(b, end) > max(a, start)]


def length(intervals: list[Span]) -> float:
    return sum((b - a).total_seconds() for a, b in intervals)


def minus(intervals: list[Span], holes: list[Span]) -> list[Span]:
    out = []
    for a, b in intervals:
        at = a
        for x, y in holes:
            if y <= at or x >= b:
                continue
            if x > at:
                out.append((at, x))
            at = max(at, y)
        if at < b:
            out.append((at, b))
    return out


def judge(fleet: Fleet, sensors: dict[tuple[str, str], Sensor], t: Target, host: str, alerts: list[dict],
          ready: dict | None, start: datetime, end: datetime) -> dict:
    """The verdict of one detection on one host over the window."""
    row: dict[str, Any] = {"detection": t.id, "host": fleet.hosts.get(host, host), "verdict": "unattested", "grade": None,
                           "coverage": 0.0, "attested_seconds": 0.0, "watched_seconds": (end - start).total_seconds(),
                           "down_seconds": 0.0, "sensors": [], "intervals": [], "holes": [], "caveats": [], "reason": None,
                           "why": None, "alerts": 0}
    if alerts:
        times = sorted(a["time"] for a in alerts if a.get("time"))
        row.update(verdict="fired", alerts=len(alerts), first_alert=stamp(times[0]) if times else "")
    here = [s for (h, _k), s in sorted(sensors.items()) if h == host]
    mine = [s for s in here if (s.key == t.channel if t.proof == "channel" else bool(s.carriers.get(t.id)))]
    if not mine:
        carrier = next((s for s in here if s.key == t.channel), None) if t.channel else \
            next((s for s in here if any(r.src == t.logsource for r in s.recs)), None)
        if t.proof == "channel":
            row.update(reason="no_record", why=f"no record of the {t.channel_name} channel from this host is in the export")
        elif carrier is not None:
            row.update(reason="no_proof", why=f"{carrier.channel} is in the export and no {t.reads} is in it: nothing shows the "
                                              "sensor was set to write one")
        else:
            row.update(reason="no_record", why=f"no {t.reads} from this host is in the export")
        return row
    row["sensors"] = [s.channel for s in mine]
    blind = ready is not None and ready.get("verdict") == "BLIND" and ready.get("events") and any(
        v == 0 for v in (ready.get("coverage") or {}).values())
    if blind and ready is not None and t.proof == "event":
        issue = next((i for i in ready["issues"] if "missing" in i), ready["issues"][0] if ready["issues"] else "a field is missing")
        row.update(reason="blind", why=f"the sensor writes the record and the rule cannot read it: {issue}")
        return row
    intervals: list[Span] = []
    downs: list[list[Span]] = []
    for s in mine:
        if t.proof == "channel":
            intervals += [(r.start, r.end) for r in s.runs]
        else:
            marks = s.carriers.get(t.id) or []
            for r in s.spans():
                if bisect.bisect_right(marks, r.i1) > bisect.bisect_left(marks, r.i0):
                    intervals.append((r.start, r.end))
                elif r.end - r.start > SKEW:
                    row["holes"].append({"kind": "unproven", "severity": "medium", "channel": s.channel, "start": stamp(r.start),
                                         "end": stamp(r.end), "seconds": (r.end - r.start).total_seconds(), "missing": 0, "life": "",
                                         "cuts": [], "edge": "",
                                         "detail": f"no {t.reads} in this stretch: nothing shows the sensor was set to write one"})
        downs.append([(h.start, h.end) for h in s.holes if h.kind == "down"])
        row["holes"] += [hole_json(h, s) for h in s.holes if h.kind != "down"]
    spans = [s.watched for s in mine if s.watched]
    w0, w1 = (min(a for a, _b in spans), max(b for _a, b in spans)) if spans else (start, end)
    w0, w1 = max(w0, start), min(w1, end)
    away = union(downs[0])
    for other in downs[1:]:                                    # two sensors: time off is where both were off
        away = minus(away, minus(away, union(other)))
    off = clip(away, w0, w1) if w1 > w0 else []
    watched = length(minus([(w0, w1)], off)) if w1 > w0 else 0.0
    covered = minus(clip(union(intervals), w0, w1), off) if w1 > w0 else []
    attested = length(covered)
    row.update(attested_seconds=attested, watched_seconds=watched, coverage=round(attested / watched, 4) if watched > 0 else 0.0,
               intervals=[[stamp(a), stamp(b)] for a, b in covered], down_seconds=length(off))
    if ready is not None and ready.get("verdict") == "DEGRADED":
        row["caveats"] += ready.get("issues") or []
    if t.proof == "channel" and not any(s.carriers.get(t.id) for s in mine):
        row["caveats"].append(f"no {t.reads} is in the window, so nothing confirms its fields survive this pipeline")
    if row["verdict"] == "fired":
        return row
    if attested <= 0:
        row.update(reason="no_stretch", why="the sensor's records are there and no stretch of them is bracketed by proof: "
                                            + (row["holes"][0]["detail"] if row["holes"] else "too few records"))
        return row
    row.update(verdict="attested", grade="sequence" if all(s.mode == "sequence" for s in mine) else "rhythm")
    return row


def hole_json(h: Hole, s: Sensor) -> dict:
    return {"kind": h.kind, "severity": h.severity, "channel": s.channel, "start": stamp(h.start), "end": stamp(h.end),
            "seconds": h.seconds, "detail": h.detail, "missing": h.missing, "life": h.life, "cuts": h.cuts, "edge": h.edge}


def assess(events: list[dict], sm: Model | None = None, trace: survivability.Model | None = None, *, assets: dict | None = None,
           profile: str = profiles.NATIVE, quiet: timedelta | None = None, start: datetime | None = None,
           end: datetime | None = None, filter_: str | None = None, only_host: str | None = None) -> dict:
    """Every detection on every host of an export: fired, attested or unattested, with the breaks in the record."""
    sm = sm or load_model()
    trace = trace or survivability.load_model()
    fleet = Fleet(events, sm, assets)
    wanted = targets(sm, trace, filter_)
    by_source: dict[str, list[Target]] = defaultdict(list)
    for t in wanted:
        by_source[t.logsource].append(t)
    if fleet.start is None or fleet.end is None:
        raise SilenceError("no record of the export carries a time this tool can read")
    w0, w1 = start or fleet.start, end or fleet.end
    if w1 <= w0:
        raise SilenceError("the window is empty: --to must be later than --from" if start or end else
                           "every record of the export carries the same time: a stretch needs two records at different times")
    fleet.start, fleet.end = w0, w1
    hosts = sorted(h for h in fleet.hosts if not only_host or only_host.lower() in (h, short(h)))
    if only_host and not hosts:
        raise SilenceError(f"no record of the export comes from host '{only_host}'")
    every = {(h, k): sense(fleet, h, k, by_source, quiet) for (h, k) in sorted(fleet.streams)}
    settle(fleet, every)
    sensors = {k: s for k, s in every.items() if k[0] in hosts}

    dets, corrs = load_detections(), load_correlations()
    alerts, _stats = run_replay(events, dets, assets or {}, corrs=corrs)
    alerts = [a for a in alerts if a.get("time") is None or w0 <= a["time"] <= w1]
    fired: dict[tuple[str, str], list[dict]] = defaultdict(list)
    fired_corr: dict[str, list[dict]] = defaultdict(list)
    for a in alerts:
        if a.get("correlation"):
            fired_corr[a["rule"]].append(a)
        else:
            fired[(a["rule"], str(a.get("host", "")).strip().lower())].append(a)

    likes = [SimpleNamespace(id=t.id, rule=t.rule, contract=t.contract) for t in wanted]
    ready: dict[tuple[str, str], dict] = {}
    for h in hosts:
        evs = [r.ev for (hh, _k), recs in fleet.streams.items() if hh == h for r in recs]
        for res in doctor.diagnose(evs, likes, profile):
            ready[(h, res["detection"])] = res

    rows: list[dict] = []
    for t in wanted:
        if t.reach == "host":
            scope = [h for h in hosts if h in fleet.windows]
        else:
            scope = [h for h in hosts if any(s.carriers.get(t.id) for (hh, _k), s in sensors.items() if hh == h)]
        if not scope:
            rows.append({"detection": t.id, "host": None, "verdict": "fired" if fired_corr.get(t.id) else "unattested", "grade": None,
                         "coverage": 0.0, "attested_seconds": 0.0, "watched_seconds": 0.0, "down_seconds": 0.0, "sensors": [],
                         "intervals": [], "holes": [], "caveats": [], "reason": "no_observer",
                         "alerts": len(fired_corr.get(t.id, [])), "why": f"no host in the export writes what this rule reads: {t.reads}"})
            continue
        for h in scope:
            got = fired_corr.get(t.id, []) if t.kind == "correlation" else fired.get((t.id, h), [])
            rows.append(judge(fleet, sensors, t, h, got, ready.get((h, t.id)), w0, w1))

    folders = {d.id: d.folder for d in dets} | {c.id: c.folder for c in corrs}
    detections = {}
    for t in wanted:
        mine = [r for r in rows if r["detection"] == t.id]
        watched = sum(r["watched_seconds"] for r in mine if r["host"])
        detections[t.id] = {
            "title": t.title, "kind": t.kind, "reads": t.reads, "proof": t.proof, "reach": t.reach, "why": t.why, "enable": t.enable,
            "behaviour": behaviour(folders.get(t.id)),
            "blind_spots": len(((t.contract.get("detection_logic") or {}).get("blind_spots")) or []),
            "hosts": sum(1 for r in mine if r["host"]), "attested": sum(1 for r in mine if r["verdict"] == "attested"),
            "fired": sum(1 for r in mine if r["verdict"] == "fired"),
            "unattested": sum(1 for r in mine if r["verdict"] == "unattested"),
            "coverage": round(sum(r["attested_seconds"] for r in mine) / watched, 4) if watched else 0.0,
        }
    counts = Counter(r["verdict"] for r in rows)
    watched = sum(r["watched_seconds"] for r in rows if r["host"])
    return {
        "format": FORMAT, "rasd": VERSION, "profile": profile,
        "window": {"start": stamp(w0), "end": stamp(w1), "seconds": (w1 - w0).total_seconds()},
        "records": fleet.total, "undated": fleet.undated, "hosts": [fleet.hosts[h] for h in hosts],
        "claim": sm.claim, "limits": sm.limits, "position": trace.position,
        "counts": {"pairs": len(rows), "fired": counts.get("fired", 0), "attested": counts.get("attested", 0),
                   "unattested": counts.get("unattested", 0),
                   "coverage": round(sum(r["attested_seconds"] for r in rows) / watched, 4) if watched else 0.0,
                   "sequence": sum(1 for r in rows if r["grade"] == "sequence"),
                   "rhythm": sum(1 for r in rows if r["grade"] == "rhythm")},
        "detections": detections, "pairs": rows, "breaks": breaks_of(fleet, sensors, w0, w1), "down": downs_of(fleet, sensors, w0, w1),
        "sensors": [sensor_json(fleet, s) for _k, s in sorted(sensors.items())],
        "alerts": [{"time": stamp(a.get("time")), "rule": a["rule"], "host": a.get("host"), "entity": a.get("entity"),
                    "summary": a.get("summary", "")} for a in alerts],
    }


def sensor_json(fleet: Fleet, s: Sensor) -> dict:
    ids = [r.rid for r in s.recs if r.rid is not None]
    return {"host": fleet.hosts.get(s.host, s.host), "channel": s.channel, "records": len(s.recs), "grade": s.mode, "note": s.note,
            "first": stamp(s.recs[0].time) if s.recs else "", "last": stamp(s.recs[-1].time) if s.recs else "",
            "first_number": min(ids) if ids else None, "last_number": max(ids) if ids else None,
            "quiet_after_seconds": s.bound.total_seconds() if s.bound else None, "runs": len(s.runs),
            "runs_at": [[stamp(r.start), stamp(r.end)] for r in s.runs], "holes": [hole_json(h, s) for h in s.holes],
            "breaks": sum(1 for h in s.holes if h.kind != "down"), "down_seconds": sum(h.seconds for h in s.holes if h.kind == "down")}


def breaks_of(fleet: Fleet, sensors: dict[tuple[str, str], Sensor], start: datetime, end: datetime) -> list[dict]:
    """Every stretch a sensor's proof does not cover, one row per stretch: a stop that silences every channel of a
    host is one break, told by the channel whose records say the most about it."""
    rows: list[dict] = []
    for (host, _key), s in sorted(sensors.items()):
        for h in s.holes:
            if h.kind == "down" or h.end <= start or h.start >= end:
                continue
            same = next((r for r in rows if r["_host"] == host and h.kind in ("stopped", "quiet") and r["kind"] in ("stopped", "quiet")
                         and r["_start"] < h.end and r["_end"] > h.start), None)
            if same is None:
                rows.append({"severity": h.severity, "host": fleet.hosts.get(host, host), "channels": [s.channel], "kind": h.kind,
                             "start": stamp(h.start), "end": stamp(h.end), "seconds": h.seconds, "detail": h.detail,
                             "missing": h.missing, "life": h.life, "cuts": h.cuts, "edge": h.edge,
                             "_host": host, "_start": h.start, "_end": h.end, "_said": len(h.found)})
                continue
            same["channels"].append(s.channel)
            same["_start"], same["_end"] = min(same["_start"], h.start), max(same["_end"], h.end)
            same.update(start=stamp(same["_start"]), end=stamp(same["_end"]), seconds=(same["_end"] - same["_start"]).total_seconds(),
                        severity=min(same["severity"], h.severity, key=SEVERITY_ORDER.index),
                        cuts=list(dict.fromkeys(same["cuts"] + h.cuts)), life=same["life"] or h.life)
            if len(h.found) > same["_said"] or (h.kind == "stopped" and same["kind"] == "quiet"):
                same.update(detail=h.detail, kind=h.kind, _said=len(h.found))
    rows.sort(key=lambda b: (SEVERITY_ORDER.index(b["severity"]), b["start"], b["host"], b["channels"]))
    return [{k: v for k, v in r.items() if not k.startswith("_")} for r in rows]


def downs_of(fleet: Fleet, sensors: dict[tuple[str, str], Sensor], start: datetime, end: datetime) -> list[dict]:
    """The stretches a host was off or asleep, which count neither for nor against a detection."""
    out: list[dict] = []
    for (host, _key), s in sorted(sensors.items()):
        for h in s.holes:
            if h.kind != "down" or h.end <= start or h.start >= end:
                continue
            same = next((d for d in out if d["_host"] == host and d["_start"] < h.end and d["_end"] > h.start), None)
            if same is None:
                out.append({"host": fleet.hosts.get(host, host), "what": h.detail.split(" for ")[0], "_host": host,
                            "_start": h.start, "_end": h.end})
            else:
                same["_start"], same["_end"] = min(same["_start"], h.start), max(same["_end"], h.end)
    out.sort(key=lambda d: (d["_host"], d["_start"]))
    return [{"host": d["host"], "start": stamp(d["_start"]), "end": stamp(d["_end"]),
             "seconds": (d["_end"] - d["_start"]).total_seconds(), "what": d["what"]} for d in out]


# --------------------------------------------------------------------------- #
# This host
# --------------------------------------------------------------------------- #
def wevtutil() -> str | None:
    """The Windows tool that reads event logs, where there is one."""
    return shutil.which("wevtutil") if os.name == "nt" else None


def collect(days: float, channels: tuple[str, ...] = LIVE_CHANNELS) -> tuple[list[dict], list[dict]]:
    """The records this Windows host wrote in the last `days`, read with wevtutil (read only), and what happened per channel."""
    from datasets import EVENT_RE, xml_event           # imported here: datasets is large and only this path reads XML
    tool = wevtutil()
    if not tool:
        raise SilenceError("reading this host's own logs needs Windows and wevtutil: pass an export instead (rasd silence EXPORT)")
    ms = int(days * 86_400_000)
    events: list[dict] = []
    notes = []

    def read(channel: str, query: str, limit: int) -> tuple[list[dict], int, str]:
        """wevtutil's answer, parsed a piece at a time from a file: a large log is never held as one text."""
        cmd = [tool, "qe", channel, "/f:xml", "/uni:true", "/rd:false", f"/c:{limit}", f"/q:{query}"]
        got: list[dict] = []
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as errors:
            code = subprocess.run(cmd, stdout=out, stderr=errors, check=False).returncode
            errors.seek(0)
            raw = errors.read(65536)
            err = (raw.decode("utf-16-le", errors="replace") + raw.decode(errors="replace")).lower()
            out.seek(0)
            decode, text = codecs.getincrementaldecoder("utf-16-le")(errors="replace"), ""
            while True:
                piece = out.read(1 << 20)
                text += decode.decode(piece, final=not piece)
                last = 0
                for m in EVENT_RE.finditer(text):
                    ev = xml_event(m.group(0))
                    if ev:
                        got.append(ev)
                    last = m.end()
                text = text[last:]
                if not piece:
                    break
        return got, code, err

    for channel in channels:
        # the first record of the window by time, then every record from its number on: a record stamped with an old
        # clock (the record of a wake) is inside the numbers and outside a time filter
        got, code, err = read(channel, f"*[System[TimeCreated[timediff(@SystemTime) <= {ms}]]]", 1)
        if got and isinstance(got[0].get("EventRecordID"), int):
            got, code, err = read(channel, f"*[System[(EventRecordID >= {got[0]['EventRecordID']})]]", LIVE_LIMIT)
        events += got
        if got:
            state = "read" + (f" (the first {LIVE_LIMIT} records of the window)" if len(got) >= LIVE_LIMIT else "")
        elif not code:
            state = "read: no record in the window"
        elif "denied" in err or code == 5:
            state = "not readable without elevation: run from an elevated prompt to include it"
        elif code == 15007 or "could not be found" in err:
            state = "the channel does not exist on this host"
        else:
            state = f"wevtutil ended with code {code}"
        notes.append({"channel": channel, "records": len(got), "state": state})
    return events, notes


# --------------------------------------------------------------------------- #
# Check
# --------------------------------------------------------------------------- #
def check(sm: Model, trace: survivability.Model) -> list[str]:
    errs: list[str] = []
    where = MODEL.relative_to(ROOT).as_posix()
    if not sm.claim:
        errs.append(f"{where}: claim is empty")
    if not sm.fields:
        errs.append(f"{where}: sequence.fields names no record number field")
    if not sm.limits:
        errs.append(f"{where}: limits is empty: a certificate must say what it does not say")
    for aid, w in sm.witnesses.items():
        if aid not in trace.artifacts:
            errs.append(f"{where}: witness {aid} is not an artifact of dfir/trace/model.yml")
            continue
        if w.proof not in PROOFS:
            errs.append(f"{where}: witness {aid}: proof must be one of {', '.join(PROOFS)}")
        if w.basis not in BASES:
            errs.append(f"{where}: witness {aid}: basis must be one of {', '.join(BASES)}")
        if not w.why or not w.enable:
            errs.append(f"{where}: witness {aid}: why and enable are both needed")
        store = trace.stores.get(trace.artifacts[aid].store) or {}
        if w.proof == "channel" and not store.get("channel"):
            errs.append(f"{where}: witness {aid}: a channel proof needs a store with a channel, and {trace.artifacts[aid].store} has none")
    read = {fp.reads for fp in trace.footprints.values()}
    errs += [f"{where}: no witness for {a}, which a detection reads (dfir/trace/footprints.yml)" for a in sorted(read - set(sm.witnesses))]

    by_source = survivability.rules_by_source()
    known = {d.id for ds in by_source.values() for d in ds}
    seen: set[str] = set()
    for c in sm.cuts:
        at = f"{where}: cut {c.id}"
        if not c.id or c.id in seen:
            errs.append(f"{at}: every cut needs its own id")
        seen.add(c.id)
        if c.edge not in EDGES:
            errs.append(f"{at}: edge must be one of {', '.join(EDGES)}")
        if c.basis not in BASES:
            errs.append(f"{at}: basis must be one of {', '.join(BASES)}")
        if c.source is not None and not str(c.source).startswith("https://"):
            errs.append(f"{at}: source must be an https URL")
        if "Channel" not in c.record or "EventID" not in c.record:
            errs.append(f"{at}: `record` must name at least a Channel and an EventID")
        if not (c.cuts in ("all", "named") or (isinstance(c.cuts, tuple) and c.cuts)):
            errs.append(f"{at}: cuts must be a list of channels, `named` or `all`")
        errs += [f"{at}: erasure {e} is not in dfir/trace/model.yml" for e in c.erasures if e not in trace.erasures]
        if c.detection and c.detection not in known:
            errs.append(f"{at}: detection {c.detection} does not exist")
        for e in c.erasures:                       # a cut a rule reads must be a trace RASD-Trace gives that rule too
            marks = trace.erasures[e].marks if e in trace.erasures else ()
            if c.detection and not any(m.detection == c.detection for m in marks):
                errs.append(f"{at}: {e} leaves no trace read by {c.detection} in dfir/trace/model.yml")
        if not c.event:
            errs.append(f"{at}: a sample event is needed, so the engine can say which rule reads this record")
            continue
        if not holds(c.event, c.record):
            errs.append(f"{at}: the sample event is not a record that `record` describes")
        got = survivability.fired(c.event, by_source)
        want = [c.detection] if c.detection else []
        if got != want:
            errs.append(f"{at}: the sample event fires {got or 'no rule'}, the model says {want or 'no rule'}"
                        + ("" if want else " (a rule now reads this record: name it in `detection`)"))
    for d in sm.down:
        at = f"{where}: down {d.id}"
        if d.basis not in BASES:
            errs.append(f"{at}: basis must be one of {', '.join(BASES)}")
        if not d.start or not d.end:
            errs.append(f"{at}: both `from` and `to` are needed")
    return errs


def cut_events_fire(sm: Model) -> list[str]:
    """Each cut's sample event against the engine, without the rest of the check (for the tests)."""
    by_source = survivability.rules_by_source()
    out = []
    for c in sm.cuts:
        if c.event:
            try:
                got = [d.id for d in by_source.get(route(c.event) or "", []) if matches(d.rule, c.event)]
            except SigmaError as e:
                out.append(f"{c.id}: {e}")
                continue
            if sorted(got) != ([c.detection] if c.detection else []):
                out.append(f"{c.id}: fires {sorted(got)}")
    return out


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def pct(x: float) -> str:
    return "100%" if x >= 0.99995 else f"{100 * x:.1f}%"


def scope_text(b: dict) -> str:
    if not b["spec"]:
        return "tested on samples; no behaviour spec proves it over every event"
    n = len(b["gaps"])
    gaps = f"{plural(n, 'documented variant')} slip{'s' * (n == 1)} past" if n else "no known gap"
    return f"{plural(b['fires'], 'variant')} proven on every event · {gaps}"


def sample_result() -> dict:
    if not SAMPLE_EXPORT.exists():
        raise SilenceError(f"{SAMPLE_EXPORT.relative_to(ROOT)} is missing: python samples/silence/generate.py")
    return assess(load_jsonl(SAMPLE_EXPORT), assets=load_assets(str(SAMPLE_ASSETS)) if SAMPLE_ASSETS.exists() else {})


@functools.lru_cache(maxsize=1)
def sample_summary() -> dict:
    """For the metrics pages: the size of the model and the verdicts on the sample fleet."""
    sm, res = load_model(), sample_result()
    return {"witnesses": len(sm.witnesses), "cuts": len(sm.cuts), "down": len(sm.down), "hosts": len(res["hosts"]),
            "records": res["records"], "breaks": len(res["breaks"]), **res["counts"]}


def summary_line(res: dict) -> str:
    c = res["counts"]
    high = sum(1 for b in res["breaks"] if b["severity"] == "high")
    return (f"{c['pairs']} detection-host pairs: {c['attested']} attested ({c['sequence']} by record sequence, {c['rhythm']} by rhythm), "
            f"{c['fired']} fired, {c['unattested']} unattested · {pct(c['coverage'])} of the watched time attested · "
            f"{plural(len(res['breaks']), 'break')} in the record ({high} high)")


def break_rows(res: dict) -> list[str]:
    rows = []
    for b in res["breaks"]:
        channel = b["channels"][0] if len(b["channels"]) == 1 else f"{len(b['channels'])} channels"
        rows.append(f"| {b['severity']} | {b['host']} | {channel} | {b['start']} | {b['end']} | {md_text(b['detail'])} | "
                    f"{md_text(b['life'])} |")
    return rows


def sensor_rows(res: dict) -> list[str]:
    rows = []
    for s in res["sensors"]:
        numbers = f"{s['first_number']} to {s['last_number']}" if s["first_number"] is not None else ""
        after = human(s["quiet_after_seconds"]) if s["quiet_after_seconds"] else "too few records to say"
        off = human(s["down_seconds"]) if s["down_seconds"] else ""
        rows.append(f"| {s['host']} | {s['channel']} | {s['records']} | {numbers} | {s['grade']} | {after} | {s['breaks']} | {off} | "
                    f"{md_text(s['note'])} |")
    return rows


def render(res: dict) -> str:
    """The results block of dfir/silence/README.md, from the sample fleet."""
    w = res["window"]
    lines = [
        BLOCK_START,
        f"**Sample fleet:** `samples/silence/fleet.jsonl`, {res['records']} records from {len(res['hosts'])} hosts over "
        f"{human(w['seconds'])} ({w['start']} to {w['end']} UTC).",
        "",
        summary_line(res) + ".",
        "",
        "| Detection | Reads | Hosts | Attested | Fired | Unattested | Watched time attested |",
        "|---|---|---|---|---|---|---|",
    ]
    for ident, d in res["detections"].items():
        lines.append(f"| `{ident}` | {md_text(d['reads'])} | {d['hosts']} | {d['attested']} | {d['fired']} | {d['unattested']} | "
                     f"{pct(d['coverage']) if d['hosts'] else ''} |")
    lines += ["", "<sub>attested: quiet, between two proofs that the sensor was recording, with every record between them present · "
              "fired: the rule raised an alert · unattested: quiet, and nothing shows the sensor could have spoken.</sub>", "",
              "### Breaks in the record", "",
              "Every stretch a sensor's proof does not cover, the gravest first.", "",
              "| Severity | Host | Channel | From | To | What the records say | The host meanwhile |", "|---|---|---|---|---|---|---|",
              *break_rows(res)]
    if res["down"]:
        lines += ["", "Not counted for or against any detection: "
                  + "; ".join(f"{d['host']} {d['what']} for {human(d['seconds'])} ({d['start']} to {d['end']})" for d in res["down"]) + "."]
    lines += ["", "### Quiet that proves nothing", "",
              "| Detection | Host | Why | What would make it evidence |", "|---|---|---|---|"]
    for r in res["pairs"]:
        if r["verdict"] == "unattested":
            d = res["detections"][r["detection"]]
            lines.append(f"| `{r['detection']}` | {r['host'] or 'none'} | {md_text(r['why'] or '')} | {md_text(d['enable'])} |")
    lines += ["", "### Sensors", "",
              "| Host | Channel | Records | Record numbers | Grade | Quiet after | Breaks | Off | Note |", "|---|---|---|---|---|---|---|---|---|",
              *sensor_rows(res), BLOCK_END]
    return "\n".join(lines)


def with_block(text: str, block: str) -> str:
    if BLOCK_START not in text or BLOCK_END not in text:
        raise SilenceError(f"{README.relative_to(ROOT)}: the markers {BLOCK_START} and {BLOCK_END} are missing")
    head, rest = text.split(BLOCK_START, 1)
    return head + block + rest.split(BLOCK_END, 1)[1]


def certificate(res: dict, inputs: list[dict], notes: list[dict] | None = None, how: str = "") -> str:
    """The certificate: what was read, what is claimed, every verdict with what it rests on, and what it does not say."""
    w, c = res["window"], res["counts"]
    issued = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    lines = ["# Certificate of silence", "",
             f"Issued by RASD {res['rasd']} on {issued} UTC, for the window {w['start']} to {w['end']} UTC ({human(w['seconds'])}).", "",
             "## The claim", "", res["claim"] + ".", "", f"**Position of the intruder:** {res['position']}.", "",
             "## What was read", "", "| Input | Records | SHA-256 |", "|---|---|---|"]
    lines += [f"| `{md_text(i['name'])}` | {i['records']} | `{i['sha256']}` |" for i in inputs]
    lines += [f"| {n['channel']} (this host) | {n['records']} | {n['state']} |" for n in notes or []]
    lines += ["", f"{plural(res['records'], 'record')} from {plural(len(res['hosts']), 'host')}, read with the `{res['profile']}` profile"
              + (f"; {res['undated']} carried no readable time and were left out" if res["undated"] else "") + ".", "",
              "## The verdict", "", summary_line(res) + ".", ""]
    fired = [r for r in res["pairs"] if r["verdict"] == "fired"]
    if fired:
        lines += ["### The quiet is broken", "", "| Detection | Host | Alerts | First |", "|---|---|---|---|"]
        lines += [f"| `{r['detection']}` | {r['host'] or 'the fleet'} | {r['alerts']} | {r.get('first_alert', '')} |" for r in fired]
        lines += ["", "`rasd replay` turns these alerts into storylines and case folders.", ""]
    lines += ["### Attested", "",
              "| Detection | Host | Watched time attested | Grade | Sensor | What the quiet covers |", "|---|---|---|---|---|---|"]
    for r in res["pairs"]:
        if r["verdict"] == "attested":
            d = res["detections"][r["detection"]]
            lines.append(f"| `{r['detection']}` | {r['host']} | {pct(r['coverage'])} of {human(r['watched_seconds'])} | {r['grade']} | "
                         f"{', '.join(r['sensors'])} | {md_text(scope_text(d['behaviour']))} |")
    if not c["attested"]:
        lines.append("| none | | | | | |")
    lines += ["", "### Quiet that proves nothing", "", "| Detection | Host | Why | What would make it evidence |", "|---|---|---|---|"]
    for r in res["pairs"]:
        if r["verdict"] == "unattested":
            lines.append(f"| `{r['detection']}` | {r['host'] or 'none'} | {md_text(r['why'] or '')} | "
                         f"{md_text(res['detections'][r['detection']]['enable'])} |")
    if not c["unattested"]:
        lines.append("| none | | | |")
    lines += ["", "## Breaks in the record", ""]
    if res["breaks"]:
        lines += ["| Severity | Host | Channel | From | To | What the records say | The host meanwhile |", "|---|---|---|---|---|---|---|",
                  *break_rows(res)]
    else:
        lines.append("None: every sensor's records are bracketed and complete over the window.")
    if res["down"]:
        lines += ["", "Not counted for or against any detection: "
                  + "; ".join(f"{d['host']} {d['what']} for {human(d['seconds'])} ({d['start']} to {d['end']})" for d in res["down"]) + "."]
    gaps = [(i, d) for i, d in res["detections"].items() if d["behaviour"]["gaps"]]
    if gaps:
        lines += ["", "## Documented variants a quiet rule does not cover", "",
                  "Each is a known gap of `rasd certify`, with an engine-confirmed event in docs/CERTIFICATES.md. An attested verdict "
                  "does not speak for them.", ""]
        lines += [f"- `{i}`: {md_text('; '.join(d['behaviour']['gaps']))}" for i, d in gaps]
    lines += ["", "## Sensors", "",
              "| Host | Channel | Records | Record numbers | Grade | Quiet after | Breaks | Off | Note |", "|---|---|---|---|---|---|---|---|---|",
              *sensor_rows(res), "", "## What this certificate does not say", ""]
    lines += [f"- {md_text(x)}" for x in res["limits"]]
    lines += ["", "## Check it yourself", "",
              "The verdicts are computed from the inputs above and the rules of this build: the same inputs and the same build give "
              "the same verdicts. Compare the SHA-256 of each input, then run:", "", "```",
              how or ("rasd silence " + " ".join(i["name"] for i in inputs)).strip(), "```", "",
              "<sub>Generated by RASD-Silence · Attack-to-Defense Validation Framework</sub>", ""]
    return "\n".join(lines)


def _at(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%d %H:%M:%S")


def _ticks(start: datetime, end: datetime) -> list[tuple[datetime, str]]:
    """Round hours across the window, half a dozen at most, each with the label it needs: the day where it changes."""
    span = (end - start).total_seconds()
    step = next((s for s in (3600, 7200, 10800, 21600, 43200, 86400, 172800, 604800) if span / s <= 6), 2592000)
    day = datetime(start.year, start.month, start.day)
    first = day + timedelta(seconds=step * math.ceil((start - day).total_seconds() / step))
    ticks = [first + timedelta(seconds=step * k) for k in range(int(max(0.0, (end - first).total_seconds()) // step) + 1)]
    return [(t, f"{t:%m-%d}" if step >= 86400 else f"{t:%m-%d %H:%M}" if k == 0 or (t.hour, t.minute) == (0, 0) else f"{t:%H:%M}")
            for k, t in enumerate(ticks)]


def write_html(path: str, res: dict, inputs: list[dict], notes: list[dict] | None = None) -> None:
    """The answer as one page: the map of every sensor over the window, then the tables of the certificate."""
    e = lambda x: html.escape(str(x))
    w, c = res["window"], res["counts"]
    w0, w1 = _at(w["start"]), _at(w["end"])
    span = max(1.0, (w1 - w0).total_seconds())

    def left(t: datetime) -> float:
        return min(100.0, max(0.0, (t - w0).total_seconds() / span * 100))

    def seg(a: str, b: str, kind: str, tip: str) -> str:
        x0, x1 = left(_at(a)), left(_at(b))
        return f'<i class="{kind}" style="left:{x0:.3f}%;width:{max(0.0, x1 - x0):.3f}%" title="{e(tip)}"></i>'

    def table(head: list[str], rows: list[list[str]], none: str) -> str:
        if not rows:
            return f'<p class="muted">{e(none)}</p>'
        body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
        return f'<div class="table-wrap"><table><tr>{"".join(f"<th>{e(h)}</th>" for h in head)}</tr>{body}</table></div>'

    hits: dict[str, list[dict]] = defaultdict(list)
    for a in res["alerts"]:
        if a.get("time") and a.get("host"):
            hits[str(a["host"])].append(a)
    axis = "".join(f'<span style="left:{left(t):.3f}%">{label}</span>' for t, label in _ticks(w0, w1))
    hosts: dict[str, list[str]] = defaultdict(list)
    for s in res["sensors"]:
        bars = "".join(seg(a, b, "ok", f"records whole from {a} to {b} ({s['grade']})") for a, b in s["runs_at"])
        bars += "".join(seg(h["start"], h["end"], "off" if h["kind"] == "down" else h["severity"],
                            f"{h['start']} to {h['end']}: {h['detail']}" + (f" ({h['life']})" if h["life"] else "")) for h in s["holes"])
        bars += "".join(seg(a["time"], a["time"], "hit", f"{a['time']} alert: {a['rule']}") for a in hits.get(s["host"], []))
        hosts[s["host"]].append(f'<div class="row"><span class="ch">{e(s["channel"])}<small>{e(s["grade"])}</small></span>'
                                f'<div class="bar">{bars}</div></div>')
    maps = "".join(f'<section class="card"><h3>{e(host)}</h3>{"".join(rows)}</section>' for host, rows in hosts.items())

    def meter(x: float) -> str:
        return f'<span class="meter"><i style="width:{100 * x:.1f}%"></i></span> {pct(x)}'
    detections = [[f"<b>{e(i)}</b>", e(d["reads"]), str(d["hosts"]), str(d["attested"]), str(d["fired"]), str(d["unattested"]),
                   meter(d["coverage"]) if d["hosts"] else "", e(scope_text(d["behaviour"]))] for i, d in res["detections"].items()]
    breaks = [[f'<b class="{b["severity"]}-text">{e(b["severity"])}</b>', e(b["host"]), e(", ".join(b["channels"])), e(b["start"]),
               e(b["end"]), e(b["detail"]), e(b["life"])] for b in res["breaks"]]
    groups: dict[tuple[str, str], list[str]] = defaultdict(list)
    for r in res["pairs"]:
        if r["verdict"] == "unattested":
            groups[(r["detection"], r["why"] or "")].append(r["host"] or "no host")
    blind = [[f"<b>{e(i)}</b>", e(", ".join(names)), e(why), e(res["detections"][i]["enable"])] for (i, why), names in groups.items()]
    fired = [[f"<b>{e(r['detection'])}</b>", e(r["host"] or "the fleet"), str(r["alerts"]), e(r.get("first_alert", ""))]
             for r in res["pairs"] if r["verdict"] == "fired"]
    read = [[e(i["name"]), str(i["records"]), f"<code>{e(i['sha256'])}</code>"] for i in inputs]
    read += [[e(n["channel"]) + " (this host)", str(n["records"]), e(n["state"])] for n in notes or []]
    off = "".join(f"<li>{e(d['host'])} {e(d['what'])} for {e(human(d['seconds']))} ({e(d['start'])} to {e(d['end'])})</li>" for d in res["down"])
    high = sum(1 for b in res["breaks"] if b["severity"] == "high")
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RASD-Silence</title><style>
:root{{--bg:#fbfaf7;--fg:#1d1c1a;--muted:#6b6862;--card:#fff;--line:#e6e2da;--gold:#9a7a45;--sage:#4f7a4f;--high:#b3412e;--med:#a8741a;--low:#8d8a83}}
@media (prefers-color-scheme:dark){{:root{{--bg:#111214;--fg:#e9e5dc;--muted:#9a968d;--card:#1a1b1e;--line:#2c2d31;--gold:#d7af87;--sage:#87af87;--high:#ef7b66;--med:#e3b25b;--low:#77736c}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}}
main{{max-width:1120px;margin:0 auto;padding:32px 16px 64px}}h1{{font-size:26px;margin:0}}h2{{font-size:18px;margin:36px 0 12px;color:var(--gold)}}h3{{margin:0 0 10px;font-size:15px}}
.muted,small{{color:var(--muted)}}small{{margin-left:8px;font-size:11px}}.claim{{border-left:3px solid var(--gold);padding:4px 0 4px 14px;margin:18px 0;max-width:80ch}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:20px}}
.kpi,.card{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px}}.kpi b{{display:block;font-size:24px}}.card{{margin-bottom:12px}}
.row{{display:grid;grid-template-columns:minmax(150px,300px) 1fr;gap:12px;align-items:center;margin:5px 0;font-size:13px}}.ch{{overflow-wrap:anywhere}}
.bar,.axis{{position:relative;height:16px;background:var(--line);border-radius:4px;overflow:hidden}}.bar i{{position:absolute;top:0;bottom:0;min-width:2px}}.bar i.high,.bar i.medium,.bar i.low{{min-width:3px;z-index:1}}
.axisrow{{padding:0 15px}}.axis{{background:none;height:18px;overflow:visible;margin:0 0 4px}}.axis span{{position:absolute;font-size:11px;color:var(--muted);border-left:1px solid var(--line);padding-left:3px;white-space:nowrap}}
.ok{{background:var(--sage)}}.high{{background:var(--high)}}.medium{{background:var(--med)}}.low{{background:var(--low)}}
.off{{background:repeating-linear-gradient(135deg,var(--muted) 0 2px,var(--line) 2px 7px)}}.hit{{background:var(--fg);width:2px!important;z-index:2}}
.legend{{display:flex;flex-wrap:wrap;gap:16px;font-size:13px;color:var(--muted);margin:8px 0 14px}}.legend i{{display:inline-block;width:22px;height:10px;border-radius:3px;margin-right:6px;vertical-align:middle}}
.meter{{display:inline-block;width:70px;height:8px;background:var(--line);border-radius:4px;overflow:hidden;vertical-align:middle;margin-right:6px}}.meter i{{display:block;height:100%;background:var(--sage)}}
.high-text{{color:var(--high)}}.medium-text{{color:var(--med)}}.low-text{{color:var(--muted)}}code{{font-size:12px;color:var(--muted);overflow-wrap:anywhere}}
.table-wrap{{overflow-x:auto}}table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}}
th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);font-size:13.5px;vertical-align:top}}th{{color:var(--muted);font-weight:500}}
li{{margin:4px 0}}footer{{margin-top:40px;color:var(--muted);font-size:13px}}
</style></head><body><main>
<h1>RASD-Silence</h1><p class="muted">What the quiet proves · {e(w['start'])} to {e(w['end'])} UTC ({e(human(w['seconds']))}) · {e(plural(res['records'], 'record'))} from {e(plural(len(res['hosts']), 'host'))}</p>
<p class="claim">{e(res['claim'])}.</p>
<div class="kpis"><div class="kpi"><span class="muted">Attested</span><b>{c['attested']}</b><span class="muted">{c['sequence']} by record sequence · {c['rhythm']} by rhythm</span></div>
<div class="kpi"><span class="muted">Fired</span><b>{c['fired']}</b><span class="muted">the quiet is broken</span></div>
<div class="kpi"><span class="muted">Unattested</span><b>{c['unattested']}</b><span class="muted">quiet that proves nothing</span></div>
<div class="kpi"><span class="muted">Watched time attested</span><b>{pct(c['coverage'])}</b><span class="muted">of {c['pairs']} detection-host pairs</span></div>
<div class="kpi"><span class="muted">Breaks in the record</span><b>{len(res['breaks'])}</b><span class="muted">{high} high</span></div></div>
<h2>The record, sensor by sensor</h2>
<div class="legend"><span><i class="ok"></i>the proof holds</span><span><i class="off"></i>host off or asleep, not counted</span>
<span><i class="high"></i>break, high</span><span><i class="medium"></i>break, medium</span><span><i class="low"></i>break, low</span>
<span><i class="hit" style="width:2px"></i>alert</span><span>no colour: no record to answer for</span></div>
<div class="row axisrow"><span></span><div class="axis">{axis}</div></div>{maps}
<h2>The quiet is broken</h2>{table(["Detection", "Host", "Alerts", "First"], fired, "No rule raised an alert in the window.")}
<h2>Every detection</h2>{table(["Detection", "Reads", "Hosts", "Attested", "Fired", "Unattested", "Watched time attested", "What the quiet covers"], detections, "No detection.")}
<h2>Breaks in the record</h2>{table(["Severity", "Host", "Channel", "From", "To", "What the records say", "The host meanwhile"], breaks, "None: every sensor's records are bracketed and whole over the window.")}
{f'<p class="muted">Not counted for or against any detection:</p><ul>{off}</ul>' if off else ''}
<h2>Quiet that proves nothing</h2>{table(["Detection", "Hosts", "Why", "What would make it evidence"], blind, "None: every quiet rule is attested or fired.")}
<h2>What was read</h2>{table(["Input", "Records", "SHA-256"], read, "No input.")}
<h2>What this does not say</h2><ul>{"".join(f"<li>{e(x)}</li>" for x in res['limits'])}</ul>
<footer>Generated by RASD-Silence {e(res['rasd'])} · Attack-to-Defense Validation Framework · position of the intruder: {e(res['position'])}</footer></main></body></html>"""
    write_output(path, doc)


def print_report(res: dict, notes: list[dict] | None = None, top: int = 12) -> None:
    w, c = res["window"], res["counts"]
    print(f"{BOLD}RASD-Silence · what the quiet proves{RESET}")
    print(f"{DIM}{plural(res['records'], 'record')} · {plural(len(res['hosts']), 'host')} · {w['start']} to {w['end']} UTC "
          f"({human(w['seconds'])}) · profile {res['profile']}{RESET}")
    for n in notes or []:
        print(f"  {GREEN if n['records'] else YELLOW}{n['channel']:<40}{RESET} {n['records']:>7} records  {DIM}{n['state']}{RESET}")
    fired = [r for r in res["pairs"] if r["verdict"] == "fired"]
    if fired:
        print(f"\n{BOLD}The quiet is broken{RESET}")
        for r in fired:
            print(f"  {RED}FIRED     {RESET} {r['detection']:<46} {r['host'] or 'the fleet':<20} {plural(r['alerts'], 'alert')}"
                  f"{DIM}, first {r.get('first_alert', '')}{RESET}")
    if c["attested"]:
        print(f"\n{BOLD}Quiet that is evidence{RESET}  {DIM}(hosts attested · their watched time attested · grade){RESET}")
    for ident, d in res["detections"].items():
        mine = [r for r in res["pairs"] if r["detection"] == ident and r["verdict"] == "attested"]
        if not mine:
            continue
        weak = min(mine, key=lambda r: r["coverage"])
        share = sum(r["attested_seconds"] for r in mine) / max(1.0, sum(r["watched_seconds"] for r in mine))
        grade = "sequence" if all(r["grade"] == "sequence" for r in mine) else "rhythm"
        tail = f" · weakest {weak['host']} {pct(weak['coverage'])}" if weak["coverage"] < 0.99995 else ""
        print(f"  {GREEN}ATTESTED  {RESET} {ident:<46} {len(mine)}/{d['hosts']} hosts · {pct(share)} · {grade}{DIM}{tail}{RESET}")
        print(f"             {DIM}{scope_text(d['behaviour'])}{RESET}")
    blind = [r for r in res["pairs"] if r["verdict"] == "unattested"]
    if blind:
        print(f"\n{BOLD}Quiet that proves nothing{RESET}")
        groups: dict[tuple[str, str], list[str]] = defaultdict(list)
        for r in blind:
            groups[(r["detection"], r["why"] or "")].append(r["host"] or "")
        for (ident, why), hosts in groups.items():
            names = ", ".join(h for h in hosts[:4] if h) + (f" and {len(hosts) - 4} more" if len(hosts) > 4 else "")
            print(f"  {YELLOW}UNATTESTED{RESET} {ident:<46} {names}")
            print(f"             {DIM}{why}{RESET}")
            print(f"             {GREEN}+ {res['detections'][ident]['enable']}{RESET}")
    if res["breaks"]:
        print(f"\n{BOLD}Breaks in the record{RESET}")
        colour = {"high": RED, "medium": YELLOW, "low": DIM}
        for b in res["breaks"][:top]:
            channel = b["channels"][0] if len(b["channels"]) == 1 else f"{len(b['channels'])} channels"
            print(f"  {colour[b['severity']]}{b['severity'].upper():<6}{RESET} {b['host']:<20} {channel:<38} {b['start'][5:16]} → {b['end'][5:16]}")
            print(f"         {b['detail']}")
            if b["life"]:
                print(f"         {RED}{b['life']}{RESET}")
        if len(res["breaks"]) > top:
            print(f"  {DIM}… {len(res['breaks']) - top} more in the certificate{RESET}")
    for d in res["down"]:
        print(f"  {DIM}not counted: {d['host']} {d['what']} for {human(d['seconds'])} ({d['start'][5:16]} → {d['end'][5:16]}){RESET}")
    print(f"\n{BOLD}{c['attested']} attested · {c['fired']} fired · {c['unattested']} unattested{RESET} of {c['pairs']} detection-host pairs · "
          f"{pct(c['coverage'])} of the watched time attested · {plural(len(res['breaks']), 'break')} in the record")
    print(f"{DIM}An attested verdict holds for the behaviours each rule is proven to catch and for the anti-forensic actions "
          f"RASD-Trace catalogues; the certificate lists both.{RESET}")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def when(text: str | None, name: str) -> datetime | None:
    if not text:
        return None
    t = parse_time({"TimeCreated": text})
    if t is None:
        raise SilenceError(f"--{name} {text}: not a time (write it as 2026-10-05T07:00:00Z)")
    return t


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logs", nargs="*", help="JSONL exports; none reads this Windows host's own event logs")
    ap.add_argument("--profile", help="telemetry profile from profiles/ (or 'auto') the export is written in")
    ap.add_argument("--assets", help="CSV ip,host,role: resolves the client address a domain controller records")
    ap.add_argument("--from", dest="start", help="start of the window (UTC), default the first record")
    ap.add_argument("--to", dest="end", help="end of the window (UTC), default the last record")
    ap.add_argument("--quiet", type=float, help="minutes without a record after which a channel counts as quiet")
    ap.add_argument("--filter", help="only the detections whose id contains this text")
    ap.add_argument("--host", help="only this host")
    ap.add_argument("--days", type=float, default=7.0, help="with no export: how far back to read this host's logs")
    ap.add_argument("--yes", action="store_true", help="with no export: do not wait for Enter before reading this host's logs")
    ap.add_argument("--certificate", help="write the certificate (Markdown) to this file")
    ap.add_argument("--html", help="write the answer as one page (HTML) to this file")
    ap.add_argument("--json", help="write the result as JSON to this file")
    ap.add_argument("--check", action="store_true", help="the model against RASD-Trace, the rules and the engine; the results page current")
    ap.add_argument("--write", action="store_true", help="render the results block of dfir/silence/README.md from the sample fleet")
    args = ap.parse_args()
    sm, trace = load_model(), survivability.load_model()

    if args.check or args.write:
        errs = check(sm, trace)
        if errs:
            for e in errs:
                print(f"  {RED}✗{RESET} {e}")
            print(f"{RED}{len(errs)} problem(s) in the silence model{RESET}")
            return 1
        block = render(sample_result())
        if args.write:
            README.write_text(with_block(README.read_text(encoding="utf-8"), block), encoding="utf-8", newline="\n")
            print(f"wrote {README.relative_to(ROOT).as_posix()}")
            return 0
        if with_block(README.read_text(encoding="utf-8"), block) != README.read_text(encoding="utf-8"):
            print(f"{RED}{README.relative_to(ROOT).as_posix()} is stale (run: rasd build){RESET}")
            return 1
        print(f"{GREEN}silence model consistent{RESET} · {len(sm.witnesses)} witnesses, {len(sm.cuts)} cut records, "
              f"{len(sm.down)} down pairs · results page current")
        return 0

    notes: list[dict] | None = None
    inputs: list[dict] = []
    if args.logs:
        raw = []
        for p in args.logs:
            path = Path(p)
            if not path.exists():
                raise SilenceError(f"{p}: no such file")
            got = load_jsonl(path)
            raw += got
            inputs.append({"name": p, "records": len(got), "sha256": sha256(path)})
        events, used = profiles.apply(raw, args.profile)
    else:
        if not wevtutil():
            raise SilenceError("no export given. rasd silence EXPORT.jsonl reads an export; on Windows, rasd silence alone "
                               "reads this host's own event logs")
        print(f"{BOLD}RASD-Silence{RESET} reads this host's own event logs for the last {args.days:g} days: "
              f"{', '.join(LIVE_CHANNELS)}.\nIt reads only; nothing on this host is changed and nothing leaves it.")
        if not args.yes and sys.stdin.isatty():
            try:
                input("Press Enter to start (Ctrl+C to stop) ")
            except (EOFError, KeyboardInterrupt):
                print()
                return 130
        events, notes = collect(args.days)
        used = profiles.NATIVE
        if not events:
            for n in notes:
                print(f"  {YELLOW}{n['channel']:<40}{RESET} {n['state']}")
            raise SilenceError("no channel of this host could be read")
    assets = load_assets(args.assets)
    if args.assets:
        inputs.append({"name": args.assets, "records": len(assets), "sha256": sha256(Path(args.assets))})
    how = ["rasd", "silence", *args.logs]
    for flag, value in (("--profile", args.profile), ("--assets", args.assets), ("--from", args.start), ("--to", args.end),
                        ("--quiet", args.quiet and f"{args.quiet:g}"), ("--filter", args.filter), ("--host", args.host),
                        ("--days", None if args.logs else f"{args.days:g}")):
        if value:
            how += [flag, str(value)]
    res = assess(events, sm, trace, assets=assets, profile=used, quiet=timedelta(minutes=args.quiet) if args.quiet else None,
                 start=when(args.start, "from"), end=when(args.end, "to"), filter_=args.filter, only_host=args.host)
    print_report(res, notes)
    target, page = args.certificate, args.html
    if notes is not None and not (target or page):     # this host, asked with nothing but Enter: its certificate beside the answer
        name = "".join(c if c.isalnum() or c in "-_" else "-" for c in (res["hosts"][0] if res["hosts"] else "host"))
        target = f"rasd-silence-{name}-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}.md"
        page = target[:-3] + ".html"
    if target:
        write_output(target, certificate(res, inputs, notes, " ".join(how)))
        print(f"[+] certificate: {target}")
    if page:
        write_html(page, res, inputs, notes)
        print(f"[+] page: {page}")
    if args.json:
        write_output(args.json, json.dumps({**res, "inputs": inputs, "channels_read": notes or []}, indent=2, ensure_ascii=False) + "\n")
        print(f"[+] JSON: {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
