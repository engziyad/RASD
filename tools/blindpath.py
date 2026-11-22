#!/usr/bin/env python3
"""
blindpath.py - RASD-Blindpath: the route an intruder walks through the behaviours a rule set claims to detect.

A coverage map colours a technique green when a rule exists for it. `rasd blindpath` asks what the map
cannot: from one host to another, can every leg of the way be walked through green cells with no alert?
A behaviour is called unseen on a host only on proof:

  dark      the export holds no record of the sensor its rules read from that host (rasd silence)
  witness   one sequence of events of the behaviour, replayed through every rule and correlation, raises
            no alert. The events are a variant a behaviour spec documents and rasd certify shows slipping
            past the rule, or a correlation's own true positives paced under its threshold

A leg is open on a host when one behaviour of its stage is unseen there, and held when every one is seen.
A route is unseen when every leg from the origin to the target is open; otherwise the first held leg is
where it is seen. The plan is the fewest changes (a variant closed in a rule, a sensor turned on on a
host) after which every route is seen by a given leg, for each leg in turn.

Usage:
  rasd blindpath                               this Windows host: its own event logs, read only
  rasd blindpath EXPORT [EXPORT ...]           one or more JSONL exports (--profile for ECS, CIM ...)
  rasd blindpath EXPORT --assets assets.csv    host roles decide the origins and the targets
  rasd blindpath EXPORT --origin WS01 --target DC01
  rasd blindpath EXPORT --certificate blindpath.md --html blindpath.html --json blindpath.json
  rasd blindpath EXPORT --baseline last.json   what changed since an earlier answer (exit 1 when it got worse)
  rasd blindpath EXPORT --witnesses w.jsonl    the events of every witness, to replay through your own SIEM
  rasd blindpath --check                       the model against the rules, the specs and the engine (in CI)

Options:
  --profile NAME     telemetry profile from profiles/ (or 'auto') the export is written in
  --assets FILE      CSV ip,host,role: the roles that start and end a route
  --origin HOST      a host a route starts from (repeatable; default: the roles of the model)
  --target HOST      a host a route ends on (repeatable; default: the roles of the model)
  --from / --to      the window (UTC), default the first and last record of the export
  --days N           with no export: how far back to read this host's logs (default 7)
  --yes              with no export: do not wait for Enter before reading this host's logs
  --certificate F    write the certificate as Markdown (with no export it is written beside the answer
                     as rasd-blindpath-<host>-<time>.md, with the page as .html)
  --html F           write the answer as one page (HTML): the map of every host and stage, the routes, the plan
  --json F           write the result as JSON, every witness with its events
  --strict           exit 1 when a route is unseen end to end
  --baseline F       an earlier --json answer for the same fleet: print what changed since, and exit 1 when a
                     route that was seen is now unseen or seen later, or a leg that was held is now open
  --witnesses F      write the events of every witness a verdict rests on as JSONL (rasd replay reads it)
  --check            the model against the rules, the behaviour specs, RASD-Trace, the decoys and the
                     engine; the results page current
  --write            render the results block of purple/blindpath/README.md from the sample fleet

What it rests on is written once in purple/blindpath/model.yml: the stages, the legs of a route, each
behaviour with the rules that watch it, and who decides every documented variant (docs/BLINDPATH.md).
"""
from __future__ import annotations

import argparse
import functools
import html
import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from itertools import combinations
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (BOLD, DIM, GREEN, PURPLE, RED, RESET, ROOT, VERSION, YELLOW, load_detections, load_jsonl, md_text,
                    write_output)
import certify
from convert import logsource_key
from correlation import Correlation, burst_events, burst_values, evaluate, guaranteed_burst, iso, load_correlations
import deceive
import profiles
from replay import load_assets, parse_time, replay as run_replay, route
from sigma_engine import compile_rule
import silence
import survivability

BLINDPATH = PURPLE / "blindpath"
MODEL = BLINDPATH / "model.yml"
README = BLINDPATH / "README.md"
BLOCK_START, BLOCK_END = "<!-- rasd:blindpath:start -->", "<!-- rasd:blindpath:end -->"
FORMAT = 1
ENDS = ("origin", "target")
DECIDERS = ("intruder", "environment")
DARK = ("no_record", "no_proof", "blind")
SYSMON_IDS = {"process_creation": 1, "process_access": 10, "registry_set": 13}
ID_FIELDS = ("EventID", "EventCode", "event_id", "code")
CHANNEL_FIELDS = ("Channel", "channel", "source")
DAY = datetime(2026, 1, 5)
PACED_WINDOWS = 3
SEARCH_BUDGET = 200_000
OPTION_CAP = 64
Atom = tuple[str, str, str]
NONE: frozenset[Atom] = frozenset()


class BlindpathError(SystemExit):
    pass


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else str(path)


# --------------------------------------------------------------------------- #
# The model
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Stage:
    id: str
    title: str


@dataclass(frozen=True)
class Leg:
    stage: str
    at: str
    title: str


@dataclass(frozen=True)
class Step:
    id: str
    stage: str
    title: str
    technique: str
    observers: tuple[str, ...]


@dataclass(frozen=True)
class Choice:
    by: str
    needs: str
    why: str


@dataclass(frozen=True)
class Tripwire:
    detection: str
    stage: str | None
    catches: str
    misses: str


@dataclass
class Model:
    claim: str
    position: str
    stages: dict[str, Stage]
    route: list[Leg]
    origins: list[str]
    targets: list[str]
    steps: list[Step]
    ways: dict[tuple[str, str], Choice]
    tripwires: list[Tripwire]
    apart: dict[str, str]
    limits: list[str]
    doubled: list[str]

    def in_stage(self, stage: str) -> list[Step]:
        return [s for s in self.steps if s.stage == stage]


def load_model(path: Path = MODEL) -> Model:
    if not path.exists():
        raise BlindpathError(f"{rel(path)} is missing")
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(doc, dict):
        raise BlindpathError(f"{rel(path)}: a mapping is expected at the top level")

    def rows(key: str) -> list[dict]:
        value = doc.get(key) or []
        if not isinstance(value, list) or not all(isinstance(x, dict) for x in value):
            raise BlindpathError(f"{rel(path)}: `{key}` must be a list of mappings")
        return value

    def texts(key: str) -> list[str]:
        value = doc.get(key) or []
        if not isinstance(value, list):
            raise BlindpathError(f"{rel(path)}: `{key}` must be a list")
        return [str(x) for x in value]

    stage_rows, step_rows = rows("stages"), rows("steps")
    stages = {str(s.get("id", "")): Stage(str(s.get("id", "")), str(s.get("title", ""))) for s in stage_rows}
    steps = [Step(str(s.get("id", "")), str(s.get("stage", "")), str(s.get("title", "")), str(s.get("technique", "")),
                  tuple(str(o) for o in s.get("observers") or [])) for s in step_rows]
    doubled = [f"stage `{i}`" for i, n in Counter(str(s.get("id", "")) for s in stage_rows).items() if n > 1]
    doubled += [f"step `{i}`" for i, n in Counter(s.id for s in steps).items() if n > 1]
    placed = doc.get("ways") or {}
    if not isinstance(placed, dict) or not all(isinstance(v, list) for v in placed.values()):
        raise BlindpathError(f"{rel(path)}: `ways` must map a detection to a list of variants")
    ways: dict[tuple[str, str], Choice] = {}
    for rule, items in placed.items():
        for w in items:
            key = (str(rule), str((w or {}).get("variant", "")))
            if key in ways:
                doubled.append(f"variant `{key[1]}` of `{key[0]}`")
            ways[key] = Choice(str(w.get("by", "")), str(w.get("needs", "") or ""), str(w.get("why", "") or ""))
    apart = doc.get("apart") or {}
    if not isinstance(apart, dict):
        raise BlindpathError(f"{rel(path)}: `apart` must map a detection to its reason")
    return Model(
        claim=" ".join(str(doc.get("claim", "")).split()), position=" ".join(str(doc.get("position", "")).split()), stages=stages,
        route=[Leg(str(r.get("stage", "")), str(r.get("at", "")), str(r.get("title", ""))) for r in rows("route")],
        origins=texts("origins"), targets=texts("targets"), steps=steps, ways=ways,
        tripwires=[Tripwire(str(t.get("detection", "")), str(t["stage"]) if t.get("stage") else None, str(t.get("catches", "")),
                            str(t.get("misses", ""))) for t in rows("tripwires")],
        apart={str(k): str(v) for k, v in apart.items()}, limits=texts("limits"), doubled=doubled)


# --------------------------------------------------------------------------- #
# The rules, and what the repository already proves about them
# --------------------------------------------------------------------------- #
@dataclass
class Book:
    dets: list[Any]
    corrs: list[Correlation]
    targets: dict[str, silence.Target]
    cert: dict[str, dict]
    specs: dict[str, certify.Spec]
    bases: dict[str, Any]

    def artifact(self, rule: str) -> str:
        t = self.targets[rule]
        return t.artifact or t.logsource

    def local(self, rule: str) -> bool:
        """The rule reads a record of the host the act runs on; otherwise an observer records it for others."""
        t = self.targets[rule]
        return t.reach == "host" or t.artifact is None

    def variants(self, rule: str, expect: str) -> list[dict]:
        rows = ((self.cert.get(rule) or {}).get("behaviour") or {}).get("variants") or []
        return [v for v in rows if v["expect"] == expect]

    def corr(self, rule: str) -> Correlation | None:
        return next((c for c in self.corrs if c.id == rule), None)


@functools.lru_cache(maxsize=1)
def book() -> Book:
    dets, corrs = list(load_detections()), list(load_correlations())
    sm, trace = silence.load_model(), survivability.load_model()
    specs = {}
    for ident, folder in [(d.id, d.folder) for d in dets] + [(c.id, c.folder) for c in corrs]:
        if (folder / certify.SPEC).exists():
            specs[ident] = certify.load_spec(folder / certify.SPEC)
    return Book(dets, corrs, {t.id: t for t in silence.targets(sm, trace)}, {r["id"]: r for r in certify.run()}, specs,
                {c.id: compile_rule(c.base) for c in corrs})


# --------------------------------------------------------------------------- #
# Ways around: event sequences the engine replays
# --------------------------------------------------------------------------- #
@dataclass
class Way:
    """One sequence of events of a behaviour, and every rule that alerts when it is replayed."""
    step: str
    kind: str
    detection: str
    variant: str
    label: str
    needs: str
    fix: str
    events: list[dict]
    fired: tuple[str, ...]
    inside: tuple[str, ...]
    sources: tuple[str, ...]
    id: int = 0

    @property
    def atom(self) -> Atom | None:
        """The rule change that closes this way; a threshold walked under has none."""
        return ("rule", self.detection, self.variant) if self.kind != "pace" and self.fix else None


def dress(ev: dict, t: silence.Target) -> dict | None:
    """The event as its sensor writes it: the channel, the event id and a time a spec leaves out. None when
    the engine would not route it to the log source of the rule it comes from."""
    out = {k: v for k, v in ev.items() if not str(k).startswith("_")}
    if t.channel_name and not any(k in out for k in CHANNEL_FIELDS):
        out["Channel"] = t.channel_name
    if not any(k in out for k in ID_FIELDS):
        eid = SYSMON_IDS.get(t.logsource) if "sysmon" in (t.channel or "") else next(iter(t.ids)) if len(t.ids) == 1 else None
        if eid is not None:
            out["EventID"] = eid
    if parse_time(out) is None:
        out["TimeCreated"] = iso(DAY + timedelta(hours=1))
    return out if route(out) == t.logsource else None


def in_variant(ev: dict, v: certify.Variant) -> bool:
    return all(fs.holds(certify._value(ev, f)) for f, fs in v.fields.items())


def need(c: Correlation) -> int | None:
    """How many events or values make the correlation alert; None when its condition is not 'at least'."""
    p = c.params
    return p.threshold + (1 if p.op == "gt" else 0) if p.op in ("gte", "gt") else None


def pace_gap(c: Correlation, per: int) -> float:
    return min(20.0, max(1.0, (c.params.timespan - 120) / max(1, per)))


def paced(c: Correlation, template: dict, per: int, b: Book) -> list[dict]:
    """`per` events in each of three windows two lengths apart: under the count in a tumbling and in a sliding window."""
    p, gap = c.params, pace_gap(c, per)
    times = [k * 2.0 * p.timespan + 60.0 + i * gap for k in range(PACED_WINDOWS) for i in range(per)]
    return burst_events(p, template, times, DAY, burst_values(p, template, b.bases[c.id]))


def suffixed(own: str):
    return lambda i: f"{own}{i:03d}"


def sequence(template: dict, v: certify.Variant, own: Correlation | None, b: Book) -> tuple[list[dict], str]:
    """The events that stand for one documented variant. A variant a correlation counts is paced under its
    threshold; a variant its own correlation does not count is sent as a burst that would always alert."""
    src = route(template)
    counting = [c for c in b.corrs if need(c) is not None and src == logsource_key(c.base) and b.bases[c.id](template)]
    if counting:
        c = min(counting, key=lambda c: need(c) or 0)
        per = (need(c) or 0) - 1
        events = paced(c, template, per, b) if per >= 1 else []
        return (events, "variant") if events and all(in_variant(e, v) for e in events) else ([template], "variant")
    if own is None:
        return [template], "variant"
    p = own.params
    times = [60.0 + i * 5.0 for i in range(guaranteed_burst(p) or max(1, p.threshold))]
    mine = str(template.get(p.counted) or "") if p.counted else ""
    for values in ([suffixed(mine)] if mine else []) + [burst_values(p, template)]:
        events = burst_events(p, template, times, DAY, values)
        if all(in_variant(e, v) for e in events):
            return events, "uncounted"
    return [{**template, "TimeCreated": iso(DAY + timedelta(seconds=x))} for x in times], "uncounted"


def alerts_on(events: list[dict], b: Book) -> tuple[str, ...]:
    alerts, _stats = run_replay(events, b.dets, {}, corrs=b.corrs)
    return tuple(sorted({str(a["rule"]) for a in alerts}))


def exclusions(events: list[dict], rules: tuple[str, ...], b: Book) -> tuple[str, ...]:
    """The design exclusions of the observers that every event of the sequence stands in."""
    out = []
    for o in rules:
        spec = b.specs.get(o)
        out += [f"{o}: {v.name}" for v in (spec.variants if spec else [])
                if v.expect == "quiet" and v.fields and all(in_variant(e, v) for e in events)]
    return tuple(out)


def ways_of(step: Step, m: Model, b: Book) -> list[Way]:
    out: list[Way] = []
    for o in step.observers:
        t, spec, corr = b.targets[o], b.specs.get(o), b.corr(o)
        named = {v.name: v for v in (spec.variants if spec else [])}
        for row in b.variants(o, "bypass"):
            choice, v = m.ways.get((o, row["variant"])), named.get(row["variant"])
            template = dress(row["event"], t) if row.get("result") == "bypass" else None
            if template is None or v is None or choice is None or choice.by != "intruder":
                continue
            events, kind = sequence(template, v, corr, b)
            urls = tuple(str((spec.sources.get(s) or {}).get("url", "")) for s in row.get("sources") or []) if spec else ()
            out.append(Way(step.id, kind, o, v.name, v.name, choice.needs, " ".join(str(row.get("fix") or "").split()), events,
                           alerts_on(events, b), exclusions(events, step.observers, b), tuple(u for u in urls if u)))
        count = need(corr) if corr is not None else None
        if corr is None or count is None or count < 2:
            continue
        told: set[tuple[str, ...]] = set()
        for tp in corr.tests("true_positive"):
            template = dress(tp, t)
            if template is None or not b.bases[o](template):
                continue
            events = paced(corr, template, count - 1, b)
            fired = alerts_on(events, b)
            if fired in told:
                continue
            told.add(fired)
            what = f"distinct {corr.params.field}" if corr.params.counted else "events"
            label = (f"paced under its threshold: {count - 1} {what} in each {silence.human(corr.params.timespan)} window, "
                     f"where the rule counts {count}")
            out.append(Way(step.id, "pace", o, str(tp.get("_case") or "a true positive of the rule"), label, "", "", events, fired,
                           exclusions(events, step.observers, b), ()))
    return out


def all_ways(m: Model, b: Book) -> dict[str, list[Way]]:
    out: dict[str, list[Way]] = {}
    n = 0
    for s in m.steps:
        out[s.id] = ways_of(s, m, b) if all(o in b.targets for o in s.observers) else []
        for w in out[s.id]:
            n += 1
            w.id = n
    return out


# --------------------------------------------------------------------------- #
# The fleet: which rule can see on which host
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Sight:
    state: str
    host: str | None
    why: str
    enable: str
    caveat: str


ABSENT = Sight("absent", None, "", "", "")


class Fleet:
    """The verdicts of rasd silence, read as one question: can this rule see an act on this host?"""

    def __init__(self, res: dict, b: Book):
        self.res, self.b = res, b
        self.hosts: list[str] = [str(h) for h in res["hosts"]]
        self.rows: dict[str, dict[str | None, dict]] = defaultdict(dict)
        for r in res["pairs"]:
            self.rows[r["detection"]][r["host"]] = r

    def read(self, rule: str, row: dict) -> Sight:
        if row["verdict"] in ("fired", "attested"):
            return Sight("live", row["host"], "", "", "")
        if row["reason"] in DARK:
            return Sight("dark", row["host"], str(row["why"] or ""), str(row["fix"] or self.res["detections"][rule]["enable"]), "")
        return Sight("live", row["host"], "", "", str(row["why"] or ""))

    def sight(self, rule: str, host: str, fixes: frozenset[Atom] = NONE) -> Sight:
        rows = self.rows.get(rule) or {}
        if rule not in self.b.targets:
            return ABSENT
        if self.b.local(rule):
            s = self.read(rule, rows[host]) if host in rows else ABSENT
        else:
            seen = [self.read(rule, r) for h, r in rows.items() if h is not None]
            s = next((x for x in seen if x.state == "live"), seen[0] if seen else ABSENT)
        return Sight("live", s.host, "", "", "") if s.state == "dark" and self.atom(rule, s) in fixes else s

    def atom(self, rule: str, s: Sight) -> Atom:
        return ("sensor", str(s.host), self.b.artifact(rule))

    def sensor(self, atom: Atom) -> tuple[str, str]:
        """What a sensor change reads and how it is turned on."""
        for rule, t in self.b.targets.items():
            for row in (self.rows.get(rule) or {}).values():
                s = self.read(rule, row)
                if s.state == "dark" and self.atom(rule, s) == atom:
                    return t.reads, s.enable
        return atom[2], ""


def rest(rule: str, s: Sight, fleet: Fleet) -> dict:
    d = fleet.res["detections"][rule]
    return {"rule": rule, "spec": bool(d["behaviour"]["spec"]), "fires": d["behaviour"]["fires"],
            "exclusions": d["behaviour"]["exclusions"], "blind_spots": d["blind_spots"], "caveat": s.caveat}


def judge(step: Step, host: str, fleet: Fleet, ways: list[Way], fixes: frozenset[Atom] = NONE) -> dict:
    """One behaviour on one host: unseen (and by what proof), seen (and on what it rests), or absent from the export."""
    b = fleet.b
    sights = {o: fleet.sight(o, host, fixes) for o in step.observers}
    out: dict[str, Any] = {"step": step.id, "verdict": "absent", "by": None, "way": None, "ways": [], "needs": "",
                           "dark": [], "rests": [], "caught": [], "note": ""}
    if all(s.state == "absent" for s in sights.values()):
        return out
    out["dark"] = [{"rule": o, "host": s.host, "why": s.why, "enable": s.enable} for o, s in sights.items() if s.state == "dark"]
    live = [o for o, s in sights.items() if s.state == "live"]
    if not live:
        out.update(verdict="unseen", by="dark")
        return out
    out["rests"] = [rest(o, sights[o], fleet) for o in live]
    kinds = sorted({b.artifact(o) for o in live})
    if len(kinds) > 1:
        out.update(verdict="seen", note="two records of the one act are read here: " + " and ".join(b.targets[o].reads for o in live))
        return out
    mine = [w for w in ways if b.artifact(w.detection) == kinds[0] and (w.atom is None or w.atom not in fixes)]
    opened = [w for w in mine if not any(fleet.sight(r, host, fixes).state == "live" for r in w.fired)]
    if opened:
        best = min(opened, key=lambda w: (bool(w.needs), w.id))
        out.update(verdict="unseen", by="witness", way=best.id, ways=[w.id for w in opened], needs=best.needs)
        return out
    out["verdict"] = "seen"
    out["caught"] = [{"way": w.id, "by": [r for r in w.fired if fleet.sight(r, host, fixes).state == "live"]} for w in mine]
    return out


def proven(step: dict) -> bool:
    return any(r["spec"] and r["fires"] for r in step["rests"])


def cell(host: str, stage: str, fleet: Fleet, m: Model, ways: dict[str, list[Way]], fixes: frozenset[Atom] = NONE) -> dict:
    steps = [judge(s, host, fleet, ways[s.id], fixes) for s in m.in_stage(stage)]
    walked = [s for s in steps if s["verdict"] != "absent"]
    verdict = "unwatched" if not walked else "open" if any(s["verdict"] == "unseen" for s in walked) else "held"
    return {"host": host, "stage": stage, "verdict": verdict, "proven": verdict == "held" and all(proven(s) for s in walked),
            "steps": walked}


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
def roles_of(fleet: Fleet, assets: dict | None) -> dict[str, str]:
    known = {str(row.get("host", "")).strip().lower(): str(row.get("role", "") or "").strip() for row in (assets or {}).values()}
    out = {}
    for h in fleet.hosts:
        role = known.get(h.lower()) or known.get(h.lower().split(".")[0])
        if role:
            out[h] = role
    return out


def pick(names: list[str], fleet: Fleet, flag: str) -> list[str]:
    out: list[str] = []
    for name in names:
        found = [h for h in fleet.hosts if h.lower() == name.lower()] or \
                [h for h in fleet.hosts if h.lower().split(".")[0] == name.lower().split(".")[0]]
        if len(found) != 1:
            raise BlindpathError(f"--{flag} {name}: " + ("no host of the export answers to it" if not found else
                                                         "more than one host of the export answers to it"))
        out += [h for h in found if h not in out]
    return out


def ends(fleet: Fleet, m: Model, assets: dict | None, origins: list[str], targets: list[str]) -> tuple[list[str], list[str], str]:
    """The hosts routes start from and end on, and how they were chosen."""
    roles = roles_of(fleet, assets)
    o, t = pick(origins, fleet, "origin"), pick(targets, fleet, "target")
    if len(fleet.hosts) == 1:
        return list(fleet.hosts), list(fleet.hosts), "one host: the walk on this host alone"
    told_o, told_t = "named" if o else "", "named" if t else ""
    if not t:
        t = [h for h in fleet.hosts if roles.get(h) in m.targets] if roles else \
            sorted({str(h) for rule, rows in fleet.rows.items() if rule in fleet.b.targets and not fleet.b.local(rule)
                    for h in rows if h is not None})
        told_t = ("roles" if roles else "observers") if t else "all"
        t = t or list(fleet.hosts)
    if not o:
        o = [h for h in fleet.hosts if roles.get(h) in m.origins] if roles else []
        told_o = "roles" if o else "rest"
        o = o or [h for h in fleet.hosts if h not in t] or list(fleet.hosts)
    if told_o == told_t and told_t in ("named", "roles"):
        return o, t, "named on the command line" if told_t == "named" else "the roles of the assets file"
    said_t = {"named": "targets named on the command line", "roles": "targets by the roles of the assets file",
              "observers": "no assets file: the hosts that record for others are the targets",
              "all": "no target could be told apart: every host is one"}[told_t]
    said_o = {"named": "origins named on the command line", "roles": "origins by the roles of the assets file",
              "rest": "every host an origin" if set(o) == set(fleet.hosts) else "every other host an origin"}[told_o]
    return o, t, f"{said_t}; {said_o}"


def signature(c: dict) -> tuple:
    return (c["verdict"], c["proven"], tuple((s["step"], s["by"], s["way"], s["needs"]) for s in c["steps"] if s["verdict"] == "unseen"))


def routes(cells: dict[tuple[str, str], dict], m: Model, origins: list[str], targets: list[str], single: bool) -> list[dict]:
    """Every origin to every target, grouped where the legs read the same."""
    def classes(hosts: list[str], at: str) -> dict[tuple, list[str]]:
        out: dict[tuple, list[str]] = defaultdict(list)
        for h in hosts:
            out[tuple(signature(cells[(h, leg.stage)]) for leg in m.route if leg.at == at)].append(h)
        return out

    groups = []
    for o_sig, o_hosts in classes(origins, "origin").items():
        for t_sig, t_hosts in classes(targets, "target").items():
            count = sum(1 for o in o_hosts for t in t_hosts if single or o != t)
            if not count:
                continue
            sigs = {"origin": iter(o_sig), "target": iter(t_sig)}
            legs = []
            for n, leg in enumerate(m.route, 1):
                verdict, sure, unseen = next(sigs[leg.at])
                legs.append({"n": n, "stage": leg.stage, "at": leg.at, "title": leg.title, "verdict": verdict, "proven": sure,
                             "unseen": [{"step": s, "by": by, "way": way, "needs": needs} for s, by, way, needs in unseen]})
            first = next((leg for leg in legs if leg["verdict"] == "held"), None)
            groups.append({"origins": o_hosts, "targets": t_hosts, "count": count, "verdict": "seen" if first else "unseen",
                           "seen_at": first and first["n"], "proven": bool(first and first["proven"]), "legs": legs})
    return sorted(groups, key=lambda g: (g["seen_at"] or 0, g["targets"], g["origins"]))


def walk(fleet: Fleet, m: Model, ways: dict[str, list[Way]], origins: list[str], targets: list[str], single: bool,
         fixes: frozenset[Atom] = NONE) -> tuple[dict[tuple[str, str], dict], list[dict]]:
    """The map and the routes, as they are or as they would be with `fixes` in place."""
    cells = {(h, s): cell(h, s, fleet, m, ways, fixes) for h in fleet.hosts for s in m.stages}
    return cells, routes(cells, m, origins, targets, single)


# --------------------------------------------------------------------------- #
# The plan: the fewest changes after which every route is seen by a leg
# --------------------------------------------------------------------------- #
def minimal(sets: list[frozenset[Atom]]) -> list[frozenset[Atom]]:
    out: list[frozenset[Atom]] = []
    for s in sorted(set(sets), key=lambda s: (len(s), sorted(s))):
        if not any(o <= s for o in out):
            out.append(s)
    return out


def repairs_step(step: Step, host: str, fleet: Fleet, ways: list[Way]) -> list[frozenset[Atom]]:
    """Every smallest set of changes after which the behaviour is seen on the host; empty when none is known."""
    if judge(step, host, fleet, ways)["verdict"] != "unseen":
        return [NONE]
    dark = [(r, fleet.sight(r, host)) for r in [*step.observers, *(r for w in ways for r in w.fired)]]
    sensors = sorted({fleet.atom(r, s) for r, s in dark if s.state == "dark"})
    found: list[frozenset[Atom]] = []
    for size in range(len(sensors) + 1):
        for on in combinations(sensors, size):
            fixes = frozenset(on)
            got = judge(step, host, fleet, ways, fixes)
            if got["verdict"] == "unseen" and got["by"] == "witness":
                closing = [w.atom for w in ways if w.id in got["ways"]]
                if any(a is None for a in closing):
                    continue
                fixes |= frozenset(a for a in closing if a is not None)
                got = judge(step, host, fleet, ways, fixes)
            if got["verdict"] == "seen":
                found.append(fixes)
    return minimal(found)


def repairs_cell(host: str, stage: str, fleet: Fleet, m: Model, ways: dict[str, list[Way]]) -> tuple[list[frozenset[Atom]], bool]:
    """The same for a whole leg on a host, and whether every combination was kept."""
    steps = [s for s in m.in_stage(stage) if judge(s, host, fleet, ways[s.id])["verdict"] != "absent"]
    acc, whole = [NONE] if steps else [], True
    for s in steps:
        mine = repairs_step(s, host, fleet, ways[s.id])
        acc = minimal([a | r for a in acc for r in mine])
        whole, acc = whole and len(acc) <= OPTION_CAP, acc[:OPTION_CAP]
    return acc, whole


def cheapest(demands: list[list[frozenset[Atom]]]) -> tuple[frozenset[Atom], bool] | None:
    """One option for every demand with the smallest union, and whether the search proved it the smallest.
    None when a demand has no option."""
    if any(not d for d in demands):
        return None
    todo: list[list[frozenset[Atom]]] = []
    for d in demands:
        if NONE not in d and d not in todo:
            todo.append(d)
    shared = Counter(a for d in todo for a in frozenset().union(*d))
    chosen: frozenset[Atom] = NONE
    rest_: list[list[frozenset[Atom]]] = []
    for d in todo:
        if all(shared[a] == 1 for o in d for a in o):
            chosen |= min(d, key=lambda o: (len(o), sorted(o)))
        else:
            rest_.append(d)
    best: list[frozenset[Atom] | None] = [None]
    nodes = [0]

    def search(have: frozenset[Atom], left: list[list[frozenset[Atom]]]) -> None:
        nodes[0] += 1
        if best[0] is not None and len(have) >= len(best[0]):
            return
        left = [d for d in left if not any(o <= have for o in d)]
        if not left:
            best[0] = have
            return
        if nodes[0] > SEARCH_BUDGET and best[0] is not None:
            return
        d = min(left, key=len)
        for o in sorted(d, key=lambda o: (len(o - have), sorted(o))):
            search(have | o, [x for x in left if x is not d])

    search(NONE, rest_)
    return chosen | (best[0] or NONE), nodes[0] <= SEARCH_BUDGET


def stuck(host: str, stage: str, fleet: Fleet, m: Model, ways: dict[str, list[Way]]) -> list[str]:
    """Why a leg cannot be held on a host with the changes this model knows."""
    steps = [s for s in m.in_stage(stage) if judge(s, host, fleet, ways[s.id])["verdict"] != "absent"]
    if not steps:
        return [f"{m.stages[stage].title}: no behaviour of this stage has a sensor in the export"]
    out = []
    for s in steps:
        if repairs_step(s, host, fleet, ways[s.id]):
            continue
        got = judge(s, host, fleet, ways[s.id], frozenset(fleet.atom(o, x) for o in s.observers
                                                           if (x := fleet.sight(o, host)).state == "dark"))
        named = [w for w in ways[s.id] if w.id in got["ways"] and w.atom is None]
        out += [f"{s.title} is paced under a threshold, which no rule change closes" if w.kind == "pace" else
                f"{s.title}: the variant '{w.variant}' has no rule change in its behaviour spec" for w in named[:1]] or \
               [f"{s.title}: no change this model knows makes it seen"]
    return out


def change(atom: Atom, fleet: Fleet, ways: dict[str, list[Way]]) -> dict:
    kind, first, second = atom
    if kind == "rule":
        w = next(w for group in ways.values() for w in group if w.atom == atom)
        return {"kind": "rule", "rule": first, "variant": second, "change": w.fix}
    reads, enable = fleet.sensor(atom)
    return {"kind": "sensor", "host": first, "reads": reads, "change": enable}


def ladder(fleet: Fleet, m: Model, ways: dict[str, list[Way]], origins: list[str], targets: list[str], single: bool) -> list[dict]:
    """For each leg in turn, the fewest changes after which every route is seen by that leg. Every route is seen
    by a leg exactly when every origin holds one of its legs up to there, or every target does (or, with hosts
    that are both, every host but one), so each side is the smallest union of one repair per host."""
    known: dict[tuple[str, str], tuple[list[frozenset[Atom]], bool]] = {}

    def options(host: str, legs: list[Leg], at: str) -> tuple[list[frozenset[Atom]], bool]:
        got: list[frozenset[Atom]] = []
        whole = True
        for leg in legs:
            if single or leg.at == at:
                key = (host, leg.stage)
                if key not in known:
                    known[key] = repairs_cell(host, leg.stage, fleet, m, ways)
                got, whole = got + known[key][0], whole and known[key][1]
        return minimal(got), whole

    def reasons(legs: list[Leg]) -> list[str]:
        out: list[str] = []
        for leg in legs:
            for h in (origins if single or leg.at == "origin" else targets):
                if not known.get((h, leg.stage), ([NONE], True))[0]:
                    out += [x for x in stuck(h, leg.stage, fleet, m, ways) if x not in out]
        return out

    rungs: list[dict] = []
    for k in range(1, len(m.route) + 1):
        legs = m.route[:k]
        plans: list[tuple[str, list[tuple[list[frozenset[Atom]], bool]]]] = []
        if single:
            plans.append(("this host", [options(origins[0], legs, "origin")]))
        else:
            plans.append(("every origin", [options(o, legs, "origin") for o in origins]))
            plans.append(("every target", [options(t, legs, "target") for t in targets]))
            plans += [(f"every host but {x}", [options(o, legs, "origin") for o in origins if o != x]
                       + [options(t, legs, "target") for t in targets if t != x]) for x in origins if x in targets]
        best: tuple[str, frozenset[Atom], bool] | None = None
        for side, demands in plans:
            got = cheapest([d for d, _whole in demands])
            if got is not None and (best is None or len(got[0]) < len(best[1])):
                best = (side, got[0], got[1] and all(whole for _d, whole in demands))
        rung: dict[str, Any] = {"leg": k, "title": legs[-1].title, "reachable": best is not None, "count": None, "side": None,
                                "exact": None, "changes": [], "atoms": None, "same_as": None, "open": reasons(legs),
                                "cannot": reasons(legs[-1:])}
        if best is not None:
            side, fixes, exact = best
            _cells, after = walk(fleet, m, ways, origins, targets, single, fixes)
            if any(g["seen_at"] is None or g["seen_at"] > k for g in after):
                raise BlindpathError(f"internal error: the plan for leg {k} leaves a route unseen")
            rung.update(count=len(fixes), side=side, exact=exact, changes=[change(a, fleet, ways) for a in sorted(fixes)],
                        atoms=[list(a) for a in sorted(fixes)])
            rung["same_as"] = next((r["leg"] for r in rungs if r["atoms"] == rung["atoms"]), None)
        rungs.append(rung)
    return rungs


def leverage(fleet: Fleet, m: Model, ways: dict[str, list[Way]], origins: list[str], targets: list[str], single: bool,
             cells: dict[tuple[str, str], dict], groups: list[dict]) -> list[dict]:
    """What each change buys alone: a sensor turned on on one host, or every documented variant of one rule
    closed. The plan answers for the fewest changes together; this ranks them one at a time."""
    b = fleet.b
    bundles: dict[str, frozenset[Atom]] = {}
    for w in (w for group in ways.values() for w in group):
        if w.atom is not None:
            bundles[w.detection] = bundles.get(w.detection, NONE) | {w.atom}
    sensors = sorted({("sensor", str(d["host"]), b.artifact(d["rule"])) for c in cells.values() for s in c["steps"] for d in s["dark"]})
    unseen = sum(g["count"] for g in groups if g["verdict"] == "unseen")
    rows = []
    for kind, name, fixes in [("sensor", a[1], frozenset({a})) for a in sensors] + [("rule", r, f) for r, f in sorted(bundles.items())]:
        local = kind == "sensor" and all(b.local(r) for r in b.targets if b.artifact(r) == next(iter(fixes))[2])
        hosts = [name] if local and name in fleet.hosts else fleet.hosts
        after = {**cells, **{(h, s): cell(h, s, fleet, m, ways, fixes) for h in hosts for s in m.stages}}
        held = sum(1 for key, c in after.items() if c["verdict"] == "held" and cells[key]["verdict"] == "open")
        then = routes(after, m, origins, targets, single)
        seen = unseen - sum(g["count"] for g in then if g["verdict"] == "unseen")
        if not held and not seen:
            continue
        what = (f"{name}: turn on {fleet.sensor(next(iter(fixes)))[0]}" if kind == "sensor" else
                f"`{name}`: close its {silence.plural(len(fixes), 'documented variant')}")
        rows.append({"kind": kind, "what": what, "changes": len(fixes), "legs_held": held, "routes_seen": seen,
                     "every_route_by": max(g["seen_at"] for g in then) if then and all(g["seen_at"] for g in then) else None,
                     "atoms": [list(a) for a in sorted(fixes)]})
    return sorted(rows, key=lambda r: (-r["routes_seen"], -r["legs_held"], r["changes"], r["what"]))


def routes_at(res: dict) -> dict[tuple[str, str], int | None]:
    """Every route of an answer with the leg that first sees it; None when it is unseen end to end."""
    return {(o, t): g["seen_at"] for g in res["routes"] for o in g["origins"] for t in g["targets"] if res["single"] or o != t}


def since(res: dict, old: dict) -> dict:
    """What changed since an earlier answer for the same fleet. Worse is a route now unseen or seen later, or a
    leg that was held and is now open."""
    if not isinstance(old, dict) or old.get("format") != FORMAT or not all(k in old for k in ("routes", "cells", "hosts", "single")):
        raise BlindpathError("--baseline: not a rasd blindpath --json answer of this format")
    rank = lambda leg: 10 ** 6 if leg is None else leg
    was_r, now_r = routes_at(old), routes_at(res)
    moved = [{"origin": o, "target": t, "was": was_r[(o, t)], "now": now_r[(o, t)]} for o, t in sorted(set(was_r) & set(now_r))
             if was_r[(o, t)] != now_r[(o, t)]]
    was_c = {(c["host"], c["stage"]): c["verdict"] for c in old["cells"]}
    now_c = {(c["host"], c["stage"]): c["verdict"] for c in res["cells"]}
    turned = [{"host": h, "stage": st, "was": was_c[(h, st)], "now": now_c[(h, st)]} for h, st in sorted(set(was_c) & set(now_c))
              if was_c[(h, st)] != now_c[(h, st)]]
    was_s = {(c["host"], s["step"]): s["verdict"] for c in old["cells"] for s in c["steps"]}
    now_s = {(c["host"], s["step"]): s["verdict"] for c in res["cells"] for s in c["steps"]}
    steps = [{"host": h, "step": st, "was": was_s[(h, st)], "now": now_s[(h, st)]} for h, st in sorted(set(was_s) & set(now_s))
             if was_s[(h, st)] != now_s[(h, st)]]
    out = {"routes_worse": [r for r in moved if rank(r["now"]) > rank(r["was"])],
           "routes_better": [r for r in moved if rank(r["now"]) < rank(r["was"])],
           "legs_opened": [c for c in turned if c["was"] == "held" and c["now"] == "open"],
           "legs_held": [c for c in turned if c["was"] == "open" and c["now"] == "held"],
           "now_unseen": [s for s in steps if s["now"] == "unseen"], "now_seen": [s for s in steps if s["was"] == "unseen"],
           "hosts_new": sorted(set(res["hosts"]) - set(old["hosts"])), "hosts_gone": sorted(set(old["hosts"]) - set(res["hosts"])),
           "baseline_rasd": old.get("rasd"), "baseline_window": old.get("window")}
    out["worse"] = bool(out["routes_worse"] or out["legs_opened"])
    return out


def witness_events(res: dict) -> list[dict]:
    """The events of every witness a verdict rests on, each marked with its witness, behaviour and rule."""
    return [{**ev, "_witness": f"W{w['id']}", "_step": w["step"], "_rule": w["rule"]} for w in res["ways"] if w["used"] for ev in w["events"]]


# --------------------------------------------------------------------------- #
# The answer
# --------------------------------------------------------------------------- #
def assess(res: dict, m: Model | None = None, *, assets: dict | None = None, origins: list[str] | None = None,
           targets: list[str] | None = None) -> dict:
    """`res` is the answer of rasd silence for an export (silence.assess): the sensors are judged once, there."""
    m, b = m or load_model(), book()
    fleet = Fleet(res, b)
    ways = all_ways(m, b)
    o, t, how = ends(fleet, m, assets, list(origins or []), list(targets or []))
    single = len(fleet.hosts) == 1 or (o == t and len(o) == 1)
    cells, groups = walk(fleet, m, ways, o, t, single)
    flat = [w for group in ways.values() for w in group]
    used = {s["way"] for c in cells.values() for s in c["steps"] if s["way"]}
    steps = [s for c in cells.values() for s in c["steps"]]
    sight: dict[int, dict[str, int]] = {}
    for g in groups:
        if g["seen_at"]:
            at = sight.setdefault(g["seen_at"], {"routes": 0, "on_tests": 0})
            at["routes"] += g["count"]
            at["on_tests"] += 0 if g["proven"] else g["count"]
    tripwires = []
    for tw in m.tripwires:
        rows = {h: fleet.read(tw.detection, r) for h, r in (fleet.rows.get(tw.detection) or {}).items() if h is not None}
        armed, dark = sorted(h for h, s in rows.items() if s.state == "live"), sorted(h for h, s in rows.items() if s.state == "dark")
        tripwires.append({"detection": tw.detection, "stage": tw.stage, "catches": tw.catches, "misses": tw.misses, "armed": armed,
                          "state": "armed" if armed else "dark" if dark else "not in this export"})
    not_walked = [{"rule": rule, "variant": name, "why": c.why} for (rule, name), c in m.ways.items() if c.by == "environment"]
    caveats = sorted({(r["rule"], c["host"], r["caveat"]) for c in cells.values() for s in c["steps"] for r in s["rests"] if r["caveat"]})
    return {
        "format": FORMAT, "rasd": VERSION, "profile": res.get("profile"), "claim": m.claim, "position": m.position,
        "limits": m.limits, "window": res["window"], "records": res["records"], "hosts": fleet.hosts,
        "roles": roles_of(fleet, assets), "origins": o, "targets": t, "ends": how, "single": single,
        "rules": len(b.dets), "correlations": len(b.corrs),
        "stages": [{"id": s.id, "title": s.title} for s in m.stages.values()],
        "legs": [{"n": n, "stage": leg.stage, "at": leg.at, "title": leg.title} for n, leg in enumerate(m.route, 1)],
        "steps": {s.id: {"stage": s.stage, "title": s.title, "technique": s.technique, "observers": list(s.observers)} for s in m.steps},
        "ways": [{"id": w.id, "step": w.step, "kind": w.kind, "rule": w.detection, "variant": w.variant, "label": w.label,
                  "needs": w.needs, "fix": w.fix, "closable": w.atom is not None, "events": w.events, "fired": list(w.fired),
                  "inside": list(w.inside), "sources": list(w.sources), "used": w.id in used} for w in flat],
        "cells": list(cells.values()), "routes": groups, "ladder": ladder(fleet, m, ways, o, t, single),
        "leverage": leverage(fleet, m, ways, o, t, single, cells, groups),
        "tripwires": tripwires, "not_walked": not_walked,
        "caveats": [{"rule": r, "host": h, "why": why} for r, h, why in caveats],
        "counts": {
            "cells": len(cells), **{v: sum(1 for c in cells.values() if c["verdict"] == v) for v in ("open", "held", "unwatched")},
            "held_on_tests": sum(1 for c in cells.values() if c["verdict"] == "held" and not c["proven"]),
            "walked": len(steps), "unseen": sum(1 for s in steps if s["verdict"] == "unseen"),
            "by_witness": sum(1 for s in steps if s["by"] == "witness"), "by_dark": sum(1 for s in steps if s["by"] == "dark"),
            "seen": sum(1 for s in steps if s["verdict"] == "seen"), "ways": len(flat), "ways_quiet": sum(1 for w in flat if not w.fired),
            "routes": sum(g["count"] for g in groups), "routes_unseen": sum(g["count"] for g in groups if g["verdict"] == "unseen"),
            "routes_seen": sum(g["count"] for g in groups if g["verdict"] == "seen"),
            "routes_seen_on_tests": sum(g["count"] for g in groups if g["verdict"] == "seen" and not g["proven"]),
            "first_sight": {str(k): v for k, v in sorted(sight.items())},
        },
        "silence": res["counts"],
    }


def sample_result() -> dict:
    assets = load_assets(str(silence.SAMPLE_ASSETS)) if silence.SAMPLE_ASSETS.exists() else {}
    return assess(silence.sample_result(), assets=assets)


@functools.lru_cache(maxsize=1)
def sample_summary() -> dict:
    """For the metrics pages: the size of the model and the routes of the sample fleet."""
    m, res = load_model(), sample_result()
    plans = [r for r in res["ladder"] if r["reachable"]]
    easiest = min(plans, key=lambda r: (r["count"], r["leg"])) if plans else None
    return {"steps": len(m.steps), "stages": len(m.stages), "legs": len(m.route), "tripwires": len(m.tripwires),
            "hosts": len(res["hosts"]), "plan": easiest and easiest["count"], "plan_leg": easiest and easiest["leg"], **res["counts"]}


# --------------------------------------------------------------------------- #
# The model against the repository
# --------------------------------------------------------------------------- #
def check(m: Model, b: Book) -> list[str]:
    errs: list[str] = [f"{d} is written twice" for d in m.doubled]
    observers = {o for s in m.steps for o in s.observers}
    wires = {t.detection for t in m.tripwires}
    decoys = {str(d.get("detection")) for d in deceive.load_inventory()["decoys"] if d.get("detection")}
    if not m.claim or not m.position or not m.limits:
        errs.append("the claim, the position and the limits must be written")
    if not m.origins or not m.targets:
        errs.append("`origins` and `targets` must each name a role")
    for stage in m.stages.values():
        if not stage.id or not stage.title:
            errs.append(f"stage `{stage.id}`: an id and a title are needed")
    if not m.route:
        errs.append("`route` names no leg")
    for n, leg in enumerate(m.route, 1):
        if leg.at not in ENDS or not leg.title:
            errs.append(f"leg {n}: `at` must be origin or target, and a title is needed")
        if not m.in_stage(leg.stage):
            errs.append(f"leg {n}: no step is written for stage `{leg.stage}`")
    for s in m.steps:
        if s.stage not in m.stages:
            errs.append(f"step `{s.id}`: unknown stage `{s.stage}`")
        if not s.id or not s.title or not s.observers or len(set(s.observers)) != len(s.observers):
            errs.append(f"step `{s.id}`: an id, a title and observers named once are needed")
        for o in s.observers:
            if o not in b.targets:
                errs.append(f"step `{s.id}`: `{o}` is not a detection or a correlation of this repository")
            elif not o.startswith(s.technique + "_"):
                errs.append(f"step `{s.id}`: `{o}` is not a rule for {s.technique}")
            elif len(s.observers) > 1 and b.targets[o].artifact is None:
                errs.append(f"step `{s.id}`: `{o}` reads a record RASD-Trace does not model, so it cannot share a step")
    for rule in sorted(set(b.targets) - observers - wires - set(m.apart)):
        errs.append(f"`{rule}` is not placed: name it as the observer of a step, as a tripwire, or under `apart` with the reason")
    for rule in sorted((wires | set(m.apart)) - set(b.targets)):
        errs.append(f"`{rule}` is not a detection or a correlation of this repository")
    for rule in sorted((observers & wires) | (observers & set(m.apart)) | (wires & set(m.apart))):
        errs.append(f"`{rule}` is placed twice")
    for rule in sorted(wires ^ decoys):
        errs.append(f"`{rule}`: the tripwires must be the detections of deceive/decoys.yml, no more and no fewer")
    for t in m.tripwires:
        if t.stage is not None and t.stage not in m.stages:
            errs.append(f"tripwire `{t.detection}`: unknown stage `{t.stage}`")
        if not t.catches or not t.misses:
            errs.append(f"tripwire `{t.detection}`: what it catches and what it misses must be written")
    documented = {(o, v["variant"]) for o in observers if o in b.targets for v in b.variants(o, "bypass")}
    for rule, name in sorted(documented - set(m.ways)):
        errs.append(f"`{rule}`: the documented variant '{name}' is not placed under `ways` (by: intruder or environment)")
    for rule, name in sorted(set(m.ways) - documented):
        errs.append(f"`ways`: '{name}' is not a variant the behaviour spec of `{rule}` marks `expect: bypass`")
    for (rule, name), c in m.ways.items():
        if c.by not in DECIDERS:
            errs.append(f"`ways`: '{name}' of `{rule}`: `by` must be one of {', '.join(DECIDERS)}")
        if c.by == "environment" and not c.why:
            errs.append(f"`ways`: '{name}' of `{rule}`: a variant the intruder does not choose needs its `why`")
    if errs:
        return errs
    ways = all_ways(m, b)
    built = {(w.detection, w.variant) for group in ways.values() for w in group if w.kind != "pace"}
    for (rule, name), c in sorted(m.ways.items()):
        if c.by == "intruder" and (rule, name) not in built:
            errs.append(f"`{rule}`: the engine cannot route the witness of '{name}' to the log source of its rule")
    for group in ways.values():
        for w in group:
            if w.kind != "pace" and w.detection in w.fired:
                errs.append(f"`{w.detection}`: the rule alerts on its own documented variant '{w.variant}'")
            corr = b.corr(w.detection)
            if w.kind != "pace" or corr is None:
                continue
            per = (need(corr) or 0) - 1
            over = burst_events(corr.params, w.events[0], [60.0 + i * pace_gap(corr, per + 1) for i in range(per + 1)], DAY,
                                burst_values(corr.params, w.events[0], b.bases[corr.id]))
            if evaluate(corr, w.events) or not all(b.bases[corr.id](e) for e in w.events):
                errs.append(f"`{corr.id}`: {per} counted events in a window must stay under its threshold")
            if not evaluate(corr, over):
                errs.append(f"`{corr.id}`: {per + 1} events in one window must alert, or the pace is not one under the count")
    return errs


# --------------------------------------------------------------------------- #
# Reports
# --------------------------------------------------------------------------- #
def listed(items: list[str], most: int = 3) -> str:
    return ", ".join(items[:most]) + (f" and {len(items) - most} more" if len(items) > most else "")


def summary_line(res: dict) -> str:
    c = res["counts"]
    if res["single"]:
        g = res["routes"][0]
        return ("On this host alone the walk is unseen end to end" if g["verdict"] == "unseen" else
                f"On this host alone the walk is first seen at leg {g['seen_at']} ({g['legs'][g['seen_at'] - 1]['title']})")
    legs = {leg["n"]: leg["title"] for leg in res["legs"]}
    seen = [f"{n['routes']} first seen at leg {k} ({legs[int(k)]}" + (", on rules with no behaviour spec" if n["on_tests"] == n["routes"]
            else f", {n['on_tests']} of them on rules with no behaviour spec" if n["on_tests"] else "") + ")" for k, n in c["first_sight"].items()]
    return (f"{silence.plural(c['routes'], 'route')} from {silence.plural(len(res['origins']), 'origin')} to "
            f"{silence.plural(len(res['targets']), 'target')}: {c['routes_unseen']} unseen end to end" + "".join(f", {s}" for s in seen))


def cell_text(c: dict) -> str:
    if c["verdict"] == "unwatched":
        return "-"
    if c["verdict"] == "held":
        return "held" if c["proven"] else "held*"
    return f"open {sum(1 for s in c['steps'] if s['verdict'] == 'unseen')}/{len(c['steps'])}"


def way_text(w: dict) -> str:
    if w["kind"] == "pace":
        return w["label"]
    return w["variant"] + (f" ({len(w['events'])} events in one window, none counted)" if w["kind"] == "uncounted" else "")


def proof_text(res: dict, step: dict) -> str:
    """What makes one behaviour unseen on one host, in one line."""
    if step["by"] == "dark":
        return "dark: " + "; ".join(f"`{d['rule']}`: {d['why']}" for d in step["dark"])
    w = res["ways"][step["way"] - 1]
    said = "no alert" if not w["fired"] else "alerts only from rules with no sensor here (" + ", ".join(w["fired"]) + ")"
    tail = "".join([f" · needs: {w['needs']}" if w["needs"] else "",
                    f" · inside the exclusion {', '.join(w['inside'])}" if w["inside"] else "",
                    f" · {len(step['ways']) - 1} more ways" if len(step["ways"]) > 1 else ""])
    return (f"witness W{w['id']} of `{w['rule']}`: {way_text(w)} · {silence.plural(len(w['events']), 'event')} replayed through "
            f"{res['rules']} rules and {res['correlations']} correlations, {said}{tail}")


def unseen_groups(res: dict) -> list[tuple[dict, list[str]]]:
    groups: dict[tuple, tuple[dict, list[str]]] = {}
    for c in res["cells"]:
        for s in c["steps"]:
            if s["verdict"] == "unseen":
                key = (s["step"], s["by"], s["way"], tuple(d["why"] for d in s["dark"]) if s["by"] == "dark" else ())
                groups.setdefault(key, (s, []))[1].append(c["host"])
    return list(groups.values())


def hold_groups(res: dict) -> list[tuple[dict, list[str]]]:
    groups: dict[tuple, tuple[dict, list[str]]] = {}
    for c in res["cells"]:
        for s in c["steps"]:
            if s["verdict"] == "seen":
                key = (s["step"], tuple(r["rule"] for r in s["rests"]), s["note"])
                groups.setdefault(key, (s, []))[1].append(c["host"])
    return list(groups.values())


def rest_text(r: dict) -> str:
    if not r["spec"]:
        return f"`{r['rule']}`: its tests alone, no behaviour spec"
    return (f"`{r['rule']}`: {silence.plural(r['fires'], 'variant')} proven to fire, "
            f"{silence.plural(r['exclusions'], 'design exclusion')}")


def change_text(c: dict) -> str:
    if c["kind"] == "rule":
        return f"`{c['rule']}`: close '{c['variant']}': {c['change']}"
    return f"{c['host']}: turn on {c['reads']}: {c['change']}"


def rung_text(r: dict) -> tuple[str, list[str]]:
    """How many changes a rung of the plan takes, and what they are, one line each."""
    if not r["reachable"]:
        return "not reachable", ["No change this model knows holds a leg this far.", *r["open"]]
    if r["same_as"]:
        return str(r["count"]), [f"The same as for leg {r['same_as']}."] + (
            ["This leg itself cannot be held by a change this model knows:", *r["cannot"]] if r["cannot"] else [])
    if not r["changes"]:
        return "0", ["None: it holds today."]
    return (str(r["count"]) + ("" if r["exact"] else " (not proven the fewest)"),
            [f"On {r['side']}:", *(change_text(c) for c in r["changes"])])


def leg_text(leg: int | None) -> str:
    return "unseen end to end" if leg is None else f"seen at leg {leg}"


def since_lines(d: dict, steps: dict, stages: dict[str, str], most: int = 12) -> list[str]:
    """What changed since the baseline, one line each, the worse first."""
    def some(rows: list, text) -> list[str]:
        return [text(r) for r in rows[:most]] + ([f"and {len(rows) - most} more"] if len(rows) > most else [])

    lines = some(d["routes_worse"], lambda r: f"worse: {r['origin']} → {r['target']} was {leg_text(r['was'])}, now {leg_text(r['now'])}")
    lines += some(d["legs_opened"], lambda c: f"worse: {stages.get(c['stage'], c['stage'])} on {c['host']} was held, now open")
    lines += some(d["now_unseen"], lambda s: f"now unseen: {steps.get(s['step'], {}).get('title', s['step'])} on {s['host']}")
    lines += some(d["routes_better"], lambda r: f"better: {r['origin']} → {r['target']} was {leg_text(r['was'])}, now {leg_text(r['now'])}")
    lines += some(d["legs_held"], lambda c: f"better: {stages.get(c['stage'], c['stage'])} on {c['host']} was open, now held")
    lines += some(d["now_seen"], lambda s: f"now seen: {steps.get(s['step'], {}).get('title', s['step'])} on {s['host']}")
    lines += [f"new in this export: {h}" for h in d["hosts_new"][:most]] + [f"no longer in the export: {h}" for h in d["hosts_gone"][:most]]
    return lines or ["nothing changed: every route, leg and behaviour reads as it did"]


def route_title(g: dict, res: dict) -> str:
    if res["single"]:
        return g["origins"][0]
    return f"{listed(g['origins'])} → {listed(g['targets'])}"


def tables(res: dict, most: int = 3) -> list[str]:
    """The tables the results page and the certificate share; `most` is how many hosts a cell names before it counts."""
    steps, stages = res["steps"], res["stages"]
    by_host: dict[str, dict[str, dict]] = defaultdict(dict)
    for c in res["cells"]:
        by_host[c["host"]][c["stage"]] = c
    lines = ["### The map", "",
             "| Host | Role | " + " | ".join(s["title"] for s in stages) + " |", "|---|---|" + "---|" * len(stages)]
    for h in res["hosts"]:
        lines.append(f"| {h} | {res['roles'].get(h, '')} | " + " | ".join(cell_text(by_host[h][s["id"]]) for s in stages) + " |")
    lines += ["", "<sub>open n/m: n of the m behaviours of the stage that have a sensor in the export are unseen on that host · "
              "held: every one is seen · held*: seen, on rules with no behaviour spec · -: no behaviour of the stage has a "
              "sensor in the export.</sub>", "",
              "### Routes", "",
              "| From | To | Routes | Verdict | " + " | ".join(f"{leg['n']}. {leg['title']}" for leg in res["legs"]) + " |",
              "|---|---|---|---|" + "---|" * len(res["legs"])]
    for g in res["routes"]:
        verdict = "**unseen end to end**" if g["verdict"] == "unseen" else f"seen at leg {g['seen_at']}"
        legs = [("held" if leg["proven"] else "held*") if leg["verdict"] == "held" else "-" if leg["verdict"] == "unwatched" else
                "open: " + ", ".join(steps[u["step"]]["title"] for u in leg["unseen"]) for leg in g["legs"]]
        lines.append(f"| {listed(g['origins'], most)} | {listed(g['targets'], most)} | {g['count']} | {verdict} | " + " | ".join(legs) + " |")
    lines += ["", "### Unseen, and the proof", "", "| Behaviour | Stage | Hosts | Proof |", "|---|---|---|---|"]
    titles = {s["id"]: s["title"] for s in stages}
    for s, hosts in unseen_groups(res):
        lines.append(f"| {steps[s['step']]['title']} | {titles[steps[s['step']]['stage']]} | {listed(hosts, most)} | "
                     f"{md_text(proof_text(res, s))} |")
    lines += ["", "### The plan", "", "The fewest changes after which every route is seen by a leg, for each leg in turn.", "",
              "| Every route seen by | Changes | What changes |", "|---|---|---|"]
    for r in res["ladder"]:
        count, what = rung_text(r)
        lines.append(f"| leg {r['leg']}: {r['title']} | {count} | {'<br>'.join(md_text(x) for x in what)} |")
    lines += ["", "### What each change buys alone", "",
              "One change at a time: a sensor turned on on one host, or every documented variant of one rule closed.", "",
              "| Change | Changes | Legs it holds | Routes it lets be seen | Every route seen by |", "|---|---|---|---|---|"]
    lines += [f"| {md_text(r['what'])} | {r['changes']} | {r['legs_held']} | {r['routes_seen']} | "
              f"{'leg ' + str(r['every_route_by']) if r['every_route_by'] else '-'} |" for r in res["leverage"]]
    lines += ["", "### What each hold rests on", "", "| Behaviour | Hosts | Rests on |", "|---|---|---|"]
    for s, hosts in hold_groups(res):
        lines.append(f"| {steps[s['step']]['title']} | {len(hosts)} | " + "; ".join(rest_text(r) for r in s["rests"])
                     + (f" · {s['note']}" if s["note"] else "") + " |")
    lines += ["", "### Tripwires", "", "Not counted for or against a route: a tripwire sees the intruder who touches it and no other.",
              "", "| Decoy detection | Guards | State | Catches | Misses |", "|---|---|---|---|---|"]
    for t in res["tripwires"]:
        state = t["state"] + (f" on {listed(t['armed'])}" if t["armed"] else "")
        lines.append(f"| `{t['detection']}` | {titles.get(t['stage'], '')} | {state} | {t['catches']} | {t['misses']} |")
    lines += ["", "### Variants the intruder does not choose", "", "Documented, and not walked: the pipeline or the target decides them.",
              "", "| Rule | Variant | Why |", "|---|---|---|"]
    lines += [f"| `{v['rule']}` | {v['variant']} | {md_text(v['why'])} |" for v in res["not_walked"]]
    return lines


def render(res: dict) -> str:
    """The results block of purple/blindpath/README.md, from the sample fleet."""
    w, c = res["window"], res["counts"]
    lines = [
        BLOCK_START,
        f"**Sample fleet:** `samples/silence/fleet.jsonl`, {res['records']} records from {len(res['hosts'])} hosts over "
        f"{silence.human(w['seconds'])} ({w['start']} to {w['end']} UTC); origins and targets: {res['ends']}.",
        "",
        f"**{summary_line(res)}.** {len(res['steps'])} behaviours over {len(res['stages'])} stages were walked on every host: "
        f"{c['walked']} have a sensor in the export, {c['unseen']} of them unseen ({c['by_witness']} by a witness the engine "
        f"replays, {c['by_dark']} for want of a sensor) and {c['seen']} seen. {c['ways']} ways around were replayed through "
        f"{res['rules']} rules and {res['correlations']} correlations; {c['ways_quiet']} raise no alert.",
        "",
    ]
    return "\n".join(lines + tables(res) + [BLOCK_END])


def with_block(text: str, block: str) -> str:
    if BLOCK_START not in text or BLOCK_END not in text:
        raise BlindpathError(f"{rel(README)}: the markers {BLOCK_START} and {BLOCK_END} are missing")
    head, tail = text.split(BLOCK_START, 1)
    return head + block + tail.split(BLOCK_END, 1)[1]


def certificate(res: dict, inputs: list[dict], notes: list[dict] | None = None, how: str = "") -> str:
    """What was read, what is claimed, every route with its proof, the plan, and what this does not say."""
    w = res["window"]
    lines = ["# Certificate of the unseen route", "",
             f"{summary_line(res)}.", "",
             "## The claim", "", f"{res['claim']}.", "",
             f"Position of the intruder: {res['position']}.", "",
             "## What was read", "", "| Input | Records | SHA-256 |", "|---|---|---|"]
    lines += [f"| `{i['name']}` | {i['records']} | `{i['sha256']}` |" for i in inputs]
    lines += [f"| {n['channel']} (this host) | {n['records']} | {n['state']} |" for n in notes or []]
    lines += ["", f"Window: {w['start']} to {w['end']} UTC ({silence.human(w['seconds'])}), {res['records']} records from "
              f"{silence.plural(len(res['hosts']), 'host')}, profile {res['profile']}. Origins and targets: {res['ends']}.", "",
              f"Origins: {', '.join(res['origins'])}.", "", f"Targets: {', '.join(res['targets'])}.", ""]
    if res.get("since"):
        titles = {s["id"]: s["title"] for s in res["stages"]}
        lines += ["## Since the baseline", ""] + [f"- {md_text(x)}" for x in since_lines(res["since"], res["steps"], titles, most=200)] + [""]
    lines += tables(res, most=24)
    used = [x for x in res["ways"] if x["used"]]
    lines += ["", "## The witnesses", "",
              "Every sequence of events a verdict above rests on. Each was replayed through every rule and correlation of this "
              "build; the first event of each is printed, and the JSON output holds them all.", ""]
    for x in used:
        lines += [f"### W{x['id']}: {res['steps'][x['step']]['title']}", "",
                  f"`{x['rule']}`: {way_text(x)}" + (f", built from its true positive '{x['variant']}'" if x["kind"] == "pace" else "")
                  + f". {silence.plural(len(x['events']), 'event')}; alerts on replay: "
                  f"{', '.join(x['fired']) or 'none'}." + (f" Needs: {x['needs']}." if x["needs"] else "")
                  + (f" Closed by: {x['fix']}" if x["fix"] else " No rule change closes it."), "",
                  "```json", json.dumps(x["events"][0], ensure_ascii=False, sort_keys=True), "```", ""]
        lines += [f"Source: {u}" for u in x["sources"]] + ([""] if x["sources"] else [])
    if res["caveats"]:
        lines += ["## Taken as recording", "", "Sensors whose records are in the export and whose quiet rasd silence does not attest.",
                  ""] + [f"- `{c['rule']}` on {c['host']}: {c['why']}" for c in res["caveats"]] + [""]
    lines += ["## What this certificate does not say", ""] + [f"- {x}" for x in res["limits"]]
    lines += ["", "## How it was made", "", "```", how or ("rasd blindpath " + " ".join(i["name"] for i in inputs)).strip(), "```", "",
              f"<sub>Generated by RASD-Blindpath {res['rasd']} · Continuous Detection Assurance Framework</sub>", ""]
    return "\n".join(lines)


def write_html(path: str, res: dict, inputs: list[dict], notes: list[dict] | None = None) -> None:
    """The answer as one page: the map of every host and stage, the routes leg by leg, the plan, the proofs."""
    e = lambda x: html.escape(str(x))
    c, steps, stages = res["counts"], res["steps"], res["stages"]
    by_host: dict[str, dict[str, dict]] = defaultdict(dict)
    for x in res["cells"]:
        by_host[x["host"]][x["stage"]] = x

    def table(head: list[str], rows: list[list[str]], none: str) -> str:
        if not rows:
            return f'<p class="muted">{e(none)}</p>'
        body = "".join("<tr>" + "".join(f"<td>{cell_}</td>" for cell_ in row) + "</tr>" for row in rows)
        return f'<div class="table-wrap"><table><tr>{"".join(f"<th>{e(h)}</th>" for h in head)}</tr>{body}</table></div>'

    def square(x: dict) -> str:
        kind = "none" if x["verdict"] == "unwatched" else "open" if x["verdict"] == "open" else "held" if x["proven"] else "tests"
        tip = "; ".join(f"{steps[s['step']]['title']}: {s['verdict']}" for s in x["steps"]) or "no sensor in the export"
        return f'<td class="cell {kind}" title="{e(tip)}">{e(cell_text(x))}</td>'

    grid = "".join(f"<tr><th>{e(h)}<small>{e(res['roles'].get(h, ''))}</small></th>" + "".join(square(by_host[h][s["id"]]) for s in stages)
                   + "</tr>" for h in res["hosts"])
    cards = ""
    for g in res["routes"]:
        chips = ""
        for leg in g["legs"]:
            kind = "none" if leg["verdict"] == "unwatched" else "open" if leg["verdict"] == "open" else "held" if leg["proven"] else "tests"
            what = ", ".join(steps[u["step"]]["title"] for u in leg["unseen"]) or \
                ("no sensor in the export" if leg["verdict"] != "held" else "every behaviour is seen" if leg["proven"] else
                 "every behaviour is seen, on rules with no behaviour spec")
            chips += f'<div class="leg {kind}"><b>{leg["n"]}. {e(leg["title"])}</b><span>{e(what)}</span></div>'
        verdict = "unseen end to end" if g["verdict"] == "unseen" else f"seen at leg {g['seen_at']}"
        cards += (f'<section class="card"><h3>{e(route_title(g, res))} <small>{e(silence.plural(g["count"], "route"))} · '
                  f'<b class="{g["verdict"]}-text">{e(verdict)}</b></small></h3><div class="legs">{chips}</div></section>')
    proofs = [[e(steps[s["step"]]["title"]), e(listed(hosts)), e(proof_text(res, s))] for s, hosts in unseen_groups(res)]
    plan = [[e(f"leg {r['leg']}: {r['title']}"), e(rung_text(r)[0]), "<br>".join(e(x) for x in rung_text(r)[1])] for r in res["ladder"]]
    holds = [[e(steps[s["step"]]["title"]), str(len(hosts)), e("; ".join(rest_text(r) for r in s["rests"]) + (f" · {s['note']}" if s["note"] else ""))]
             for s, hosts in hold_groups(res)]
    wires = [[f"<b>{e(t['detection'])}</b>", e(t["state"] + (f" on {listed(t['armed'])}" if t["armed"] else "")), e(t["catches"]),
              e(t["misses"])] for t in res["tripwires"]]
    read = [[e(i["name"]), str(i["records"]), f"<code>{e(i['sha256'])}</code>"] for i in inputs]
    read += [[e(n["channel"]) + " (this host)", str(n["records"]), e(n["state"])] for n in notes or []]
    buys = [[e(r["what"]), str(r["changes"]), str(r["legs_held"]), str(r["routes_seen"]),
             e("leg " + str(r["every_route_by"]) if r["every_route_by"] else "-")] for r in res["leverage"]]
    changed = ""
    if res.get("since"):
        said = since_lines(res["since"], steps, {s["id"]: s["title"] for s in stages}, most=50)
        changed = "<h2>Since the baseline</h2><ul>" + "".join(f"<li>{e(x)}</li>" for x in said) + "</ul>"
    w = res["window"]
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RASD-Blindpath</title><style>
:root{{--bg:#fbfaf7;--fg:#1d1c1a;--muted:#6b6862;--card:#fff;--line:#e6e2da;--gold:#9a7a45;--sage:#4f7a4f;--high:#b3412e;--med:#a8741a}}
@media (prefers-color-scheme:dark){{:root{{--bg:#111214;--fg:#e9e5dc;--muted:#9a968d;--card:#1a1b1e;--line:#2c2d31;--gold:#d7af87;--sage:#87af87;--high:#ef7b66;--med:#e3b25b}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}}
main{{max-width:1120px;margin:0 auto;padding:32px 16px 64px}}h1{{font-size:26px;margin:0}}h2{{font-size:18px;margin:36px 0 12px;color:var(--gold)}}h3{{margin:0 0 10px;font-size:15px}}
.muted,small{{color:var(--muted)}}small{{margin-left:8px;font-size:11px;font-weight:400}}.claim{{border-left:3px solid var(--gold);padding:4px 0 4px 14px;margin:18px 0;max-width:80ch}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:20px}}
.kpi,.card{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px}}.kpi b{{display:block;font-size:24px}}.card{{margin-bottom:12px}}
.table-wrap{{overflow-x:auto}}table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}}
th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);font-size:13.5px;vertical-align:top}}th{{color:var(--muted);font-weight:500}}
.map th:first-child{{color:var(--fg)}}.cell{{text-align:center;font-weight:600;white-space:nowrap}}
.open{{background:color-mix(in srgb,var(--high) 20%,transparent);color:var(--high)}}.held{{background:color-mix(in srgb,var(--sage) 22%,transparent);color:var(--sage)}}
.tests{{background:color-mix(in srgb,var(--med) 20%,transparent);color:var(--med)}}.none{{color:var(--muted)}}
.legs{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px}}.leg{{border-radius:8px;padding:8px 10px;font-size:13px}}.leg b,.leg span{{display:block}}
.unseen-text{{color:var(--high)}}.seen-text{{color:var(--sage)}}code{{font-size:12px;color:var(--muted);overflow-wrap:anywhere}}
.legend{{display:flex;flex-wrap:wrap;gap:16px;font-size:13px;color:var(--muted);margin:8px 0 14px}}.legend i{{display:inline-block;width:22px;height:10px;border-radius:3px;margin-right:6px;vertical-align:middle}}
li{{margin:4px 0}}footer{{margin-top:40px;color:var(--muted);font-size:13px}}
</style></head><body><main>
<h1>RASD-Blindpath</h1><p class="muted">The route through the green cells · {e(w['start'])} to {e(w['end'])} UTC · {e(silence.plural(res['records'], 'record'))} from {e(silence.plural(len(res['hosts']), 'host'))}</p>
<p class="claim">{e(res['claim'])}.</p>
<div class="kpis"><div class="kpi"><span class="muted">Routes</span><b>{c['routes']}</b><span class="muted">{e(res['ends'])}</span></div>
<div class="kpi"><span class="muted">Unseen end to end</span><b>{c['routes_unseen']}</b><span class="muted">no alert on the whole way</span></div>
<div class="kpi"><span class="muted">Seen on the way</span><b>{c['routes_seen']}</b><span class="muted">the first held leg is named</span></div>
<div class="kpi"><span class="muted">Behaviours unseen</span><b>{c['unseen']}</b><span class="muted">{c['by_witness']} by witness · {c['by_dark']} dark, of {c['walked']}</span></div>
<div class="kpi"><span class="muted">Ways replayed</span><b>{c['ways']}</b><span class="muted">{c['ways_quiet']} raise no alert</span></div></div>
{changed}<h2>The map</h2>
<div class="legend"><span><i class="open"></i>open: a behaviour of the stage is unseen</span><span><i class="held"></i>held: every one is seen</span>
<span><i class="tests"></i>held on rules with no behaviour spec</span><span>-: no sensor in the export</span></div>
<div class="table-wrap"><table class="map"><tr><th>Host</th>{"".join(f"<th>{e(s['title'])}</th>" for s in stages)}</tr>{grid}</table></div>
<h2>Routes</h2>{cards}
<h2>The plan</h2>{table(["Every route seen by", "Changes", "What changes"], plan, "No leg to plan for.")}
<h2>What each change buys alone</h2>{table(["Change", "Changes", "Legs it holds", "Routes it lets be seen", "Every route seen by"], buys, "No single change holds a leg or lets a route be seen.")}
<h2>Unseen, and the proof</h2>{table(["Behaviour", "Hosts", "Proof"], proofs, "None: every behaviour with a sensor in the export is seen.")}
<h2>What each hold rests on</h2>{table(["Behaviour", "Hosts", "Rests on"], holds, "Nothing is held.")}
<h2>Tripwires</h2>{table(["Decoy detection", "State", "Catches", "Misses"], wires, "No decoy detection.")}
<h2>What was read</h2>{table(["Input", "Records", "SHA-256"], read, "No input.")}
<h2>What this does not say</h2><ul>{"".join(f"<li>{e(x)}</li>" for x in res['limits'])}</ul>
<footer>Generated by RASD-Blindpath {e(res['rasd'])} · Continuous Detection Assurance Framework · position of the intruder: {e(res['position'])}</footer></main></body></html>"""
    write_output(path, doc)


def print_report(res: dict, notes: list[dict] | None = None) -> None:
    w, steps, stages = res["window"], res["steps"], res["stages"]
    print(f"{BOLD}RASD-Blindpath · the route through the green cells{RESET}")
    print(f"{DIM}{silence.plural(res['records'], 'record')} · {silence.plural(len(res['hosts']), 'host')} · {w['start']} to {w['end']} UTC "
          f"· origins and targets: {res['ends']}{RESET}")
    for n in notes or []:
        print(f"  {GREEN if n['records'] else YELLOW}{n['channel']:<40}{RESET} {n['records']:>7} records  {DIM}{n['state']}{RESET}")
    print(f"\n{BOLD}{summary_line(res)}{RESET}")
    by_host: dict[str, dict[str, dict]] = defaultdict(dict)
    for c in res["cells"]:
        by_host[c["host"]][c["stage"]] = c
    wide = max(len(h) for h in res["hosts"]) + 2
    print(f"\n{BOLD}The map{RESET}  {DIM}(open n/m: n of m behaviours unseen · held*: on rules with no behaviour spec · -: no sensor){RESET}")
    print("  " + " " * wide + "".join(f"{s['title']:<18}" for s in stages))
    colour = {"open": RED, "held": GREEN, "unwatched": DIM}
    for h in res["hosts"]:
        row = "".join(f"{colour[by_host[h][s['id']]['verdict']]}{cell_text(by_host[h][s['id']]):<18}{RESET}" for s in stages)
        print(f"  {h:<{wide}}{row}")
    print(f"\n{BOLD}Routes{RESET}")
    for g in res["routes"]:
        mark = f"{RED}UNSEEN{RESET}" if g["verdict"] == "unseen" else f"{GREEN}SEEN  {RESET}"
        tail = "" if g["verdict"] == "unseen" else f" · first seen at leg {g['seen_at']}"
        print(f"  {mark} {route_title(g, res)}  {DIM}{silence.plural(g['count'], 'route')}{tail}{RESET}")
        for leg in g["legs"]:
            if leg["verdict"] == "open":
                what = "; ".join(steps[u["step"]]["title"] + (" (dark)" if u["by"] == "dark" else f" (W{u['way']})") for u in leg["unseen"])
                print(f"         {RED}{leg['n']} open{RESET} {leg['title']}: {DIM}{what}{RESET}")
            else:
                said = "held" + ("" if leg["proven"] else " on rules with no behaviour spec") if leg["verdict"] == "held" else "no sensor"
                print(f"         {GREEN if leg['verdict'] == 'held' else DIM}{leg['n']} {said}{RESET} {leg['title']}")
    used = [x for x in res["ways"] if x["used"]]
    if used:
        print(f"\n{BOLD}Witnesses the engine replayed{RESET}")
        for x in used:
            print(f"  W{x['id']:<3} {x['rule']}: {way_text(x)}")
            print(f"       {DIM}{silence.plural(len(x['events']), 'event')} · alerts: {', '.join(x['fired']) or 'none'}"
                  f"{' · needs: ' + x['needs'] if x['needs'] else ''}{RESET}")
    print(f"\n{BOLD}The plan{RESET}  {DIM}(the fewest changes after which every route is seen by a leg){RESET}")
    for r in res["ladder"]:
        count, told = rung_text(r)
        print(f"  leg {r['leg']} {r['title']:<34} {YELLOW if not r['reachable'] else GREEN}{count}{RESET} {DIM}{told[0]}{RESET}")
        for line in told[1:]:
            print(f"       {GREEN + '+ ' if r['changes'] and not r['same_as'] else DIM}{line}{RESET}")
    if res["leverage"]:
        print(f"\n{BOLD}What each change buys alone{RESET}  {DIM}(legs it holds · routes it lets be seen){RESET}")
        for r in res["leverage"][:6]:
            by = f" · every route seen by leg {r['every_route_by']}" if r["every_route_by"] else ""
            print(f"  {GREEN}+{RESET} {r['what']}  {DIM}{r['legs_held']} · {r['routes_seen']}{by}{RESET}")
    if res.get("since"):
        d = res["since"]
        print(f"\n{BOLD}Since the baseline{RESET}")
        for line in since_lines(d, steps, {s["id"]: s["title"] for s in stages}):
            print(f"  {RED if line.startswith(('worse', 'now unseen')) else GREEN if line.startswith(('better', 'now seen')) else DIM}{line}{RESET}")
    armed = [t for t in res["tripwires"] if t["armed"]]
    if armed:
        print(f"\n{BOLD}Tripwires{RESET}  {DIM}(not counted: they see the intruder who touches them){RESET}")
        for t in armed:
            print(f"  {t['detection']:<46} armed on {listed(t['armed'])}")
    print(f"\n{DIM}Held means no way around is known here, not that none exists. The limits are on the certificate.{RESET}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logs", nargs="*", help="JSONL exports; none reads this Windows host's own event logs")
    ap.add_argument("--profile", help="telemetry profile from profiles/ (or 'auto') the export is written in")
    ap.add_argument("--assets", help="CSV ip,host,role: the roles that start and end a route")
    ap.add_argument("--origin", action="append", default=[], help="a host a route starts from (repeatable)")
    ap.add_argument("--target", action="append", default=[], help="a host a route ends on (repeatable)")
    ap.add_argument("--from", dest="start", help="start of the window (UTC), default the first record")
    ap.add_argument("--to", dest="end", help="end of the window (UTC), default the last record")
    ap.add_argument("--days", type=float, default=7.0, help="with no export: how far back to read this host's logs")
    ap.add_argument("--yes", action="store_true", help="with no export: do not wait for Enter before reading this host's logs")
    ap.add_argument("--certificate", help="write the certificate (Markdown) to this file")
    ap.add_argument("--html", help="write the answer as one page (HTML) to this file")
    ap.add_argument("--json", help="write the result as JSON to this file")
    ap.add_argument("--strict", action="store_true", help="exit 1 when a route is unseen end to end")
    ap.add_argument("--baseline", help="an earlier --json answer: print what changed since, exit 1 when it got worse")
    ap.add_argument("--witnesses", help="write the events of every witness as JSONL to this file")
    ap.add_argument("--check", action="store_true", help="the model against the rules, the specs and the engine; the results page current")
    ap.add_argument("--write", action="store_true", help="render the results block of purple/blindpath/README.md from the sample fleet")
    args = ap.parse_args()
    m = load_model()

    if args.check or args.write:
        errs = check(m, book())
        if errs:
            for err in errs:
                print(f"  {RED}✗{RESET} {err}")
            print(f"{RED}{len(errs)} problem(s) in the blindpath model{RESET}")
            return 1
        block = render(sample_result())
        if args.write:
            README.write_text(with_block(README.read_text(encoding="utf-8"), block), encoding="utf-8", newline="\n")
            print(f"wrote {rel(README)}")
            return 0
        if with_block(README.read_text(encoding="utf-8"), block) != README.read_text(encoding="utf-8"):
            print(f"{RED}{rel(README)} is stale (run: rasd build){RESET}")
            return 1
        print(f"{GREEN}blindpath model consistent{RESET} · {len(m.steps)} behaviours, {len(m.route)} legs, "
              f"{len(m.tripwires)} tripwires · every witness replayed · results page current")
        return 0

    notes: list[dict] | None = None
    inputs: list[dict] = []
    if args.logs:
        raw = []
        for p in args.logs:
            path = Path(p)
            if not path.exists():
                raise BlindpathError(f"{p}: no such file")
            got = load_jsonl(path)
            raw += got
            inputs.append({"name": p, "records": len(got), "sha256": silence.sha256(path)})
        events, used = profiles.apply(raw, args.profile)
    else:
        if not silence.wevtutil():
            raise BlindpathError("no export given. rasd blindpath EXPORT.jsonl reads an export; on Windows, rasd blindpath alone "
                                 "reads this host's own event logs")
        print(f"{BOLD}RASD-Blindpath{RESET} reads this host's own event logs for the last {args.days:g} days: "
              f"{', '.join(silence.LIVE_CHANNELS)}.\nIt reads only; nothing on this host is changed, nothing is run and nothing leaves it.")
        if not args.yes and sys.stdin.isatty():
            try:
                input("Press Enter to start (Ctrl+C to stop) ")
            except (EOFError, KeyboardInterrupt):
                print()
                return 130
        events, notes = silence.collect(args.days)
        used = profiles.NATIVE
        if not events:
            for n in notes:
                print(f"  {YELLOW}{n['channel']:<40}{RESET} {n['state']}")
            raise BlindpathError("no channel of this host could be read")
    if args.assets and not Path(args.assets).exists():
        raise BlindpathError(f"{args.assets}: no such file")
    assets = load_assets(args.assets)
    if args.assets:
        inputs.append({"name": args.assets, "records": len(assets), "sha256": silence.sha256(Path(args.assets))})
    how = ["rasd", "blindpath", *args.logs]
    for flag, values in (("--profile", [args.profile]), ("--assets", [args.assets]), ("--origin", args.origin), ("--target", args.target),
                         ("--from", [args.start]), ("--to", [args.end]), ("--days", [None if args.logs else f"{args.days:g}"]),
                         ("--baseline", [args.baseline])):
        for value in values:
            if value:
                how += [flag, str(value)]
    try:
        quiet = silence.assess(events, assets=assets, profile=used, start=silence.when(args.start, "from"),
                               end=silence.when(args.end, "to"), notes=notes)
    except silence.SilenceError as err:
        raise BlindpathError(str(err)) from err
    res = assess(quiet, m, assets=assets, origins=args.origin, targets=args.target)
    if args.baseline:
        if not Path(args.baseline).exists():
            raise BlindpathError(f"{args.baseline}: no such file")
        try:
            old = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        except ValueError as err:
            raise BlindpathError(f"--baseline {args.baseline}: not JSON ({err})") from err
        res["since"] = since(res, old)
        inputs.append({"name": args.baseline, "records": len(old.get("cells") or []) if isinstance(old, dict) else 0,
                       "sha256": silence.sha256(Path(args.baseline))})
    print_report(res, notes)
    target, page = args.certificate, args.html
    if notes is not None and not (target or page):
        name = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in (res["hosts"][0] if res["hosts"] else "host"))
        target = f"rasd-blindpath-{name}-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}.md"
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
    if args.witnesses:
        events = witness_events(res)
        write_output(args.witnesses, "".join(json.dumps(ev, ensure_ascii=False) + "\n" for ev in events))
        print(f"[+] witnesses: {args.witnesses} ({silence.plural(len(events), 'event')})")
    worse = bool(res.get("since") and res["since"]["worse"])
    return 1 if worse or (args.strict and res["counts"]["routes_unseen"]) else 0


if __name__ == "__main__":
    sys.exit(main())
