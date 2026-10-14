#!/usr/bin/env python3
"""
nearmiss.py - how close does real traffic come to each alert?

prove.py shows that every condition of a rule is held in place by a test. nearmiss.py
looks at the same boundary from the other side, with real (or replayed) traffic: which
events that do NOT alert are one condition away from alerting, and which condition is the
only thing holding them back. That is where false positives come from when the
environment drifts - a legacy application starts asking for RC4 tickets, an admin script
learns an encoded command line - and where a small rule edit has the largest blast radius.

Single-event detections, over the events of their log source that do not fire
  near miss       an event that already satisfies a needed part of the rule and that ONE
                  field edit would make fire. Each one is proven with a concrete witness: the
                  same event with that one field changed, which the engine confirms alerts.
                  Flips that no single value can produce (a path that would have to end in
                  both MsMpEng.exe and rundll32.exe) and events sharing nothing needed with
                  the rule (any Security event is "one EventID away" from 1102) do not count.
  boundary load   per condition: the near misses that this condition alone keeps from
                  alerting - a condition of a selection they fail, or a filter they hit. A
                  condition carrying a large share of the log source is a sensitive boundary.
  pinned          whether a true-negative test sits on the same boundary, so CI notices if
                  the condition is loosened. A loaded boundary without one is reported and,
                  with --suggest, the corpus event is printed as a candidate true negative.

Correlations, over the same corpus
  headroom        the highest count any window and group reached without alerting, and how
                  far below the threshold that is
  near misses     windows and groups one below the threshold, with the single-event
                  detections that fired on their events (a burst one short of the
                  correlation that another rule still caught is defence in depth, made visible)
  split bursts    groups that reached the threshold within ONE window length of sliding
                  time but never inside a single clock-aligned window: a burst a window
                  boundary cut in two - the tumbling-window blind spot, found in your data

Usage
  rasd nearmiss                                   # the replay corpus
  rasd nearmiss my-export.jsonl --profile auto    # your own traffic
  rasd nearmiss --filter T1558 --suggest
  rasd nearmiss --check                           # fail on a loaded, unpinned boundary
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BOLD, DIM, GREEN, RED, RESET, YELLOW, load_detections, load_jsonl
from convert import logsource_key
from correlation import EPOCH, OPS, epoch, human, load_correlations, value_reader
from parity import REPLAY_CORPUS
from prove import parse_condition
from replay import parse_time, route
from sigma_engine import SigmaError, _get_field, compile_rule

NOISE_KEYS = ("_case",)


@dataclass(frozen=True)
class Atom:
    """One field condition of one selection (or of one branch of an OR-list selection)."""
    selection: str
    branch: int | None
    key: str
    value: Any

    def label(self) -> str:
        where = self.selection if self.branch is None else f"{self.selection}[{self.branch}]"
        vals = list(self.value) if isinstance(self.value, tuple) else [self.value]
        shown = ", ".join(repr(v) for v in vals[:3]) + (f" (+{len(vals) - 3})" if len(vals) > 3 else "")
        return f"{where}: {self.key} {shown}"

    @property
    def is_filter(self) -> bool:
        return self.selection.startswith("filter")

    @property
    def field(self) -> str:
        return self.key.split("|")[0]

    @property
    def mods(self) -> list[str]:
        return self.key.split("|")[1:]

    @property
    def values(self) -> list:
        return list(self.value) if isinstance(self.value, tuple) else [self.value]


def freeze(v: Any) -> Any:
    return tuple(v) if isinstance(v, list) else v


class Boundary:
    """A rule as a boolean formula over its field conditions, so single flips can be tried."""

    def __init__(self, rule: dict, positives: Sequence[dict] = (), negatives: Sequence[dict] = ()):
        det = rule["detection"]
        self.rule = rule
        self.fires = compile_rule(rule)
        # real values of each field, from the rule's own tests: the witnesses a flip may borrow
        self.samples: dict[str, list] = {}
        for ev in list(positives) + list(negatives):
            for k, v in ev.items():
                if k not in NOISE_KEYS and v not in self.samples.setdefault(k.lower(), []):
                    self.samples[k.lower()].append(v)
        self.atoms: list[Atom] = []
        self.shape: dict[str, list[list[Atom]]] = {}          # selection -> branches -> atoms (AND)
        for name, sel in det.items():
            if name == "condition":
                continue
            branches = [sel] if isinstance(sel, dict) else sel if isinstance(sel, list) and all(
                isinstance(s, dict) for s in sel) else None
            if branches is None:
                raise SigmaError(f"selection '{name}' is not a map or a list of maps")
            self.shape[name] = []
            for i, b in enumerate(branches):
                group = [Atom(name, None if isinstance(sel, dict) else i, k, freeze(v)) for k, v in b.items()]
                self.atoms += group
                self.shape[name].append(group)
        conds = det["condition"] if isinstance(det["condition"], list) else [det["condition"]]
        self.asts = [parse_condition(c, det) for c in conds]
        self.check = {a: compile_rule({"detection": {"one": {a.key: list(a.value) if isinstance(a.value, tuple)
                                                                else a.value}, "condition": "one"}})
                      for a in self.atoms}

    def values(self, ev: dict) -> dict[Atom, bool]:
        return {a: bool(fn(ev)) for a, fn in self.check.items()}

    def verdict(self, vals: dict[Atom, bool]) -> bool:
        sel = {name: any(all(vals[a] for a in branch) for branch in branches) for name, branches in self.shape.items()}

        def ev(node) -> bool:
            kind = node[0]
            if kind == "sel":
                return sel[node[1]]
            if kind == "not":
                return not ev(node[1])
            parts = [ev(c) for c in node[1]]
            return all(parts) if kind == "and" else any(parts)
        return any(ev(ast) for ast in self.asts)

    def candidates(self, a: Atom, ev: dict, want: bool) -> list:
        """Values for a.field that could flip a to `want`: shaped by its modifiers, or borrowed
        from the rule's own tests."""
        orig = _get_field(ev, a.field)
        o = "" if orig is None else str(orig)
        out: list = []
        if want:
            if "exists" in a.mods:
                out.append("x" if a.values[0] else None)
            for v in a.values:
                if v is None or "re" in a.mods or "exists" in a.mods:
                    continue
                sv = str(v)
                out += ([o + sv, sv] if "contains" in a.mods or "endswith" in a.mods else
                        [sv + o, sv] if "startswith" in a.mods else [v])
        else:
            out += [o + "_", "_" + o, None, ""]
            if "contains" in a.mods:
                t = o
                for v in a.values:
                    t = re.sub(re.escape(str(v)), "", t, flags=re.IGNORECASE)
                out.append(t)
        return out + self.samples.get(a.field.lower(), [])

    @staticmethod
    def edit(ev: dict, field: str, value) -> dict:
        out = {k: v for k, v in ev.items() if k.lower() != field.lower()}
        if value is not None:
            out[next((k for k in ev if k.lower() == field.lower()), field)] = value
        return out

    def holding_back(self, ev: dict) -> list[tuple[Atom, dict]]:
        """For an event that does not fire: every condition that alone keeps it from firing,
        with the witness - the event with one field edited so that exactly that condition
        flips - which the engine confirms alerts."""
        vals = self.values(ev)
        if self.verdict(vals):
            return []
        out = []
        for a in self.atoms:
            vals[a] = not vals[a]
            flips = self.verdict(vals)
            shared = flips and any(vals[x] and not x.is_filter and x is not a and not self._flip_keeps(vals, x)
                                   for x in self.atoms)
            vals[a] = not vals[a]
            if not shared:                                 # no flip, or nothing needed in common
                continue
            same = [x for x in self.atoms if x.field.lower() == a.field.lower() and x is not a]
            for value in self.candidates(a, ev, not vals[a]):
                twin = self.edit(ev, a.field, value)
                got = {x: bool(self.check[x](twin)) for x in [a, *same]}
                if got[a] != vals[a] and all(got[x] == vals[x] for x in same) and self.fires(twin):
                    out.append((a, twin))
                    break
        return out

    def _flip_keeps(self, vals: dict[Atom, bool], x: Atom) -> bool:
        """True when flipping x too would leave the (already flipped) verdict firing - x is not needed."""
        vals[x] = not vals[x]
        keeps = self.verdict(vals)
        vals[x] = not vals[x]
        return keeps


def analyse_detection(det, events: list[dict]) -> dict:
    try:
        b = Boundary(det.rule, det.tests("true_positive"), det.tests("true_negative"))
        fires = b.fires
    except SigmaError as e:
        return {"error": str(e)}
    src = logsource_key(det.rule)
    pool = [ev for ev in events if route(ev) == src]
    silent = [ev for ev in pool if not fires(ev)]
    for ev in pool[:200]:                                   # the formula must reproduce the engine
        if b.verdict(b.values(ev)) != bool(fires(ev)):
            return {"error": "the condition could not be modelled field by field"}
    load: dict[Atom, list[tuple[dict, dict]]] = {}
    for ev in silent:
        for a, twin in b.holding_back(ev):
            load.setdefault(a, []).append((ev, twin))
    pinned: dict[Atom, int] = {}
    for i, ev in enumerate(det.tests("true_negative"), 1):
        for a, _twin in b.holding_back(ev):
            pinned.setdefault(a, i)
    rows = []
    for a, pairs in sorted(load.items(), key=lambda kv: (-len(kv[1]), kv[0].label())):
        ev, twin = pairs[0]
        rows.append({"condition": a.label(), "kind": "filter" if a.is_filter else "selection", "events": len(pairs),
                     "share": round(100 * len(pairs) / len(pool), 1) if pool else 0.0,
                     "pinned_by": f"TN#{pinned[a]}" if a in pinned else None,
                     "example": {k: v for k, v in ev.items() if k not in NOISE_KEYS},
                     "witness": {"field": a.field, "from": _get_field(ev, a.field), "to": _get_field(twin, a.field)}})
    near = {id(ev) for pairs in load.values() for ev, _t in pairs}
    return {"logsource": src, "events": len(pool), "silent": len(silent), "near_misses": len(near),
            "boundaries": rows}


def windows(corr, events: list[dict]) -> dict[tuple, list[dict]]:
    """(window start, group) -> the base events counted in it, with the engine's own reading of values."""
    p = corr.params
    read, fn, src = value_reader(p), compile_rule(corr.base), logsource_key(corr.base)
    out: dict[tuple, list[dict]] = {}
    for ev in events:
        if route(ev) != src or not fn(ev):
            continue
        t = parse_time(ev)
        group = tuple(read(ev, g) for g in p.group_by)
        if t is None or None in group or (p.counted and read(ev, p.counted) is None):
            continue
        start = math.floor(epoch(t) / p.timespan) * p.timespan
        out.setdefault((start, group), []).append(ev)
    return out


def sliding_bursts(corr, events: list[dict], need: int) -> list[tuple[tuple, int, Any, Any]]:
    """Every stretch where a group reaches `need` within a span shorter than one window length,
    wherever it starts: (group, highest count, first event time, last event time), overlapping
    stretches merged."""
    p = corr.params
    read, fn, src = value_reader(p), compile_rule(corr.base), logsource_key(corr.base)
    per_group: dict[tuple, list] = {}
    for ev in events:
        if route(ev) != src or not fn(ev):
            continue
        t = parse_time(ev)
        group = tuple(read(ev, g) for g in p.group_by)
        value = read(ev, p.counted) if p.counted else None
        if t is None or None in group or (p.counted and value is None):
            continue
        per_group.setdefault(group, []).append((t, value))
    bursts = []
    span = timedelta(seconds=p.timespan)
    for group, items in sorted(per_group.items()):
        items.sort(key=lambda x: x[0])
        counts: dict = {}
        left, current = 0, None
        for right, (t, value) in enumerate(items):
            counts[value] = counts.get(value, 0) + 1
            while t - items[left][0] >= span:
                old = items[left][1]
                counts[old] -= 1
                if not counts[old]:
                    del counts[old]
                left += 1
            metric = len(counts) if p.counted else right - left + 1
            if metric < need:
                continue
            if current and items[left][0] <= current[3]:          # overlaps the stretch being built
                current = (group, max(current[1], metric), current[2], t)
            else:
                if current:
                    bursts.append(current)
                current = (group, metric, items[left][0], t)
        if current:
            bursts.append(current)
    return bursts


def analyse_correlation(corr, events: list[dict], dets) -> dict:
    p = corr.params
    if p.op not in ("gte", "gt"):
        return {"describe": p.describe(), "note": "headroom applies to at-least conditions only"}
    need = p.threshold + (1 if p.op == "gt" else 0)
    read = value_reader(p)
    rows: list[dict[str, Any]] = []
    for (start, group), evs in windows(corr, events).items():
        metric = len({read(ev, p.counted) for ev in evs}) if p.counted else len(evs)
        rows.append({"window_start": EPOCH + timedelta(seconds=start), "group": "|".join(group) or "*",
                     "metric": metric, "events": evs})
    quiet = [r for r in rows if not OPS[p.op](r["metric"], p.threshold)]
    best = max(quiet, key=lambda r: r["metric"], default=None)
    alerted = {(r["group"], r["window_start"]) for r in rows if OPS[p.op](r["metric"], p.threshold)}

    def windows_between(a, b):
        first_w = math.floor(epoch(a) / p.timespan) * p.timespan
        last_w = math.floor(epoch(b) / p.timespan) * p.timespan
        return {EPOCH + timedelta(seconds=w) for w in range(first_w, last_w + 1, p.timespan)}
    split = [{"group": "|".join(g) or "*", "metric": m, "from": a.isoformat(), "to": b.isoformat()}
             for g, m, a, b in sliding_bursts(corr, events, need)
             if not {("|".join(g) or "*", w) for w in windows_between(a, b)} & alerted]
    near = []
    for r in sorted((r for r in quiet if r["metric"] == need - 1), key=lambda r: r["window_start"]):
        caught = sorted({d.id for d in dets for ev in r["events"] if compile_rule(d.rule)(ev)})
        near.append({"window_start": r["window_start"].isoformat(), "group": r["group"], "metric": r["metric"],
                     "caught_by": caught})
    return {"describe": p.describe(), "threshold": need, "windows": len(rows),
            "alerting": len(rows) - len(quiet), "max_quiet": best["metric"] if best else 0,
            "max_quiet_at": (f"{best['group']} · {best['window_start']:%Y-%m-%d %H:%M}" if best else None),
            "headroom": need - (best["metric"] if best else 0), "near_misses": near, "split_bursts": split,
            "unit": f"distinct {p.field}" if p.counted else "events", "window": human(p.timespan)}


def analyse(events: list[dict], filter_: str | None = None) -> dict:
    """Single-event detections and the base rules of the correlations (keyed <id> (base)), then
    the correlations themselves."""
    dets = load_detections(filter_)
    corrs = load_correlations(filter_)
    all_dets = load_detections()
    singles = {d.id: analyse_detection(d, events) for d in dets}
    singles.update({f"{c.id} (base)": analyse_detection(c.base_detection(), events) for c in corrs})
    return {"detections": singles,
            "correlations": {c.id: analyse_correlation(c, events, all_dets) for c in corrs}}


def show_change(a, b, width: int = 44) -> str:
    """Before -> after, cut around the part that changed."""
    a = "<missing>" if a is None else str(a)
    b = "<missing>" if b is None else str(b)
    if len(a) <= width and len(b) <= width:
        return f"{a!r} → {b!r}"
    p = 0
    while p < min(len(a), len(b)) and a[p] == b[p]:
        p += 1
    q = 0
    while q < min(len(a), len(b)) - p and a[-1 - q] == b[-1 - q]:
        q += 1

    def cut(x: str) -> str:
        start, end = max(0, p - 12), len(x) - max(0, q - 12)
        mid = x[start:end]
        mid = mid if len(mid) <= width else mid[:width // 2] + "…" + mid[-width // 2:]
        return ("…" if start else "") + mid + ("…" if end < len(x) else "")
    return f"{cut(a)!r} → {cut(b)!r}"


def unpinned(report: dict, min_events: int = 1) -> list[str]:
    return [f"{det}: {b['condition']} ({b['events']} events)" for det, r in report["detections"].items()
            for b in r.get("boundaries", []) if not b["pinned_by"] and b["events"] >= min_events]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logs", nargs="*", help="JSONL exports (default: the replay corpus)")
    ap.add_argument("--profile", help="telemetry profile of the logs (see: rasd profiles), or 'auto'")
    ap.add_argument("--filter")
    ap.add_argument("--suggest", action="store_true", help="print a candidate true negative for every unpinned boundary")
    ap.add_argument("--check", action="store_true", help="fail when a boundary carrying traffic has no true negative")
    ap.add_argument("--json", help="write the report as JSON")
    args = ap.parse_args()

    import profiles                                     # imported here: profiles imports replay
    paths = [Path(p) for p in args.logs] or [REPLAY_CORPUS]
    events, used = profiles.apply([ev for p in paths for ev in load_jsonl(p)], args.profile)
    report = analyse(events, args.filter)

    print(f"{BOLD}Near-miss analysis · {len(events)} events from {', '.join(p.name for p in paths)}"
          + (f" · profile {used}" if used != profiles.NATIVE else "") + f"{RESET}\n")
    print(f"{BOLD}Single-event detections{RESET} {DIM}- events that one condition alone keeps from alerting{RESET}")
    for det, r in report["detections"].items():
        if "error" in r:
            print(f"  {YELLOW}?{RESET} {det}  {DIM}{r['error']}{RESET}")
            continue
        share = f"{100 * r['near_misses'] / r['events']:.0f}%" if r["events"] else "-"
        print(f"  {det:<48} {r['near_misses']:>4} of {r['events']:<4} {DIM}{r['logsource']} events ({share}) one condition away{RESET}")
        for b in r["boundaries"][:4]:
            pin = f"{GREEN}pinned by {b['pinned_by']}{RESET}" if b["pinned_by"] else f"{RED}no true negative{RESET}"
            print(f"      {b['events']:>4} × {b['condition'][:64]:<64} {pin}")
            w = b["witness"]
            print(f"             {DIM}e.g. {w['field']}: {show_change(w['from'], w['to'])} alerts{RESET}")
            if args.suggest and not b["pinned_by"]:
                print(f"           {DIM}candidate true negative: {json.dumps(b['example'], ensure_ascii=False)[:220]}{RESET}")
        if len(r["boundaries"]) > 4:
            print(f"      {DIM}+ {len(r['boundaries']) - 4} smaller boundaries (--json for all){RESET}")
    if report["correlations"]:
        print(f"\n{BOLD}Correlations{RESET} {DIM}- how close quiet windows came to the threshold{RESET}")
    for cid, r in report["correlations"].items():
        if "note" in r:
            print(f"  {cid}  {DIM}{r['note']}{RESET}")
            continue
        colour = GREEN if r["headroom"] > 1 else YELLOW
        print(f"  {cid:<48} {colour}headroom {r['headroom']}{RESET} {DIM}- quiet windows reached at most {r['max_quiet']} "
              f"of {r['threshold']} {r['unit']}" + (f" ({r['max_quiet_at']})" if r["max_quiet_at"] else "")
              + f" · {r['alerting']} alerting of {r['windows']} windows{RESET}")
        for n in r["near_misses"]:
            caught = (f"{GREEN}caught by {', '.join(n['caught_by'])}{RESET}" if n["caught_by"]
                      else f"{YELLOW}no other detection fired{RESET}")
            print(f"      near miss  {n['group']} · {n['window_start'][:16].replace('T', ' ')} · {n['metric']} of "
                  f"{r['threshold']} {r['unit']} - {caught}")
        for b in r["split_bursts"]:
            print(f"      {YELLOW}split burst{RESET} {b['group']} · {b['from'][:19].replace('T', ' ')} → {b['to'][11:19]} · "
                  f"{b['metric']} {r['unit']} within {r['window']}, cut by a window boundary - no tumbling window alerted")
    gaps = unpinned(report)
    print(f"\n{BOLD}{sum(len(r.get('boundaries', [])) for r in report['detections'].values())} loaded boundaries · "
          f"{len(gaps)} without a true negative{RESET}")
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
        print(f"[+] JSON: {args.json}")
    if args.check and gaps:
        for g in gaps:
            print(f"  {RED}✗{RESET} {g}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
