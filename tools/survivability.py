#!/usr/bin/env python3
"""
survivability.py - RASD-Trace: what an attack leaves behind, and what it costs to make it disappear.

A detection answers "did we see it". An investigation has to answer more: did it happen, when, under
which account, with which command, from where. Each answer rests on artifacts (an event record, a
Prefetch file, a registry value), and an intruder who holds the host can remove artifacts. This tool
measures how hard that is, and whether the attempt is seen.

dfir/trace/model.yml names the stores evidence lives in, the artifacts read from them, the questions
each artifact answers and the anti-forensic actions RASD knows, with what each destroys, blinds and
leaves behind. dfir/trace/footprints.yml names the artifacts each detection's technique writes. From
the two, for every detection and every question, an exhaustive search over every sequence of actions
before and after the technique decides one of three things:

  out of reach   no sequence removes the answer: a witness sits where the attacker does not
  evident        the answer can be removed, and every sequence that removes it raises a RASD alert
  exposed (n)    n actions remove the answer and raise no alert; the sequence is shown with what it
                 still leaves on the host and in the SIEM

  (default)      the survivability table, the exposed sequences, the rules that would close them
  DETECTION      one detection: its witnesses per question in collection order, its results
  --lost A,B     with DETECTION: the stores an incident already lost (or `siem`); what can still be
                 proven, and from which artifact
  --check        the model is consistent with the rules, the forwarder inputs and the engine: every
                 trace that names a detection fires it, every other trace fires no rule, every
                 detection has a footprint or a stated reason, and the results page is current
  --write        render the results block of dfir/trace/README.md
  --json FILE    the results as JSON

The search is exact for the catalogued actions and says nothing about an action the catalogue lacks:
adding one re-opens every result, which is how the model is meant to grow. Entries are documented
behaviour, not lab evidence; no result here raises a detection's maturity.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import functools
from collections import deque
from dataclasses import dataclass, field, replace
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BOLD, DFIR, DIM, GREEN, RED, RESET, ROOT, YELLOW, find_detection, load_detections, md_text
from convert import logsource_key
from correlation import load_correlations
from replay import route
from sigma_engine import SigmaError, matches

TRACE = DFIR / "trace"
MODEL = TRACE / "model.yml"
FOOTPRINTS = TRACE / "footprints.yml"
README = TRACE / "README.md"
BLOCK_START, BLOCK_END = "<!-- rasd:trace:start -->", "<!-- rasd:trace:end -->"
TECHNIQUE = "technique"
BASES = ("vendor", "practitioner")
MOMENTS = ("start", "effect")
SIEM = "siem"


class TraceError(SystemExit):
    pass


@dataclass(frozen=True)
class Artifact:
    id: str
    name: str
    store: str
    answers: frozenset[str]
    logsource: str | None
    optional: str | None
    basis: str
    source: str
    limits: str | None


@dataclass(frozen=True)
class Mark:
    """One trace an erasure leaves: an artifact, the moment it is written and the rule that reads it."""
    artifact: str
    at: str
    detection: str | None
    event: dict | None

    def key(self, action: str) -> str:
        return f"{self.artifact}:{action}" if self.event and not self.detection and self.artifact == "sysmon_1" else self.artifact


@dataclass(frozen=True)
class Erasure:
    id: str
    name: str
    example: str
    destroys: frozenset[str]
    blinds: frozenset[str]
    still_written: frozenset[str]
    stops_forwarding: bool
    basis: str
    note: str | None
    source: str | None
    marks: tuple[Mark, ...]


@dataclass(frozen=True)
class Footprint:
    detection: str
    reads: str
    writes: tuple[str, ...]
    shows: dict = field(default_factory=dict, hash=False, compare=False)
    note: str | None = None

    @property
    def artifacts(self) -> tuple[str, ...]:
        return (self.reads, *self.writes)


@dataclass
class Model:
    position: str
    questions: dict[str, str]
    stores: dict[str, dict]
    artifacts: dict[str, Artifact]
    erasures: dict[str, Erasure]
    forwarded: dict[str, str]
    forwarder_inputs: str
    footprints: dict[str, Footprint]
    not_modelled: dict[str, str]

    def remote(self, artifact: str) -> bool:
        return self.stores[self.artifacts[artifact].store]["reach"] == "remote"

    def ships(self, artifact: str) -> bool:
        return self.artifacts[artifact].store in self.forwarded

    def optional(self) -> list[str]:
        return [a.id for a in self.artifacts.values() if a.optional]


def _doc(path: Path) -> dict:
    if not path.exists():
        raise TraceError(f"{path.relative_to(ROOT)} is missing")
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(doc, dict):
        raise TraceError(f"{path.relative_to(ROOT)}: a mapping is expected at the top level")
    return doc


def build_model(model: dict, prints: dict) -> Model:
    artifacts = {
        aid: Artifact(aid, str(a.get("name", aid)), str(a.get("store", "")), frozenset(a.get("answers") or []),
                      a.get("logsource"), a.get("optional"), str(a.get("basis", "")), str(a.get("source", "")), a.get("limits"))
        for aid, a in (model.get("artifacts") or {}).items()}
    erasures = {}
    for e in model.get("erasures") or []:
        marks = tuple(Mark(str(t.get("artifact", "")), str(t.get("at", "")), t.get("detection"), t.get("event"))
                      for t in e.get("traces") or [])
        erasures[str(e.get("id"))] = Erasure(
            str(e.get("id")), str(e.get("name", "")), str(e.get("example", "")), frozenset(e.get("destroys") or []),
            frozenset(e.get("blinds") or []), frozenset(e.get("still_written") or []), bool(e.get("stops_forwarding")),
            str(e.get("basis", "")), e.get("note"), e.get("source"), marks)
    footprints = {}
    for det, f in (prints.get("footprints") or {}).items():
        writes = f.get("writes") or []
        footprints[det] = Footprint(det, str(f.get("reads", "")), tuple(str(w.get("artifact", "")) for w in writes),
                                    {str(w.get("artifact")): w.get("shows") for w in writes if w.get("shows")}, f.get("note"))
    baseline = model.get("baseline") or {}
    return Model(str(model.get("position", "")), dict(model.get("questions") or {}), dict(model.get("stores") or {}), artifacts,
                 erasures, dict(baseline.get("forwarded") or {}), str(baseline.get("forwarder_inputs", "")), footprints,
                 dict(prints.get("not_modelled") or {}))


def load_model() -> Model:
    return build_model(_doc(MODEL), _doc(FOOTPRINTS))


# --------------------------------------------------------------------------- #
# The search
# --------------------------------------------------------------------------- #
# A state is what the world looks like part-way through a sequence:
#   done      the technique has run
#   blinders  the blinding actions in effect (their exceptions differ, so the actions are kept, not the stores)
#   fwd       the forwarder still ships
#   local     the technique's artifacts still on the host
#   remote    the technique's artifacts out of reach: SIEM copies and records written on other machines
#   alert     the detection's own alert was raised
#   tamper    an action's trace reached a rule
State = tuple[bool, frozenset, bool, frozenset, frozenset, bool, bool]
START: State = (False, frozenset(), True, frozenset(), frozenset(), False, False)


def _written(m: Model, artifact: str, blinders: frozenset) -> bool:
    store = m.artifacts[artifact].store
    return not any(store in m.erasures[b].blinds and artifact not in m.erasures[b].still_written for b in blinders)


def run_technique(m: Model, fp: Footprint, state: State, enabled: frozenset) -> State:
    _done, blinders, fwd, local, remote, _alert, tamper = state
    here, away = set(local), set(remote)
    for a in fp.artifacts:
        if m.artifacts[a].optional and a not in enabled:
            continue
        if m.remote(a):
            away.add(a)
        elif _written(m, a, blinders):
            here.add(a)
            if fwd and m.ships(a):
                away.add(a)
    return (True, blinders, fwd, frozenset(here), frozenset(away), fp.reads in away, tamper)


def _seen(m: Model, e: Erasure, mark: Mark, blinders: frozenset, fwd: bool, rules: frozenset, enabled: frozenset) -> bool:
    """Does this trace reach a rule: it is written, it leaves the host, and a rule (real or supposed) reads it."""
    if not (mark.detection or mark.key(e.id) in rules):
        return False
    if m.artifacts[mark.artifact].optional and mark.artifact not in enabled:
        return False
    if m.remote(mark.artifact):
        return True
    return _written(m, mark.artifact, blinders) and fwd and m.ships(mark.artifact)


def run_erasure(m: Model, e: Erasure, state: State, rules: frozenset, enabled: frozenset) -> State:
    done, blinders, fwd, local, remote, alert, tamper = state
    after_blinders = blinders | {e.id} if e.blinds else blinders
    after_fwd = fwd and not e.stops_forwarding
    for mark in e.marks:
        if mark.at == "start":
            tamper = tamper or _seen(m, e, mark, blinders, after_fwd, rules, enabled)
        else:
            tamper = tamper or _seen(m, e, mark, after_blinders, after_fwd, rules, enabled)
    kept = frozenset(a for a in local if m.artifacts[a].store not in e.destroys)
    return (done, after_blinders, after_fwd, kept, remote, alert, tamper)


def answered(m: Model, state: State, question: str) -> bool:
    if question == "alert":
        return state[5]
    return any(question in m.artifacts[a].answers for a in state[3] | state[4])


def explore(m: Model, fp: Footprint, rules: frozenset = frozenset(), enabled: frozenset = frozenset(),
            quiet_only: bool = False) -> dict[State, tuple[int, State | None, str | None]]:
    """Every state reachable by any sequence of erasures around the technique, with the fewest actions that
    reach it and the step that led there. Breadth first, so the first visit is a cheapest one. With
    quiet_only, a state in which any alert was raised is not explored further: no quiet sequence passes
    through it."""
    seen: dict[State, tuple[int, State | None, str | None]] = {START: (0, None, None)}
    queue = deque([START])
    order = sorted(m.erasures, key=lambda eid: (m.erasures[eid].basis != "vendor", eid))
    while queue:
        state = queue.popleft()
        depth = seen[state][0]
        moves: list[tuple[str, State, int]] = []
        if not state[0]:
            moves.append((TECHNIQUE, run_technique(m, fp, state, enabled), 0))
        moves += [(eid, run_erasure(m, m.erasures[eid], state, rules, enabled), 1) for eid in order]
        for name, nxt, cost in moves:
            if quiet_only and (nxt[5] or nxt[6]):
                continue
            if nxt not in seen or seen[nxt][0] > depth + cost:
                seen[nxt] = (depth + cost, state, name)
                (queue.appendleft if cost == 0 else queue.append)(nxt)
    return seen


def path(seen: dict, state: State) -> list[str]:
    steps: list[str] = []
    while seen[state][1] is not None:
        steps.append(str(seen[state][2]))
        state = seen[state][1]
    return steps[::-1]


def questions_of(m: Model, fp: Footprint, enabled: frozenset = frozenset()) -> list[str]:
    live = [a for a in fp.artifacts if not m.artifacts[a].optional or a in enabled]
    return [q for q in m.questions if q == "alert" or any(q in m.artifacts[a].answers for a in live)]


def _cheapest(m: Model, seen: dict, question: str, quiet: bool) -> tuple[int, list[str]] | None:
    best: tuple[int, State] | None = None
    for state, (depth, _p, _n) in seen.items():
        if not state[0] or answered(m, state, question) or (quiet and (state[5] or state[6])):
            continue
        if best is None or depth < best[0]:
            best = (depth, state)
    return (best[0], path(seen, best[1])) if best else None


def survivability(m: Model, fp: Footprint, rules: frozenset = frozenset(), enabled: frozenset = frozenset(),
                  quiet_only: bool = False) -> dict[str, dict]:
    """Per question: the cheapest sequence that removes the answer (erase) and the cheapest that does so
    without any alert (quiet). None means no such sequence exists."""
    loud = None if quiet_only else explore(m, fp, rules, enabled)
    hush = explore(m, fp, rules, enabled, quiet_only=True)
    out = {}
    for q in questions_of(m, fp, enabled):
        erase = _cheapest(m, loud, q, quiet=False) if loud is not None else None
        quiet = _cheapest(m, hush, q, quiet=True)
        out[q] = {"erase": erase, "quiet": quiet,
                  "verdict": "exposed" if quiet else ("evident" if erase or quiet_only else "out of reach")}
    return out


def residue(m: Model, fp: Footprint, plan: list[str], enabled: frozenset = frozenset()) -> list[dict]:
    """Replay one sequence and list what its own actions leave: each trace, and whether it ends on the host,
    in the SIEM, or nowhere."""
    blinders: frozenset = frozenset()
    fwd = True
    left: list[dict] = []
    for step in plan:
        if step == TECHNIQUE:
            continue
        e = m.erasures[step]
        after_blinders = blinders | {e.id} if e.blinds else blinders
        after_fwd = fwd and not e.stops_forwarding
        for row in left:
            if row["host"] and m.artifacts[row["artifact"]].store in e.destroys:
                row["host"] = False
        for mark in e.marks:
            art = m.artifacts[mark.artifact]
            if art.optional and mark.artifact not in enabled:
                continue
            if m.remote(mark.artifact):
                left.append({"action": e.id, "artifact": mark.artifact, "host": False, "siem": True, "rule": mark.detection,
                             "key": mark.key(e.id)})
                continue
            written = _written(m, mark.artifact, blinders if mark.at == "start" else after_blinders)
            host = written and not (mark.at == "start" and art.store in e.destroys)
            left.append({"action": e.id, "artifact": mark.artifact, "host": host,
                         "siem": written and after_fwd and m.ships(mark.artifact), "rule": mark.detection, "key": mark.key(e.id)})
        blinders, fwd = after_blinders, after_fwd
    return [row for row in left if row["host"] or row["siem"]]


# --------------------------------------------------------------------------- #
# What would change the picture
# --------------------------------------------------------------------------- #
def rule_candidates(m: Model) -> dict[str, list[str]]:
    """Traces no rule reads yet that a SIEM rule could: they leave the host or are written elsewhere.
    key -> the actions that leave it."""
    out: dict[str, list[str]] = {}
    for e in m.erasures.values():
        for mark in e.marks:
            if mark.detection or m.artifacts[mark.artifact].optional:
                continue
            if m.remote(mark.artifact) or m.ships(mark.artifact):
                out.setdefault(mark.key(e.id), []).append(e.id)
    return out


def quiet_plans(m: Model, rules: frozenset = frozenset()) -> dict[tuple[str, str], list[str]]:
    """Under a set of supposed rules: every (detection, question) a quiet sequence can silence, with a cheapest one."""
    out = {}
    for det, fp in m.footprints.items():
        for q, res in survivability(m, fp, rules, quiet_only=True).items():
            if res["quiet"]:
                out[(det, q)] = res["quiet"][1]
    return out


def closure(m: Model) -> list[dict]:
    """The rules to write, in order. Each step looks at the cheapest quiet sequence of every exposed pair, takes
    the unread trace that reaches the SIEM in the most of them (a rule on one artifact before a rule on one
    command line), supposes a rule reads it, and searches again. It stops when nothing is exposed, or when the
    sequences that remain leave nothing a SIEM rule could read."""
    candidates = rule_candidates(m)
    chosen: frozenset = frozenset()
    steps: list[dict] = []
    plans = quiet_plans(m)
    while plans:
        votes: dict[str, int] = {}
        for (det, _q), plan in plans.items():
            keys = {r["key"] for r in residue(m, m.footprints[det], plan) if r["siem"] and not r["rule"]}
            for key in keys & (set(candidates) - chosen):
                votes[key] = votes.get(key, 0) + 1
        if not votes:
            break
        best = min(votes, key=lambda k: (-votes[k], ":" in k, k))
        chosen |= {best}
        plans = quiet_plans(m, chosen)
        steps.append({"rule": best, "actions": candidates[best], "exposed_after": len(plans)})
    return steps


def host_depth(m: Model) -> dict[str, dict[str, int]]:
    """On a host that forwards nothing: the number of actions that removes every witness of a question, alerts
    or not. It is the depth of the evidence the host itself holds."""
    alone = replace(m, forwarded={})
    out = {}
    for det, fp in m.footprints.items():
        if all(m.remote(a) for a in fp.artifacts):
            continue
        seen = explore(alone, fp)
        out[det] = {q: hit[0] for q in questions_of(m, fp) if q != "alert" and (hit := _cheapest(alone, seen, q, quiet=False))}
    return out


@functools.lru_cache(maxsize=1)
def closure_summary() -> tuple[dict, int, int]:
    """For the metrics pages: the counts, the number of rules in the closing order and the pairs left after them."""
    data = compute(load_model())
    steps = data["closure"]
    return data["counts"], len(steps), steps[-1]["exposed_after"] if steps else data["counts"]["exposed"]


def compute(m: Model) -> dict:
    results = {d: survivability(m, fp) for d, fp in m.footprints.items()}
    plans: dict[tuple[str, ...], dict] = {}
    for d, per_q in results.items():
        for q, res in per_q.items():
            if res["quiet"]:
                plan = tuple(res["quiet"][1])
                entry = plans.setdefault(plan, {"plan": list(plan), "silences": [], "residue": residue(m, m.footprints[d], list(plan))})
                entry["silences"].append(f"{d} · {q}")
    counts = {"detections": len(m.footprints), "not_modelled": len(m.not_modelled), "artifacts": len(m.artifacts),
              "erasures": len(m.erasures), "pairs": sum(len(r) for r in results.values())}
    for verdict in ("out of reach", "evident", "exposed"):
        counts[verdict] = sum(1 for r in results.values() for x in r.values() if x["verdict"] == verdict)
    return {"results": results, "plans": sorted(plans.values(), key=lambda p: (len(p["plan"]), p["plan"])),
            "closure": closure(m), "depth": host_depth(m), "counts": counts}


# --------------------------------------------------------------------------- #
# Check
# --------------------------------------------------------------------------- #
def forwarder_channels(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    return set(re.findall(r"(?m)^\[WinEventLog://([^\]]+)\]", text))


def rules_by_source() -> dict[str, list]:
    by: dict[str, list] = {}
    for d in load_detections():
        by.setdefault(logsource_key(d.rule), []).append(d)
    return by


def fired(event: dict, by_source: dict[str, list]) -> list[str]:
    out = []
    for d in by_source.get(route(event) or "", []):
        try:
            if matches(d.rule, event):
                out.append(d.id)
        except SigmaError:
            continue
    return sorted(out)


def check(m: Model) -> list[str]:
    errs: list[str] = []
    model_file, prints_file = MODEL.relative_to(ROOT), FOOTPRINTS.relative_to(ROOT)
    for aid, a in m.artifacts.items():
        if a.store not in m.stores:
            errs.append(f"{model_file}: artifact {aid}: store '{a.store}' is not defined")
        if a.basis not in BASES:
            errs.append(f"{model_file}: artifact {aid}: basis must be one of {', '.join(BASES)}")
        if not a.source.startswith("https://"):
            errs.append(f"{model_file}: artifact {aid}: source must be an https URL")
        errs += [f"{model_file}: artifact {aid}: answers '{q}', which is not a question" for q in a.answers if q not in m.questions]
        if not a.answers:
            errs.append(f"{model_file}: artifact {aid} answers no question")
    for sid, s in m.stores.items():
        if s.get("reach") not in ("host", "remote"):
            errs.append(f"{model_file}: store {sid}: reach must be host or remote")
    for sid in m.forwarded:
        if sid not in m.stores or m.stores[sid].get("reach") != "host":
            errs.append(f"{model_file}: baseline.forwarded: {sid} is not a store on the host")
    inputs = ROOT / m.forwarder_inputs
    if set(m.forwarded.values()) != forwarder_channels(inputs):
        errs.append(f"{model_file}: baseline.forwarded lists {sorted(m.forwarded.values())}, and {m.forwarder_inputs} "
                    f"ships {sorted(forwarder_channels(inputs))}")

    by_source = rules_by_source()
    known = {d.id for ds in by_source.values() for d in ds}
    for e in m.erasures.values():
        where = f"{model_file}: erasure {e.id}"
        if e.basis not in BASES:
            errs.append(f"{where}: basis must be one of {', '.join(BASES)}")
        if not (e.destroys or e.blinds or e.stops_forwarding):
            errs.append(f"{where}: destroys nothing, blinds nothing and does not stop forwarding")
        for target in e.destroys | e.blinds:
            if target not in m.stores:
                errs.append(f"{where}: store '{target}' is not defined")
            elif m.stores[target].get("reach") != "host":
                errs.append(f"{where}: store '{target}' is out of the attacker's reach")
        errs += [f"{where}: still_written '{a}' is not an artifact" for a in e.still_written if a not in m.artifacts]
        for mark in e.marks:
            if mark.artifact not in m.artifacts:
                errs.append(f"{where}: trace artifact '{mark.artifact}' is not defined")
                continue
            if mark.at not in MOMENTS:
                errs.append(f"{where}: trace {mark.artifact}: at must be one of {', '.join(MOMENTS)}")
            if mark.detection and mark.detection not in known:
                errs.append(f"{where}: trace {mark.artifact}: detection {mark.detection} does not exist")
            if mark.detection and not mark.event:
                errs.append(f"{where}: trace {mark.artifact} names a detection and gives no event to prove it")
            if mark.event:
                got = fired(mark.event, by_source)
                want = [mark.detection] if mark.detection else []
                if got != want:
                    errs.append(f"{where}: trace {mark.artifact}: the event fires {got or 'no rule'}, the model says "
                                f"{want or 'no rule'}" + ("" if want else " (a rule now reads this trace: name it in `detection`)"))

    sources = {d.id: logsource_key(d.rule) for ds in by_source.values() for d in ds}
    sources.update({c.id: logsource_key(c.base) for c in load_correlations()})
    for det, fp in m.footprints.items():
        where = f"{prints_file}: {det}"
        if det not in sources:
            errs.append(f"{where}: no such detection or correlation")
            continue
        missing = [a for a in fp.artifacts if a not in m.artifacts]
        errs += [f"{where}: artifact '{a}' is not in the model" for a in missing]
        if missing:
            continue
        if m.artifacts[fp.reads].logsource != sources[det]:
            errs.append(f"{where}: reads {fp.reads} (log source {m.artifacts[fp.reads].logsource}), and the rule reads {sources[det]}")
        if m.artifacts[fp.reads].optional:
            errs.append(f"{where}: reads {fp.reads}, which is optional: a rule cannot depend on telemetry the baseline lacks")
        if len(set(fp.artifacts)) != len(fp.artifacts):
            errs.append(f"{where}: an artifact is listed twice")
    for det in m.not_modelled:
        if det not in sources:
            errs.append(f"{prints_file}: not_modelled: {det} does not exist")
        if det in m.footprints:
            errs.append(f"{prints_file}: {det} has a footprint and is listed under not_modelled")
    errs += [f"{prints_file}: {det} has neither a footprint nor a reason under not_modelled"
             for det in sorted(sources) if det not in m.footprints and det not in m.not_modelled]
    return errs


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def plan_text(m: Model, plan: list[str]) -> str:
    return " → ".join("**the technique**" if s == TECHNIQUE else m.erasures[s].name for s in plan)


def rule_text(m: Model, key: str) -> str:
    artifact, _, action = key.partition(":")
    name = m.artifacts[artifact].name
    return f"{name} of `{m.erasures[action].example}`" if action else name


def _cell(res: dict) -> str:
    if res["verdict"] == "exposed":
        return f"exposed ({res['quiet'][0]})"
    return res["verdict"]


def render(m: Model, data: dict) -> str:
    c = data["counts"]
    asked = [q for q in m.questions if any(q in r for r in data["results"].values())]
    lines = [
        BLOCK_START,
        f"**Position:** {m.position}.",
        "",
        f"{c['detections']} detections modelled ({c['not_modelled']} not yet), {c['artifacts']} artifacts, {c['erasures']} anti-forensic actions. "
        f"Of {c['pairs']} detection-question pairs: **{c['out of reach']} out of reach**, **{c['evident']} evident**, "
        f"**{c['exposed']} exposed**.",
        "",
        "| Detection | " + " | ".join(q.capitalize() for q in asked) + " |",
        "|---|" + "---|" * len(asked),
    ]
    for det, per_q in data["results"].items():
        lines.append(f"| `{det}` | " + " | ".join(_cell(per_q[q]) if q in per_q else "" for q in asked) + " |")
    lines += ["", "<sub>out of reach: no sequence of catalogued actions removes the answer · evident: every sequence that removes it raises "
              "a RASD alert · exposed (n): n actions remove it and raise none.</sub>", ""]

    if data["plans"]:
        lines += ["### How the quiet sequences begin", "",
                  "Every exposed answer is silenced by a sequence that first blinds the telemetry, then runs the technique, then removes "
                  "what the host still holds. Grouped by the blinding step, with what that step itself sends to the SIEM before it takes "
                  "effect (`rasd trace <detection>` prints each full sequence).", "",
                  "| Before the technique | Answers it silences | Clean-up actions after | What reaches the SIEM unread |", "|---|---|---|---|"]
        openers: dict[tuple[str, ...], dict] = {}
        for p in data["plans"]:
            cut = p["plan"].index(TECHNIQUE)
            o = openers.setdefault(tuple(p["plan"][:cut]), {"pairs": 0, "after": 0, "siem": []})
            o["pairs"] += len(p["silences"])
            o["after"] = max(o["after"], len(p["plan"]) - cut - 1)
            o["siem"] += [m.artifacts[r["artifact"]].name for r in p["residue"] if r["siem"] and not r["rule"]]
        for opener, o in sorted(openers.items(), key=lambda kv: (-kv[1]["pairs"], kv[0])):
            first = " → ".join(m.erasures[s].name for s in opener) or "nothing"
            lines.append(f"| {first} | {o['pairs']} | up to {o['after']} | {md_text('; '.join(dict.fromkeys(o['siem'])) or 'nothing')} |")
        lines.append("")

    if data["closure"]:
        lines += ["### The rules that close them", "",
                  "Traces of anti-forensic actions that reach the SIEM and that no rule reads yet, in the order that removes the most "
                  "exposure. Each row supposes the rules above it are written.", "",
                  "| Order | A rule that reads | Left by | Exposed pairs after |", "|---|---|---|---|"]
        for i, step in enumerate(data["closure"], 1):
            by = ", ".join(m.erasures[a].name for a in step["actions"])
            lines.append(f"| {i} | {md_text(rule_text(m, step['rule']))} | {by} | {step['exposed_after']} |")
        last = data["closure"][-1]["exposed_after"]
        lines += ["", (f"With these {len(data['closure'])} rules every modelled answer is out of reach or evident."
                       if last == 0 else f"{last} pairs stay exposed after them: the sequences that remain leave no trace a SIEM rule could read."), ""]

    if data["depth"]:
        forensic = [q for q in asked if q != "alert"]
        lines += ["### Evidence depth on the host", "",
                  "The same search on a host that forwards nothing: how many actions remove every witness of an answer, alerts or "
                  "not. A depth of 1 is an answer that rests on a single store.", "",
                  "| Detection | " + " | ".join(q.capitalize() for q in forensic) + " |", "|---|" + "---|" * len(forensic)]
        for det, per_q in data["depth"].items():
            lines.append(f"| `{det}` | " + " | ".join(str(per_q.get(q, "")) for q in forensic) + " |")
        lines.append("")

    lines += ["### Artifacts", "", "| Artifact | Store | Answers | Basis | Limits |", "|---|---|---|---|---|"]
    for a in m.artifacts.values():
        opt = " (optional)" if a.optional else ""
        lines.append(f"| [{a.name}]({a.source}){opt} | {m.stores[a.store]['name']} | {', '.join(q for q in m.questions if q in a.answers)} | "
                     f"{a.basis} | {md_text(a.limits or '')} |")
    lines += ["", "### Anti-forensic actions", "", "| Action | Example | Destroys | Blinds | Leaves | Basis |", "|---|---|---|---|---|---|"]
    for e in m.erasures.values():
        leaves = "; ".join(f"{m.artifacts[k.artifact].name}" + (f" → `{k.detection}`" if k.detection else "") for k in e.marks)
        blinds = ", ".join([m.stores[s]["name"] for s in sorted(e.blinds)] + ["forwarding to the SIEM"] * e.stops_forwarding)
        name = f"[{e.name}]({e.source})" if e.source else e.name
        lines.append(f"| {name} | `{md_text(e.example)}` | {', '.join(m.stores[s]['name'] for s in sorted(e.destroys))} | {blinds} | "
                     f"{leaves} | {e.basis} |")
    if m.not_modelled:
        lines += ["", "### Not modelled yet", "", "| Detection | Why |", "|---|---|"]
        lines += [f"| `{d}` | {md_text(why)} |" for d, why in m.not_modelled.items()]
    lines.append(BLOCK_END)
    return "\n".join(lines)


def with_block(text: str, block: str) -> str:
    if BLOCK_START not in text or BLOCK_END not in text:
        raise TraceError(f"{README.relative_to(ROOT)}: the markers {BLOCK_START} and {BLOCK_END} are missing")
    head, rest = text.split(BLOCK_START, 1)
    return head + block + rest.split(BLOCK_END, 1)[1]


def as_json(data: dict) -> dict:
    def slim(res: dict) -> dict:
        return {"verdict": res["verdict"], "erase": res["erase"] and {"actions": res["erase"][0], "plan": res["erase"][1]},
                "quiet": res["quiet"] and {"actions": res["quiet"][0], "plan": res["quiet"][1]}}
    return {"counts": data["counts"], "results": {d: {q: slim(r) for q, r in per.items()} for d, per in data["results"].items()},
            "plans": data["plans"], "closure": data["closure"], "depth": data["depth"]}


# --------------------------------------------------------------------------- #
# Console
# --------------------------------------------------------------------------- #
VERDICT_COLOR = {"out of reach": GREEN, "evident": GREEN, "exposed": YELLOW}


def print_summary(m: Model, data: dict) -> None:
    c = data["counts"]
    print(f"{BOLD}RASD-Trace{RESET}  {c['detections']} detections · {c['artifacts']} artifacts · {c['erasures']} anti-forensic actions")
    print(f"{DIM}{m.position}{RESET}\n")
    width = max(len(d) for d in data["results"])
    for det, per_q in data["results"].items():
        cells = "  ".join(f"{q} {VERDICT_COLOR[r['verdict']]}{_cell(r)}{RESET}" for q, r in per_q.items())
        print(f"  {det:<{width}}  {cells}")
    print(f"\n{c['pairs']} pairs: {GREEN}{c['out of reach']} out of reach{RESET}, {GREEN}{c['evident']} evident{RESET}, "
          f"{YELLOW}{c['exposed']} exposed{RESET}")
    if data["closure"]:
        print(f"\n{BOLD}Rules that close the exposure, in order{RESET}")
        for i, step in enumerate(data["closure"], 1):
            print(f"  {i}. {rule_text(m, step['rule'])}  {DIM}→ {step['exposed_after']} pairs left{RESET}")


def print_detection(m: Model, det: str, lost: set[str]) -> None:
    fp = m.footprints[det]
    unknown = sorted(lost - set(m.stores))
    if unknown:
        raise TraceError(f"--lost: unknown store {', '.join(unknown)}. Stores: {', '.join(m.stores)}")
    per_q = survivability(m, fp)
    print(f"{BOLD}{det}{RESET}  reads {m.artifacts[fp.reads].name}")
    if fp.note:
        print(f"{DIM}{fp.note}{RESET}")
    if lost:
        print(f"{YELLOW}lost: {', '.join(m.stores[s]['name'] for s in sorted(lost))}{RESET}")
    for q in m.questions:
        if q == "alert":
            continue
        rows = []
        for a in fp.artifacts:
            art = m.artifacts[a]
            if q not in art.answers:
                continue
            store = m.stores[art.store]
            if art.store not in lost:
                rows.append((store["collect"], art, store["name"], "optional" if art.optional else ""))
            if m.ships(a) and SIEM not in lost and not art.optional:
                rows.append((m.stores[SIEM]["collect"], art, "SIEM copy", ""))
        if not rows and q not in per_q:
            continue
        print(f"\n  {BOLD}{q}{RESET}  {DIM}{m.questions[q]}{RESET}")
        if not [r for r in rows if not r[3]]:
            print(f"    {RED}no witness left in the baseline{RESET}")
        for _rank, art, where, tag in sorted(rows, key=lambda r: (r[0], r[1].name, r[2])):
            extra = " · ".join(x for x in (fp.shows.get(art.id), art.limits, tag and f"optional: {art.optional}") if x)
            print(f"    {art.name}  {DIM}[{where}]{RESET}" + (f"  {DIM}{extra}{RESET}" if extra else ""))
    if not lost:
        print()
        for q, res in per_q.items():
            line = f"  {q:<7} {VERDICT_COLOR[res['verdict']]}{_cell(res)}{RESET}"
            if res["quiet"]:
                line += f"  {DIM}{plan_text(m, res['quiet'][1]).replace('**', '')}{RESET}"
            elif res["erase"]:
                line += f"  {DIM}cheapest erasure, alerted: {plan_text(m, res['erase'][1]).replace('**', '')}{RESET}"
            print(line)
    print(f"\n{DIM}Collect in the order shown: the stores that roll over first come first.{RESET}")


def main() -> int:
    ap = argparse.ArgumentParser(description="RASD-Trace: evidence survivability of every detection")
    ap.add_argument("detection", nargs="?", help="one detection: witnesses per question and its results")
    ap.add_argument("--lost", help="with a detection: comma-separated stores already lost (or siem)")
    ap.add_argument("--check", action="store_true", help="validate the model against the rules, the forwarder and the engine")
    ap.add_argument("--write", action="store_true", help="render the results block of dfir/trace/README.md")
    ap.add_argument("--json", metavar="FILE", help="write the results as JSON")
    args = ap.parse_args()
    m = load_model()

    if args.detection:
        det = find_detection(args.detection).id if args.detection not in m.footprints else args.detection
        if det in m.not_modelled:
            print(f"{det} is not modelled yet: {m.not_modelled[det]}")
            return 1
        if det not in m.footprints:
            raise TraceError(f"{det} has no footprint in {FOOTPRINTS.relative_to(ROOT)}")
        print_detection(m, det, {s.strip() for s in (args.lost or "").split(",") if s.strip()})
        return 0

    errs = check(m)
    if errs:
        for e in errs:
            print(f"{RED}✗{RESET} {e}")
        print(f"\n{len(errs)} problem(s) in the trace model")
        return 1
    data = compute(m)
    block = render(m, data)
    if args.json:
        Path(args.json).write_text(json.dumps(as_json(data), indent=2) + "\n", encoding="utf-8")
    if args.write:
        README.write_text(with_block(README.read_text(encoding="utf-8"), block), encoding="utf-8")
        print(f"wrote {README.relative_to(ROOT)}")
        return 0
    if args.check:
        if with_block(README.read_text(encoding="utf-8"), block) != README.read_text(encoding="utf-8"):
            print(f"{RED}✗{RESET} {README.relative_to(ROOT)} is out of date. Run: rasd trace --write")
            return 1
        c = data["counts"]
        print(f"trace model consistent · {c['detections']} footprints · {c['pairs']} pairs: {c['out of reach']} out of reach, "
              f"{c['evident']} evident, {c['exposed']} exposed · page current")
        return 0
    print_summary(m, data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
