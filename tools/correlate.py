#!/usr/bin/env python3
"""
correlate.py - prove every correlation detection (detect/correlations/) as hard as every rule.

A correlation counts the events of a base rule per group and time window, so it can fail in
ways a single-event rule cannot: a threshold off by one, a window twice too long, a group-by
field that quietly merges every source, distinct accounts counted as events, a SIEM query
that groups or bins differently from what was tested. Each check below targets one of them.

  rule        correlation.yml and base.yml are well formed; the base rule passes lint; the
              contract declares every field (base rule, group-by, counted field) and the
              type `correlation`; every filter has a true negative and an applied tuning
  base        true positives fire, true negatives stay silent, fuzzer variants of the true
              positives still fire, and every base-rule mutant is killed (as in prove.py)
  base parity the base rule's KQL / SPL filter equals the rule on its corpus (as in parity.py)
  scenarios   every event sequence in tests/scenarios.yml fires or stays silent as declared
  mutants     every parameter mutant - threshold +1 and -1, window x2 and /2, each group-by
              field dropped, events counted instead of distinct values, each normalisation
              dropped - is caught by at least one scenario
  aggregation the generated SPL and KQL, parsed back from their text and run with each
  parity      SIEM's own semantics (null handling, where, eval / extend, bin, stats /
              summarize grouping), return exactly the engine's alerts - window, group,
              count, event count, first and last event - on every scenario and on seeded
              random sequences, for the correlation AND for every one of its mutants
  guarantee   the smallest burst that alerts whatever the window alignment (2T-1 for a
              threshold T - the arithmetic proves it), checked with the engine at 120
              alignments x 3 spreads, and shown to be tight
  queries     queries/{spl,kql}/correlations/<id>.* are what the generator writes (--check)

SIEM semantics modelled, beyond those of parity.py
  SPL  `stats ... by` drops rows whose by-field is null; dc() counts distinct non-null
       values, case-sensitively; `bin span=<n>s _time AS window_start` floors to the epoch.
       A missing or empty extracted field is null (as in parity.py), but an empty string an
       `eval` produced is a value: replace("::ffff:", "^::ffff:", "") is "", not null, which
       is why the generated `where` tests both isnotnull('F') and 'F'!="".
  KQL  string columns are never null, so `summarize by` keeps "" as a group (the generated
       query removes it with isnotempty); array_length(make_set()) is an exact distinct
       count; bin() floors to the epoch
  Both: an event is kept by `where` only when the condition is true (three-valued logic).

Usage
  python tools/correlate.py                     # prove every correlation, print the report
  python tools/correlate.py --check             # CI: the proofs, plus the generated queries are current
  python tools/correlate.py --write             # (re)write queries/{spl,kql}/correlations/
  python tools/correlate.py --filter T1110 -v
  python tools/correlate.py --json
  python tools/correlate.py --logs export.jsonl [--profile auto]    # correlation alerts in your own logs
"""
from __future__ import annotations

import argparse
import json
import math
import operator
import random
import re
import sys
import uuid
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BOLD, DIM, GREEN, RED, RESET, ROOT, YELLOW, load_detections, load_jsonl  # noqa: E402
from convert import BACKENDS, MAPPINGS, logsource_key  # noqa: E402
from correlation import (CorrelationError, Correlation, Params, alert_signature, check_guarantee, epoch,  # noqa: E402
                         evaluate, group_label, human, iso, load_correlations, param_mutants, to_kql, to_spl)
from fuzz import load_baseline, variants  # noqa: E402
from parity import (REPLAY_CORPUS, KQLParser, ParseError, SPLParser, base_errors, compile_query,  # noqa: E402
                    corpus_for, make_lookup)
from prove import accepted as accepted_base_mutants, killed_by, mutants as rule_mutants, suite  # noqa: E402
from replay import parse_time, route  # noqa: E402
from sigma_engine import SigmaError, _get_field, compile_rule, matches  # noqa: E402
from validate import (FOLDER, LEVELS, STATUSES, TECH_TAG, WARNINGS, check_contract, evidence_errors,  # noqa: E402
                      lint_rule, tuning_errors, unexercised_filters)

QUERIES = ROOT / "queries"
RANDOM_SEQUENCES = 150
COMPARE = {">=": operator.ge, ">": operator.gt, "<=": operator.le, "<": operator.lt, "=": operator.eq, "==": operator.eq}
CORRELATION_KEYS = ("title", "id", "status", "description", "author", "date", "tags", "correlation",
                    "falsepositives", "level")
BASE_KEYS = ("title", "id", "name", "status", "description", "author", "date", "logsource", "detection", "level")


def query_files(corr: Correlation) -> dict[Path, str]:
    return {QUERIES / "spl" / "correlations" / f"{corr.id}.spl": to_spl(corr) + "\n",
            QUERIES / "kql" / "correlations" / f"{corr.id}.kql": to_kql(corr) + "\n"}


# --------------------------------------------------------------------------- #
# Aggregation models: the generated query text, parsed back and run with SIEM semantics
# --------------------------------------------------------------------------- #
class _Model:
    backend = ""

    def __init__(self, text: str, corr: Correlation):
        self.text, self.source = text, logsource_key(corr.base)
        self.lookup = make_lookup(self.backend)
        self.reverse = {v: k for k, v in (MAPPINGS[self.backend].get("fields") or {}).items()}
        base = MAPPINGS[self.backend]["logsources"][self.source].strip()
        body = "\n".join(line for line in text.split("\n") if not line.startswith("//"))
        if not body.startswith(base):
            raise ParseError(f"{self.backend.upper()} does not start with the {self.source} base from tools/mappings.yml")
        self.parsed: list[tuple] = []
        for st in body[len(base):].split("\n| ")[1:]:
            self.parsed.append(self.parse(st))
        self.stages = self.parsed
        kinds = [s[0] for s in self.stages]
        if kinds.count("aggregate") != 1 or len(kinds) < 2 or kinds[-1] != "threshold" or kinds[-2] != "aggregate":
            raise ParseError(f"{self.backend.upper()} must end with one aggregation and its threshold, got {kinds}")
        if "threshold" in kinds[:-1]:
            raise ParseError(f"{self.backend.upper()} filters on a count before aggregating")

    def parse(self, stage: str):
        raise NotImplementedError

    def field(self, column: str) -> str:
        return self.reverse.get(column, column)

    def rows(self, events: list[dict]) -> list[dict]:
        out = []
        for ev in events:
            if route(ev) != self.source:                 # the base search: index / table of the log source
                continue
            t = parse_time(ev)
            if t is None:
                continue
            out.append({"ev": dict(ev), "time": epoch(t)})
        return out

    def run(self, events: list[dict]) -> list[tuple]:
        rows, groups, metric = self.rows(events), None, None
        for stage in self.stages:
            kind = stage[0]
            if kind == "where":
                rows = [r for r in rows if stage[1](r["ev"]) is True]
            elif kind == "normalize":
                for r in rows:
                    self.normalize(r, stage[1], stage[2])
            elif kind == "bin":
                for r in rows:
                    r[stage[2]] = math.floor(r["time"] / stage[1]) * stage[1]
            elif kind == "aggregate":
                groups = self.aggregate(rows, stage[1], stage[2], stage[3])
            elif kind == "threshold":
                metric = stage[1]
                groups = [g for g in groups if stage[2](g[metric], stage[3])]
        return [(g["window"], g["group"], g[metric], g["event_count"], g["first_event"], g["last_event"]) for g in groups]


class EvalValue(str):
    """A string an SPL eval produced: unlike an empty extracted field, "" here is a value, not null."""


def spl_value(v) -> str | None:
    if isinstance(v, EvalValue):
        return str(v)
    return None if v in (None, "") else str(v)


class _SPLWhere(SPLParser):
    def _val(self, ev, field) -> str | None:
        return spl_value(self.lookup(ev, field))


class SPLModel(_Model):
    backend = "spl"
    AGG = re.compile(r"(dc|values|count|min|max)(?:\((\w+)\))? as (\w+)")

    def value(self, ev: dict, column: str) -> str | None:     # missing or empty extracted field -> null
        return spl_value(self.lookup(ev, column))

    def parse(self, stage: str):
        if m := re.fullmatch(r"where (value_count|event_count)(>=|>|<=|<|=)(\d+)", stage):
            return ("threshold", m.group(1), COMPARE[m.group(2)], int(m.group(3)))
        if stage.startswith("where "):
            return ("where", _SPLWhere(stage[6:], self.lookup).parse())
        if m := re.fullmatch(r"""eval (\w+)=replace\('(\w+)', ("(?:[^"\\]|\\.)*"), ""\)""", stage):
            if m.group(1) != m.group(2):
                raise ParseError(f"SPL eval writes {m.group(1)} from {m.group(2)}")
            return ("normalize", m.group(1), re.compile(SPLParser.literal(m.group(3))))
        if m := re.fullmatch(r"bin span=(\d+)s _time AS (\w+)", stage):
            return ("bin", int(m.group(1)), m.group(2))
        if m := re.fullmatch(r"stats (.+?) by (\w+(?: \w+)*)", stage):
            aggs = self.AGG.findall(m.group(1))
            if " ".join(f"{fn}({arg}) as {out}" if arg else f"{fn} as {out}" for fn, arg, out in aggs) != m.group(1):
                raise ParseError(f"unsupported SPL stats aggregation in: {m.group(1)[:80]}")
            by = m.group(2).split()
            window = next((s[2] for s in getattr(self, "parsed", []) if s[0] == "bin"), None)
            if window not in by:
                raise ParseError("SPL stats does not group by the binned time window")
            return ("aggregate", aggs, by, window)
        raise ParseError(f"unsupported SPL stage: {stage[:80]!r}")

    def normalize(self, row: dict, column: str, rx: re.Pattern) -> None:
        v = self.value(row["ev"], column)
        row["ev"][self.field(column)] = None if v is None else EvalValue(rx.sub("", v))

    def aggregate(self, rows, aggs, by, window) -> list[dict]:
        buckets: dict[tuple, list[dict]] = {}
        for r in rows:
            key = tuple(r.get(window) if b == window else self.value(r["ev"], b) for b in by)
            if None in key:                                # stats by: a null by-field drops the row
                continue
            buckets.setdefault(key, []).append(r)
        out = []
        for key, members in buckets.items():
            g = {"window": key[by.index(window)], "group": tuple(k for b, k in zip(by, key) if b != window)}
            for fn, arg, name in aggs:
                vals = [self.value(r["ev"], arg) for r in members] if arg and arg != "_time" else None
                if fn == "count":
                    g[name] = len(members)
                elif fn == "dc":
                    g[name] = len({v for v in vals if v is not None})
                elif fn == "values":
                    g[name] = sorted({v for v in vals if v is not None})
                elif fn in ("min", "max") and arg == "_time":
                    g[name] = (min if fn == "min" else max)(r["time"] for r in members)
                else:
                    raise ParseError(f"unsupported SPL aggregation {fn}({arg})")
            out.append(g)
        return out


class KQLModel(_Model):
    backend = "kql"
    EXTRACT = re.compile(r"""extend (\w+) = coalesce\(tostring\(column_ifexists\("(\w+)", ""\)\), """
                         r"""extract\(@'Name="(\w+)">\(\[\^<\]\*\)<', 1, EventData\)\)""")
    AGG = re.compile(r"(\w+) = (array_length\(make_set\((\w+)\)\)|count\(\)|make_set\((\w+), \d+\)|"
                     r"min\(TimeGenerated\)|max\(TimeGenerated\))")

    def __init__(self, text: str, corr: Correlation):
        self.extended: set[str] = set()
        cfg = MAPPINGS["kql"].get("eventdata") or {}
        self.eventdata = logsource_key(corr.base) in cfg.get("logsources", [])
        self.native = set(cfg.get("native", []))
        super().__init__(text, corr)

    def text_value(self, ev: dict, column: str) -> str:    # string columns: missing -> ""
        v = self.lookup(ev, column)
        return "" if v is None else str(v)

    def needs(self, column: str) -> None:
        if self.eventdata and column not in self.native and column not in self.extended:
            raise ParseError(f"KQL reads {column} but never extends it from EventData (the stock table has no such column)")

    def parse(self, stage: str):
        if m := self.EXTRACT.fullmatch(stage):
            if not m.group(1) == m.group(2) == m.group(3):
                raise ParseError(f"KQL EventData extend mixes {m.group(1)}, {m.group(2)} and {m.group(3)}")
            self.extended.add(m.group(1))
            return ("extract", m.group(1))
        if m := re.fullmatch(r'extend (\w+) = replace_regex\((\w+), (@"(?:[^"]|"")*"), ""\)', stage):
            if m.group(1) != m.group(2):
                raise ParseError(f"KQL extend writes {m.group(1)} from {m.group(2)}")
            self.needs(m.group(1))
            return ("normalize", m.group(1), re.compile(KQLParser.literal(m.group(3))))
        if m := re.fullmatch(r"where (value_count|event_count) (>=|>|<=|<|==) (\d+)", stage):
            return ("threshold", m.group(1), COMPARE[m.group(2)], int(m.group(3)))
        if stage.startswith("where "):
            for column in re.findall(r"isnotempty\((\w+)\)", stage):
                self.needs(column)
            return ("where", KQLParser(stage[6:], self.lookup).parse())
        if m := re.fullmatch(r"summarize (.+?) by (\w+) = bin\(TimeGenerated, (\d+)s\)((?:, \w+)*)", stage):
            aggs = self.AGG.findall(m.group(1))
            if ", ".join(f"{name} = {expr}" for name, expr, *_ in aggs) != m.group(1):
                raise ParseError(f"unsupported KQL summarize aggregation in: {m.group(1)[:80]}")
            by = [c.strip() for c in m.group(4).split(",") if c.strip()]
            for column in by + [a[2] or a[3] for a in aggs if a[2] or a[3]]:
                self.needs(column)
            return ("aggregate", aggs, [m.group(2)] + by, int(m.group(3)))
        raise ParseError(f"unsupported KQL stage: {stage[:80]!r}")

    def normalize(self, row: dict, column: str, rx: re.Pattern) -> None:
        row["ev"][self.field(column)] = rx.sub("", self.text_value(row["ev"], column))

    def aggregate(self, rows, aggs, by, span) -> list[dict]:
        window, keys = by[0], by[1:]
        buckets: dict[tuple, list[dict]] = {}
        for r in rows:                                     # summarize by: "" is a group like any other
            key = (math.floor(r["time"] / span) * span,) + tuple(self.text_value(r["ev"], k) for k in keys)
            buckets.setdefault(key, []).append(r)
        out = []
        for key, members in buckets.items():
            g = {"window": key[0], "group": key[1:]}
            for name, expr, distinct_of, set_of in aggs:
                if distinct_of:
                    g[name] = len({self.text_value(r["ev"], distinct_of) for r in members})
                elif expr == "count()":
                    g[name] = len(members)
                elif set_of:
                    g[name] = sorted({self.text_value(r["ev"], set_of) for r in members})
                else:
                    g[name] = (min if expr.startswith("min") else max)(r["time"] for r in members)
            out.append(g)
        return out


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #
def structure_errors(corr: Correlation, ids: dict[str, str]) -> tuple[list[str], list[str]]:
    errs: list[str] = []
    rule, base, folder = corr.rule, corr.base, corr.folder
    errs += [f"correlation.yml: missing '{k}'" for k in CORRELATION_KEYS if k not in rule]
    errs += [f"base.yml: missing '{k}'" for k in BASE_KEYS if k not in base]
    for label, doc in (("correlation.yml", rule), ("base.yml", base)):
        try:
            uuid.UUID(str(doc.get("id")))
        except ValueError:
            errs.append(f"{label}: id is not a valid UUID")
        rid = str(doc.get("id"))
        if rid in ids:
            errs.append(f"{label}: duplicate id (also used by {ids[rid]})")
        ids[rid] = f"{folder.name}/{label}"
        if doc.get("status") not in STATUSES:
            errs.append(f"{label}: invalid status '{doc.get('status')}'")
        if doc.get("level") not in LEVELS:
            errs.append(f"{label}: invalid level '{doc.get('level')}'")
        if not re.match(r"^\d{4}-\d{2}-\d{2}$", str(doc.get("date", ""))):
            errs.append(f"{label}: date must be YYYY-MM-DD")
    spec = rule.get("correlation") or {}
    if spec.get("rules") != [base.get("name")]:
        errs.append("correlation.yml: correlation.rules must list exactly the base rule's name (base.yml `name:`)")
    if spec.get("generate") is not False:
        errs.append("correlation.yml: set correlation.generate: false - the base rule must never alert on its own")
    params = None
    try:
        params = corr.params
    except CorrelationError as e:
        errs.append(f"correlation.yml: {e}")
    techniques = [t for t in rule.get("tags", []) if TECH_TAG.match(str(t))]
    m = FOLDER.match(folder.name)
    if not techniques:
        errs.append("correlation.yml: no ATT&CK technique tag (attack.tXXXX)")
    if not m:
        errs.append("folder must be named <TechniqueID>_<snake_case_name>")
    elif f"attack.{m.group(1).lower()}" not in techniques:
        errs.append(f"folder technique {m.group(1)} not present in correlation.yml tags")

    lint_errors, lint_warnings = lint_rule(base)
    errs += [f"base.yml: {e}" for e in lint_errors]
    try:
        matches(base, {})
    except SigmaError as e:
        errs.append(f"base.yml detection logic: {e}")
    key = logsource_key(base)
    errs += [f"base.yml: logsource '{key}' has no {b} mapping in tools/mappings.yml"
             for b in BACKENDS if key not in MAPPINGS[b]["logsources"]]

    readme = folder / "README.md"
    if not readme.exists():
        errs.append("missing README.md")
    for name in ("README.md", "correlation.yml", "base.yml", "contract.yml", "tuning.yml", "tests/scenarios.yml"):
        if (folder / name).exists() and "TODO" in (folder / name).read_text(encoding="utf-8"):
            errs.append(f"{name} still contains TODO placeholders")
    for kind in ("true_positive", "true_negative"):
        p = folder / "tests" / f"{kind}.jsonl"
        if not p.exists() or not p.read_text(encoding="utf-8").strip():
            errs.append(f"missing or empty tests/{kind}.jsonl")
    scenarios = corr.scenarios()
    for sc in scenarios:
        if sc["expect"] not in ("fire", "silent"):
            errs.append(f"scenario '{sc['name']}': expect must be fire or silent")
        if not sc["events"]:
            errs.append(f"scenario '{sc['name']}' has no events")
    if not any(sc["expect"] == "fire" for sc in scenarios) or not any(sc["expect"] == "silent" for sc in scenarios):
        errs.append("tests/scenarios.yml needs at least one scenario that fires and one that stays silent")
    for i, a in enumerate(corr.scenario_doc().get("accepted_mutants") or [], 1):
        if not a.get("id") or len(str(a.get("reason", "")).strip()) < 30:
            errs.append(f"scenarios.yml accepted_mutants #{i}: needs an id and a reason of at least 30 characters")

    merged = {**base, "tags": rule.get("tags", [])}
    errs += check_contract(folder, merged)
    c = corr.contract
    if (c.get("detection_logic") or {}).get("type") != "correlation":
        errs.append("contract.yml: detection_logic.type must be 'correlation'")
    declared = set((c.get("data_contract") or {}).get("required_fields") or []) | \
        set((c.get("data_contract") or {}).get("optional_fields") or [])
    if params:
        missing = [f for f in params.reads() if f not in declared]
        if missing:
            errs.append(f"contract.yml: the correlation groups or counts fields not in the data contract: {missing}")
    errs += tuning_errors(folder, base)
    errs += evidence_errors(folder)
    try:
        for name in unexercised_filters(base, corr.tests("true_negative")):
            errs.append(f"filter coverage: '{name}' has no true-negative event proving it is needed")
    except SigmaError:
        pass
    return errs, lint_warnings


def base_results(corr: Correlation, fn) -> dict:
    """Single-event tests, fuzzer variants and rule mutation testing of the base rule."""
    det = corr.base_detection()
    failing = []
    for kind, expected in (("true_positive", True), ("true_negative", False)):
        for i, ev in enumerate(corr.tests(kind), 1):
            if bool(fn(ev)) != expected:
                failing.append(f"{'TP' if expected else 'TN'}#{i} {ev.get('_case', '')}".strip())
    known = set(load_baseline().get(corr.id, []))
    tried, bypasses = 0, []
    for i, ev in enumerate(corr.tests("true_positive"), 1):
        for name, _cat, new in variants(ev):
            tried += 1
            if not fn(new) and f"tp{i}:{name}" not in known:
                bypasses.append(f"TP#{i}~{name}")
    tests = suite(det)
    failing += [label for label, ev, expected in tests if label.startswith("mutation:") and bool(fn(ev)) != expected]
    accept = accepted_base_mutants(det)
    total, survivors, equivalent = 0, [], []
    for mid, kind, desc, mrule, _meta in rule_mutants(det.rule):
        total += 1
        if killed_by(mrule, tests) is None:
            if mid in accept:
                equivalent.append({"id": mid, "description": desc, "reason": accept[mid]})
            else:
                survivors.append({"id": mid, "kind": kind, "description": desc})
    stale = sorted(set(accept) - {e["id"] for e in equivalent})
    counted = total - len(equivalent)
    return {"tp": len(corr.tests("true_positive")), "tn": len(corr.tests("true_negative")), "failing": failing,
            "fuzz_tried": tried, "bypasses": bypasses,
            "fuzz": 100.0 if not tried else round(100 * (tried - len(bypasses)) / tried, 1),
            "mutants": total, "survivors": survivors, "accepted": equivalent, "stale": stale,
            "proof": 100.0 if counted == 0 else round(100 * (counted - len(survivors)) / counted, 1)}


def base_parity(corr: Correlation, fn, dets, replay_events) -> dict:
    out = {"events": 0, "kql": [], "spl": [], "errors": list(base_errors(corr.base))}
    try:
        queries = {b: compile_query(corr.base, b) for b in ("kql", "spl")}
    except (ParseError, SigmaError, re.error) as e:
        out["errors"].append(str(e))
        return out
    for label, ev in corpus_for(corr.base_detection(), dets, replay_events):
        expected = bool(fn(ev))
        out["events"] += 1
        for b, q in queries.items():
            if (q(ev) is True) != expected:
                out[b].append(label)
    return out


def problem(sc: dict, alerts: list[dict]) -> str | None:
    """None when the scenario behaved as declared, else what went wrong."""
    labels = sorted({group_label(a) for a in alerts})
    if sc["expect"] == "silent":
        return None if not alerts else f"alerted for {', '.join(labels)}"
    if not alerts:
        return "stayed silent"
    if sc.get("groups") is not None and sorted(str(g) for g in sc["groups"]) != labels:
        return f"alerted for {labels}, expected {sorted(str(g) for g in sc['groups'])}"
    if sc.get("alerts") is not None and len(alerts) != sc["alerts"]:
        return f"{len(alerts)} alert(s), expected {sc['alerts']}"
    return None


def scenario_results(corr: Correlation, params: Params, fn, scenarios: list[dict]) -> list[dict]:
    out = []
    for sc in scenarios:
        alerts = evaluate(corr, sc["events"], params, fn)
        out.append({"name": sc["name"], "expect": sc["expect"], "events": len(sc["events"]),
                    "alerts": len(alerts), "groups": sorted({group_label(a) for a in alerts}),
                    "known_limit": sc.get("known_limit"), "problem": problem(sc, alerts)})
    return out


def mutant_results(corr: Correlation, params: Params, fn, scenarios: list[dict]) -> dict:
    accept = corr.accepted_mutants()
    rows = []
    for mid, desc, mp in param_mutants(params):
        wrong = [(sc, problem(sc, evaluate(corr, sc["events"], mp, fn))) for sc in scenarios]
        wrong = [(sc, why) for sc, why in wrong if why]
        # prefer a scenario whose verdict flips (fires instead of staying silent, or the reverse)
        # over one where only the alerting group or the number of alerts differs
        flips = [sc for sc, why in wrong if why.startswith(("alerted for", "stayed silent"))
                 and (sc["expect"] == "silent") == why.startswith("alerted for")]
        killer = (flips or [sc for sc, _ in wrong] or [None])[0]
        rows.append({"id": mid, "description": desc, "killed_by": killer["name"] if killer else None,
                     "verdict_flip": bool(flips), "accepted": accept.get(mid) if killer is None else None})
    survivors = [r for r in rows if r["killed_by"] is None and not r["accepted"]]
    stale = sorted(set(accept) - {r["id"] for r in rows if r["killed_by"] is None})
    counted = len(rows) - sum(1 for r in rows if r["accepted"])
    return {"mutants": rows, "survivors": survivors, "stale": stale,
            "score": 100.0 if counted == 0 else round(100 * (counted - len(survivors)) / counted, 1)}


def random_sequences(corr: Correlation, params: Params, count: int = RANDOM_SEQUENCES):
    """Seeded event sequences that stress grouping, counting, normalisation and windows.

    Half are noise (any test or scenario event, fields swapped for other values, empty or
    missing); half are bursts around the threshold: one source, distinct and repeated counted
    values, spread over one to three windows - the sequences where an off-by-one, a wrong
    window or a lost normalisation would change the alerts."""
    rng = random.Random(f"rasd-correlate:{corr.id}")
    fn = compile_rule(corr.base)
    pool = [{k: v for k, v in ev.items() if k != "_case"}
            for ev in corr.tests("true_positive") + corr.tests("true_negative")]
    pool += [ev for sc in corr.scenarios() for ev in sc["events"]]
    hits = [ev for ev in pool if fn(ev)] or pool
    choices: dict[str, list] = {}
    for f in params.reads():
        seen = sorted({str(v) for ev in pool if (v := _get_field(ev, f)) not in (None, "")})[:8]
        extra = [v[7:] if v.startswith("::ffff:") else "::ffff:" + v for v in seen[:3]] + [v.upper() for v in seen[:2]]
        choices[f] = seen + extra + ["", None, "::ffff:"]

    def setf(ev: dict, f: str, v) -> None:
        for k in [k for k in ev if k.lower() == f.lower()]:
            del ev[k]
        if v is not None:
            ev[f] = v

    start = datetime(2026, 10, 12, 9, 50)
    for i in range(count):
        burst = i % 2 == 1
        horizon = rng.choice((30, params.timespan / 2, params.timespan, params.timespan * 1.5) if burst else
                             (90, params.timespan, params.timespan * 2.5, 3600))
        seq = []
        if burst:                                          # a burst around the threshold
            # mostly a real source; sometimes one that is empty, or only becomes empty once
            # normalised (::ffff:) - the bursts that prove the not-null and not-empty tests
            group = {g: rng.choice(["", "::ffff:"]) if rng.random() < 0.15 else rng.choice([v for v in choices[g] if v])
                     for g in params.group_by}
            size = max(1, params.threshold + rng.randint(-2, 6))
            for n in range(size):
                ev = dict(rng.choice(hits))
                for g, v in group.items():
                    setf(ev, g, v if rng.random() < 0.85 else rng.choice(choices[g]))
                if params.counted:                         # mostly distinct, sometimes a repeat
                    setf(ev, params.counted, f"acct{n if rng.random() < 0.8 else rng.randrange(size):02d}")
                seq.append(ev)
        for _ in range(rng.randint(0 if i % 2 else 1, 30)):  # noise
            ev = dict(rng.choice(pool))
            for f, vals in choices.items():
                if rng.random() < 0.6:
                    setf(ev, f, rng.choice(vals))
            seq.append(ev)
        for ev in seq:
            ev.pop("UtcTime", None)
            ev["TimeCreated"] = iso(start + timedelta(seconds=round(rng.uniform(0, horizon), 3)))
            if rng.random() < 0.02:
                del ev["TimeCreated"]
        yield seq


def aggregation_parity(corr: Correlation, params: Params, fn, scenarios: list[dict]) -> dict:
    variants_ = [("rule", params)] + [(mid, mp) for mid, _d, mp in param_mutants(params)]
    sequences = [(f"scenario '{sc['name']}'", sc["events"]) for sc in scenarios]
    sequences += [(f"random #{i}", seq) for i, seq in enumerate(random_sequences(corr, params), 1)]
    out = {"parameter_sets": len(variants_), "sequences": len(sequences), "comparisons": 0, "alerts": 0,
           "spl": [], "kql": [], "errors": []}
    for label, mp in variants_:
        try:
            models = {"spl": SPLModel(to_spl(corr, mp), corr), "kql": KQLModel(to_kql(corr, mp), corr)}
        except (ParseError, re.error, KeyError) as e:
            out["errors"].append(f"{label}: {e}")
            continue
        for name, events in sequences:
            expected = sorted(alert_signature(a) for a in evaluate(corr, events, mp, fn))
            out["comparisons"] += 1
            out["alerts"] += len(expected)
            for b, model in models.items():
                got = sorted(model.run(events))
                if got != expected:
                    out[b].append({"parameters": label, "events": name, "engine": expected, b: got})
    return out


def guarantee_result(corr: Correlation, params: Params, fn) -> dict | None:
    for ev in corr.tests("true_positive"):
        template = {k: v for k, v in ev.items() if k != "_case"}
        if fn(template) and all(_get_field(template, g) not in (None, "") for g in params.group_by):
            return check_guarantee(corr, template, params)
    return {"burst": None, "checked": 0, "failures": [{"reason": "no true positive can serve as the burst template"}],
            "tight": False}


def check(filter_: str | None = None, queries: bool = False) -> dict:
    corrs = load_correlations(filter_)
    dets = load_detections()
    ids = {str(d.rule.get("id")): f"{d.id}/rule.yml" for d in dets}
    pool = dets + [c.base_detection() for c in load_correlations()]
    replay_events = load_jsonl(REPLAY_CORPUS) if REPLAY_CORPUS.exists() else []
    report = {}
    for corr in corrs:
        r: dict = {"title": corr.title, "technique": corr.technique, "errors": [], "warnings": []}
        errs, warns = structure_errors(corr, ids)
        r["errors"] += errs
        r["warnings"] += warns
        try:
            params, fn = corr.params, compile_rule(corr.base)
        except (CorrelationError, SigmaError) as e:
            r["errors"].append(str(e))
            report[corr.id] = r
            continue
        r["describe"] = params.describe()
        r["unit"] = f"distinct {params.field}" if params.counted else "events"
        r["window"] = human(params.timespan)
        r["group_by"] = list(params.group_by)
        scenarios = corr.scenarios()
        r["base"] = base_results(corr, fn)
        r["base_parity"] = base_parity(corr, fn, pool, replay_events)
        r["scenarios"] = scenario_results(corr, params, fn, scenarios)
        r["correlation_mutants"] = mutant_results(corr, params, fn, scenarios)
        r["aggregation_parity"] = aggregation_parity(corr, params, fn, scenarios)
        r["guarantee"] = guarantee_result(corr, params, fn)
        if queries:
            for path, text in query_files(corr).items():
                if not path.exists() or path.read_text(encoding="utf-8") != text:
                    r["errors"].append(f"{path.relative_to(ROOT)} is out of date - run: python rasd.py correlate --write")
        report[corr.id] = r
    return report


def failures(r: dict) -> list[str]:
    """Every reason this correlation is not proven, in plain words."""
    out = list(r["errors"])
    if "base" not in r:
        return out
    b, bp, cm, ap, g = r["base"], r["base_parity"], r["correlation_mutants"], r["aggregation_parity"], r["guarantee"]
    out += [f"base rule test fails: {f}" for f in b["failing"]]
    out += [f"base rule evaded by fuzzer variant {v}" for v in b["bypasses"]]
    out += [f"base rule mutant survives: {s['description']} (id: {s['id']})" for s in b["survivors"]]
    out += [f"stale base-rule acceptance {s} - remove it from tests/mutations.yml" for s in b["stale"]]
    out += [f"base rule parity: {e}" for e in bp["errors"]]
    out += [f"base rule {k.upper()} differs from the rule on {e}" for k in ("kql", "spl") for e in bp[k][:3]]
    out += [f"scenario '{s['name']}': {s['problem']}" for s in r["scenarios"] if s["problem"]]
    out += [f"correlation mutant survives: {s['description']} (id: {s['id']}) - add a scenario that only the "
            "original correlation gets right" for s in cm["survivors"]]
    out += [f"stale acceptance {s} - remove it from tests/scenarios.yml" for s in cm["stale"]]
    out += [f"aggregation parity: {e}" for e in ap["errors"]]
    for k in ("spl", "kql"):
        out += [f"{k.upper()} aggregation differs from the engine ({d['parameters']}, {d['events']}): "
                f"engine {d['engine']} vs {k.upper()} {d[k]}" for d in ap[k][:3]]
    if g is not None and (g["failures"] or not g["tight"]):
        out.append(f"burst guarantee not verified: {g['failures'][:2] or 'bound is not tight'}")
    return out


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def write_queries(corrs: list[Correlation]) -> int:
    n = 0
    for corr in corrs:
        for path, text in query_files(corr).items():
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                path.write_text(text, encoding="utf-8")
            n += 1
    return n


def run_logs(paths: list[str], profile: str | None, filter_: str | None) -> int:
    import profiles                                     # imported here: profiles imports replay
    events, used = profiles.apply([ev for p in paths for ev in load_jsonl(Path(p))], profile)
    if used != profiles.NATIVE:
        print(f"telemetry profile: {used}")
    total = 0
    for corr in load_correlations(filter_):
        alerts = evaluate(corr, events)
        total += len(alerts)
        colour = RED if alerts else GREEN
        print(f"{colour}{len(alerts):3d}{RESET}  {corr.id}  {DIM}{corr.params.describe()}{RESET}")
        for a in alerts:
            p = corr.params
            what = f"{a['value_count']} distinct {p.field}" if p.counted else f"{a['event_count']} events"
            print(f"       {a['window_start']:%Y-%m-%d %H:%M} UTC  {group_label(a):<24} {what} · "
                  f"{a['event_count']} events {a['first_event']:%H:%M:%S}-{a['last_event']:%H:%M:%S}"
                  + (f"  {DIM}{', '.join(a['values'][:6])}{'…' if len(a['values']) > 6 else ''}{RESET}" if a["values"] else ""))
    print(f"\n{BOLD}{total} correlation alert(s) over {len(events)} events{RESET}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--filter")
    ap.add_argument("--check", action="store_true", help="also fail when the generated queries are out of date")
    ap.add_argument("--write", action="store_true", help="write queries/{spl,kql}/correlations/")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true", help="list every scenario and mutant")
    ap.add_argument("--logs", nargs="+", help="evaluate the correlations over these JSONL exports instead")
    ap.add_argument("--profile", help="telemetry profile of --logs (see: python rasd.py profiles), or 'auto'")
    args = ap.parse_args()

    if args.logs:
        return run_logs(args.logs, args.profile, args.filter)
    if args.write:
        n = write_queries(load_correlations(args.filter))
        print(f"[+] wrote {n} correlation queries to queries/spl/correlations and queries/kql/correlations")
        return 0
    report = check(args.filter, queries=args.check)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
        return 1 if any(failures(r) for r in report.values()) else 0

    print(f"{BOLD}Correlation proof · base rule, scenarios, mutants, aggregation parity, burst guarantee{RESET}\n")
    if not report:
        print("  no correlation detections in detect/correlations/")
        return 0
    bad = 0
    for cid, r in report.items():
        problems = failures(r)
        bad += bool(problems)
        print(f"{GREEN + '✓' if not problems else RED + '✗'}{RESET} {BOLD}{cid}{RESET}  {DIM}{r.get('describe', '')}{RESET}")
        if "base" in r:
            b, bp, cm, ap_, g = (r["base"], r["base_parity"], r["correlation_mutants"], r["aggregation_parity"],
                                 r["guarantee"])
            fired = sum(1 for s in r["scenarios"] if s["expect"] == "fire")
            limits = [s for s in r["scenarios"] if s["known_limit"]]
            killed = len(cm["mutants"]) - len(cm["survivors"]) - sum(1 for m in cm["mutants"] if m["accepted"])
            print(f"    base rule    {b['tp']} TP · {b['tn']} TN · {b['mutants']} mutants, {b['proof']:.0f}% killed · "
                  f"fuzzer {b['fuzz']:.0f}% of {b['fuzz_tried']} variants · KQL/SPL identical on {bp['events']} events")
            print(f"    scenarios    {len(r['scenarios'])} ({fired} fire · {len(r['scenarios']) - fired} silent"
                  + (f" · {len(limits)} pinned known limit{'s' if len(limits) > 1 else ''}" if limits else "") + ")")
            print(f"    mutants      {killed}/{len(cm['mutants'])} parameter mutants killed ({cm['score']:.0f}%)")
            print(f"    parity       SPL and KQL equal the engine on {ap_['comparisons']} sequence runs "
                  f"({ap_['sequences']} sequences × {ap_['parameter_sets']} parameter sets, {ap_['alerts']} alerts)")
            if g and g.get("burst"):
                print(f"    guarantee    {g['burst']}+ {r['unit']} within {r['window']} always alert, whatever the window "
                      f"alignment (checked at {g['alignments']} alignments × {g['spreads']} spreads); "
                      f"{g['burst'] - 1} can be split by a window boundary")
            if args.verbose:
                for s in r["scenarios"]:
                    tag = f"{YELLOW}known limit{RESET} " if s["known_limit"] else ""
                    print(f"      {GREEN + '✓' if not s['problem'] else RED + '✗'}{RESET} {s['expect']:<6} {tag}{s['name']}"
                          f"  {DIM}{s['events']} events → {s['alerts']} alert(s){RESET}")
                for m in cm["mutants"]:
                    state = (f"killed by '{m['killed_by']}'" if m["killed_by"] else
                             f"accepted: {m['accepted']}" if m["accepted"] else f"{RED}SURVIVES{RESET}")
                    print(f"      {DIM}{m['id']:<22}{RESET} {m['description']:<44} {DIM}{state}{RESET}")
        for w in r["warnings"]:
            print(f"    {YELLOW}!{RESET} {w}")
        for p in problems:
            print(f"    {RED}{p}{RESET}")
    verdict = f"{GREEN}all proven{RESET}" if not bad else f"{RED}{bad} not proven{RESET}"
    print(f"\n{BOLD}{len(report)} correlation detection(s) · {verdict}{RESET}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
