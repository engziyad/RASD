#!/usr/bin/env python3
"""
prove.py - rule mutation testing: is every part of every rule defended by a test?

The event mutations (mutation_test.py) and the fuzzer (fuzz.py) ask whether a rule
survives attacker variation. prove.py asks the opposite question: would the TESTS
notice if the RULE were broken?

It makes small, systematic edits to each rule - the edits a tired engineer makes in a
pull request - and re-runs the full test suite (true positives, true negatives,
technique mutations, generic mutations, fuzzer variants) against every broken copy:

  drop-value     delete one value from a value list           ('vbscript:' removed)
  drop-field     delete one field condition from a selection   (Image check removed)
  drop-branch    delete one map from an OR-list of maps
  drop-operand   delete one operand of an and / or in the condition
                 (quantifiers such as `1 of selection_*` are expanded first)

A broken copy that still passes every test is a SURVIVING MUTANT: that piece of the rule
could be deleted tomorrow and CI would stay green - nothing proves it is needed. Each
survivor says which test is missing, and --suggest synthesises a candidate event that
would kill it (verified against both rule versions; edit it for realism before use).

Proof score = killed / (all mutants - accepted). 100% means every value, every field and
every branch of every rule is held in place by at least one test.

Some mutants are EQUIVALENT: deleting the part changes nothing on any real input (for
example a tool name that the tool's own command line already gives away). Those can be
accepted in tests/mutations.yml with the exact id and a written reason:

  accepted_rule_mutants:
    - id: "value:susp_name:ServiceName|startswith:BTOBTO"
      reason: "smbexec's ImagePath always starts with %COMSPEC%, so susp_path fires too"

An acceptance that no longer matches a surviving mutant fails the run, so stale
exceptions cannot pile up.

Usage
  rasd prove
  rasd prove --filter T1218 --suggest
  rasd prove --json
"""
from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from certify import CertifyError, RulePair
from common import BOLD, DIM, GREEN, RED, RESET, YELLOW, load_detections
from fuzz import load_baseline, variants
from mutation_test import generic_mutations, technique_mutations
from sigma_engine import SigmaError, _match_single, matches, resolve_pattern, tokenize


# --------------------------------------------------------------------------- #
# Condition AST: parse -> mutate -> render
# --------------------------------------------------------------------------- #
def parse_condition(cond: str, detection: dict):
    tokens, pos = tokenize(cond), [0]

    def peek():
        return tokens[pos[0]].lower() if pos[0] < len(tokens) else None

    def take():
        pos[0] += 1
        return tokens[pos[0] - 1]

    def expr():
        parts = [term()]
        while peek() == "or":
            take()
            parts.append(term())
        return parts[0] if len(parts) == 1 else ("or", parts)

    def term():
        parts = [factor()]
        while peek() == "and":
            take()
            parts.append(factor())
        return parts[0] if len(parts) == 1 else ("and", parts)

    def factor():
        tok = peek()
        if tok == "not":
            take()
            return ("not", factor())
        if tok == "(":
            take()
            node = expr()
            take()
            return node
        if tok in ("1", "all") and pos[0] + 1 < len(tokens) and tokens[pos[0] + 1].lower() == "of":
            quant = take().lower()
            take()
            names = resolve_pattern(detection, take())
            leaves = [("sel", n) for n in names]
            return leaves[0] if len(leaves) == 1 else ("or" if quant == "1" else "and", leaves)
        return ("sel", take())

    return expr()


def render(node) -> str:
    kind = node[0]
    if kind == "sel":
        return node[1]
    if kind == "not":
        return f"not {render(node[1])}"
    return "(" + f" {kind} ".join(render(c) for c in node[1]) + ")"


def operand_mutants(node, path=""):
    """Yield (description, mutated_ast) for every single-operand deletion."""
    kind = node[0]
    if kind == "not":
        for desc, sub in operand_mutants(node[1], path):
            yield desc, ("not", sub)
    elif kind in ("and", "or"):
        kids = node[1]
        for i, child in enumerate(kids):
            rest = kids[:i] + kids[i + 1:]
            yield f"drop '{render(child)}' from {kind}", rest[0] if len(rest) == 1 else (kind, rest)
        for i, child in enumerate(kids):
            for desc, sub in operand_mutants(child, path):
                yield desc, (kind, kids[:i] + [sub] + kids[i + 1:])


def sels_in(node) -> list[str]:
    if node[0] == "sel":
        return [node[1]]
    if node[0] == "not":
        return sels_in(node[1])
    return [n for c in node[1] for n in sels_in(c)]


# --------------------------------------------------------------------------- #
# Mutant generation
# --------------------------------------------------------------------------- #
def mutants(rule: dict):
    """Yield (id, kind, description, mutated_rule, meta)."""
    det = rule["detection"]
    conds = det["condition"] if isinstance(det["condition"], list) else [det["condition"]]
    used: list[str] = []
    for ci, cond in enumerate(conds):
        ast = parse_condition(cond, det)
        used += [n for n in sels_in(ast) if n not in used]
        for desc, new_ast in operand_mutants(ast):
            m = copy.deepcopy(rule)
            new = list(conds)
            new[ci] = render(new_ast)
            m["detection"]["condition"] = new if isinstance(det["condition"], list) else new[0]
            yield f"operand:{ci}:{desc}", "drop-operand", desc, m, {}

    for name in used:
        sel = det[name]
        if isinstance(sel, list) and all(isinstance(s, dict) for s in sel) and len(sel) > 1:
            for i in range(len(sel)):
                m = copy.deepcopy(rule)
                del m["detection"][name][i]
                yield f"branch:{name}:{i}", "drop-branch", f"{name}: drop branch #{i + 1}", m, {}
        maps = [(None, sel)] if isinstance(sel, dict) else \
               [(i, s) for i, s in enumerate(sel)] if isinstance(sel, list) and all(isinstance(s, dict) for s in sel) else []
        for bi, mp in maps:
            where = name if bi is None else f"{name}[{bi}]"
            for key, value in mp.items():
                if len(mp) > 1:
                    m = copy.deepcopy(rule)
                    target = m["detection"][name] if bi is None else m["detection"][name][bi]
                    del target[key]
                    yield f"field:{where}:{key}", "drop-field", f"{where}: drop '{key}'", m, \
                          {"selection": name, "branch": bi, "key": key}
                if isinstance(value, list) and len(value) > 1:
                    for vi, v in enumerate(value):
                        m = copy.deepcopy(rule)
                        target = m["detection"][name] if bi is None else m["detection"][name][bi]
                        target[key] = value[:vi] + value[vi + 1:]
                        yield f"value:{where}:{key}:{v}", "drop-value", f"{where}: drop {key} value {v!r}", m, \
                              {"selection": name, "branch": bi, "key": key, "value": v, "siblings": value}


# --------------------------------------------------------------------------- #
# Test suite and kill check
# --------------------------------------------------------------------------- #
def suite(det) -> list[tuple[str, dict, bool]]:
    tps, tns = det.tests("true_positive"), det.tests("true_negative")
    known_bypasses = set(load_baseline().get(det.id, []))
    out = [(f"TP#{i}", ev, True) for i, ev in enumerate(tps, 1)]
    out += [(f"TN#{i}", ev, False) for i, ev in enumerate(tns, 1)]
    out += [(f"mutation:{n}", ev, exp) for n, ev, exp in technique_mutations(det.folder, tps)]
    out += [(f"mutation:{n}", ev, exp) for n, ev, exp in generic_mutations(tps)]
    for i, ev in enumerate(tps, 1):
        out += [(f"TP#{i}~{n}", v, True) for n, _c, v in variants(ev) if f"tp{i}:{n}" not in known_bypasses]
    return out


def killed_by(rule: dict, tests) -> str | None:
    for label, ev, expected in tests:
        try:
            if matches(rule, ev) != expected:
                return label
        except SigmaError:
            return label
    return None


# --------------------------------------------------------------------------- #
# Suggestions: synthesise an event that kills a surviving mutant
# --------------------------------------------------------------------------- #
def _replace_ci(text: str, old: str, new: str) -> str:
    return re.sub(re.escape(old), lambda _m: new, text, count=1, flags=re.IGNORECASE)


def _break(value: str, mods: list[str]) -> str:
    if "endswith" in mods:
        return value + "_"
    if "startswith" in mods:
        return "_" + value
    return value[::-1] + "_"


def suggest(rule: dict, mutant: dict, meta: dict, tests) -> dict | None:
    """Return an event that the original rule and the mutant classify differently."""
    pool = [ev for _l, ev, _e in tests]
    candidates = []
    key = meta.get("key")
    if key:
        field, *mods = key.split("|")
        for ev in pool:
            actual = next((ev[k] for k in ev if k.lower() == field.lower()), None)
            if not isinstance(actual, str):
                continue
            if "value" in meta and "re" not in mods:                 # swap a sibling value for the dropped one
                for sib in meta["siblings"]:
                    if sib != meta["value"] and _match_single(actual, sib, mods) and isinstance(sib, str):
                        new = copy.deepcopy(ev)
                        k = next(k for k in ev if k.lower() == field.lower())
                        new[k] = _replace_ci(actual, sib, str(meta["value"])) if sib.lower() in actual.lower() \
                            else str(meta["value"])
                        candidates.append(new)
            new = copy.deepcopy(ev)                                    # break this field only
            k = next(k for k in ev if k.lower() == field.lower())
            new[k] = _break(actual, mods)
            candidates.append(new)
    candidates += pool
    for ev in candidates:
        try:
            if matches(rule, ev) != matches(mutant, ev):
                return {"event": {k: v for k, v in ev.items() if k != "_case"},
                        "expect": "true_positive" if matches(rule, ev) else "true_negative"}
        except SigmaError:
            continue
    return None


# --------------------------------------------------------------------------- #
def accepted(det) -> dict[str, str]:
    path = det.folder / "tests" / "mutations.yml"
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else None
    return {a["id"]: a["reason"] for a in (doc or {}).get("accepted_rule_mutants") or []}


def _prove_equivalent(rule: dict, mutant: dict, want_event: bool, entry: dict) -> bool | None:
    """Ask the automata whether the dropped part changes any event's verdict. True: no event can tell the
    two versions apart, so the part is redundant on every possible input (a proof, not a sample). False:
    an event distinguishes them, so the acceptance holds only for realistic inputs, not for all of them;
    the event is attached when events are wanted. None: the pair cannot be modelled exactly."""
    try:
        diff = RulePair(rule, mutant).difference()
    except CertifyError:
        return None
    if diff is not None and want_event:
        entry["distinguisher"] = diff
    return diff is None


def prove(filter_: str | None = None, want_suggestions: bool = False) -> dict:
    report = {}
    for det in load_detections(filter_):
        tests, accept = suite(det), accepted(det)
        total, survivors, equivalent = 0, [], []
        for mid, kind, desc, mrule, meta in mutants(det.rule):
            total += 1
            if killed_by(mrule, tests) is None:
                s = {"id": mid, "kind": kind, "description": desc}
                if mid in accept:
                    entry = {**s, "reason": accept[mid]}
                    entry["proven_equivalent"] = _prove_equivalent(det.rule, mrule, want_suggestions, entry)
                    equivalent.append(entry)
                    continue
                if want_suggestions:
                    s["suggestion"] = suggest(det.rule, mrule, meta, tests)
                survivors.append(s)
        stale = sorted(set(accept) - {e["id"] for e in equivalent})
        counted = total - len(equivalent)
        score = 100.0 if counted == 0 else round(100 * (counted - len(survivors)) / counted, 1)
        report[det.id] = {"mutants": total, "survivors": survivors, "accepted": equivalent, "stale": stale,
                          "score": score, "tests": len(tests),
                          "proven_equiv": sum(e.get("proven_equivalent") is True for e in equivalent)}
    return report


HINT = {
    "drop-value": "no test depends on this value - add a true positive (or, in a filter, a true negative) that only it matches",
    "drop-field": "no test depends on this condition - add a look-alike true negative that fails only this check",
    "drop-branch": "no test depends on this branch - add an event that only this branch matches",
    "drop-operand": "no test depends on this operand - add an event that only this part of the condition decides",
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--filter")
    ap.add_argument("--suggest", action="store_true", help="synthesise a killing event for each survivor")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--min", type=float, default=100.0, help="fail below this proof score (default 100)")
    args = ap.parse_args()
    report = prove(args.filter, args.suggest)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 1 if any(r["score"] < args.min or r["stale"] for r in report.values()) else 0
    print(f"{BOLD}Rule mutation testing · is every part of every rule proven by a test?{RESET}\n")
    width = max(len(k) for k in report) if report else 10
    total = dead = 0
    failing = False
    for det, r in report.items():
        total += r["mutants"] - len(r["accepted"])
        dead += r["mutants"] - len(r["accepted"]) - len(r["survivors"])
        colour = GREEN if r["score"] == 100 and not r["stale"] else (YELLOW if r["score"] >= args.min else RED)
        failing |= r["score"] < args.min or bool(r["stale"])
        extra = f"  {DIM}{len(r['accepted'])} accepted as equivalent{RESET}" if r["accepted"] else ""
        print(f"{colour}{r['score']:5.1f}%{RESET}  {det:<{width}}  {r['mutants']:3d} mutants  "
              f"{len(r['survivors']):2d} surviving  {DIM}{r['tests']} tests{RESET}{extra}")
        for a in r["accepted"]:
            pe = a.get("proven_equivalent")
            tag = (f"{GREEN}proven equivalent on every input{RESET}" if pe is True else
                   f"{YELLOW}redundant only on realistic inputs{RESET}" if pe is False else
                   f"{DIM}not comparable by the automata{RESET}")
            print(f"         {DIM}accepted{RESET} {a['description']}  {tag}")
            if pe is False and args.suggest and a.get("distinguisher"):
                w = a["distinguisher"]
                side = "the original fires, the trimmed rule stays quiet" if w["old_fires"] else \
                       "the trimmed rule fires, the original stays quiet"
                print(f"           {DIM}an input the stated reason rules out ({side}): "
                      f"{json.dumps(w['event'], ensure_ascii=False)[:200]}{RESET}")
        for sid in r["stale"]:
            print(f"         {RED}stale acceptance{RESET} {sid} - no longer a surviving mutant, remove it from mutations.yml")
        for s in r["survivors"]:
            print(f"         {YELLOW}survivor{RESET} {s['description']}  {DIM}id: {s['id']}{RESET}")
            print(f"           {DIM}{HINT[s['kind']]}{RESET}")
            if args.suggest:
                sug = s.get("suggestion")
                if sug:
                    print(f"           {GREEN}candidate {sug['expect']}{RESET}: "
                          f"{DIM}{json.dumps(sug['event'], ensure_ascii=False)[:240]}{RESET}")
                else:
                    print(f"           {DIM}no candidate found - the mutant may be equivalent (redundant rule part){RESET}")
    overall = 100.0 if total == 0 else 100 * dead / total
    eq = sum(len(r["accepted"]) for r in report.values())
    proven_eq = sum(r["proven_equiv"] for r in report.values())
    print(f"\n{BOLD}{total + eq} rule mutants · {dead} killed · {eq} accepted as equivalent "
          f"({proven_eq} proven so for every input by the automata) · proof score {overall:.1f}%{RESET}")
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
