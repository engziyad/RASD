#!/usr/bin/env python3
"""
tune.py - tuning impact analysis: what does a filter cost, and what does it buy?

Every SOC tunes rules to cut noise. Most tuning is done blind: a filter is added because
an alert was annoying, and nobody checks which attacks the filter now hides. tune.py
measures both sides of every tuning in detections/<id>/tuning.yml before it is applied:

  security cost   true positives, technique mutations, case mutations and fuzzer
                  variants the filter would suppress - attacks the rule stops seeing
  noise benefit   alerts the filter removes from a real or replayed log corpus

  SAFE   the filter suppresses no attack variant in the test corpus
  RISKY  the filter hides at least one attack variant - it must be narrowed, or marked
         `rejected` so the reasoning stays on record

Applied tunings are checked for consistency instead: the named selection must exist in
rule.yml and be used under `not` in the condition (or, for `kind: exception`, be used
positively to take abused binaries back out of a filter).

Usage
  rasd tune                         # all detections, replay corpus as noise source
  rasd tune --filter T1558 --logs my-export.jsonl
  rasd tune --check                 # CI: fail on a RISKY proposed tuning or a broken applied one
"""
from __future__ import annotations

import argparse
import copy
import fnmatch
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BOLD, DIM, GREEN, RED, RESET, ROOT, YELLOW, load_detections, load_jsonl
from convert import logsource_key
from prove import suite
from replay import route
from sigma_engine import SigmaError, compile_rule, matches, tokenize

DEFAULT_LOGS = [ROOT / "samples" / "replay" / "lab-day.jsonl"]


def load_tuning(det) -> dict:
    path = det.folder / "tuning.yml"
    return (yaml.safe_load(path.read_text(encoding="utf-8")) or {}) if path.exists() else {}


def with_filter(rule: dict, name: str, selection: dict) -> dict:
    tuned = copy.deepcopy(rule)
    det = tuned["detection"]
    det[name] = selection
    cond = det["condition"]
    det["condition"] = [f"({c}) and not {name}" for c in cond] if isinstance(cond, list) else f"({cond}) and not {name}"
    return tuned


def negated_selections(rule: dict) -> set[str]:
    """Selections that appear inside a `not` (directly or through `not 1 of filter_*`)."""
    det = rule["detection"]
    names = [k for k in det if k not in ("condition", "timeframe")]
    out: set[str] = set()
    for cond in det["condition"] if isinstance(det["condition"], list) else [det["condition"]]:
        tokens = [t.lower() for t in tokenize(cond)]
        raw = tokenize(cond)
        depth_stack: list[int] = []
        negated_depths: list[int] = []
        for i, tok in enumerate(tokens):
            if tok == "(":
                depth_stack.append(i)
            elif tok == ")":
                if negated_depths and negated_depths[-1] == len(depth_stack):
                    negated_depths.pop()
                if depth_stack:
                    depth_stack.pop()
            elif tok == "not":
                if i + 1 < len(tokens) and tokens[i + 1] == "(":
                    negated_depths.append(len(depth_stack) + 1)
            elif tok not in ("and", "or", "1", "all", "of", "them"):
                direct = i >= 1 and tokens[i - 1] == "not"
                quant = i >= 3 and tokens[i - 1] == "of" and tokens[i - 3] == "not"
                if direct or quant or negated_depths:
                    out |= {n for n in names if fnmatch.fnmatchcase(n, raw[i])}
    return out


def referenced(rule: dict) -> set[str]:
    det = rule["detection"]
    names = [k for k in det if k not in ("condition", "timeframe")]
    conds = det["condition"] if isinstance(det["condition"], list) else [det["condition"]]
    return {n for c in conds for tok in tokenize(c) for n in names if fnmatch.fnmatchcase(n, tok)}


def noise_events(logs: list[Path], rule: dict) -> list[dict]:
    src = logsource_key(rule)
    return [ev for p in logs if p.exists() for ev in load_jsonl(p) if route(ev) == src]


def analyse(det, logs: list[Path]) -> list[dict]:
    doc = load_tuning(det)
    tests = [t for t in suite(det) if t[2] is True]                    # attack variants only
    noise = noise_events(logs, det.rule)
    baseline_alerts = [ev for ev in noise if _safe(det.rule, ev)]
    out = []
    for t in doc.get("tunings") or []:
        r = {"id": t.get("id"), "status": t.get("status"), "residual_risk": t.get("residual_risk", "-"), "problems": []}
        if t.get("status") == "applied":
            sel = t.get("selection")
            if sel not in det.rule["detection"]:
                r["problems"].append(f"selection '{sel}' does not exist in rule.yml")
            elif t.get("kind") == "exception":
                if sel not in referenced(det.rule) or sel in negated_selections(det.rule):
                    r["problems"].append(f"exception '{sel}' must be used positively in the condition")
            elif sel not in negated_selections(det.rule):
                r["problems"].append(f"selection '{sel}' is not used under `not` in the condition")
            r["verdict"] = "APPLIED" if not r["problems"] else "BROKEN"
            out.append(r)
            continue
        flt = t.get("filter")
        if not isinstance(flt, dict) or not flt:
            r["problems"].append("a proposed or rejected tuning needs a `filter` selection")
            r["verdict"] = "BROKEN"
            out.append(r)
            continue
        tuned = with_filter(det.rule, f"tune_{t.get('id')}", flt)
        try:
            compile_rule(tuned)                    # a filter the engine refuses would read as "hides everything"
        except SigmaError as e:
            r["problems"].append(f"the filter is refused: {e}")
            r["verdict"] = "BROKEN"
            out.append(r)
            continue
        hidden = [label for label, ev, _exp in tests if _safe(det.rule, ev) and not _safe(tuned, ev)]
        removed = [ev for ev in baseline_alerts if not _safe(tuned, ev)]
        r.update({"hidden": hidden, "tested": len(tests), "removed": len(removed), "alerts": len(baseline_alerts),
                  "verdict": "SAFE" if not hidden else "RISKY"})
        if t.get("status") == "proposed" and hidden:
            r["problems"].append(f"would hide {len(hidden)} attack variant(s) - narrow it or mark it rejected")
        out.append(r)
    return out


def _safe(rule: dict, ev: dict) -> bool:
    try:
        return matches(rule, ev)
    except SigmaError:
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--filter")
    ap.add_argument("--logs", nargs="*", help="noise corpus (default: samples/replay/lab-day.jsonl)")
    ap.add_argument("--check", action="store_true", help="exit 1 on a broken applied tuning or a RISKY proposed one")
    ap.add_argument("-v", "--verbose", action="store_true", help="list every hidden attack variant")
    args = ap.parse_args()
    logs = [Path(p) for p in args.logs] if args.logs else DEFAULT_LOGS

    print(f"{BOLD}Tuning impact · security cost vs noise benefit{RESET}\n")
    failing = 0
    for det in load_detections(args.filter):
        rows = analyse(det, logs)
        if not rows:
            print(f"  {DIM}{det.id}: no tunings{RESET}")
            continue
        print(f"  {BOLD}{det.id}{RESET}")
        for r in rows:
            colour = {"SAFE": GREEN, "APPLIED": GREEN, "RISKY": YELLOW if r["status"] == "rejected" else RED,
                      "BROKEN": RED}[r["verdict"]]
            if r["verdict"] in ("APPLIED", "BROKEN") and "hidden" not in r:
                detail = "in rule.yml" if r["verdict"] == "APPLIED" else "; ".join(r["problems"])
            else:
                detail = (f"hides {len(r['hidden'])}/{r['tested']} attack variants · "
                          f"removes {r['removed']}/{r['alerts']} corpus alerts · residual risk {r['residual_risk']}")
            print(f"    {colour}{r['verdict']:<7}{RESET} {r['status']:<8} {r['id']:<26} {detail}")
            for h in (r.get("hidden") or [])[: None if args.verbose else 3]:
                print(f"             {DIM}would hide {h}{RESET}")
            for p in r["problems"]:
                if r["verdict"] != "BROKEN":
                    print(f"             {RED}{p}{RESET}")
            failing += bool(r["problems"])
    if failing:
        print(f"\n{RED}{failing} tuning problem(s){RESET}")
    return 1 if (args.check and failing) else 0


if __name__ == "__main__":
    sys.exit(main())
