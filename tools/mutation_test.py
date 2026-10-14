#!/usr/bin/env python3
"""
mutation_test.py - prove detections survive evasion variants, not just fixed samples.

Two layers
  1. Generic mutations (every detection, generated automatically):
     each true-positive event is replayed in UPPER and lower case.
     Windows paths, command-line flags and most field values are case-insensitive,
     so an attacker changing case must not escape a rule.
  2. Technique mutations (tests/mutations.yml, hand-curated):
     copy a true-positive event (`base`, 1-based line number), override fields
     with `set`, and assert `should_match`. Covers parameter abbreviations,
     alternate prefixes, argument re-ordering, quoting, renamed binaries, and the
     benign look-alikes that must stay silent.

Usage
  rasd mutate
  rasd mutate --filter T1059
"""
from __future__ import annotations

import argparse
import copy
import os
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DETECTIONS, load_jsonl, selected
from sigma_engine import SigmaError, matches

ROOT = Path(__file__).resolve().parent.parent
GREEN, RED, BOLD, RESET = "\033[32m", "\033[31m", "\033[1m", "\033[0m"
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    GREEN = RED = BOLD = RESET = ""


def load_tp(folder: Path) -> list[dict]:
    return load_jsonl(folder / "tests" / "true_positive.jsonl")


def recase(event: dict, fn) -> dict:
    return {k: (fn(v) if isinstance(v, str) and k != "_case" else v) for k, v in event.items()}


def generic_mutations(tps: list[dict]):
    for i, ev in enumerate(tps, 1):
        yield f"generic_upper_tp{i}", recase(ev, str.upper), True
        yield f"generic_lower_tp{i}", recase(ev, str.lower), True


def technique_mutations(folder: Path, tps: list[dict]):
    path = folder / "tests" / "mutations.yml"
    if not path.exists():
        return
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    for m in doc.get("mutations", []):
        base = m["base"]
        if not 1 <= base <= len(tps):
            raise SystemExit(f"{path}: mutation '{m['name']}' base {base} out of range (1..{len(tps)})")
        ev = copy.deepcopy(tps[base - 1])
        ev.update(m["set"])
        yield m["name"], ev, bool(m["should_match"])


def run(filter_: str | None = None) -> list[dict]:
    results = []
    for folder in sorted(p for p in DETECTIONS.iterdir() if p.is_dir()):
        if not selected(folder.name, filter_):
            continue
        rule = yaml.safe_load((folder / "rule.yml").read_text(encoding="utf-8"))
        tps = load_tp(folder)
        for kind, gen in (("generic", generic_mutations(tps)), ("technique", technique_mutations(folder, tps))):
            for name, event, expected in gen:
                try:
                    got, err = matches(rule, event), None
                except SigmaError as e:
                    got, err = None, str(e)
                results.append({"detection": folder.name, "kind": kind, "name": name,
                                "expected": expected, "got": got, "error": err,
                                "passed": err is None and got == expected})
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--filter")
    args = ap.parse_args()
    results = run(args.filter)

    by_rule: dict[str, list[dict]] = {}
    for r in results:
        by_rule.setdefault(r["detection"], []).append(r)
    for name, rs in by_rule.items():
        tech = [r for r in rs if r["kind"] == "technique"]
        gen = [r for r in rs if r["kind"] == "generic"]
        ok = all(r["passed"] for r in rs)
        mark = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
        print(f"[{mark}] {name:<50} generic {sum(r['passed'] for r in gen)}/{len(gen)}"
              f"  technique {sum(r['passed'] for r in tech)}/{len(tech)}")
        for r in rs:
            if not r["passed"]:
                why = r["error"] or f"expected match={r['expected']} got={r['got']}"
                print(f"         {RED}- {r['name']}: {why}{RESET}")

    passed = sum(r["passed"] for r in results)
    colour = GREEN if passed == len(results) else RED
    print(f"\n{colour}{BOLD}{passed}/{len(results)} mutation cases passed{RESET}")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
