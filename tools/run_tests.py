#!/usr/bin/env python3
"""
run_tests.py - unit-test every detection against its own sample telemetry.

For each detect/detections/<technique>/:
  tests/true_positive.jsonl  -> every event MUST trigger the rule
  tests/true_negative.jsonl  -> no event may trigger the rule

Exit code is non-zero on any failure, so CI blocks the merge.

Usage
  rasd test
  rasd test --junit reports/junit.xml
  rasd test --filter T1059
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sigma_engine import SigmaError, matches

ROOT = Path(__file__).resolve().parent.parent
from common import DETECTIONS, load_jsonl  # noqa: E402  (BOM-tolerant, reports file:line on bad JSON)

GREEN, RED, DIM, BOLD, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    GREEN = RED = DIM = BOLD = RESET = ""


def run(filter_: str | None) -> list[dict]:
    results = []
    for folder in sorted(p for p in DETECTIONS.iterdir() if p.is_dir()):
        if filter_ and filter_.lower() not in folder.name.lower():
            continue
        rule = yaml.safe_load((folder / "rule.yml").read_text(encoding="utf-8"))
        for kind, expected in (("true_positive", True), ("true_negative", False)):
            for i, event in enumerate(load_jsonl(folder / "tests" / f"{kind}.jsonl"), 1):
                case = event.get("_case", f"{kind}#{i}")
                start = time.perf_counter()
                try:
                    got, error = matches(rule, event), None
                except SigmaError as e:
                    got, error = None, str(e)
                results.append({
                    "detection": folder.name, "kind": kind, "case": case,
                    "expected": expected, "got": got, "error": error,
                    "passed": error is None and got == expected,
                    "ms": (time.perf_counter() - start) * 1000,
                })
    return results


def print_report(results: list[dict]) -> None:
    current = None
    for r in results:
        if r["detection"] != current:
            current = r["detection"]
            print(f"\n{BOLD}{current}{RESET}")
        mark = f"{GREEN}PASS{RESET}" if r["passed"] else f"{RED}FAIL{RESET}"
        tag = "TP" if r["kind"] == "true_positive" else "TN"
        extra = f"  {RED}{r['error']}{RESET}" if r["error"] else ""
        if not r["passed"] and not r["error"]:
            extra = f"  {RED}expected match={r['expected']} got={r['got']}{RESET}"
        print(f"  [{mark}] {tag}  {r['case']}{DIM}{extra}{RESET}")

    passed = sum(r["passed"] for r in results)
    rules = len({r["detection"] for r in results})
    colour = GREEN if passed == len(results) else RED
    print(f"\n{colour}{BOLD}{passed}/{len(results)} test cases passed across {rules} detections{RESET}")


def write_junit(results: list[dict], path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    failures = sum(not r["passed"] for r in results)
    lines = ['<?xml version="1.0" encoding="UTF-8"?>',
             f'<testsuite name="rasd-detections" tests="{len(results)}" failures="{failures}">']
    for r in results:
        name = quoteattr(f"{r['kind']}: {r['case']}")
        lines.append(f'  <testcase classname={quoteattr(r["detection"])} name={name} time="{r["ms"]/1000:.4f}">')
        if not r["passed"]:
            msg = r["error"] or f"expected match={r['expected']} got={r['got']}"
            lines.append(f'    <failure message={quoteattr(msg)}>{escape(msg)}</failure>')
        lines.append("  </testcase>")
    lines.append("</testsuite>")
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_step_summary(results: list[dict]) -> None:
    """Render a Markdown table into the GitHub Actions job summary."""
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if not target:
        return
    by_rule: dict[str, list[dict]] = {}
    for r in results:
        by_rule.setdefault(r["detection"], []).append(r)
    rows = ["| Detection | TP | TN | Status |", "|---|---|---|---|"]
    for name, rs in by_rule.items():
        tp = sum(1 for r in rs if r["kind"] == "true_positive" and r["passed"])
        tn = sum(1 for r in rs if r["kind"] == "true_negative" and r["passed"])
        tpt = sum(1 for r in rs if r["kind"] == "true_positive")
        tnt = sum(1 for r in rs if r["kind"] == "true_negative")
        ok = "✅" if all(r["passed"] for r in rs) else "❌"
        rows.append(f"| `{name}` | {tp}/{tpt} | {tn}/{tnt} | {ok} |")
    with open(target, "a", encoding="utf-8") as fh:
        fh.write("## Detection unit tests\n\n" + "\n".join(rows) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--junit", help="write JUnit XML report to this path")
    ap.add_argument("--filter", help="only run detections whose folder contains this text")
    args = ap.parse_args()

    results = run(args.filter)
    if not results:
        print("No test cases found.")
        return 1
    print_report(results)
    if args.junit:
        write_junit(results, args.junit)
    write_step_summary(results)
    return 0 if all(r["passed"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
