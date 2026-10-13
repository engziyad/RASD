#!/usr/bin/env python3
"""
explain.py - show exactly why a detection fired (or stayed silent) on an event.

Every selection and every field check is printed with its verdict, the value the
event actually carried, and which expected value matched. Built for the SOC
analyst asking "why did this alert?" and the engineer asking "why didn't it?".

Usage
  python tools/explain.py T1059.001                       # first true-positive sample
  python tools/explain.py T1059.001 --tn 2                # second true-negative sample
  python tools/explain.py T1218 --event '{"Image": "...", "CommandLine": "..."}'
  python tools/explain.py T1558 --file logs.jsonl --line 42
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BOLD, DIM, GOLD, GREEN, RED, RESET, find_detection, load_jsonl  # noqa: E402
from sigma_engine import explain  # noqa: E402


def mark(ok: bool) -> str:
    return f"{GREEN}✓{RESET}" if ok else f"{RED}✗{RESET}"


def short(v, n=90) -> str:
    s = json.dumps(v, ensure_ascii=False) if not isinstance(v, str) else v
    return s if len(s) <= n else s[: n - 1] + "…"


def print_selection(sel: dict, indent: str):
    if sel["type"] == "all-of":
        for f in sel["fields"]:
            mods = "|" + "|".join(f["modifiers"]) if f["modifiers"] else ""
            print(f"{indent}{mark(f['result'])} {f['field']}{DIM}{mods}{RESET} = {short(f['actual'])}")
            if f["result"]:
                print(f"{indent}    {DIM}matched: {short(f['matched_values'])}{RESET}")
            else:
                print(f"{indent}    {DIM}expected {'all of' if 'all' in f['modifiers'] else 'one of'}: {short(f['expected'])}{RESET}")
    elif sel["type"] == "any-of":
        for i, alt in enumerate(sel["alternatives"], 1):
            print(f"{indent}{mark(alt['result'])} alternative {i}")
            print_selection(alt, indent + "    ")
    else:
        print(f"{indent}{mark(sel['result'])} keywords {short(sel['keywords'])}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("detection", help="folder name, technique ID or rule UUID (prefix allowed)")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--event", help="event as a JSON object")
    src.add_argument("--file", help="JSONL file")
    src.add_argument("--tp", type=int, help="n-th true-positive sample (default 1)")
    src.add_argument("--tn", type=int, help="n-th true-negative sample")
    ap.add_argument("--line", type=int, default=1, help="line in --file (1-based)")
    ap.add_argument("--json", action="store_true", help="print the raw trace as JSON")
    args = ap.parse_args()

    d = find_detection(args.detection)
    if args.event:
        event = json.loads(args.event)
    elif args.file:
        event = load_jsonl(Path(args.file))[args.line - 1]
    elif args.tn:
        event = d.tests("true_negative")[args.tn - 1]
    else:
        event = d.tests("true_positive")[(args.tp or 1) - 1]

    trace = explain(d.rule, event)
    if args.json:
        print(json.dumps(trace, indent=2, ensure_ascii=False, default=str))
        return 0
    verdict = f"{RED}{BOLD}MATCH{RESET}" if trace["matched"] else f"{GREEN}{BOLD}NO MATCH{RESET}"
    print(f"{GOLD}{d.title}{RESET}  {DIM}{d.id}{RESET}")
    if event.get("_case"):
        print(f"{DIM}case: {event['_case']}{RESET}")
    print(f"condition: {BOLD}{trace['condition']}{RESET}  →  {verdict}\n")
    for name, sel in trace["selections"].items():
        print(f"{mark(sel['result'])} {BOLD}{name}{RESET}")
        print_selection(sel, "    ")
    return 0


if __name__ == "__main__":
    sys.exit(main())
