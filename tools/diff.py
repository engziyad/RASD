#!/usr/bin/env python3
"""
diff.py - semantic diff for detections: what does this rule change actually DO?

A text diff of a Sigma rule tells you which lines changed. It does not tell you
which events will now alert, or stop alerting. `diff` loads every changed rule as
it was at a git reference and as it is now, replays both against the whole test
corpus (every detection's samples, plus any logs you pass), and reports each event
whose verdict flips.

  - true positive that no longer matches   -> REGRESSION (fails the command)
  - true negative that now matches         -> NEW FALSE POSITIVE (fails the command)
  - expected verdict restored              -> fixed
  - any other event that flips             -> behaviour change, review it

Usage
  python tools/diff.py                        # working tree vs HEAD
  python tools/diff.py --base origin/main     # what a pull request changes
  python tools/diff.py --base HEAD~3 --logs samples/replay/lab-day.jsonl
  python tools/diff.py --fuzz                 # include evasion variants: shows bypasses fixed/opened
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BOLD, DETECTIONS, DIM, GREEN, RED, RESET, ROOT, YELLOW, load_detections, load_jsonl  # noqa: E402
from fuzz import variants  # noqa: E402
from sigma_engine import SigmaError, matches  # noqa: E402


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout


def old_rule(base: str, rel: str) -> dict | None:
    try:
        return yaml.safe_load(git("show", f"{base}:{rel}"))
    except subprocess.CalledProcessError:
        return None


def safe(rule: dict, ev: dict) -> bool | None:
    try:
        return matches(rule, ev)
    except SigmaError:
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default="HEAD", help="git reference to compare against (default HEAD)")
    ap.add_argument("--logs", nargs="*", default=[], help="extra JSONL logs to include in the corpus")
    ap.add_argument("--fuzz", action="store_true", help="also compare on every evasion variant of the true positives")
    args = ap.parse_args()

    try:
        git("rev-parse", "--verify", args.base)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"{RED}'{args.base}' is not a valid git reference (is this a git checkout?){RESET}")
        return 2

    dets = load_detections()
    corpus = []   # (label, event, expectation for its own detection or None)
    for d in dets:
        for kind, exp in (("true_positive", True), ("true_negative", False)):
            for i, ev in enumerate(d.tests(kind), 1):
                corpus.append((f"{d.id} {'TP' if exp else 'TN'}#{i}", ev, d.id, exp))
                if exp and args.fuzz:
                    for name, _cat, var in variants(ev):
                        corpus.append((f"{d.id} TP#{i}~{name}", var, d.id, True))
    for p in args.logs:
        for i, ev in enumerate(load_jsonl(Path(p)), 1):
            corpus.append((f"{Path(p).name}:{i}", ev, None, None))

    changed = 0; failures = 0
    for d in dets:
        rel = str((d.folder / "rule.yml").relative_to(ROOT))
        before = old_rule(args.base, rel)
        if before == d.rule:
            continue
        changed += 1
        if before is None:
            print(f"{BOLD}{d.id}{RESET}  {GREEN}new detection{RESET}")
            hits = [lbl for lbl, ev, own, exp in corpus if own != d.id and safe(d.rule, ev)]
            if hits:
                print(f"    {YELLOW}also matches {len(hits)} event(s) from other corpora: {', '.join(hits[:5])}{RESET}")
            continue
        flips = []
        for label, ev, own, exp in corpus:
            a, b = safe(before, ev), safe(d.rule, ev)
            if a != b:
                kind = "change"
                if own == d.id and exp is True:
                    kind = "fixed" if b else "REGRESSION"
                elif own == d.id and exp is False:
                    kind = "NEW FALSE POSITIVE" if b else "fixed"
                flips.append((kind, label, a, b))
        status = f"{GREEN}no behaviour change{RESET}" if not flips else f"{len(flips)} verdict change(s)"
        print(f"{BOLD}{d.id}{RESET}  {status}")
        for kind, label, a, b in flips:
            colour = GREEN if kind == "fixed" else (YELLOW if kind == "change" else RED)
            failures += kind not in ("change", "fixed")
            print(f"    {colour}{kind:<18}{RESET} {label}  {DIM}{'match' if a else 'no match'} → {'match' if b else 'no match'}{RESET}")
    removed = [r for r in git("diff", "--name-only", "--diff-filter=D", args.base, "--", str(DETECTIONS.relative_to(ROOT))).split() if r.endswith("rule.yml")]
    for r in removed:
        print(f"{BOLD}{Path(r).parent.name}{RESET}  {RED}removed{RESET}")
    if not changed and not removed:
        print(f"{DIM}No detection rules differ from {args.base}.{RESET}")
    print(f"\n{BOLD}{changed} changed · {len(removed)} removed · {failures} blocking finding(s){RESET}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
