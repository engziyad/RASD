#!/usr/bin/env python3
"""
overlap.py - which detections fire on the same events?

Overlap is not automatically bad (two rules can see one attack from two angles),
but unexplained overlap means duplicate alerts for the SOC and wasted SIEM cost.
This replays every rule over every sample event (plus optional logs) and reports
each pair that co-fires, so the overlap is either intended and documented, or removed.

Usage
  rasd overlap
  rasd overlap --logs samples/replay/lab-day.jsonl
"""
from __future__ import annotations

import argparse
import itertools
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BOLD, DIM, RESET, YELLOW, load_detections, load_jsonl
from convert import logsource_key
from replay import route
from sigma_engine import SigmaError, matches


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--logs", nargs="*", default=[])
    args = ap.parse_args()
    dets = load_detections()
    events = [ev for d in dets for k in ("true_positive", "true_negative") for ev in d.tests(k)]
    events += [ev for p in args.logs for ev in load_jsonl(Path(p))]
    fired = defaultdict(set)
    for i, ev in enumerate(events):
        src = route(ev)
        for d in dets:
            if src and src != logsource_key(d.rule):
                continue
            try:
                if matches(d.rule, ev):
                    fired[d.id].add(i)
            except SigmaError:
                pass
    pairs = []
    for a, b in itertools.combinations(sorted(fired), 2):
        both = fired[a] & fired[b]
        if both:
            jacc = len(both) / len(fired[a] | fired[b])
            pairs.append((len(both), jacc, a, b))
    print(f"{BOLD}Co-firing detections over {len(events)} events{RESET}\n")
    if not pairs:
        print(f"  {DIM}none - every event is claimed by at most one detection{RESET}")
    for n, j, a, b in sorted(pairs, reverse=True):
        print(f"  {YELLOW}{n:3d} shared{RESET}  {j:5.0%} overlap  {a}  ↔  {b}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
