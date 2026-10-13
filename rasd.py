#!/usr/bin/env python3
"""
RASD - Attack-to-Defense Validation Framework. One command for the whole chain.

  author      new        scaffold a detection that fails CI until it is complete
  verify      lint       rules, contracts, tuning guides, evidence, deep static checks
              test       true-positive / true-negative samples
              mutate     hand-written + generic evasion mutations
              fuzz       automatic evasion fuzzing against a regression baseline
              prove      rule mutation testing: is every value, field and branch proven by a test?
              parity     the generated KQL / SPL return exactly what the tested rule returns
              correlate  Sigma correlations: scenarios, parameter mutants, aggregation parity, burst guarantee
              nearmiss   traffic one field edit away from an alert, and how close quiet windows come to a threshold
              tune       security cost vs noise benefit of every tuning
              diff       semantic diff: which events change verdict vs a git ref
              overlap    detections that co-fire on the same events
  understand  explain    why a rule matched (or did not) an event, field by field
              score      Engineering Quality Score and Operational Validation Score
  deploy      build      KQL + SPL (rules and correlations), Splunk app, cards, views, coverage, scores, banner, red docs, chain outputs
              convert    print queries for one backend
              doctor     check YOUR log export: READY / DEGRADED / BLIND per rule (--profile for ECS, CIM ...)
              profiles   telemetry profiles: which one fits an export (--detect), what each covers
              splunk     the detections as a Splunk app: scheduled alerts, indexes, forwarder inputs
  operate     red        validate and render every offensive test from its test.yml
              replay     run every rule over logs: risk-ranked alerts, noise forecast, storylines
              benchmark  events/s, memory, slowest rule and regex - on an export or N synthetic events
              evidence   turn a real lab run into verifiable evidence.md (fired / missed)
              chain      the 20-point attack-to-defense map, maturity, matrices, metrics
              links      every relative link in every Markdown file resolves
  all         ci         everything the pipeline runs, in order

Examples
  python rasd.py ci
  python rasd.py chain
  python rasd.py prove --filter T1218 --suggest
  python rasd.py parity --filter T1558 -v
  python rasd.py correlate -v
  python rasd.py correlate --logs dc-export.jsonl
  python rasd.py nearmiss my-export.jsonl --profile auto --suggest
  python rasd.py explain T1218 --tp 5
  python rasd.py replay samples/replay/lab-day.jsonl --assets samples/replay/assets.csv --html report.html
  python rasd.py doctor my-export.jsonl --profile auto
  python rasd.py benchmark --generate 100000
  python rasd.py evidence --results emulation-results.json --logs lab-export.jsonl --siem-alerts siem-alerts.csv
  python rasd.py diff --base origin/main --fuzz
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TOOLS = ROOT / "tools"
PY = sys.executable

COMMANDS = {
    "new": ["new_detection.py"], "lint": ["validate.py"], "test": ["run_tests.py"],
    "mutate": ["mutation_test.py"], "fuzz": ["fuzz.py"], "prove": ["prove.py"], "parity": ["parity.py"],
    "tune": ["tune.py"], "diff": ["diff.py"], "overlap": ["overlap.py"], "explain": ["explain.py"],
    "score": ["score.py"], "convert": ["convert.py"], "doctor": ["doctor.py"], "red": ["red.py"],
    "replay": ["replay.py"], "evidence": ["evidence.py"], "chain": ["chain.py"], "links": ["links.py"],
    "coverage": ["coverage.py"], "views": ["generate_views.py"], "splunk": ["splunk_app.py"],
    "profiles": ["profiles.py"], "benchmark": ["benchmark.py"], "correlate": ["correlate.py"],
    "nearmiss": ["nearmiss.py"],
}
BUILD = [["convert.py", "--all", "--out", "queries"], ["correlate.py", "--write"], ["generate_views.py"], ["coverage.py"], ["score.py"],
         ["banner.py", "--svg", "docs/assets/banner.svg"], ["red.py"], ["splunk_app.py"], ["profiles.py", "--readme"], ["chain.py"]]
CI = [["validate.py"], ["-m", "unittest", "discover", "-s", "tests"], ["run_tests.py"], ["mutation_test.py"],
      ["fuzz.py", "--check"], ["prove.py"], ["parity.py"], ["correlate.py", "--check"], ["nearmiss.py", "--check"], ["tune.py", "--check"], ["red.py", "--check"], ["splunk_app.py", "--check"], ["profiles.py", "--check"],
      *BUILD, ["chain.py", "--check"], ["links.py"]]


def run(argv: list[str]) -> int:
    cmd = [PY, *argv] if argv[0] == "-m" else [PY, str(TOOLS / argv[0]), *argv[1:]]
    return subprocess.call(cmd, cwd=ROOT, env={**os.environ, "NO_BANNER": "1"})


def steps(seq: list[list[str]], title: str) -> int:
    for argv in seq:
        label = " ".join(argv).replace(".py", "")
        print(f"\n\033[38;5;180m▸ {label}\033[0m" if sys.stdout.isatty() else f"\n> {label}")
        rc = run(argv)
        if rc:
            print(f"\n{title} failed at: {label}")
            return rc
    print(f"\n{title} passed.")
    return 0


def main() -> int:
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help", "help"):
        subprocess.call([PY, str(TOOLS / "banner.py")])
        print(__doc__)
        return 0
    if args[0] in ("--version", "version"):
        sys.path.insert(0, str(TOOLS))
        from common import VERSION
        print(f"RASD {VERSION}")
        return 0
    cmd, rest = args[0], args[1:]
    if cmd in ("ci", "build"):
        subprocess.call([PY, str(TOOLS / "banner.py")])
        return steps(CI if cmd == "ci" else BUILD, cmd)
    if cmd not in COMMANDS:
        print(f"Unknown command '{cmd}'. Run: python rasd.py help")
        return 2
    return run(COMMANDS[cmd] + rest)


if __name__ == "__main__":
    sys.exit(main())
