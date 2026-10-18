#!/usr/bin/env python3
"""
RASD - Attack-to-Defense Validation Framework. One command for the whole chain.

  author      new        scaffold a detection that fails CI until it is complete
  verify      lint       rules, contracts, tuning guides, evidence, deep static checks
              sigma      the Sigma subset RASD supports, proven in the engine and RASD's SPL / KQL models; the rest refused
              test       true-positive / true-negative samples
              mutate     hand-written + generic evasion mutations
              fuzz       automatic evasion fuzzing against a regression baseline
              prove      rule mutation testing: is every value, field and branch proven by a test?
              parity     the generated KQL / SPL return exactly what the tested rule returns (modelled semantics, not a live SIEM)
              correlate  Sigma correlations: scenarios, parameter mutants, aggregation parity, burst guarantee
              nearmiss   traffic one field edit away from an alert, and how close quiet windows come to a threshold
              tune       security cost vs noise benefit of every tuning
              diff       semantic diff: which events change verdict vs a git ref
              overlap    detections that co-fire on the same events
  understand  explain    why a rule matched (or did not) an event, field by field
              score      Engineering Score and Operational Score
  deploy      build      KQL + SPL (rules and correlations), Defender XDR queries, Splunk app, cards, views, coverage, scores,
                         Sigma support page, banner, red docs, profiles README, public dataset pages, chain outputs
              coverage   the ATT&CK Navigator layer and the coverage matrix
              views      the audience views (SOC L1, incident response, purple team, GRC)
              convert    print queries for one backend
              doctor     check YOUR log export: READY / DEGRADED / BLIND per rule (--profile for ECS, CIM ...)
              profiles   telemetry profiles: which one fits an export (--detect), what each covers
              splunk     the detections as a Splunk app: scheduled alerts, indexes, forwarder inputs
  operate     red        validate and render every offensive test from its test.yml
              replay     run every rule over logs: risk-ranked alerts, noise forecast, storylines,
                         --case-dir: one case folder per storyline
              benchmark  events/s, memory, slowest rule and regex - on an export or N synthetic events
              evidence   turn a real lab run into verifiable evidence.md (fired / missed);
                         --run reads the lab run's zip or folder (--strict: hashes and manifest required)
              datasets   public attack datasets: fetch them pinned and hashed, replay every rule, record the result
              chain      the 20-point attack-to-defense map, maturity, matrices, metrics
              links      every relative link in every Markdown file resolves
  all         ci         the full pipeline, in order (the CI workflow adds ruff, mypy, script parse checks and the drift check)

Install the `rasd` command into a virtual environment with `pip install -e .` and run `rasd <command>`;
without installing, `python rasd.py <command>` from a clone runs the same command.

Examples
  rasd ci
  rasd chain
  rasd prove --filter T1218 --suggest
  rasd parity --filter T1558 -v
  rasd correlate -v
  rasd correlate --logs dc-export.jsonl
  rasd nearmiss my-export.jsonl --profile auto --suggest
  rasd explain T1218 --tp 5
  rasd replay samples/replay/lab-day.jsonl --assets samples/replay/assets.csv --html report.html
  rasd replay my-export.jsonl --assets assets.csv --case-dir reports/cases
  rasd doctor my-export.jsonl --profile auto
  rasd benchmark --generate 100000
  rasd evidence --run lab-20261012-101500.zip dc-export.jsonl siem-alerts.csv
  rasd datasets fetch && rasd datasets run
  rasd evidence --results emulation-results.json --logs lab-export.jsonl --siem-alerts siem-alerts.csv
  rasd diff --base origin/main --fuzz
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
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
    "nearmiss": ["nearmiss.py"], "sigma": ["sigma_support.py"], "datasets": ["datasets.py"],
}
BUILD = [["convert.py", "--all", "--out", "queries"], ["correlate.py", "--write"], ["generate_views.py"], ["coverage.py"], ["score.py"],
         ["sigma_support.py"],
         ["banner.py", "--svg", "docs/assets/banner.svg"], ["red.py"], ["splunk_app.py"], ["profiles.py", "--readme"],
         ["datasets.py", "render"], ["chain.py"]]
CI = [["validate.py"], ["sigma_support.py", "--check"], ["-m", "unittest", "discover", "-s", "tests"], ["run_tests.py"], ["mutation_test.py"],
      ["fuzz.py", "--check"], ["prove.py"], ["parity.py"], ["correlate.py", "--check"], ["nearmiss.py", "--check"], ["tune.py", "--check"], ["red.py", "--check"], ["splunk_app.py", "--check"], ["profiles.py", "--check"],
      ["datasets.py", "check"],
      *BUILD, ["chain.py", "--check"], ["links.py"]]


def run(argv: list[str], cwd: Path = ROOT) -> int:
    """Run one tool. The build and CI steps run from the repository root; a single command runs
    from the folder it was typed in, so the paths it is given mean what they mean there (the
    tools find the repository's own files from their location)."""
    cmd = [PY, *argv] if argv[0] == "-m" else [PY, str(TOOLS / argv[0]), *argv[1:]]
    return subprocess.call(cmd, cwd=cwd, env={**os.environ, "NO_BANNER": "1"})


def steps(seq: list[list[str]], title: str) -> int:
    if seq is CI and not (os.environ.get("RASD_PWSH") or shutil.which("pwsh")):
        print("note: pwsh (PowerShell 7) was not found, so the PowerShell script tests are skipped; "
              "install it or set RASD_PWSH to run them")
    timings: list[tuple[str, float]] = []
    for argv in seq:
        label = " ".join(argv).replace(".py", "")
        print(f"\n\033[38;5;180m▸ {label}\033[0m" if sys.stdout.isatty() else f"\n> {label}")
        start = time.monotonic()
        rc = run(argv)
        took = time.monotonic() - start
        timings.append((label, took))
        print(f"  ({took:.1f} s)")
        if rc:
            print(f"\n{title} failed at: {label}")
            return rc
    slowest = ", ".join(f"{label} {took:.0f} s" for label, took in sorted(timings, key=lambda x: -x[1])[:3])
    print(f"\n{title} passed in {sum(took for _, took in timings):.0f} s (slowest: {slowest}).")
    return 0


def main() -> int:
    if not TOOLS.is_dir():
        # a plain `pip install .` copies only this file; the detections and tools live in the clone
        print("rasd runs from a clone of the repository. Inside the clone: pip install -e .", file=sys.stderr)
        return 2
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
        print(f"Unknown command '{cmd}'. Run: rasd help")
        return 2
    return run(COMMANDS[cmd] + rest, cwd=Path.cwd())


if __name__ == "__main__":
    sys.exit(main())
