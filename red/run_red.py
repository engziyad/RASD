#!/usr/bin/env python3
"""
run_red.py - RASD-Red runner for the web and Linux tests.

The Windows and Active Directory tests run through Invoke-RasdEmulation.ps1; this
runner does the same job for the tests whose runner is python (web) or bash (linux):

  1. discovers every red/web/* and red/linux/* test from its test.json
  2. runs the selected steps with one random run marker
  3. hashes every file the steps and the collect script write to the output folder
  4. runs cleanup and records it as verified (exit 0), manual (exit 3) or failed
  5. writes emulation-results.json in the same format as the PowerShell runner, so
     `rasd evidence` and the purple matrices read both the same way

Lab use only. Web tests refuse any target that resolves to a public address.

--dry-run prints which steps would run or be skipped, and why - including a web target the
lab guard refuses - and runs nothing, like Invoke-RasdEmulation.ps1 -DryRun.

Usage
  python3 red/run_red.py --list
  python3 red/run_red.py --platform web linux --lab-confirmed --target http://127.0.0.1:3000 --dry-run
  python3 red/run_red.py --test cron_persistence --lab-confirmed
  python3 red/run_red.py --platform web --lab-confirmed --target http://127.0.0.1:3000
  RASD_LAB_EMAIL=... RASD_LAB_PASSWORD=... python3 red/run_red.py --test idor_testing --lab-confirmed --target http://127.0.0.1:3000
"""
from __future__ import annotations

import argparse
import datetime as dt
import getpass
import hashlib
import json
import os
import platform
import secrets
import socket
import subprocess
import sys
from pathlib import Path

RED = Path(__file__).resolve().parent
PLATFORMS = ("web", "linux")
EXIT_MANUAL = 3


def host_ips() -> list[str]:
    """Non-loopback addresses of this host (best effort, no third-party modules)."""
    ips = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ips.add(str(info[4][0]).split("%")[0])
    except OSError:
        pass
    try:                                    # the address used for outbound traffic, without sending anything
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            ips.add(s.getsockname()[0])
    except OSError:
        pass
    return sorted(ip for ip in ips if not ip.startswith("127.") and ip != "::1")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def catalog() -> list[dict]:
    tests = []
    for p in PLATFORMS:
        for path in sorted((RED / p).glob("*/test.json")):
            t = json.loads(path.read_text(encoding="utf-8"))
            t["folder"] = path.parent
            tests.append(t)
    return tests


def command(test: dict, script: str, marker: str, extra: list[str]) -> list[str]:
    path = str(test["folder"] / script)
    if script.endswith(".py"):
        return [sys.executable, path, "--marker", marker, *extra]
    if script.endswith(".sh"):
        return ["bash", path, "--marker", marker, *extra]
    raise SystemExit(f"{test['id']}: unsupported script type {script}")


def target_refusal(url: str) -> str | None:
    """Why the web lab guard refuses this target, or None when it is a lab address."""
    sys.path.insert(0, str(RED / "web"))
    import rasd_web
    try:
        rasd_web.lab_target(url)
    except rasd_web.Refused as e:
        return str(e)
    return None


def target_is_loopback(url: str | None) -> bool:
    """The lab application runs on this host: its access log records the requests as coming
    from a loopback address, which then belongs to this run's evidence."""
    if not url:
        return False
    import ipaddress
    import urllib.parse
    host = urllib.parse.urlsplit(url).hostname or ""
    try:
        addrs = {str(info[4][0]).split("%")[0] for info in socket.getaddrinfo(host, None)}
    except OSError:
        return False
    return bool(addrs) and all(ipaddress.ip_address(a).is_loopback for a in addrs)


def plan_state(step: dict, available: dict, refused: str | None) -> str:
    missing = [p for p in step.get("parameters") or [] if not available.get(p)]
    if "Target" in missing and refused:
        return f"refused ({refused})"
    if missing:
        return "skip (missing parameter: " + ", ".join(f"--{p.lower()}" for p in missing) + ")"
    return "run"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--test", nargs="*", default=[], help="test ids (folder names)")
    ap.add_argument("--platform", nargs="*", default=[], choices=PLATFORMS)
    ap.add_argument("--technique", nargs="*", default=[], help="ATT&CK IDs")
    ap.add_argument("--lab-confirmed", action="store_true")
    ap.add_argument("--target", help="web tests: base URL of the lab application")
    ap.add_argument("--out-dir", help="results folder (default red/results/<timestamp>)")
    ap.add_argument("--dry-run", action="store_true", help="show which steps would run or be skipped, run nothing")
    args = ap.parse_args()

    tests = catalog()
    if args.list:
        for t in tests:
            print(f"{t['platform']:<7} {t['id']:<28} {t.get('technique') or 'posture':<10} "
                  f"{' | '.join(s['name'] for s in t['steps'])}")
        return 0
    if not args.lab_confirmed:
        print("Refusing to run without --lab-confirmed.", file=sys.stderr)
        return 2
    selected = [t for t in tests if t["id"] in args.test or t["platform"] in args.platform
                or (t.get("technique") and t["technique"] in args.technique)]
    if not selected:
        print("No test selected: use --test, --platform or --technique (see --list).", file=sys.stderr)
        return 2

    refused = target_refusal(args.target) if args.target else None
    available = {"Target": None if refused else args.target}

    if args.dry_run:
        for t in selected:
            for s in t["steps"]:
                print(f"{t['id']:<28} {s['id']:<24} {plan_state(s, available, refused)}")
        print("\n(dry run: nothing was executed)")
        return 2 if refused and any(t["platform"] == "web" for t in selected) else 0
    if refused and any(t["platform"] == "web" for t in selected):
        print(f"Refusing: {refused}", file=sys.stderr)
        return 2

    marker = "rasd_" + secrets.token_hex(4)
    out_dir = Path(args.out_dir or RED / "results" / dt.datetime.now().strftime("%Y%m%d-%H%M%S")).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    results = []
    ips = host_ips()
    print(f"run marker: {marker}\nresults:    {out_dir}\n")

    for t in selected:
        test_dir = out_dir / t["id"]
        env = {**os.environ, "RASD_OUT_DIR": str(test_dir)}
        ran = []
        for s in t["steps"]:
            rec = {"technique": t.get("technique"), "test": t["id"], "step": s["id"], "name": s["name"],
                   "detections": s.get("detections") or [], "correlations": s.get("correlations") or [],
                   "status": "skipped", "reason": None,
                   "host": platform.node(), "host_ips": ips, "user": getpass.getuser(), "marker": marker,
                   "bind": s.get("bind") or {},
                   "utc_start": None, "utc_end": None, "error": None, "cleanup": "not-run", "artifacts": []}
            if t["platform"] == "web" and target_is_loopback(available.get("Target")):
                rec["host_ips"] = ips + ["127.0.0.1", "::1"]     # the app's log sees this run as loopback
            missing = [p for p in s.get("parameters") or [] if not available.get(p)]
            if missing:
                rec["reason"] = "missing parameter: " + ", ".join(f"--{p.lower()}" for p in missing)
                print(f"[{t['id']}] skipped - {rec['reason']}")
                results.append(rec)
                continue
            extra = ["--lab-confirmed"]
            for p in s.get("parameters") or []:
                extra += [f"--{p.lower()}", str(available[p])]   # present: missing parameters skip the step
            print(f"[{t.get('technique') or 'posture'}] {s['name']}")
            rec["utc_start"] = utc_now()
            proc = subprocess.run(command(t, s["script"], marker, extra), env=env)
            rec["utc_end"] = utc_now()
            rec["status"] = "executed" if proc.returncode == 0 else "error"
            if proc.returncode:
                rec["error"] = f"exit code {proc.returncode}"
            results.append(rec)
            ran.append(rec)

        if not ran:
            continue
        scripts = t.get("scripts") or {}
        if scripts.get("collect"):
            subprocess.run(command(t, scripts["collect"], marker, []), env=env)
        artifacts = [{"path": str(p), "sha256": sha256(p)} for p in sorted(test_dir.rglob("*")) if p.is_file()]
        cleanup = "not-run"
        if scripts.get("cleanup"):
            rc = subprocess.run(command(t, scripts["cleanup"], marker, []), env=env).returncode
            cleanup = "verified" if rc == 0 else ("manual" if rc == EXIT_MANUAL else "failed")
        for rec in ran:
            rec["cleanup"], rec["artifacts"] = cleanup, artifacts
        print()

    results_path = out_dir / "emulation-results.json"
    results_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    executed = sum(r["status"] == "executed" for r in results)
    print(f"[+] {executed}/{len(results)} step(s) executed · results: {results_path}")
    return 0 if all(r["status"] != "error" for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
