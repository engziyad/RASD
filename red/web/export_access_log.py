#!/usr/bin/env python3
"""export_access_log.py - a web access log (combined format) to the JSONL that rasd reads.

nginx, Apache and Node servers (OWASP Juice Shop writes logs/access.log.<date>) log one line
per request in the combined format:

  127.0.0.1 - - [13/Oct/2026:10:01:00 +0000] "GET /api/Cards HTTP/1.1" 401 31 "-" "RASD-Red/rasd_1a2b3c4d"

This reads those lines and writes one JSON object per request with the W3C / Sigma webserver
field names the web rules use: c-ip, cs-username, cs-method, cs-uri-stem, cs-uri-query,
sc-status, sc-bytes, cs-referer, cs-user-agent, plus TimeCreated in UTC. Every RASD-Red web
request carries the run marker in its User-Agent, so `--marker` keeps only one run's requests.

Usage
  python3 red/web/export_access_log.py --input access.log --since 2026-10-13T10:00:00Z --out web-export.jsonl
  python3 red/web/export_access_log.py --input access.log --marker rasd_1a2b3c4d --out web-export.jsonl

Standard library only. Reads one file, writes one file; changes nothing.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<method>[A-Za-z]+) (?P<target>\S+)(?: [^"]*)?" '
    r'(?P<status>\d{3}) (?P<bytes>\S+)(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?')


def parse_line(line: str) -> dict | None:
    """One combined-format line to a webserver event, or None when the line is not one."""
    m = COMBINED.match(line.strip())
    if not m:
        return None
    try:
        t = datetime.strptime(m.group("time"), "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
    except ValueError:
        return None
    stem, _, query = m.group("target").partition("?")
    return {
        "TimeCreated": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "c-ip": m.group("ip"),
        "cs-username": m.group("user"),
        "cs-method": m.group("method").upper(),
        "cs-uri-stem": stem,
        "cs-uri-query": query,
        "sc-status": m.group("status"),
        "sc-bytes": m.group("bytes"),
        "cs-referer": m.group("referer") or "-",
        "cs-user-agent": m.group("agent") or "-",
    }


def parse_since(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc) - timedelta(hours=2)
    t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def read_events(lines, since: datetime, marker: str | None = None):
    for line in lines:
        ev = parse_line(line)
        if not ev:
            continue
        if marker and marker not in ev["cs-user-agent"]:
            continue
        if datetime.fromisoformat(ev["TimeCreated"].replace("Z", "+00:00")) >= since:
            yield ev


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", required=True, help="access log in combined format, or - for standard input")
    ap.add_argument("--out", default="web-export.jsonl", help="output JSONL (default web-export.jsonl)")
    ap.add_argument("--since", help="ISO time; requests before it are skipped (default: two hours ago)")
    ap.add_argument("--marker", help="keep only requests whose User-Agent carries this run marker")
    args = ap.parse_args()
    if args.input != "-" and not Path(args.input).exists():
        print(f"{args.input} not found", file=sys.stderr)
        return 2
    since = parse_since(args.since)
    # closed by the with statement below (standard input included)
    handle = sys.stdin if args.input == "-" else open(args.input, encoding="utf-8", errors="replace")  # noqa: SIM115
    count = 0
    with handle, open(args.out, "w", encoding="utf-8") as out:
        for ev in read_events(handle, since, args.marker):
            out.write(json.dumps(ev, ensure_ascii=False) + "\n")
            count += 1
    print(f"{count} requests since {since.isoformat()} from {args.input} -> {args.out}")
    return 0 if count else 1


if __name__ == "__main__":
    sys.exit(main())
