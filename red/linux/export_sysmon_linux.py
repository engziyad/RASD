#!/usr/bin/env python3
"""export_sysmon_linux.py - Sysmon for Linux events from syslog to the JSONL that rasd reads.

Sysmon for Linux writes each event to syslog as one line ending in an <Event> XML document.
This reads those lines (a syslog file, or journald output on standard input), keeps the
events of the run window, and writes one JSON object per event with the same field names
as the Windows export: Channel, EventID, Computer, TimeCreated and every EventData field
(Image, CommandLine, ParentImage ...). The output goes straight into `rasd evidence`,
`rasd replay` and `rasd doctor`.

Usage (on the Linux lab host, after a red test)
  python3 red/linux/export_sysmon_linux.py --since 2026-10-13T09:00:00Z --out lab-export.jsonl
  journalctl -t sysmon -o cat --since "-2h" | python3 red/linux/export_sysmon_linux.py --input - --out lab-export.jsonl

Standard library only. Reads logs, writes one file; changes nothing on the host.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path

DEFAULT_INPUTS = ("/var/log/syslog", "/var/log/messages")
DEFAULT_EVENT_IDS = (1, 3, 11)        # process creation, network connection, file creation
EVENT = re.compile(r"<Event[\s>].*?</Event>", re.S)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_event(xml_text: str) -> dict | None:
    """One <Event> document to a flat dict, or None when it is not a Sysmon event."""
    try:
        # the lab host's own syslog, read locally; expat 2.4+ refuses entity-expansion bombs and
        # ElementTree never fetches external entities
        root = ET.fromstring(xml_text)  # noqa: S314
    except ET.ParseError:
        return None
    out: dict = {}
    for part in root:
        name = _local(part.tag)
        if name == "System":
            for el in part:
                tag, text = _local(el.tag), (el.text or "").strip()
                if tag == "EventID" and text.isdigit():
                    out["EventID"] = int(text)
                elif tag in ("Channel", "Computer") and el.text:
                    out[tag] = el.text.strip()
                elif tag == "TimeCreated" and el.get("SystemTime"):
                    out["TimeCreated"] = el.get("SystemTime")
        elif name == "EventData":
            for el in part:
                if _local(el.tag) == "Data" and el.get("Name"):
                    out[el.get("Name")] = el.text or ""
    return out if "EventID" in out and "sysmon" in out.get("Channel", "").lower() else None


def event_time(ev: dict) -> datetime | None:
    raw = ev.get("UtcTime") or ev.get("TimeCreated")
    if not raw:
        return None
    raw = str(raw).replace(" ", "T").rstrip("Z")
    raw = re.sub(r"(\.\d{6})\d+", r"\1", raw)          # SystemTime carries nanoseconds
    try:
        return datetime.fromisoformat(raw).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def parse_since(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc) - timedelta(hours=2)
    t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def read_events(lines, since: datetime, event_ids: set[int]):
    for line in lines:
        for m in EVENT.finditer(line):
            ev = parse_event(m.group(0))
            if not ev or ev["EventID"] not in event_ids:
                continue
            t = event_time(ev)
            if t is None or t >= since:
                yield ev


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", help="syslog file, or - for standard input (default: /var/log/syslog or /var/log/messages)")
    ap.add_argument("--out", default="lab-export.jsonl", help="output JSONL (default lab-export.jsonl)")
    ap.add_argument("--since", help="ISO time; events before it are skipped (default: two hours ago)")
    ap.add_argument("--event-id", type=int, nargs="*", default=list(DEFAULT_EVENT_IDS), help="Sysmon event IDs to keep (default 1 3 11)")
    args = ap.parse_args()
    since = parse_since(args.since)
    if args.input == "-":
        source, handle = "standard input", sys.stdin
    else:
        path = Path(args.input) if args.input else next((Path(p) for p in DEFAULT_INPUTS if Path(p).exists()), None)
        if path is None or not path.exists():
            print(f"no syslog file found ({', '.join(DEFAULT_INPUTS)}); pass --input or pipe journalctl with --input -", file=sys.stderr)
            return 2
        source, handle = str(path), path.open(encoding="utf-8", errors="replace")
    count = 0
    with handle, open(args.out, "w", encoding="utf-8") as out:
        for ev in read_events(handle, since, set(args.event_id)):
            out.write(json.dumps(ev, ensure_ascii=False) + "\n")
            count += 1
    print(f"{count} Sysmon for Linux events since {since.isoformat()} from {source} -> {args.out}")
    return 0 if count else 1


if __name__ == "__main__":
    sys.exit(main())
