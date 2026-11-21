#!/usr/bin/env python3
"""
generate.py - build the sample `rasd health` reads: three ordinary days, then a day the pipeline breaks.

Everything here is invented: hosts, users and addresses belong to a fictional lab domain (corp.lab).
Nothing is attacked on the fourth day. Five things stop working, each without an error anywhere, and
every one of them leaves some detection looking at less than it did the day before:

  WS03         Sysmon stops at 10:30. The host stays up and keeps writing its Security and System logs
  every WS     a new Sysmon configuration is pushed at 06:00 without the ProcessAccess rule: event 10 is
               gone from the whole fleet, and the LSASS rule has nothing left to read
  WS01         the forwarder is replaced by one that cuts command lines at 1024 characters
  LNX01        a pipeline update renames CommandLine to command_line
  DC01         the forwarder falls behind from 13:00 to 16:00: those events reach the index 20 to 40
               minutes late, after the scheduled searches have read their slices

and the scheduler's own record shows two more: the honey-file search skipped under load, and the
object-enumeration search missing from the schedule.

Outputs
  baseline.json     the three days as `rasd health --save-baseline` keeps them: counts, not events
  today.jsonl       the fourth day, as a SIEM would export it, with the time each event was indexed
  scheduler.jsonl   that day's record of scheduled runs (the fields of Splunk's scheduler log)

Deterministic: the same seed always produces the same files.
"""
from __future__ import annotations

import json
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

OUT = Path(__file__).resolve().parent
ROOT = OUT.parent.parent
START = datetime(2026, 11, 3, 6, 0, 0)                    # a Tuesday
TODAY = START + timedelta(days=3)
END = TODAY + timedelta(days=1)
DC, FS, LNX, WEB = "DC01.corp.lab", "SRV-FS01.corp.lab", "lnx01.corp.lab", "web01.corp.lab"
WS = [f"WS{n:02d}.corp.lab" for n in range(1, 5)]
USERS = dict(zip(WS, ["amal", "badr", "dana", "faisal"], strict=True))
IPS = {DC: "10.20.30.2", FS: "10.20.30.20", **{h: f"10.20.30.{11 + i}" for i, h in enumerate(WS)}}
SYSMON, SECURITY, SYSTEM, LINUX = "Microsoft-Windows-Sysmon/Operational", "Security", "System", "Linux-Sysmon/Operational"

SYSMON_STOPS = TODAY + timedelta(hours=4, minutes=30)      # WS03, 10:30
BACKLOG = (TODAY + timedelta(hours=7), TODAY + timedelta(hours=10))      # DC01, 13:00 to 16:00
CUT = 1024

PROCESSES = [
    ("C:\\Windows\\System32\\svchost.exe", "svchost.exe", "C:\\Windows\\System32\\svchost.exe -k netsvcs -p", "C:\\Windows\\System32\\services.exe"),
    ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "chrome.exe",
     "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --type=renderer", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"),
    ("C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "OUTLOOK.EXE",
     "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\"", "C:\\Windows\\explorer.exe"),
    ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "PowerShell.EXE",
     "powershell.exe -NoProfile -File C:\\Scripts\\inventory.ps1", "C:\\Windows\\System32\\svchost.exe"),
]
LONG = ("C:\\Program Files\\Vendor\\Agent\\agent.exe", "agent.exe",
        "\"C:\\Program Files\\Vendor\\Agent\\agent.exe\" --policy " + "A1b2C3d4" * 150, "C:\\Windows\\System32\\services.exe")
LINUX_COMMANDS = [("/usr/bin/python3", "python3 /opt/app/worker.py --queue default"), ("/usr/bin/bash", "bash /usr/local/bin/rotate-logs.sh"),
                  ("/usr/sbin/cron", "/usr/sbin/CRON -f"), ("/usr/bin/curl", "curl -fsS http://127.0.0.1:8080/health")]
PATHS = ["/", "/rest/products/search", "/api/Products", "/assets/public/main.js", "/rest/user/whoami"]


def iso(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def working(t: datetime) -> bool:
    return 7 <= t.hour < 19


def moments(rng: random.Random, start: datetime, end: datetime, per_hour: float, only_working: bool = False):
    """Poisson arrivals at a steady rate; workstations only produce them in working hours."""
    t = start
    while True:
        t += timedelta(seconds=rng.expovariate(per_hour / 3600))
        if t >= end:
            return
        if not only_working or working(t):
            yield t.replace(microsecond=(t.microsecond // 1000) * 1000)


def record(t: datetime, channel: str, host: str, lag: float, **fields) -> dict:
    return {"TimeCreated": iso(t), "Channel": channel, "Computer": host, **fields, "IngestionTime": iso(t + timedelta(seconds=lag))}


def day(rng: random.Random, start: datetime, end: datetime, broken: bool) -> list[dict]:
    out: list[dict] = []

    def lag() -> float:
        return round(rng.uniform(2, 20), 1)                  # the pipeline's ordinary delay, in seconds

    for host in WS:
        user = f"CORP\\{USERS[host]}"
        for t in moments(rng, start, end, 4, only_working=True):
            if broken and host == WS[2] and t >= SYSMON_STOPS:
                continue
            image, original, command, parent = LONG if rng.random() < 0.12 else rng.choice(PROCESSES)
            if broken and host == WS[0]:
                command = command[:CUT]
            out.append(record(t, SYSMON, host, lag(), EventID=1, User=user, Image=image, OriginalFileName=original,
                              CommandLine=command, ParentImage=parent))
        if not broken:
            for t in moments(rng, start, end, 2, only_working=True):
                out.append(record(t, SYSMON, host, lag(), EventID=10, SourceImage="C:\\Program Files\\Vendor\\Agent\\agent.exe",
                                  TargetImage="C:\\Windows\\System32\\lsass.exe", GrantedAccess="0x1000"))
        for t in moments(rng, start, end, 1, only_working=True):
            if broken and host == WS[2] and t >= SYSMON_STOPS:
                continue
            out.append(record(t, SYSMON, host, lag(), EventID=13, Image="C:\\Windows\\System32\\svchost.exe",
                              TargetObject="HKLM\\SOFTWARE\\Vendor\\Agent\\LastCheck", Details=f"DWORD (0x{rng.randrange(1 << 20):08x})"))
        for t in moments(rng, start, end, 1):
            out.append(record(t, SECURITY, host, lag(), EventID=4624, TargetUserName=USERS[host], LogonType="7"))
        for t in moments(rng, start, end, 0.5):
            out.append(record(t, SYSTEM, host, lag(), EventID=7036, Provider_Name="Service Control Manager",
                              param1="Background Intelligent Transfer Service", param2=rng.choice(["running", "stopped"])))
    out.append(record(start + timedelta(hours=3, minutes=12), SYSTEM, WS[0], 6.0, EventID=7045, Provider_Name="Service Control Manager",
                      ServiceName="VendorAgentUpdater", ImagePath="\"C:\\Program Files\\Vendor\\Agent\\updater.exe\" --service"))
    kerberos = [(4768, 2), (4769, 3), (4624, 2), (4625, 1), (4771, 0.5), (4776, 0.5)]
    for eid, per_hour in kerberos:
        for t in moments(rng, start, end, per_hour):
            client = rng.choice(WS)
            late = broken and BACKLOG[0] <= t < BACKLOG[1]
            fields: dict = {"EventID": eid, "TargetUserName": USERS[client], "IpAddress": f"::ffff:{IPS[client]}"}
            if eid == 4769:
                fields.update(ServiceName=rng.choice(["svc_sql", "svc_iis", "svc_backup"]), TicketEncryptionType="0x12", Status="0x0")
            elif eid in (4768, 4771):
                fields.update(Status="0x0" if eid == 4768 else "0x18")
            elif eid == 4625:
                fields.update(Status="0xc000006d", SubStatus="0xc000006a")
            out.append(record(t, SECURITY, DC, rng.uniform(1200, 2400) if late else lag(), **fields))
    for t in moments(rng, start, end, 2, only_working=True):
        client = rng.choice(WS)
        out.append(record(t, SECURITY, FS, lag(), EventID=4663, SubjectUserName=USERS[client], ObjectType="File",
                          ObjectName=f"D:\\Shares\\Projects\\{rng.choice(['plan.xlsx', 'notes.docx', 'budget.xlsx'])}",
                          AccessList="%%4416", ProcessName="C:\\Windows\\System32\\svchost.exe"))
    for t in moments(rng, start, end, 3):
        image, command = rng.choice(LINUX_COMMANDS)
        named = {"command_line": command} if broken else {"CommandLine": command}
        out.append(record(t, LINUX, LNX, lag(), EventID=1, User="svc_app", Image=image, **named))
    for t in moments(rng, start, end, 5):
        out.append({"TimeCreated": iso(t), "host": WEB.split(".")[0], "c-ip": f"10.20.40.{rng.randrange(10, 60)}", "cs-method": "GET",
                    "cs-uri-stem": rng.choice(PATHS), "sc-status": "200", "cs-user-agent": "Mozilla/5.0",
                    "IngestionTime": iso(t + timedelta(seconds=lag()))})
    out.sort(key=lambda e: (e["TimeCreated"], e.get("Computer", e.get("host", ""))))
    return out


def build() -> tuple[list[dict], list[dict], list[dict]]:
    """(the three days, the fourth day, the fourth day's scheduled runs)."""
    rng = random.Random(2026)
    before = day(rng, START, TODAY, broken=False)
    today = day(rng, TODAY, END, broken=True)
    sys.path.insert(0, str(ROOT / "tools"))
    from common import load_detections
    from correlation import load_correlations
    runs = []
    names = [d.id for d in load_detections()] + [c.id for c in load_correlations()]
    for det_id in names:
        if det_id == "T1190_object_id_enumeration":
            continue                                           # the search is no longer scheduled: no record of it at all
        for slot in range(0, 24 * 12, 12):                     # one record an hour is enough to tell the story
            t = TODAY + timedelta(minutes=5 * slot)
            skipped = det_id == "T1552.001_honey_file_access" and 8 <= t.hour < 18
            runs.append({"_time": iso(t), "savedsearch_name": f"RASD - {det_id}", "status": "skipped" if skipped else "success",
                         **({"reason": "The maximum number of concurrent historical scheduled searches on this instance has been reached"}
                            if skipped else {"run_time": round(rng.uniform(0.4, 2.2), 2)})})
    return before, today, runs


def lines(records: list[dict]) -> str:
    return "".join(json.dumps(r, separators=(",", ":")) + "\n" for r in records)


def baseline_text(before: list[dict]) -> str:
    sys.path.insert(0, str(ROOT / "tools"))
    import health
    return json.dumps(health.to_baseline(health.measure(before, health.needs(), until=TODAY)), indent=1) + "\n"


def main() -> None:
    before, today, runs = build()
    (OUT / "baseline.json").write_text(baseline_text(before), encoding="utf-8", newline="\n")
    (OUT / "today.jsonl").write_text(lines(today), encoding="utf-8", newline="\n")
    (OUT / "scheduler.jsonl").write_text(lines(runs), encoding="utf-8", newline="\n")
    print(f"baseline.json: {len(before)} events over {(TODAY - START).days} days · today.jsonl: {len(today)} events · "
          f"scheduler.jsonl: {len(runs)} runs")


if __name__ == "__main__":
    main()
