#!/usr/bin/env python3
"""
generate.py - build the synthetic fleet export used to demo `rasd silence`.

Everything here is invented: hosts, users and addresses belong to a fictional lab domain (corp.lab).
The export is one day of eight hosts as a SIEM would hold it: every record with the number Windows
gave it (EventRecordID), so a missing record leaves a hole in the count. Most of the fleet is quiet and
provably so. Each of the other hosts shows one way a quiet rule stops being evidence:

  WS01        shuts down for the night and starts in the morning: the hours in between are not counted
  WS02        an intrusion (encoded PowerShell, a Run key, an LSASS dump): the quiet is broken
  WS03        the log forwarder is stopped and the Sysmon log cleared: the records written in between
              never left the host, and the System log keeps the record of the clear
  WS04        a run of records is cut out of the Security log, and no record says why
  WS05        every channel goes quiet for three and a half hours with no shutdown, while the domain
              controller keeps recording the host; it comes back with a start and no stop before it
  WS06        Sysmon is installed without process access: the LSASS rule has nothing to read
  SRV-FS01    a server without Sysmon, shipped by a pipeline that drops the record number: its quiet
              can only be judged by its rhythm

Deterministic: the same seed always produces the same file.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

OUT = Path(__file__).resolve().parent
rng = random.Random(2026)          # deterministic
START = datetime(2026, 11, 2, 6, 0, 0)
END = START + timedelta(hours=24)
DC, FS = "DC01.corp.lab", "SRV-FS01.corp.lab"
WS = [f"WS{n:02d}.corp.lab" for n in range(1, 7)]
HOSTS = [DC, FS, *WS]
USERS = dict(zip(WS, ["amal", "badr", "dana", "faisal", "huda", "khalid"], strict=True))
IPS = {DC: "10.20.30.2", FS: "10.20.30.20", **{h: f"10.20.30.{11 + i}" for i, h in enumerate(WS)}}
SYSMON, SECURITY, SYSTEM = "Microsoft-Windows-Sysmon/Operational", "Security", "System"
PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
SC = "C:\\Windows\\System32\\sc.exe"

# the moments the story turns on
SHUTDOWN, BOOT = START + timedelta(hours=12, minutes=2), START + timedelta(hours=23, minutes=55)          # WS01
INTRUSION = START + timedelta(hours=7, minutes=20)                                                           # WS02
FORWARDER_STOP, CLEAR = START + timedelta(hours=9, minutes=5, seconds=2), START + timedelta(hours=9, minutes=40, seconds=10)   # WS03
FORWARDER_START = CLEAR + timedelta(seconds=21)
CUT_FROM, CUT_TO = START + timedelta(hours=20, minutes=15), START + timedelta(hours=20, minutes=40)        # WS04
BLIND_FROM, BLIND_TO = START + timedelta(hours=19, minutes=10), START + timedelta(hours=22, minutes=40)    # WS05
BASE = {SYSMON: 40_000, SECURITY: 300_000, SYSTEM: 12_000}


def iso(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def up(host: str, t: datetime) -> bool:
    """The host is running and, as far as anyone can see, working."""
    if host == WS[0]:
        return not SHUTDOWN <= t <= BOOT
    return True


def walk(day: tuple[int, int], night: tuple[int, int]) -> list[datetime]:
    out, t = [], START + timedelta(seconds=rng.randint(5, day[0]))
    while t < END:
        out.append(t)
        lo, hi = day if 6 <= t.hour < 18 else night
        t += timedelta(seconds=rng.randint(lo, hi), milliseconds=rng.randint(0, 999))
    return out


def proc(image: str, cmd: str, parent: str, user: str, ofn: str | None = None) -> dict:
    return {"EventID": 1, "User": f"CORP\\{user}", "Image": image, "OriginalFileName": ofn or image.rsplit("\\", 1)[-1],
            "CommandLine": cmd, "ParentImage": parent}


def lsass_read() -> dict:
    return {"EventID": 10, "SourceImage": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MsMpEng.exe",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe", "GrantedAccess": "0x1410"}


def run_key(host: str) -> dict:
    user = USERS.get(host, "svc_ops")
    return {"EventID": 13, "EventType": "SetValue", "Image": f"C:\\Users\\{user}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
            "TargetObject": f"HKU\\S-1-5-21-1000-{HOSTS.index(host)}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive",
            "Details": f"\"C:\\Users\\{user}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background"}


def sysmon(host: str) -> dict:
    user = USERS.get(host, "svc_ops")
    pick = rng.random()
    if pick < 0.50:                                    # network, file and DNS records: the channel's background
        return {"EventID": rng.choice([3, 11, 22]), "Image": "C:\\Windows\\System32\\svchost.exe"}
    if pick < 0.62:
        return proc("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                    "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --type=renderer",
                    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", user)
    if pick < 0.72:
        return proc("C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\svchost.exe -k netsvcs -p",
                    "C:\\Windows\\System32\\services.exe", "SYSTEM")
    if pick < 0.80:
        return proc(PS, "powershell.exe -NoProfile -Command Get-Process | Sort-Object CPU", "C:\\Windows\\explorer.exe", user,
                    "PowerShell.EXE")
    if pick < 0.86:
        return proc("C:\\Windows\\System32\\schtasks.exe", "schtasks /query /fo LIST", "C:\\Windows\\System32\\cmd.exe", user)
    if pick < 0.94:
        return lsass_read() if host != WS[5] else {"EventID": 22, "Image": "C:\\Windows\\System32\\svchost.exe"}
    return run_key(host)


def security(host: str, t: datetime) -> dict:
    if host == DC:
        client = rng.choice([h for h in WS if up(h, t) and not (h == WS[4] and BLIND_FROM <= t <= BLIND_TO)])
        user, ip = USERS[client], f"::ffff:{IPS[client]}"
        pick = rng.random()
        if pick < 0.45:
            return {"EventID": 4769, "TargetUserName": f"{user}@CORP.LAB", "ServiceName": rng.choice(["svc_sql", "svc_iis", "svc_backup"]),
                    "TicketEncryptionType": "0x12", "TicketOptions": "0x40810000", "Status": "0x0", "IpAddress": ip}
        if pick < 0.75:
            return {"EventID": 4768, "TargetUserName": user, "ServiceName": "krbtgt", "TicketEncryptionType": "0x12", "Status": "0x0",
                    "IpAddress": ip}
        return {"EventID": 4624, "TargetUserName": user, "LogonType": "3", "WorkstationName": client.split(".")[0],
                "IpAddress": IPS[client]}
    if host == FS:
        client = rng.choice([h for h in WS if up(h, t) and not (h == WS[4] and BLIND_FROM <= t <= BLIND_TO)])
        if rng.random() < 0.6:
            return {"EventID": 4663, "SubjectUserName": USERS[client], "ObjectType": "File",
                    "ObjectName": "D:\\Shares\\Finance\\" + rng.choice(["budget-2026.xlsx", "forecast-q4.xlsx", "invoices.csv"]),
                    "AccessList": "%%4416", "ProcessName": "C:\\Windows\\System32\\svchost.exe"}
        return {"EventID": 4624, "TargetUserName": USERS[client], "LogonType": "3", "WorkstationName": client.split(".")[0],
                "IpAddress": IPS[client]}
    return rng.choice([{"EventID": 4624, "TargetUserName": "SYSTEM", "LogonType": "5"},
                       {"EventID": 4672, "SubjectUserName": "SYSTEM"},
                       {"EventID": 4634, "TargetUserName": USERS[host], "LogonType": "7"},
                       {"EventID": 4624, "TargetUserName": USERS[host], "LogonType": "7"}])


def system() -> dict:
    return rng.choice([{"EventID": 7036, "Provider_Name": "Service Control Manager"},
                       {"EventID": 7040, "Provider_Name": "Service Control Manager"},
                       {"EventID": 10016, "Provider_Name": "Microsoft-Windows-DistributedCOM"},
                       {"EventID": 1014, "Provider_Name": "Microsoft-Windows-DNS-Client"},
                       {"EventID": 37, "Provider_Name": "Microsoft-Windows-Kernel-Processor-Power"}])


def start_records(host: str, at: datetime, clean: bool) -> dict[str, list[tuple[datetime, dict]]]:
    """What a host writes when it starts. Without a clean shutdown before it, the Event Log service says so (6008)."""
    s = lambda n: at + timedelta(seconds=n)
    out: dict[str, list[tuple[datetime, dict]]] = {
        SYSTEM: [(s(2), {"EventID": 12, "Provider_Name": "Microsoft-Windows-Kernel-General"}),
                 (s(10), {"EventID": 6009, "Provider_Name": "EventLog"}),
                 (s(11), {"EventID": 6005, "Provider_Name": "EventLog"})],
        SECURITY: [(s(15), {"EventID": 4608})],
        SYSMON: [(s(20), {"EventID": 4, "State": "Started"}), (s(41), lsass_read()), (s(95), run_key(host)),
                 (s(120), proc("C:\\Windows\\explorer.exe", "C:\\Windows\\explorer.exe", "C:\\Windows\\System32\\userinit.exe",
                               USERS[host]))],
    }
    if not clean:
        out[SYSTEM].insert(0, (s(1), {"EventID": 6008, "Provider_Name": "EventLog"}))
    return out


def build() -> list[dict]:
    rng.seed(2026)                 # the same file however many times it is built
    streams: dict[tuple[str, str], list[tuple[datetime, dict]]] = {}
    for host in HOSTS:
        if host != FS:
            streams[(host, SYSMON)] = [(t, sysmon(host)) for t in walk((180, 600), (600, 1500))]
        pace = ((120, 420), (120, 420)) if host == DC else (((300, 1200), (300, 1200)) if host == FS else ((600, 1800), (600, 1800)))
        streams[(host, SECURITY)] = [(t, security(host, t)) for t in walk(*pace)]
        streams[(host, SYSTEM)] = [(t, system()) for t in walk((900, 2700), (900, 2700))]

    def keep(host: str, channel: str, drop) -> int:
        before = streams[(host, channel)]
        streams[(host, channel)] = [(t, e) for t, e in before if not drop(t)]
        return len(before) - len(streams[(host, channel)])

    def add(host: str, channel: str, t: datetime, ev: dict) -> None:
        streams[(host, channel)].append((t, ev))

    jumps: dict[tuple[str, str], tuple[datetime, int]] = {}

    # WS01: a clean shutdown in the evening, a start in the morning
    h = WS[0]
    for channel in (SYSMON, SECURITY, SYSTEM):
        keep(h, channel, lambda t: SHUTDOWN - timedelta(seconds=5) <= t <= BOOT + timedelta(minutes=3))
    add(h, SYSTEM, SHUTDOWN, {"EventID": 1074, "Provider_Name": "User32"})
    add(h, SYSMON, SHUTDOWN + timedelta(seconds=5), {"EventID": 4, "State": "Stopped"})
    add(h, SECURITY, SHUTDOWN + timedelta(seconds=8), {"EventID": 1100, "Provider_Name": "Microsoft-Windows-Eventlog"})
    add(h, SYSTEM, SHUTDOWN + timedelta(seconds=9), {"EventID": 6006, "Provider_Name": "EventLog"})
    add(h, SYSTEM, SHUTDOWN + timedelta(seconds=10), {"EventID": 13, "Provider_Name": "Microsoft-Windows-Kernel-General"})
    for channel, records in start_records(h, BOOT, clean=True).items():
        for t, ev in records:
            add(h, channel, t, ev)

    # WS02: the intrusion
    h, u = WS[1], USERS[WS[1]]
    stage = f"C:\\Users\\{u}\\AppData\\Roaming\\Microsoft\\Teamsync"
    at = lambda m, s=0: INTRUSION + timedelta(minutes=m, seconds=s)
    add(h, SYSMON, at(0), proc(PS, "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
                               "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", u, "PowerShell.EXE"))
    add(h, SYSMON, at(3, 2), {"EventID": 13, "EventType": "SetValue", "Image": PS,
                              "TargetObject": "HKU\\S-1-5-21-1000-3\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\TeamsSync",
                              "Details": f"{stage}\\tsync.exe"})
    add(h, SYSMON, at(9, 40), proc("C:\\Windows\\System32\\rundll32.exe",
                                   "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, #24 704 C:\\Windows\\Temp\\m.dmp full", PS, u,
                                   "RUNDLL32.EXE"))
    add(h, SYSMON, at(9, 41), {"EventID": 10, "SourceImage": "C:\\Windows\\System32\\rundll32.exe",
                               "TargetImage": "C:\\Windows\\System32\\lsass.exe", "GrantedAccess": "0x1fffff"})

    # WS03: the forwarder stopped, the Sysmon log cleared, the forwarder started again
    h, u = WS[2], USERS[WS[2]]
    gone = keep(h, SYSMON, lambda t: FORWARDER_STOP - timedelta(seconds=30) <= t <= FORWARDER_START + timedelta(seconds=30))
    add(h, SYSMON, FORWARDER_STOP, proc(SC, "sc stop SplunkForwarder", "C:\\Windows\\System32\\cmd.exe", u))
    add(h, SYSMON, FORWARDER_START, proc(SC, "sc start SplunkForwarder", "C:\\Windows\\System32\\cmd.exe", u))
    add(h, SYSTEM, CLEAR, {"EventID": 104, "Provider_Name": "Microsoft-Windows-Eventlog", "Channel_Cleared": SYSMON,
                           "SubjectUserName": u})
    jumps[(h, SYSMON)] = (FORWARDER_START, gone + 4)        # what the clear took: the records in between and the intruder's own

    # WS04: a run of records cut out of the Security log
    h = WS[3]
    gone = keep(h, SECURITY, lambda t: CUT_FROM <= t <= CUT_TO)
    jumps[(h, SECURITY)] = (CUT_TO, gone + 20)

    # WS05: nothing written for three and a half hours, then a start with no stop before it
    h = WS[4]
    for channel in (SYSMON, SECURITY, SYSTEM):
        keep(h, channel, lambda t: BLIND_FROM <= t <= BLIND_TO + timedelta(minutes=3))
    for channel, records in start_records(h, BLIND_TO, clean=False).items():
        for t, ev in records:
            add(h, channel, t, ev)
    for minutes, eid in ((32, 4769), (68, 4624), (117, 4769), (161, 4768)):       # the domain controller still sees it
        t = BLIND_FROM + timedelta(minutes=minutes)
        ev = {"EventID": eid, "TargetUserName": f"{USERS[h]}@CORP.LAB", "Status": "0x0", "IpAddress": f"::ffff:{IPS[h]}"}
        if eid == 4769:
            ev |= {"ServiceName": "svc_sql", "TicketEncryptionType": "0x12", "TicketOptions": "0x40810000"}
        elif eid == 4768:
            ev |= {"ServiceName": "krbtgt", "TicketEncryptionType": "0x12"}
        else:
            ev = {"EventID": 4624, "TargetUserName": USERS[h], "LogonType": "3", "WorkstationName": h.split(".")[0], "IpAddress": IPS[h]}
        add(DC, SECURITY, t, ev)

    events = []
    for (host, channel), records in streams.items():
        number = BASE[channel] + 1000 * HOSTS.index(host)
        jump = jumps.get((host, channel))
        for t, ev in sorted(records, key=lambda r: r[0]):
            if jump and t >= jump[0]:
                number, jump = number + jump[1], None
            number += 1
            head = {"TimeCreated": iso(t), "Channel": channel, "Computer": host}
            if host != FS:                              # the file server's pipeline drops the record number
                head["EventRecordID"] = number
            events.append({**head, **ev})
    events.sort(key=lambda e: (e["TimeCreated"], e["Computer"], e["Channel"]))
    return events


def main() -> None:
    events = build()
    (OUT / "fleet.jsonl").write_text("".join(json.dumps(e, separators=(",", ":")) + "\n" for e in events), encoding="utf-8", newline="\n")
    with (OUT / "assets.csv").open("w", encoding="utf-8", newline="\n") as fh:
        fh.write("ip,host,role\n")
        for h in HOSTS:
            role = "domain-controller" if h == DC else ("server" if h == FS else "workstation")
            fh.write(f"{IPS[h]},{h},{role}\n")
    print(f"[+] {len(events)} events -> samples/silence/fleet.jsonl (+ assets.csv)")


if __name__ == "__main__":
    main()
