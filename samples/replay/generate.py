#!/usr/bin/env python3
"""
generate.py - build the synthetic "lab day" corpus used to demo `rasd replay`.

Everything here is invented: hosts, users, IPs and hashes belong to a fictional
lab domain (corp.lab). The corpus mixes a full day of ordinary activity with one
intrusion on WS07 and a few benign events that trip rules on purpose, so replay
shows both a real attack storyline and realistic false positives. The intrusion
includes a password spray, and the day includes ordinary password typos and a
stale saved password, so the correlation detections face both.

Deterministic: the same seed always produces the same file.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

OUT = Path(__file__).resolve().parent
rng = random.Random(1932)          # deterministic
DAY = datetime(2026, 10, 5, 0, 0, 0)
HOSTS = [f"WS{n:02d}.corp.lab" for n in range(1, 13)]
SERVERS = ["SRV-FS01.corp.lab", "SRV-APP02.corp.lab", "SRV-SQL01.corp.lab"]
DC = "DC01.corp.lab"
USERS = ["amal", "badr", "dana", "faisal", "huda", "khalid", "lama", "majed", "nora", "omar", "reem", "sami"]
IPS = {h: f"10.20.30.{10 + i}" for i, h in enumerate(HOSTS + SERVERS)}
SYSMON, SECURITY, SYSTEM = "Microsoft-Windows-Sysmon/Operational", "Security", "System"
PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"


def ts(t: datetime) -> str:
    return t.strftime("%Y-%m-%d %H:%M:%S.") + f"{t.microsecond // 1000:03d}"


def proc(t, host, user, image, cmd, parent, ofn=None):
    return {"UtcTime": ts(t), "Channel": SYSMON, "EventID": 1, "Computer": host, "User": f"CORP\\{user}",
            "Image": image, "OriginalFileName": ofn or image.rsplit("\\", 1)[-1], "CommandLine": cmd,
            "ParentImage": parent}


def benign(t: datetime) -> list[dict]:
    host = rng.choice(HOSTS); user = USERS[HOSTS.index(host)]
    pick = rng.random()
    if pick < 0.30:
        return [proc(t, host, user, "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                     "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --type=renderer",
                     "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe")]
    if pick < 0.45:
        return [proc(t, host, user, "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
                     "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\"", "C:\\Windows\\explorer.exe")]
    if pick < 0.55:
        return [proc(t, host, user, PS, "powershell.exe -NoProfile -Command Get-Process | Sort-Object CPU",
                     "C:\\Windows\\explorer.exe", "PowerShell.EXE")]
    if pick < 0.62:
        return [proc(t, host, user, "C:\\Windows\\System32\\schtasks.exe", "schtasks /query /fo LIST",
                     "C:\\Windows\\System32\\cmd.exe")]
    if pick < 0.70:
        return [proc(t, host, "SYSTEM", PS,
                     "powershell.exe -NonInteractive -enc JABzAD0AJwBjAG8AbQBwAGwAaQBhAG4AYwBlACcA",
                     "C:\\Windows\\CCM\\CcmExec.exe", "PowerShell.EXE")]
    if pick < 0.78:
        return [{"UtcTime": ts(t), "Channel": SYSMON, "EventID": 10, "Computer": host,
                 "SourceImage": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MsMpEng.exe",
                 "TargetImage": "C:\\Windows\\System32\\lsass.exe", "GrantedAccess": "0x1410"}]
    if pick < 0.84:
        return [{"UtcTime": ts(t), "Channel": SYSMON, "EventID": 13, "EventType": "SetValue", "Computer": host,
                 "Image": f"C:\\Users\\{user}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
                 "TargetObject": f"HKU\\S-1-5-21-1000-{HOSTS.index(host)}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive",
                 "Details": f"\"C:\\Users\\{user}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background"}]
    svc = rng.choice(["svc_sql", "svc_iis", "svc_backup", "svc_reports"])
    return [{"UtcTime": ts(t), "Channel": SECURITY, "EventID": 4769, "Computer": DC,
             "TargetUserName": f"{user}@CORP.LAB", "ServiceName": svc, "TicketEncryptionType": "0x12",
             "TicketOptions": "0x40810000", "Status": "0x0", "IpAddress": f"::ffff:{IPS[host]}"}]


def intrusion(start: datetime) -> list[dict]:
    h = "WS07.corp.lab"; u, ip = USERS[HOSTS.index(h)], IPS[h]
    t = lambda m, s=0: start + timedelta(minutes=m, seconds=s)
    stage = f"C:\\Users\\{u}\\AppData\\Roaming\\Microsoft\\Teamsync"
    ev = [
        proc(t(0), h, u, PS, "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
             "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "PowerShell.EXE"),
        proc(t(2, 10), h, u, "C:\\Windows\\System32\\schtasks.exe",
             f"schtasks /create /sc onlogon /tn \"Teams Updater\" /tr \"{stage}\\tsync.exe\" /f", PS),
        {"UtcTime": ts(t(3, 2)), "Channel": SYSMON, "EventID": 13, "EventType": "SetValue", "Computer": h,
         "Image": PS, "TargetObject": "HKU\\S-1-5-21-1000-6\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\TeamsSync",
         "Details": f"{stage}\\tsync.exe"},
        proc(t(9, 40), h, u, "C:\\Windows\\System32\\rundll32.exe",
             "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, #24 704 C:\\Windows\\Temp\\m.dmp full", PS, "RUNDLL32.EXE"),
        {"UtcTime": ts(t(9, 41)), "Channel": SYSMON, "EventID": 10, "Computer": h,
         "SourceImage": "C:\\Windows\\System32\\rundll32.exe", "TargetImage": "C:\\Windows\\System32\\lsass.exe",
         "GrantedAccess": "0x1fffff"},
    ]
    # password spray: one seasonal password against nine accounts over LDAP binds; seven fail
    # Kerberos pre-authentication (4771, client as ::ffff:IP), two fall back to NTLM (4625, plain IP)
    for k, name in enumerate(["amal", "badr", "dana", "faisal", "huda", "khalid", "majed", "nora", "reem"]):
        if k < 7:
            ev.append({"UtcTime": ts(t(11, 20 + k)), "Channel": SECURITY, "EventID": 4771, "Computer": DC,
                       "TargetUserName": name, "ServiceName": "krbtgt/CORP.LAB", "TicketOptions": "0x40810010",
                       "Status": "0x18", "PreAuthType": "2", "IpAddress": f"::ffff:{ip}"})
        else:
            ev.append({"UtcTime": ts(t(11, 20 + k)), "Channel": SECURITY, "EventID": 4625, "Computer": DC,
                       "TargetUserName": name, "TargetDomainName": "CORP", "Status": "0xc000006d",
                       "SubStatus": "0xc000006a", "LogonType": "3", "WorkstationName": "WS07", "IpAddress": ip})
    for k, svc in enumerate(["svc_sql", "svc_iis", "svc_backup", "svc_reports"]):
        ev.append({"UtcTime": ts(t(14, 5 + k * 3)), "Channel": SECURITY, "EventID": 4769, "Computer": DC,
                   "TargetUserName": f"{u}@CORP.LAB", "ServiceName": svc, "TicketEncryptionType": "0x17",
                   "TicketOptions": "0x40810000", "Status": "0x0", "IpAddress": f"::ffff:{ip}"})
    ev += [
        proc(t(19, 30), h, u, "C:\\Windows\\System32\\wevtutil.exe", "wevtutil cl Security", "C:\\Windows\\System32\\cmd.exe"),
        {"UtcTime": ts(t(19, 31)), "Channel": SECURITY, "EventID": 1102, "Computer": h,
         "SubjectUserName": u, "SubjectDomainName": "CORP"},
        {"UtcTime": ts(t(22, 0)), "Channel": SYSTEM, "EventID": 7045, "Computer": "SRV-FS01.corp.lab",
         "Provider_Name": "Service Control Manager", "ServiceName": "BTOBTO",
         "ImagePath": "%COMSPEC% /Q /c echo cd ^> \\\\127.0.0.1\\C$\\__output 2^>^&1 > %TEMP%\\execute.bat",
         "AccountName": "LocalSystem"},
    ]
    return ev


def failed_logon(t: datetime, host: str, user: str, status: str = "0x18") -> dict:
    return {"UtcTime": ts(t), "Channel": SECURITY, "EventID": 4771, "Computer": DC, "TargetUserName": user,
            "ServiceName": "krbtgt/CORP.LAB", "TicketOptions": "0x40810010", "Status": status, "PreAuthType": "2",
            "IpAddress": f"::ffff:{IPS[host]}"}


def ordinary_failures() -> list[dict]:
    """Authentication failures every domain has: typos, a stale saved password, a disabled account.
    None of them is a spray, and the password-spray correlation must stay silent on all of them."""
    at = lambda h, m, s=0: DAY + timedelta(hours=h, minutes=m, seconds=s)
    out = [failed_logon(at(8, 41, 12), "WS02.corp.lab", "badr"), failed_logon(at(13, 12, 40), "WS05.corp.lab", "huda"),
           failed_logon(at(16, 55, 3), "WS11.corp.lab", "reem"),
           failed_logon(at(11, 2, 30), "WS09.corp.lab", "nora", status="0x12")]          # disabled: not a wrong password
    out += [failed_logon(at(10, 40, 5) + timedelta(seconds=55 * k), "WS03.corp.lab", "dana") for k in range(6)]
    return out


def known_false_positives() -> list[dict]:
    """Benign activity that legitimately trips rules - the noise replay should surface."""
    return [
        {"UtcTime": ts(DAY + timedelta(hours=14, minutes=3)), "Channel": SYSTEM, "EventID": 7045,
         "Computer": "SRV-APP02.corp.lab", "Provider_Name": "Service Control Manager", "ServiceName": "PSEXESVC",
         "ImagePath": "%SystemRoot%\\PSEXESVC.exe", "AccountName": "LocalSystem"},
        {"UtcTime": ts(DAY + timedelta(hours=11, minutes=40)), "Channel": SECURITY, "EventID": 4769, "Computer": DC,
         "TargetUserName": "printsvc@CORP.LAB", "ServiceName": "svc_legacy_scan", "TicketEncryptionType": "0x17",
         "TicketOptions": "0x40810000", "Status": "0x0", "IpAddress": f"::ffff:{IPS['SRV-APP02.corp.lab']}"},
        {"UtcTime": ts(DAY + timedelta(hours=16, minutes=20)), "Channel": SECURITY, "EventID": 4769, "Computer": DC,
         "TargetUserName": "printsvc@CORP.LAB", "ServiceName": "svc_legacy_scan", "TicketEncryptionType": "0x17",
         "TicketOptions": "0x40810000", "Status": "0x0", "IpAddress": f"::ffff:{IPS['SRV-APP02.corp.lab']}"},
    ]


def main() -> None:
    events = []
    t = DAY + timedelta(hours=7)
    while t < DAY + timedelta(hours=19):
        events += benign(t)
        t += timedelta(seconds=rng.randint(40, 200))
    events += intrusion(DAY + timedelta(hours=9, minutes=12, seconds=3))
    events += known_false_positives()
    events += ordinary_failures()
    events.sort(key=lambda e: e["UtcTime"])
    (OUT / "lab-day.jsonl").write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
    with (OUT / "assets.csv").open("w", encoding="utf-8") as fh:
        fh.write("ip,host,role\n")
        for h, ip in IPS.items():
            fh.write(f"{ip},{h},{'server' if h.startswith('SRV') else 'workstation'}\n")
        fh.write(f"10.20.30.2,{DC},domain-controller\n")
    with (OUT / "users.csv").open("w", encoding="utf-8") as fh:
        fh.write("user,privileged\n")
        for u in USERS:
            fh.write(f"{u},false\n")
        fh.write("it.admin,true\nprintsvc,false\n")
    print(f"[+] {len(events)} events -> samples/replay/lab-day.jsonl (+ assets.csv, users.csv)")


if __name__ == "__main__":
    main()
