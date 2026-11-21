#!/usr/bin/env python3
"""splunk_lab.py - the lab's own Splunk, asked over its management port.

A lab run is half of the evidence. The other half is the SIEM: did the scheduled search raise
the alert, on which host, and how long after the step. This talks to a Splunk that runs beside
the lab host (a container on a Linux host, the service on a Windows host) and does what a
person would do in its UI after a run:

  inputs    write the lab's inputs app: which files of this host Splunk reads, into which index
  ready     wait until a probe written on the lab host can be found in Splunk (the feed works)
  wait      wait until every detection the run expects has raised its alert, or the time is up;
            for an alert that did not come, say why as far as Splunk can tell
  export    save the alerts of the run as siem-alerts.csv, the --siem-alerts input of rasd evidence
  searches  run every saved search of the RASD app once and record what Splunk said of each
  feeds     for every feed the alerts read: how many records Splunk holds and which fields it reads
  about     record which Splunk this was: version, build, licence, the apps installed

Usage (the password is read from the environment, never from the command line)
  export SPLUNK_PASSWORD=...
  python3 red/lab/splunk_lab.py inputs --host lab-linux01 --out /tmp/rasd_lab_inputs \\
      --monitor /lab/sysmon/sysmon.log:linux:sysmon:linux
  python3 red/lab/splunk_lab.py ready    --url https://172.17.0.3:8089 --search 'index=linux rasd-probe-1'
  python3 red/lab/splunk_lab.py wait     --url https://172.17.0.3:8089 --results red/results/<run>/emulation-results.json
  python3 red/lab/splunk_lab.py export   --url https://172.17.0.3:8089 --results red/results/<run>/emulation-results.json --out siem-alerts.csv
  python3 red/lab/splunk_lab.py searches --url https://172.17.0.3:8089 --out siem-searches.json
  python3 red/lab/splunk_lab.py about    --url https://172.17.0.3:8089 --out siem.json

Standard library only. It starts search jobs and reads their results; it changes nothing else in
Splunk. The management port's certificate is one nobody signed, so it is accepted only on the lab
host itself or on a private address: this is a lab tool, not a client for a production Splunk.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import ipaddress
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

APP = "rasd"
ALERT_INDEX = "rasd_alerts"
ALERT_PREFIX = "RASD - "
EXPORT_REPORT = "RASD - alert export"
EXPORT_COLUMNS = ("_time", "ss_name", "host", "alert_hosts", "result_count", "first_event", "last_event")
VENDOR_ADDONS = ("Splunk_TA_windows", "Splunk_TA_microsoft_sysmon", "Splunk_TA_sysmon-for-linux", "Splunk_TA_nix")
EARLY = 120             # seconds before the first step a search of the run starts from
DEFAULT_WAIT = 840      # seconds after the last step: two 5-minute slices, the longest wait of a correlation, and a margin


class LabError(Exception):
    """A refusal or a failure the person running the lab has to read."""


def utc(text: object) -> datetime:
    """An ISO 8601 time (PowerShell writes seven decimals, Splunk three and an offset) or epoch seconds."""
    raw = str(text).strip()
    try:
        return datetime.fromtimestamp(float(raw), timezone.utc)
    except ValueError:
        pass
    m = re.fullmatch(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d+))?\s*(Z|UTC|GMT|[+-]\d{2}:?\d{2})?", raw)
    if not m:
        raise LabError(f"{raw}: not a time this tool can read")
    zone = m.group(4) or "Z"
    offset = "+00:00" if zone in ("Z", "UTC", "GMT") else (zone if ":" in zone else f"{zone[:3]}:{zone[3:]}")
    fraction = (m.group(3) or "0")[:6].ljust(6, "0")
    return datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}.{fraction}{offset}").astimezone(timezone.utc)


def iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def lab_address(url: str) -> str:
    """The URL when it is one this tool may talk to: https, on this host or on a private address."""
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    if parts.scheme != "https" or not host:
        raise LabError(f"{url}: the management port is https://<address>:8089")
    if host != "localhost":
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise LabError(f"{host}: give the address of the lab's Splunk, not a name") from exc
        if not (address.is_loopback or address.is_private):
            raise LabError(f"{host}: not this host and not a private address - this tool talks to a lab Splunk only")
    return url.rstrip("/")


class Splunk:
    def __init__(self, url: str, user: str, password: str) -> None:
        self.url = lab_address(url)
        self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        # the lab Splunk's own certificate: accepted because lab_address() allowed only this host or a private address
        self.tls = ssl.create_default_context()
        self.tls.check_hostname = False
        self.tls.verify_mode = ssl.CERT_NONE

    def call(self, method: str, path: str, data: dict | None = None, timeout: int = 120) -> bytes:
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        req = urllib.request.Request(self.url + path, data=body, method=method)   # noqa: S310 - https only, see lab_address
        req.add_header("Authorization", self.auth)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=self.tls) as resp:   # noqa: S310
                return resp.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:600]
            raise LabError(f"Splunk answered {exc.code} to {method} {path.split('?')[0]}: {detail}") from exc
        except (urllib.error.URLError, OSError) as exc:
            raise LabError(f"Splunk did not answer on {self.url}: {exc}") from exc

    def get(self, path: str, **params: str) -> dict:
        query = urllib.parse.urlencode({"output_mode": "json", **params})
        return json.loads(self.call("GET", f"{path}?{query}"))

    def search(self, spl: str, earliest: str, latest: str = "now", timeout: int = 300) -> list[dict]:
        """Run a search to its end and return its rows."""
        text = spl if spl.lstrip().startswith("|") else f"search {spl}"
        body = self.call("POST", "/services/search/jobs/export",
                         {"search": text, "earliest_time": earliest, "latest_time": latest, "output_mode": "json"}, timeout)
        rows = []
        for line in body.decode("utf-8", "replace").splitlines():
            if line.strip():
                item = json.loads(line)
                if isinstance(item.get("result"), dict):
                    rows.append(item["result"])
        return rows

    def saved(self) -> list[dict]:
        """The saved searches of the RASD app, as Splunk holds them."""
        doc = self.get(f"/servicesNS/nobody/{APP}/saved/searches", count="0", search=f"eai:acl.app={APP}")
        return [{"name": e["name"], **e["content"]} for e in doc.get("entry", []) if e.get("acl", {}).get("app") == APP]

    def dispatch(self, name: str, earliest: str, latest: str = "now", timeout: int = 300, rows: int = 0) -> dict:
        """Run one saved search once, without its alert actions, and say what Splunk said of it."""
        path = f"/servicesNS/nobody/{APP}/saved/searches/{urllib.parse.quote(name, safe='')}/dispatch"
        started = time.monotonic()
        sid = json.loads(self.call("POST", path, {"trigger_actions": "0", "dispatch.earliest_time": earliest,
                                                   "dispatch.latest_time": latest, "output_mode": "json"}))["sid"]
        content: dict = {}
        while time.monotonic() - started < timeout:
            content = self.get(f"/services/search/jobs/{urllib.parse.quote(sid, safe='')}")["entry"][0]["content"]
            if content.get("isDone") or content.get("isFailed"):
                break
            time.sleep(2)
        messages = [f"{m.get('type')}: {m.get('text')}" for m in content.get("messages") or []
                    if str(m.get("type", "")).upper() in ("ERROR", "FATAL", "WARN")]
        failed = bool(content.get("isFailed")) or not content.get("isDone") or any(m.startswith(("ERROR", "FATAL")) for m in messages)
        verdict = {"name": name, "ok": not failed, "state": content.get("dispatchState"), "results": int(content.get("resultCount") or 0),
                   "events_scanned": int(content.get("scanCount") or 0), "messages": messages}
        if rows and verdict["results"]:
            got = self.get(f"/services/search/jobs/{urllib.parse.quote(sid, safe='')}/results", count=str(rows))
            verdict["rows"] = got.get("results") or []
        return verdict


def connect(args: argparse.Namespace) -> Splunk:
    password = os.environ.get("SPLUNK_PASSWORD")
    if not password:
        raise LabError("set SPLUNK_PASSWORD in the environment (the lab Splunk's admin password)")
    return Splunk(args.url, args.user, password)


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    path.with_name(path.name + ".sha256").write_text(f"{digest}  {path.name}\n", encoding="utf-8", newline="\n")


# --------------------------------------------------------------------------- #
# the run: what it expects, and when
# --------------------------------------------------------------------------- #
def read_steps(results: Path) -> list[dict]:
    doc = json.loads(results.read_text(encoding="utf-8-sig"))
    steps = doc.get("steps") if isinstance(doc, dict) else doc
    return [s for s in steps or [] if isinstance(s, dict)]


def expected(steps: list[dict]) -> list[str]:
    """Every detection and correlation a step that ran is expected to raise."""
    out: list[str] = []
    for s in steps:
        if str(s.get("status", "")).lower() != "executed":
            continue
        for det in [*(s.get("detections") or []), *(s.get("correlations") or [])]:
            if det not in out:
                out.append(str(det))
    return out


def window(steps: list[dict]) -> tuple[datetime, datetime]:
    ran = [s for s in steps if s.get("utc_start")]
    if not ran:
        raise LabError("the run has no step with a start time: nothing to ask Splunk about")
    start = min(utc(s["utc_start"]) for s in ran)
    end = max(utc(s.get("utc_end") or s["utc_start"]) for s in ran)
    return start, end


def holds(splunk: Splunk, earliest: str, index: str = "*") -> list[dict]:
    """What Splunk holds since a time: records by index, source, sourcetype and host, its own indexes left out."""
    rows = splunk.search(f"| tstats count where index={index} by index, source, sourcetype, host", earliest)
    return [{"index": str(r.get("index")), "source": str(r.get("source")), "sourcetype": str(r.get("sourcetype")),
             "host": str(r.get("host")), "records": int(r.get("count") or 0)} for r in rows if not str(r.get("index", "")).startswith("_")]


def held_line(row: dict) -> str:
    return f"index={row['index']} source={row['source']} sourcetype={row['sourcetype']} host={row['host']}: {row['records']} record(s)"


def fired(splunk: Splunk, since: datetime) -> dict[str, dict]:
    rows = splunk.search(f'index={ALERT_INDEX} sourcetype="rasd:alert" | stats count min(_time) as first values(alert_host) as hosts by detection',
                         iso(since))
    return {r["detection"]: r for r in rows if r.get("detection")}


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #
def cmd_inputs(args: argparse.Namespace) -> int:
    stanzas = []
    for spec in args.monitor:
        path, _, rest = spec.partition(":")
        index, _, sourcetype = rest.partition(":")
        if not path.startswith("/") or not index or not sourcetype:
            raise LabError(f"{spec}: give PATH:INDEX:SOURCETYPE, the path as Splunk sees it, from the root")
        stanzas.append(f"[monitor://{path}]\ndisabled = 0\nindex = {index}\nsourcetype = {sourcetype}\nhost = {args.host}\n")
    out = Path(args.out)
    (out / "default").mkdir(parents=True, exist_ok=True)
    header = "# Written by red/lab/splunk_lab.py for one lab run: the files of the lab host this Splunk reads.\n"
    (out / "default" / "inputs.conf").write_text(header + "\n" + "\n".join(stanzas), encoding="utf-8", newline="\n")
    (out / "default" / "app.conf").write_text(
        header + f"[install]\nis_configured = 1\n\n[ui]\nis_visible = 0\nlabel = RASD Lab Inputs\n\n"
        f"[launcher]\nversion = {datetime.now(timezone.utc):%Y.%m.%d}\n\n[package]\nid = {out.name}\n",
        encoding="utf-8", newline="\n")
    print(f"[+] {out}: {len(stanzas)} input(s), host = {args.host}")
    return 0


def cmd_ready(args: argparse.Namespace) -> int:
    splunk = connect(args)
    deadline = time.monotonic() + args.timeout
    while True:
        try:
            rows = splunk.search(f"{args.search} | stats count", "-15m")
            count = int(rows[0]["count"]) if rows else 0
        except LabError as exc:
            count, rows = 0, []
            print(f"  not yet: {exc}")
        if count:
            print(f"[+] the feed reaches Splunk: {count} record(s) for: {args.search}")
            return 0
        if time.monotonic() >= deadline:
            print(f"[!] nothing in Splunk after {args.timeout} s for: {args.search}")
            try:
                held = holds(splunk, "-60m")
            except LabError as exc:
                held = []
                print(f"    and Splunk does not say what it holds: {exc}")
            for row in held:
                print("    Splunk holds: " + held_line(row))
            if not held:
                print("    Splunk holds no record of the last hour in any index of its own making: the feed does not reach it")
            return 1
        time.sleep(5)


def explain(splunk: Splunk, det: str, since: datetime) -> list[str]:
    """Why an expected alert is not there, as far as Splunk itself can tell."""
    name = f"{ALERT_PREFIX}{det}"
    lines: list[str] = []
    saved = next((s for s in splunk.saved() if s["name"] == name), None)
    if not saved:
        return [f"{name}: Splunk has no saved search of that name - is the rasd app installed?"]
    spl = str(saved.get("search", ""))
    try:
        now = splunk.search(spl, iso(since))
    except LabError as exc:
        return [f"{name}: Splunk refuses the search: {exc}"]
    runs = splunk.search(f'index=_internal sourcetype=scheduler savedsearch_name="{name}" '
                         "| table _time status result_count scheduled_time dispatch_time run_time | sort 0 _time", iso(since))
    lines.append(f"{name}: {len(runs)} scheduled run(s) since the run began: "
                 + (", ".join(f"{r.get('status')}/{r.get('result_count', '?')} result(s)" for r in runs[-6:]) or "none"))
    if now:
        lines.append(f"  the same search finds {len(now)} row(s) now: the scheduled runs did not, so the events were late or outside their slice")
        return lines
    base = spl.split("|")[0].strip()
    count = splunk.search(f"{base} | stats count", iso(since))
    n = int(count[0]["count"]) if count else 0
    lines.append(f"  the search finds nothing now; its first part ({base}) finds {n} record(s)")
    if n:
        fields = splunk.search(f"{base} | head 200 | fieldsummary | sort 0 - count | head 40 | table field count", iso(since))
        lines.append("  fields Splunk reads there: " + ", ".join(f"{r.get('field')}({r.get('count')})" for r in fields))
        for r in splunk.search(f"{base} | head 2 | table _raw", iso(since)):
            lines.append("  a record: " + str(r.get("_raw", ""))[:900])
    else:
        source = base.split(" EventCode=")[0].split(" EventID=")[0]
        seen = splunk.search(f"{source} | stats count by index, sourcetype, source, host", iso(since))
        lines.append("  without the event id: " + (", ".join(f"{r.get('index')}/{r.get('sourcetype')}/{r.get('source')}/{r.get('host')}: {r.get('count')}"
                                                              for r in seen) or "nothing either - no record of this log source reached Splunk"))
        index = re.search(r"\bindex=(\S+)", source)
        if not seen and index:
            held = holds(splunk, iso(since), index.group(1))
            lines.append(f"  the index {index.group(1)} holds: " + ("; ".join(held_line(r) for r in held)
                                                                   or "nothing - the events never arrived"))
    return lines


def cmd_wait(args: argparse.Namespace) -> int:
    splunk = connect(args)
    steps = read_steps(Path(args.results))
    want = expected(steps)
    start, end = window(steps)
    since = start - timedelta(seconds=EARLY)
    deadline = end + timedelta(seconds=args.timeout)
    print(f"the run expects {len(want)} alert(s): {', '.join(want) or 'none'}")
    print(f"steps {start:%H:%M:%S} to {end:%H:%M:%S} UTC; waiting until {deadline:%H:%M:%S} UTC at the latest")
    have: dict[str, dict] = {}
    while True:
        have = fired(splunk, since)
        missing = [d for d in want if d not in have]
        print(f"  {datetime.now(timezone.utc):%H:%M:%S}  {len(want) - len(missing)}/{len(want)} raised" + (f"; waiting for {', '.join(missing)}" if missing else ""))
        if not missing or datetime.now(timezone.utc) >= deadline:
            break
        time.sleep(20)
    report = []
    for det in want:
        row = have.get(det)
        if row:
            at = datetime.fromtimestamp(float(row["first"]), timezone.utc)
            report.append(f"raised  {det}  at {at:%H:%M:%S} UTC, {(at - start).total_seconds():.0f} s after the first step; host {row.get('hosts')}")
        else:
            report.append(f"MISSING {det}")
            report += ["        " + line for line in explain(splunk, det, since)]
    for det in sorted(set(have) - set(want)):
        report.append(f"also    {det}  ({have[det].get('count')} alert(s)): not expected by a step of this run")
    print("\n".join(report))
    if args.out:
        Path(args.out).write_text("\n".join(report) + "\n", encoding="utf-8", newline="\n")
    return 1 if any(d not in have for d in want) else 0


def cmd_export(args: argparse.Namespace) -> int:
    splunk = connect(args)
    start, _end = window(read_steps(Path(args.results)))
    rows = splunk.search(f'| savedsearch "{EXPORT_REPORT}"', iso(start - timedelta(seconds=EARLY)))
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=EXPORT_COLUMNS, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for row in rows:
        row["_time"] = utc(row.get("_time", "")).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"     # one spelling, whatever Splunk's is
        writer.writerow({k: ("" if row.get(k) is None else row.get(k)) for k in EXPORT_COLUMNS})
    write(Path(args.out), out.getvalue())
    print(f"[+] {args.out}: {len(rows)} alert(s) from the report '{EXPORT_REPORT}'")
    for row in rows:
        print(f"    {row.get('_time')}  {row.get('ss_name')}  host={row.get('host')}  results={row.get('result_count')}")
    return 0


def cmd_searches(args: argparse.Namespace) -> int:
    splunk = connect(args)
    saved = sorted(splunk.saved(), key=lambda s: s["name"])
    if not saved:
        raise LabError(f"Splunk holds no saved search of the {APP} app")
    out = []
    for s in saved:
        try:
            verdict = splunk.dispatch(s["name"], args.earliest, rows=args.rows if args.show and s["name"].startswith(args.show) else 0)
        except LabError as exc:
            verdict = {"name": s["name"], "ok": False, "state": "REFUSED", "results": 0, "events_scanned": 0, "messages": [str(exc)]}
        verdict["scheduled"] = str(s.get("cron_schedule") or "") if str(s.get("is_scheduled", "0")) in ("1", "True", "true") else ""
        out.append(verdict)
        mark = "ok  " if verdict["ok"] else "FAIL"
        print(f"  {mark} {verdict['name']:<58} {verdict['state']:<8} {verdict['results']:>5} row(s) from {verdict['events_scanned']:>6} event(s)"
              + ("  " + " | ".join(verdict["messages"])[:300] if verdict["messages"] else ""))
        for row in verdict.pop("rows", []):
            print("         " + json.dumps(row, ensure_ascii=False)[:700])
    bad = [v for v in out if not v["ok"]]
    write(Path(args.out), json.dumps({"window": args.earliest, "searches": out}, indent=1) + "\n")
    print(f"{len(out) - len(bad)}/{len(out)} saved searches of the {APP} app ran to the end on this Splunk" + (f"; {len(bad)} did not" if bad else ""))
    return 1 if bad else 0


def cmd_feeds(args: argparse.Namespace) -> int:
    splunk = connect(args)
    bases: list[str] = []
    for s in splunk.saved():
        if s["name"].startswith(ALERT_PREFIX) and not s["name"].startswith(EXPORT_REPORT):
            base = str(s.get("search", "")).split("|")[0].strip()
            if base and base not in bases:
                bases.append(base)
    out = []
    for base in sorted(bases):
        rows = splunk.search(f"{base} | stats count dc(host) as hosts", args.earliest)
        records = int(rows[0]["count"]) if rows else 0
        fields = splunk.search(f"{base} | head 500 | fieldsummary | where count > 0 | sort 0 - count | table field count",
                               args.earliest) if records else []
        out.append({"search": base, "records": records, "hosts": int(rows[0].get("hosts") or 0) if rows else 0,
                    "fields": {str(r.get("field")): int(r.get("count") or 0) for r in fields}})
        print(f"  {records:>7} record(s)  {base}")
        if fields:
            print("          fields: " + ", ".join(f"{r.get('field')}" for r in fields[:70]))
        if records and args.sample:
            for r in splunk.search(f"{base} | head 1 | table _raw", args.earliest):
                print("          a record: " + str(r.get("_raw", ""))[:1800])
    held = holds(splunk, args.earliest)
    print("what Splunk holds, by index, source, sourcetype and host:")
    for row in held:
        print("  " + held_line(row))
    write(Path(args.out), json.dumps({"window": args.earliest, "feeds": out, "holds": held}, indent=1) + "\n")
    return 0


def cmd_about(args: argparse.Namespace) -> int:
    splunk = connect(args)
    deadline = time.monotonic() + args.timeout
    while True:
        try:
            info = splunk.get("/services/server/info")["entry"][0]["content"]
            break
        except LabError as exc:
            if time.monotonic() >= deadline:
                raise
            print(f"  not yet: {str(exc)[:160]}")
            time.sleep(5)
    apps = {e["name"]: str(e["content"].get("version") or "") for e in splunk.get("/services/apps/local", count="0").get("entry", [])
            if not e["content"].get("disabled")}
    indexes = sorted(e["name"] for e in splunk.get("/services/data/indexes", count="0").get("entry", []) if not e["name"].startswith("_"))
    doc = {
        "product": "Splunk Enterprise" if str(info.get("product_type", "")).lower() in ("enterprise", "splunk") else str(info.get("product_type")),
        "version": str(info.get("version")), "build": str(info.get("build")),
        "licence": str(info.get("activeLicenseGroup") or info.get("licenseState") or ""),
        "os": str(info.get("os_name") or ""),
        "apps": {k: v for k, v in sorted(apps.items()) if k.startswith("rasd")},
        "vendor_addons": sorted(a for a in apps if a in VENDOR_ADDONS or a.lower().startswith(("splunk_ta_", "ta-"))),
        "indexes": indexes,
        "terms": args.terms,
    }
    if args.out:
        write(Path(args.out), json.dumps(doc, indent=1) + "\n")
    print(json.dumps(doc, indent=1))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)

    def online(name: str, help_: str) -> argparse.ArgumentParser:
        p = sub.add_parser(name, help=help_)
        p.add_argument("--url", required=True, help="the management port of the lab's Splunk: https://<this host or a private address>:8089")
        p.add_argument("--user", default="admin")
        return p

    p = sub.add_parser("inputs", help="write the lab's inputs app")
    p.add_argument("--host", required=True, help="the lab host's name, as its own events and the run's results carry it")
    p.add_argument("--monitor", action="append", default=[], metavar="PATH:INDEX:SOURCETYPE", required=True)
    p.add_argument("--out", required=True, help="the app folder to write (its name is the app's id)")
    p.set_defaults(run=cmd_inputs)

    p = online("ready", "wait until a probe can be found in Splunk")
    p.add_argument("--search", required=True)
    p.add_argument("--timeout", type=int, default=180)
    p.set_defaults(run=cmd_ready)

    p = online("wait", "wait for the alerts the run expects")
    p.add_argument("--results", required=True, help="the run's emulation-results.json")
    p.add_argument("--timeout", type=int, default=DEFAULT_WAIT, help=f"seconds to wait after the last step (default {DEFAULT_WAIT})")
    p.add_argument("--out", help="also write the report to this file")
    p.set_defaults(run=cmd_wait)

    p = online("export", "save the run's alerts as the --siem-alerts file of rasd evidence")
    p.add_argument("--results", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(run=cmd_export)

    p = online("searches", "run every saved search of the RASD app once")
    p.add_argument("--earliest", default="-60m", help="how far back each search reads (default -60m)")
    p.add_argument("--show", default="", metavar="PREFIX", help="print the first rows of the searches whose name starts with this")
    p.add_argument("--rows", type=int, default=5)
    p.add_argument("--out", required=True)
    p.set_defaults(run=cmd_searches)

    p = online("feeds", "what Splunk holds and reads on every feed the alerts use")
    p.add_argument("--earliest", default="-60m")
    p.add_argument("--sample", action="store_true", help="also print one record of each feed")
    p.add_argument("--out", required=True)
    p.set_defaults(run=cmd_feeds)

    p = online("about", "record which Splunk this was")
    p.add_argument("--timeout", type=int, default=240, help="seconds to wait for Splunk to answer")
    p.add_argument("--terms", default="", help="who accepted the Splunk General Terms for this run, in a few words")
    p.add_argument("--out")
    p.set_defaults(run=cmd_about)

    args = ap.parse_args()
    try:
        return int(args.run(args))
    except LabError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
