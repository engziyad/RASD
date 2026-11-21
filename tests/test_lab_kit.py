"""The lab kit as it runs on machines that exist for one run: the workflow's own limits, and the faults
the first real runs found, each held in place here."""
import argparse
import configparser
import io
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "red" / "lab"))

import evidence  # noqa: E402
import health  # noqa: E402
import splunk_lab  # noqa: E402
import red  # noqa: E402
from convert import MAPPINGS  # noqa: E402

WORKFLOW = ROOT / ".github" / "workflows" / "lab-run.yml"
LAB_HOSTS = ("windows", "linux", "web")
PINNED = re.compile(r"[^@\s]+@[0-9a-f]{40}")
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
DECOY_LOG = "/var/tmp/opencanary.log"  # noqa: S108 - the path inside the decoy container, never opened here


def workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def steps_of(job: dict) -> list[dict]:
    return list(job.get("steps") or [])


def script_of(job: dict) -> str:
    return "\n".join(str(s.get("run") or "") for s in steps_of(job))


def position(job: dict, name: str) -> int:
    names = [str(s.get("name") or "") for s in steps_of(job)]
    if name not in names:
        raise AssertionError(f"no step named {name!r} among {names}")
    return names.index(name)


class LabWorkflow(unittest.TestCase):
    """What the hosted lab may do is decided by this file: a change that widens it has to change a test."""

    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding="utf-8")
        cls.doc = workflow()
        cls.jobs = cls.doc["jobs"]

    def test_only_a_person_starts_a_lab_run(self):
        triggers = self.doc.get("on", self.doc.get(True))
        self.assertEqual(triggers, {"workflow_dispatch": None},
                         "attack steps run when a person starts them: never on a push, a pull request or a schedule")

    def test_the_jobs_are_the_three_lab_hosts_and_the_evidence(self):
        self.assertEqual(sorted(self.jobs), sorted([*LAB_HOSTS, "evidence"]))
        self.assertEqual(sorted(self.jobs["evidence"]["needs"]), sorted(LAB_HOSTS))

    def test_only_the_evidence_job_may_write_and_only_to_a_branch_of_its_own(self):
        self.assertEqual(self.doc["permissions"], {"contents": "read"})
        for name in LAB_HOSTS:
            self.assertNotIn("permissions", self.jobs[name], f"{name}: a lab host works with the read-only default")
        self.assertEqual(self.jobs["evidence"]["permissions"], {"contents": "write", "actions": "read"})
        script = script_of(self.jobs["evidence"])
        pushes = re.findall(r"git push[^\n]*", script)
        self.assertEqual(len(pushes), 1, pushes)
        self.assertIn('branch="lab-evidence/run-$GITHUB_RUN_ID"', script)
        self.assertRegex(pushes[0], r'git push --quiet origin "\$branch"$')
        self.assertNotRegex(script, r"--force|HEAD:|origin main")

    def test_a_lab_host_holds_no_credential_of_the_repository(self):
        for name in LAB_HOSTS:
            job = self.jobs[name]
            checkout = next(s for s in steps_of(job) if str(s.get("uses", "")).startswith("actions/checkout@"))
            self.assertIs(checkout.get("with", {}).get("persist-credentials"), False, name)
            block = yaml.safe_dump(job)
            self.assertNotIn("secrets.", block, name)
            self.assertNotIn("github.token", block, name)
            self.assertNotIn("GH_TOKEN", block, name)

    def test_every_action_is_pinned_to_a_commit(self):
        used = [str(s["uses"]) for job in self.jobs.values() for s in steps_of(job) if s.get("uses")]
        self.assertGreaterEqual(len(used), 8)
        for ref in used:
            self.assertRegex(ref, PINNED, f"{ref}: pin an action to a full commit SHA")

    def test_each_host_is_marked_as_a_lab_host_before_anything_runs_on_it(self):
        for name in LAB_HOSTS:
            job = self.jobs[name]
            marked = position(job, "Mark this runner as a RASD lab host")
            self.assertLess(marked, position(job, "The plan"), name)
            self.assertLess(position(job, "The plan"), position(job, "Lab run"), f"{name}: the plan is shown before the run")
        self.assertIn("'RASD_LAB_HOST', $env:COMPUTERNAME, 'Machine'", script_of(self.jobs["windows"]))
        for name in ("linux", "web"):
            self.assertIn("/etc/rasd-lab-host", script_of(self.jobs[name]), name)

    def test_the_opt_in_steps_never_run_on_a_hosted_runner(self):
        switches = sorted({s["opt_in"] for t in red.load_tests() for s in t["steps"] if s.get("opt_in")})
        self.assertEqual(switches, ["IncludeCredentialAccess", "IncludeSecurityLogClear"],
                         "a new opt-in switch has to be kept out of the hosted lab here")
        for switch in switches:
            self.assertNotIn(switch, self.text, f"-{switch} belongs on a machine that is ours")
        calls = re.findall(r"Invoke-RasdLabRun\.ps1[^\n]*", script_of(self.jobs["windows"]))
        self.assertEqual(len(calls), 2, "the plan and the run")
        for call in calls:
            self.assertIn("-LabConfirmed", call)
            self.assertNotRegex(call, r"-Force\b", "a run is never forced past a failed readiness check")
        for name in ("linux", "web"):
            runs = re.findall(r"red/run_red\.py[^\n|]*", script_of(self.jobs[name]))
            self.assertEqual(len(runs), 2, f"{name}: the plan and the run")
            for call in runs:
                self.assertIn("--lab-confirmed", call)
                self.assertIn(f"--platform {name}", call)

    def test_the_targets_are_the_lab_host_itself_and_what_runs_beside_it(self):
        windows = script_of(self.jobs["windows"])
        self.assertEqual(set(re.findall(r"-Target (\S+)", windows)), {"$env:COMPUTERNAME"})
        self.assertIn("-Value $env:COMPUTERNAME", windows, "the only trusted host of the WinRM client is the lab host")
        self.assertEqual(self.jobs["web"]["env"]["TARGET"], "http://127.0.0.1:3000")
        linux = script_of(self.jobs["linux"])
        self.assertIn('--volume "$PWD/deceive/opencanary/settings.json:/etc/opencanaryd/opencanary.conf:ro"', linux,
                      "the decoy host runs the configuration this repository commits, read-only")
        self.assertIn('echo "DECOY=http://$decoy"', linux)
        self.assertNotRegex(linux, r"--publish|-p \d", "the decoy is reached on the runner's own bridge, never published")
        for job, key in (("linux", "OPENCANARY_IMAGE"), ("web", "JUICE_SHOP_IMAGE")):
            image = self.jobs[job]["env"][key]
            self.assertRegex(image, r":v?\d+\.\d+\.\d+$", f"{image}: a lab image is pinned to a version")

    def test_no_real_siem_and_no_wait_for_one(self):
        self.assertEqual(set(re.findall(r"-SiemWaitMinutes (\S+)", script_of(self.jobs["windows"]))), {"0"})
        self.assertNotIn("--siem-alerts", script_of(self.jobs["evidence"]))

    def test_evidence_is_written_kept_pruned_rebuilt_and_checked_before_it_is_pushed(self):
        job = self.jobs["evidence"]
        order = [position(job, n) for n in (
            "Read the runs", "Turn each run into evidence", "Drop the kept runs this one replaces",
            "Rebuild the pages", "The evidence is what the kept runs give", "Push the evidence as a branch",
            "A detection whose step ran did not fire")]
        self.assertEqual(order, sorted(order))
        script = script_of(job)
        self.assertEqual(script.count("rasd evidence --run "), 3)
        self.assertEqual(script.count('--keep "$keep"'), 3, "every part of a hosted run is kept with its evidence")
        self.assertIn('keep="hosted-$GITHUB_RUN_ID"', script)
        self.assertIn('rasd evidence --run "$runs/lab-windows/lab-windows.zip" --strict', script,
                      "the Windows run is a zip with a manifest: it is read in strict mode")
        self.assertIn("rasd evidence --prune", script)
        self.assertIn("rasd evidence --check", script)
        last = steps_of(job)[-1]
        self.assertEqual(last.get("if"), "steps.evidence.outputs.missed == '1'")
        self.assertIn("exit 1", last["run"], "a detection that missed its own step fails the run after the evidence is pushed")

    def test_a_run_is_uploaded_even_when_a_step_failed(self):
        for name in LAB_HOSTS:
            upload = next(s for s in steps_of(self.jobs[name]) if str(s.get("uses", "")).startswith("actions/upload-artifact@"))
            self.assertEqual(upload.get("if"), "always()", name)
            self.assertEqual(upload["with"]["name"], f"lab-{name}")
        self.assertEqual(self.jobs["evidence"].get("if"), "always()")


class FakeSplunk:
    """A Splunk that answers from a script: what the alert index holds on each poll, and the saved searches."""

    def __init__(self, polls=(), saved=(), export=(), found=None, info=None):
        self.polls = list(polls)
        self._saved = list(saved)
        self.export = list(export)
        self.found = found or {}
        self.info = info or {}
        self.asked: list[str] = []

    def search(self, spl, earliest, latest="now", timeout=300):
        self.asked.append(spl)
        if spl.startswith(f"index={splunk_lab.ALERT_INDEX} ") and "by detection" in spl:
            rows = self.polls.pop(0) if len(self.polls) > 1 else (self.polls[0] if self.polls else [])
            return [{"detection": d, "count": "1", "first": str(t), "hosts": "lab-linux01"} for d, t in rows]
        if spl.startswith("| savedsearch"):
            return [dict(r) for r in self.export]
        return [dict(r) for r in next((v for k, v in self.found.items() if k in spl), [])]

    def saved(self):
        return [dict(x) for x in self._saved]

    def dispatch(self, name, earliest, latest="now", timeout=300, rows=0):
        bad = name.endswith("broken")
        return {"name": name, "ok": not bad, "state": "FAILED" if bad else "DONE", "results": 0, "events_scanned": 0,
                "messages": ["ERROR: Unknown search command 'nope'."] if bad else []}

    def get(self, path, **params):
        return self.info[path]


class SplunkLab(unittest.TestCase):
    """red/lab/splunk_lab.py against a scripted Splunk: what it expects of a run, what it writes, and
    that what it writes is what `rasd evidence` reads."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.t0 = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(seconds=90)

    def results(self, age=0, **extra):
        start = self.t0 - timedelta(seconds=age)
        steps = [
            {"test": "cron_persistence", "status": "executed", "detections": ["T1053.003_crontab_noninteractive_install"], "correlations": [],
             "utc_start": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"), "utc_end": (start + timedelta(seconds=2)).strftime("%Y-%m-%dT%H:%M:%S.000Z")},
            {"test": "web", "status": "executed", "detections": [], "correlations": ["T1190_object_id_enumeration"],
             "utc_start": (start + timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%S.0000000Z"),
             "utc_end": (start + timedelta(seconds=9)).strftime("%Y-%m-%dT%H:%M:%S.0000000Z")},
            {"test": "skipped", "status": "skipped", "detections": ["T1003.001_lsass_memory_access"], "correlations": []},
        ]
        path = self.tmp / "emulation-results.json"
        path.write_text(json.dumps(steps), encoding="utf-8")
        return path

    def run_command(self, fn, fake, **args):
        out = io.StringIO()
        with mock.patch.object(splunk_lab, "connect", return_value=fake), mock.patch.object(splunk_lab.time, "sleep"), redirect_stdout(out):
            code = fn(argparse.Namespace(url="https://127.0.0.1:8089", user="admin", **args))
        return code, out.getvalue()

    def test_it_reads_every_spelling_of_a_time_it_meets(self):
        for text, want in (("2026-11-20T18:01:01.210Z", "2026-11-20T18:01:01.210000+00:00"),
                           ("2026-10-12T06:00:00.0000000Z", "2026-10-12T06:00:00+00:00"),            # PowerShell: seven decimals
                           ("2026-11-21 00:52:00.000 GMT", "2026-11-21T00:52:00+00:00"),             # Splunk's JSON results
                           ("2026-11-21T04:10:03.000+0300", "2026-11-21T01:10:03+00:00"),
                           ("2026-11-21T01:10:03.000+00:00", "2026-11-21T01:10:03+00:00"),
                           ("1795225803.25", "2026-11-21T01:50:03.250000+00:00")):
            self.assertEqual(splunk_lab.utc(text).isoformat(), want, text)
        for bad in ("", "yesterday", "21/Nov/2026:00:48:50 +0000"):
            with self.assertRaises(splunk_lab.LabError):
                splunk_lab.utc(bad)

    def test_it_talks_to_a_lab_splunk_and_to_nothing_else(self):
        for url in ("https://127.0.0.1:8089", "https://localhost:8089", "https://172.17.0.3:8089/", "https://10.0.0.5:8089", "https://[::1]:8089"):
            self.assertEqual(splunk_lab.lab_address(url), url.rstrip("/"))
        for url in ("http://127.0.0.1:8089", "https://8.8.8.8:8089", "https://splunk.example.com:8089", "https://:8089", "127.0.0.1:8089"):
            with self.assertRaises(splunk_lab.LabError, msg=url):
                splunk_lab.lab_address(url)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SPLUNK_PASSWORD", None)
            with self.assertRaises(splunk_lab.LabError):
                splunk_lab.connect(argparse.Namespace(url="https://127.0.0.1:8089", user="admin"))

    def test_what_a_run_expects_is_what_its_executed_steps_name(self):
        steps = splunk_lab.read_steps(self.results())
        self.assertEqual(splunk_lab.expected(steps), ["T1053.003_crontab_noninteractive_install", "T1190_object_id_enumeration"])
        start, end = splunk_lab.window(steps)
        self.assertEqual((start, end), (self.t0, self.t0 + timedelta(seconds=9)))
        with self.assertRaises(splunk_lab.LabError):
            splunk_lab.window([{"status": "skipped"}])

    def test_the_inputs_app_names_the_lab_host_and_the_indexes_the_searches_read(self):
        out = self.tmp / "rasd_lab_inputs"
        with redirect_stdout(io.StringIO()):
            code = splunk_lab.cmd_inputs(argparse.Namespace(host="lab-linux01", out=str(out), monitor=[
                "/lab/sysmon/sysmon.log:linux:sysmon:linux", "/lab/web/access.log*:web:access_combined"]))
        self.assertEqual(code, 0)
        conf = configparser.ConfigParser(interpolation=None)
        conf.read(out / "default" / "inputs.conf", encoding="utf-8")
        self.assertEqual(dict(conf["monitor:///lab/sysmon/sysmon.log"]), {"disabled": "0", "index": "linux", "sourcetype": "sysmon:linux", "host": "lab-linux01"})
        self.assertEqual(conf["monitor:///lab/web/access.log*"]["sourcetype"], "access_combined")
        for spec in ("relative/file.log:linux:sysmon:linux", "/lab/x.log", "/lab/x.log:linux"):
            with self.assertRaises(splunk_lab.LabError, msg=spec):
                splunk_lab.cmd_inputs(argparse.Namespace(host="h", out=str(out), monitor=[spec]))
        # what the workflow feeds is what the generated searches read
        text = WORKFLOW.read_text(encoding="utf-8")
        spl = MAPPINGS["spl"]["logsources"]
        for source, spec in (("linux/process_creation", "/lab/sysmon/sysmon.log:linux:sysmon:linux"),
                             ("opencanary/honeypot", "/lab/canary/opencanary.log:deception:opencanary"),
                             ("webserver", "/lab/web/access.log*:web:access_combined")):
            self.assertIn(f"--monitor {spec}", text.replace('"', ""))
            _path, index, sourcetype = spec.split(":", 2)
            self.assertIn(f"index={index}", spl[source])
            self.assertIn(sourcetype, spl[source].replace('"', ""))

    def test_wait_ends_when_every_expected_alert_is_there(self):
        at = self.t0.timestamp() + 300
        fake = FakeSplunk(polls=[[], [("T1053.003_crontab_noninteractive_install", at)],
                                 [("T1053.003_crontab_noninteractive_install", at), ("T1190_object_id_enumeration", at + 60),
                                  ("T1046_decoy_service_interaction", at)]])
        report = self.tmp / "siem-wait.txt"
        code, out = self.run_command(splunk_lab.cmd_wait, fake, results=str(self.results()), timeout=900, out=str(report))
        self.assertEqual(code, 0, out)
        self.assertIn("0/2 raised", out)
        self.assertIn("2/2 raised", out)
        text = report.read_text(encoding="utf-8")
        self.assertIn("raised  T1053.003_crontab_noninteractive_install", text)
        self.assertIn("300 s after the first step", text)
        self.assertIn("also    T1046_decoy_service_interaction", text, "an alert no step of the run expects is named, not hidden")

    def test_wait_says_why_an_alert_did_not_come(self):
        name = "RASD - T1190_object_id_enumeration"
        saved = [{"name": name, "search": "index=web sourcetype=access_combined | where 1=1"}]
        fake = FakeSplunk(polls=[[("T1053.003_crontab_noninteractive_install", self.t0.timestamp())]], saved=saved,
                          found={"sourcetype=scheduler": [{"status": "success", "result_count": "0"}],
                                 "| stats count by index": []})
        code, out = self.run_command(splunk_lab.cmd_wait, fake, results=str(self.results(age=3000)), timeout=10, out=None)
        self.assertEqual(code, 1)
        self.assertIn("MISSING T1190_object_id_enumeration", out)
        self.assertIn("1 scheduled run(s) since the run began: success/0 result(s)", out)
        self.assertIn("no record of this log source reached Splunk", out)
        self.assertIn("the index web holds: nothing - the events never arrived", out)
        # the events arrived, under another name than the one the searches read: say the name they have
        fake = FakeSplunk(polls=[[]], saved=saved, found={"| tstats count where index=web": [
            {"index": "web", "source": "/var/log/app/access.log", "sourcetype": "access_combined_wcookie", "host": "lab-linux01", "count": "32"}]})
        code, out = self.run_command(splunk_lab.cmd_wait, fake, results=str(self.results(age=3000)), timeout=10, out=None)
        self.assertIn("the index web holds: index=web source=/var/log/app/access.log sourcetype=access_combined_wcookie host=lab-linux01: 32 record(s)",
                      out)
        # the same search finding rows now is a different story: the events were late
        fake = FakeSplunk(polls=[[]], saved=saved, found={"where 1=1": [{"result_count": "3"}]})
        code, out = self.run_command(splunk_lab.cmd_wait, fake, results=str(self.results(age=3000)), timeout=10, out=None)
        self.assertIn("finds 1 row(s) now", out)
        fake = FakeSplunk(polls=[[]], saved=[])
        code, out = self.run_command(splunk_lab.cmd_wait, fake, results=str(self.results(age=3000)), timeout=10, out=None)
        self.assertIn("Splunk has no saved search of that name", out)

    def test_a_feed_that_arrives_under_another_name_is_shown_as_what_arrived(self):
        held = [{"index": "sysmon", "source": "WinEventLog:Microsoft-Windows-Sysmon/Operational", "sourcetype": "XmlWinEventLog", "host": "LAB-WS01",
                 "count": "40"},
                {"index": "_internal", "source": "splunkd.log", "sourcetype": "splunkd", "host": "LAB-WS01", "count": "900"}]
        search = 'index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 rasd-siem-probe-1'
        code, out = self.run_command(splunk_lab.cmd_ready, FakeSplunk(found={"| tstats count where index=*": held}), search=search, timeout=0)
        self.assertEqual(code, 1)
        self.assertIn("Splunk holds: index=sysmon source=WinEventLog:Microsoft-Windows-Sysmon/Operational sourcetype=XmlWinEventLog "
                      "host=LAB-WS01: 40 record(s)", out)
        self.assertNotIn("_internal", out, "Splunk's own indexes are not the lab's feed")
        code, out = self.run_command(splunk_lab.cmd_ready, FakeSplunk(), search=search, timeout=0)
        self.assertIn("the feed does not reach it", out)
        code, out = self.run_command(splunk_lab.cmd_ready, FakeSplunk(found={"rasd-siem-probe-1 | stats count": [{"count": "2"}]}), search=search,
                                     timeout=0)
        self.assertEqual(code, 0, out)
        # feeds: every channel the alerts read, and what the indexes hold whatever its name
        saved = [{"name": "RASD - T1190_object_id_enumeration", "search": "index=web sourcetype=access_combined | where 1=1"}]
        fake = FakeSplunk(saved=saved, found={"| stats count dc(host)": [{"count": "0", "hosts": "0"}], "| tstats count where index=*": held})
        out_file = self.tmp / "siem-feeds.json"
        code, out = self.run_command(splunk_lab.cmd_feeds, fake, earliest="-60m", sample=False, out=str(out_file))
        doc = json.loads(out_file.read_text(encoding="utf-8"))
        self.assertEqual((code, [f["records"] for f in doc["feeds"]]), (0, [0]))
        self.assertEqual(doc["holds"], [{"index": "sysmon", "source": "WinEventLog:Microsoft-Windows-Sysmon/Operational",
                                         "sourcetype": "XmlWinEventLog", "host": "LAB-WS01", "records": 40}])

    def test_the_export_is_what_rasd_evidence_reads_as_siem_alerts(self):
        fake = FakeSplunk(export=[{"_time": "2026-11-21 00:52:00.000 GMT", "ss_name": "RASD - T1190_object_id_enumeration", "host": "::ffff:127.0.0.1",
                                   "alert_hosts": "::ffff:127.0.0.1", "result_count": "6", "first_event": "1795222130", "last_event": "1795222133",
                                   "_raw": "left out"}])
        out_file = self.tmp / "siem-alerts.csv"
        code, out = self.run_command(splunk_lab.cmd_export, fake, results=str(self.results()), out=str(out_file))
        self.assertEqual(code, 0, out)
        self.assertEqual(out_file.read_text(encoding="utf-8").splitlines(), [
            "_time,ss_name,host,alert_hosts,result_count,first_event,last_event",
            "2026-11-21T00:52:00.000Z,RASD - T1190_object_id_enumeration,::ffff:127.0.0.1,::ffff:127.0.0.1,6,1795222130,1795222133"])
        digest, name = (self.tmp / "siem-alerts.csv.sha256").read_text(encoding="utf-8").split()
        self.assertEqual((digest, name), (evidence.sha256(out_file), "siem-alerts.csv"))
        self.assertEqual(evidence.export_kind(out_file), "siem")
        alert = evidence.load_siem(out_file)[0]
        self.assertEqual(evidence.siem_time(alert["_time"]).isoformat(), "2026-11-21T00:52:00")
        self.assertIn('| savedsearch "RASD - alert export"', fake.asked[0], "the export is the app's own report")

    def test_what_it_records_of_the_splunk_is_what_evidence_reads_as_the_siem(self):
        fake = FakeSplunk(info={
            "/services/server/info": {"entry": [{"content": {"product_type": "enterprise", "version": "10.4.5", "build": "de9225ad9740",
                                                             "activeLicenseGroup": "Trial", "os_name": "Linux"}}]},
            "/services/apps/local": {"entry": [{"name": "rasd", "content": {"version": "1.7.0"}}, {"name": "rasd_fields", "content": {"version": "1.7.0"}},
                                               {"name": "search", "content": {"version": "10.4.5"}},
                                               {"name": "Splunk_TA_windows", "content": {"version": "9.0.1", "disabled": True}}]},
            "/services/data/indexes": {"entry": [{"name": "linux"}, {"name": "_internal"}, {"name": "rasd_alerts"}]}})
        out_file = self.tmp / "siem.json"
        code, out = self.run_command(splunk_lab.cmd_about, fake, timeout=5, terms="accepted for this run by the person who started it", out=str(out_file))
        self.assertEqual(code, 0, out)
        doc = json.loads(out_file.read_text(encoding="utf-8"))
        self.assertEqual((doc["product"], doc["version"], doc["licence"], doc["vendor_addons"], doc["indexes"]),
                         ("Splunk Enterprise", "10.4.5", "Trial", [], ["linux", "rasd_alerts"]))
        self.assertEqual(evidence.platform_line(evidence.siem_platform(out_file)),
                         "Splunk Enterprise 10.4.5 (build de9225ad9740), Trial licence; apps: rasd 1.7.0, rasd_fields 1.7.0; vendor add-ons: none")

    def test_a_search_splunk_refuses_fails_the_command(self):
        fake = FakeSplunk(saved=[{"name": "RASD - T1190_object_id_enumeration", "is_scheduled": "1", "cron_schedule": "*/1 * * * *"},
                                 {"name": "RASD Health - silent", "is_scheduled": "1", "cron_schedule": "7 * * * *"}])
        out_file = self.tmp / "siem-searches.json"
        code, out = self.run_command(splunk_lab.cmd_searches, fake, earliest="-60m", show="", rows=5, out=str(out_file))
        self.assertEqual(code, 0, out)
        self.assertIn("2/2 saved searches of the rasd app ran to the end", out)
        self.assertEqual([s["scheduled"] for s in json.loads(out_file.read_text(encoding="utf-8"))["searches"]], ["*/1 * * * *", "7 * * * *"])
        fake = FakeSplunk(saved=[{"name": "RASD - broken", "is_scheduled": "1", "cron_schedule": "*/5 * * * *"}])
        code, out = self.run_command(splunk_lab.cmd_searches, fake, earliest="-60m", show="", rows=5, out=str(out_file))
        self.assertEqual(code, 1)
        self.assertIn("Unknown search command", out)
        with self.assertRaises(splunk_lab.LabError):
            self.run_command(splunk_lab.cmd_searches, FakeSplunk(), earliest="-60m", show="", rows=5, out=str(out_file))


class WhatTheFirstRunsFound(unittest.TestCase):
    """Faults no synthetic test showed until the kit ran on a real host."""

    def test_the_exporter_reads_every_windows_event_the_detections_read(self):
        export = (ROOT / "red" / "Export-LabTelemetry.ps1").read_text(encoding="utf-8")
        ids = re.search(r"\[int\[\]\] \$EventId = @\(([^)]*)\)", export)
        channels = re.search(r"\[string\[\]\] \$LogName = @\(([^)]*)\)", export)
        self.assertTrue(ids and channels)
        exported = {int(x) for x in ids.group(1).split(",")}
        logs = {x.strip().strip("'") for x in channels.group(1).split(",")}
        self.assertEqual(logs, {SYSMON_CHANNEL, "Security", "System"})
        spl = MAPPINGS["spl"]["logsources"]
        wanted: dict[int, set[str]] = {}
        for need in health.needs(None):
            where = str(spl.get(need.source, ""))
            if need.source.startswith("windows/"):
                self.assertTrue(need.ids, f"{need.detection}: a Windows log rule names the event ids it reads")
                for eid in need.ids:
                    wanted.setdefault(int(eid), set()).add(need.detection)
            elif SYSMON_CHANNEL in where:
                code = re.search(r"EventCode=(\d+)", where)
                self.assertTrue(code, f"{need.source}: the Sysmon log source names its event id")
                wanted.setdefault(int(code.group(1)), set()).add(need.detection)
        self.assertGreaterEqual(len(wanted), 12)
        missing = {eid: sorted(dets) for eid, dets in wanted.items() if eid not in exported}
        self.assertEqual(missing, {}, "the default export leaves out an event a detection reads: its lab run can never fire")
        self.assertEqual(exported - set(wanted), set(), "the default export reads an event no detection reads")

    def test_the_dc_export_the_lab_run_asks_for_covers_the_domain_detections(self):
        runner = (ROOT / "red" / "lab" / "Invoke-RasdLabRun.ps1").read_text(encoding="utf-8")
        asked = re.search(r"On the lab DC: \.\\red\\Export-LabTelemetry\.ps1 -LogName Security -EventId ([\d,]+)", runner)
        self.assertTrue(asked)
        on_dc = {int(x) for x in asked.group(1).split(",")}
        kerberos_and_logon = {4625, 4768, 4769, 4771, 4776}
        read = {int(eid) for need in health.needs(None) if need.source == "windows/security" for eid in need.ids}
        self.assertEqual(on_dc, kerberos_and_logon & read)

    def test_the_readiness_check_reads_sysmon_output_as_utf16(self):
        readiness = (ROOT / "red" / "lab" / "Test-LabReadiness.ps1").read_text(encoding="utf-8")
        self.assertIn("(& $sysmonExe -c 2>&1 | Out-String) -replace \"`0\", ''", readiness,
                      "Sysmon writes UTF-16 to a pipe: read as it comes, 'ProcessAccess' is never found in it")

    def test_the_linux_sysmon_configuration_logs_every_process_and_nothing_else(self):
        import xml.etree.ElementTree as ET
        # this repository's own configuration file
        root = ET.parse(ROOT / "red" / "lab" / "sysmon-rasd-linux.xml").getroot()  # noqa: S314
        groups = {child.tag: child for rg in root.iter("RuleGroup") for child in rg}
        self.assertEqual(groups["ProcessCreate"].get("onmatch"), "exclude")
        self.assertEqual(len(groups["ProcessCreate"]), 0, "every process creation is logged")
        for tag, group in groups.items():
            if tag != "ProcessCreate":
                self.assertEqual((group.get("onmatch"), len(group)), ("include", 0), f"{tag}: nothing else is logged")

    def test_the_decoy_host_configuration_the_lab_mounts_is_the_one_the_rule_reads(self):
        import json
        settings = json.loads((ROOT / "deceive" / "opencanary" / "settings.json").read_text(encoding="utf-8"))
        self.assertTrue(settings.get("http.enabled"), "the decoy probe speaks HTTP to the decoy")
        handlers = settings["logger"]["kwargs"]["handlers"]
        self.assertTrue(any(h.get("filename") == DECOY_LOG for h in handlers.values()),
                        "the lab copies the decoy's records out of the file the decoy writes")
        self.assertIn(f"rasd-decoy:{DECOY_LOG}", WORKFLOW.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
