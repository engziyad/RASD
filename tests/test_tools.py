"""Tests for the RASD toolchain: fuzzer, replay, doctor, explain, linter, banner (python -m unittest)."""
import copy
import csv
import dataclasses
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile
from typing import ClassVar
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import banner  # noqa: E402
import chain  # noqa: E402
import convert  # noqa: E402
import links  # noqa: E402
import red  # noqa: E402
import tune  # noqa: E402
import doctor  # noqa: E402
import evidence  # noqa: E402
import fuzz  # noqa: E402
import parity  # noqa: E402
import prove  # noqa: E402
import replay  # noqa: E402
import splunk_app  # noqa: E402
import benchmark  # noqa: E402
import profiles  # noqa: E402
import datasets  # noqa: E402
import validate  # noqa: E402
from common import find_detection, load_detections, load_jsonl  # noqa: E402
from convert import logsource_key  # noqa: E402
from correlation import load_correlations  # noqa: E402
from sigma_engine import compile_rule, explain, matches  # noqa: E402


class Fuzzer(unittest.TestCase):
    def test_variants_change_the_event_and_are_unique(self):
        ev = {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "OriginalFileName": "PowerShell.EXE",
              "CommandLine": "powershell -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAHAAdQByAHAAbABlACcA", "EventID": 1}
        seen = set()
        for name, cat, new in fuzz.variants(ev):
            self.assertNotEqual(new, ev, name)
            self.assertIn(cat, ("semantic", "normalization", "plausible"))
            key = str(sorted(new.items()))
            self.assertNotIn(key, seen, name)
            seen.add(key)
        names = {n for n, _, _ in fuzz.variants(ev)}
        self.assertTrue({"ps_slash_prefix", "ps_param_encodedcommand", "binary_renamed"} <= names)

    def test_forward_slash_only_rewrites_file_paths(self):
        ev = {"CommandLine": 'schtasks /create /ru "NT AUTHORITY\\SYSTEM" /tr C:\\Windows\\svc.exe'}
        (_, _, new), = list(fuzz.t_forward_slash(ev))
        self.assertIn("NT AUTHORITY\\SYSTEM", new["CommandLine"])
        self.assertIn("C:/Windows/svc.exe", new["CommandLine"])

    def test_repository_has_no_unaccepted_bypasses(self):
        report = fuzz.fuzz()
        baseline = fuzz.load_baseline()
        for det, r in report.items():
            new = {b["id"] for b in r["bypasses"]} - set(baseline.get(det, []))
            self.assertFalse(new, f"{det}: {sorted(new)}")


class Replay(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        events = load_jsonl(ROOT / "samples" / "replay" / "lab-day.jsonl")
        cls.alerts, cls.stats = replay.replay(events, load_detections(), replay.load_assets(str(ROOT / "samples" / "replay" / "assets.csv")))
        cls.stories = replay.storylines(cls.alerts, 60)

    def test_routing(self):
        self.assertEqual(replay.route({"Channel": "Security", "EventID": 4769}), "windows/security")
        self.assertEqual(replay.route({"EventID": 1, "Image": "x"}), "process_creation")
        self.assertEqual(replay.route({"Channel": "System", "EventID": 7045}), "windows/system")
        self.assertIsNone(replay.route({"Channel": "Application", "EventID": 1000}))

    def test_the_record_time_wins_over_sysmon_utctime(self):
        """A public capture whose Sysmon UtcTime is 19 h away from TimeCreated: the Sysmon event
        and the Security event written beside it must stay side by side."""
        sysmon = {"EventID": 10, "UtcTime": "2023-08-16 04:53:46.060", "TimeCreated": "2023-08-15T09:53:46.119Z"}
        security = {"EventID": 4703, "TimeCreated": "2023-08-15T09:53:46.248Z"}
        self.assertEqual(replay.parse_time(sysmon).isoformat(), "2023-08-15T09:53:46.119000")
        self.assertLess((replay.parse_time(security) - replay.parse_time(sysmon)).total_seconds(), 1)
        self.assertEqual(replay.parse_time({"UtcTime": "2026-10-12 06:00:01.120"}).isoformat(), "2026-10-12T06:00:01.120000")
        self.assertEqual(replay.parse_time({"TimeCreated": "not a time", "UtcTime": "2026-10-12 06:00:01"}).hour, 6)

    def test_intrusion_storyline_is_reconstructed(self):
        self.assertEqual(len(self.stories), 1)
        s = self.stories[0]
        self.assertEqual(s["entity"], "WS07.corp.lab")
        self.assertGreaterEqual(s["techniques"], 6)
        self.assertGreaterEqual(s["score"], 70)
        self.assertTrue(s["pivots"], "lateral movement to SRV-FS01 should be linked")

    def test_kerberos_events_resolve_to_client_host(self):
        kerb = [a for a in self.alerts if a["technique"] == "T1558.003" and a["user"].startswith("lama")]
        self.assertTrue(kerb and all(a["entity"] == "WS07.corp.lab" for a in kerb))

    def test_benign_noise_does_not_alert(self):
        noisy = [a for a in self.alerts if a["technique"] in ("T1059.001", "T1003.001", "T1547.001")]
        self.assertTrue(all(a["entity"] == "WS07.corp.lab" for a in noisy), "SCCM, Defender and OneDrive must stay silent")


class ReplayCases(unittest.TestCase):
    """--case-dir: one folder per storyline, observed facts only, safe to open in a spreadsheet."""

    @classmethod
    def setUpClass(cls):
        sample = ROOT / "samples" / "replay" / "lab-day.jsonl"
        dets, corrs = load_detections(), load_correlations()
        alerts, _ = replay.replay(load_jsonl(sample), dets,
                                  replay.load_assets(str(ROOT / "samples" / "replay" / "assets.csv")), corrs=corrs)
        cls.stories = replay.storylines(alerts, 60)
        cls.rules = {**{d.id: d for d in dets}, **{c.id: c for c in corrs}}
        cls.tmp = Path(tempfile.mkdtemp())
        cls.cases = replay.write_cases(cls.tmp, cls.stories, cls.rules, [str(sample)])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_every_storyline_gets_its_four_files(self):
        self.assertEqual(len(self.cases), len(self.stories))
        for folder in self.cases:
            self.assertEqual(sorted(p.name for p in folder.iterdir()),
                             ["analyst_closure.md", "case_summary.md", "observables.csv", "timeline.json"])

    def test_timeline_keeps_each_alert_with_the_fields_its_rule_read(self):
        story, doc = self.stories[0], json.loads((self.cases[0] / "timeline.json").read_text(encoding="utf-8"))
        self.assertIsNone(doc["disposition"])
        self.assertEqual(len(doc["alerts"]), story["alerts"])
        self.assertEqual([a["time_utc"] for a in doc["alerts"]], sorted(a["time_utc"] for a in doc["alerts"]))
        self.assertEqual(doc["sources"][0]["sha256"], evidence.sha256(ROOT / "samples" / "replay" / "lab-day.jsonl"))
        self.assertTrue(doc["other_hosts"], "the pivot to SRV-FS01 is kept")
        for a in doc["alerts"]:
            if "event" in a:
                reads = validate.rule_fields(self.rules[a["rule"]].rule["detection"])
                self.assertTrue(reads & set(a["event"]), a["rule"])
                self.assertLessEqual(set(a["event"]), reads | set(replay.CONTEXT_FIELDS) | set(replay.USER_FIELDS))
            else:
                self.assertTrue(a["correlation"]["values"], a["rule"])
        spray = next(a for a in doc["alerts"] if a["rule"] == "T1110.003_password_spray_burst")
        self.assertEqual(spray["correlation"]["group"], {"IpAddress": "10.20.30.16"})

    def test_observables_list_what_the_alerts_carry_once_each(self):
        rows = list(csv.DictReader((self.cases[0] / "observables.csv").read_text(encoding="utf-8").splitlines()))
        seen = {(r["type"], r["value"]) for r in rows}
        self.assertEqual(len(seen), len(rows))
        for expected in (("host", "WS07.corp.lab"), ("address", "10.20.30.16"),
                         ("target_process", "C:\\Windows\\System32\\lsass.exe"), ("account", "amal")):
            self.assertIn(expected, seen)

    def test_the_analyst_sets_the_disposition_not_the_replay(self):
        summary = (self.cases[0] / "case_summary.md").read_text(encoding="utf-8")
        notes = (self.cases[0] / "analyst_closure.md").read_text(encoding="utf-8")
        self.assertIn("| Disposition | not set", summary)
        self.assertNotIn("True Positive", summary + notes)
        self.assertEqual(re.findall(r"(?m)^## (.+)$", notes),
                         ["Escalation to incident response", "Benign Positive", "False Positive"])
        self.assertIn("Containment:  none yet | <action taken, time UTC>", notes)

    def test_logged_text_cannot_break_the_files(self):
        hostile = '=HYPERLINK("x")|`whoami`|'
        self.assertEqual(replay._spreadsheet_safe(hostile), "'" + hostile)
        self.assertEqual(replay._spreadsheet_safe("cmd.exe /c"), "cmd.exe /c")
        cell = replay._code(hostile)
        self.assertTrue(cell.startswith("``") and cell.endswith("``"))
        self.assertEqual(re.findall(r"(?<!\\)\|", cell), [])
        self.assertEqual(replay._slug("..\\..\\Evil Host/x"), "evil-host-x")
        self.assertEqual(replay._cell("see https://203.0.113.9/x or www.example.org"),
                         "see https\\://203.0.113.9/x or www\\.example.org")

    def test_logged_values_are_shown_never_rendered(self):
        import copy
        story = copy.deepcopy(self.stories[0])
        story["entity"] = "![x](http://203.0.113.9/p.png)"
        for a in story["steps"]:
            a["user"], a["host"] = "[click](http://203.0.113.9/)", "<img src=x>"
            if a.get("_event"):
                a["_event"] = {**a["_event"], "User": "a\n```\n# injected"}
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        folder = replay.write_cases(tmp, [story], self.rules, [str(ROOT / "samples" / "replay" / "lab-day.jsonl")])[0]
        summary = (folder / "case_summary.md").read_text(encoding="utf-8")
        notes = (folder / "analyst_closure.md").read_text(encoding="utf-8")
        rendered = re.sub(r"(?ms)^(`{3,})text\n.*?^\1$", "", notes)      # code blocks show text as it is
        for text in (summary, rendered):
            self.assertNotRegex(text, r"(?<!\\)!\[x(?<!\\)\]\(")
            self.assertNotRegex(text, r"(?<!\\)\[click(?<!\\)\]\(")
            self.assertNotIn("<img", text)
        self.assertNotRegex(notes, r"(?m)^# injected")
        fences = re.findall(r"(?m)^(`{3,})(text)?$", notes)
        self.assertEqual(len(fences), 6)
        self.assertEqual(len({f for f, _ in fences}), 1, "every block opens and closes with the same fence")

    def test_cli_writes_the_cases_where_it_runs(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        shutil.copy(ROOT / "samples" / "replay" / "lab-day.jsonl", tmp / "export.jsonl")
        shutil.copy(ROOT / "samples" / "replay" / "assets.csv", tmp / "assets.csv")
        out = subprocess.run([sys.executable, str(ROOT / "rasd.py"), "replay", "export.jsonl", "--assets", "assets.csv",
                              "--case-dir", "cases"], cwd=tmp, capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertTrue((tmp / "cases" / "case-01-ws07.corp.lab" / "case_summary.md").exists())
        self.assertFalse((ROOT / "cases").exists())


class Doctor(unittest.TestCase):
    def test_ecs_export_gets_mapping_fixes(self):
        res = {r["detection"]: r for r in doctor.diagnose(load_jsonl(ROOT / "samples" / "doctor" / "ecs-export.jsonl"), load_detections())}
        r = res["T1059.001_powershell_encoded_command"]
        self.assertEqual(r["verdict"], "BLIND")
        self.assertIn("add 'CommandLine: [process.command_line]' for process_creation to a profile in profiles/ "
                      "and pass --profile", r["fixes"])

    def test_truncation_is_detected(self):
        res = {r["detection"]: r for r in doctor.diagnose(load_jsonl(ROOT / "samples" / "doctor" / "sysmon-truncated-export.jsonl"), load_detections())}
        r = res["T1059.001_powershell_encoded_command"]
        self.assertEqual(r["verdict"], "DEGRADED")
        self.assertTrue(any("1024 chars" in i for i in r["issues"]))


class Explain(unittest.TestCase):
    def test_trace_agrees_with_matches(self):
        for d in load_detections():
            for ev in d.tests("true_positive") + d.tests("true_negative"):
                self.assertEqual(explain(d.rule, ev)["matched"], matches(d.rule, ev))

    def test_trace_shows_matching_value(self):
        d = find_detection("T1218")
        t = explain(d.rule, d.tests("true_positive")[4])
        self.assertTrue(t["selections"]["susp_minidump"]["result"])


class Linter(unittest.TestCase):
    def test_detects_case_typos_unused_selections_and_bad_regex(self):
        rule = {"logsource": {"category": "process_creation"},
                "detection": {"sel": {"Commandline|contains": "abcd", "Image|re": "(x"}, "dead": {"Image": "x"}, "condition": "sel"}}
        errors, _ = validate.lint_rule(rule)
        joined = " | ".join(errors)
        self.assertIn("should be 'CommandLine'", joined)
        self.assertIn("'dead' is defined but never used", joined)
        self.assertIn("invalid regex", joined)

    def test_repository_rules_are_lint_clean(self):
        for d in load_detections():
            errors, _ = validate.lint_rule(d.rule)
            self.assertEqual(errors, [], d.id)


class Parity(unittest.TestCase):
    def test_deployed_queries_agree_with_the_engine(self):
        for det, r in parity.check().items():
            self.assertFalse(r["kql"] or r["spl"] or r["errors"], det)
            self.assertGreater(r["events"], 50, det)

    def test_spl_null_semantics_are_modelled(self):
        lookup = parity.make_lookup("spl")
        naive = parity.SPLParser("match('A', \"x\") AND NOT (match('B', \"y\"))", lookup).parse()
        safe = parity.SPLParser("match('A', \"x\") AND NOT (match(coalesce('B', \"\"), \"y\"))", lookup).parse()
        ev = {"A": "x"}                              # B missing
        self.assertIsNone(naive(ev))                 # NOT NULL -> NULL -> event dropped
        self.assertIs(safe(ev), True)

    def test_kql_strings_are_never_null(self):
        q = parity.KQLParser('A contains @"x" and not(B endswith @"y")', parity.make_lookup("kql")).parse()
        self.assertIs(q({"A": "xx"}), True)
        self.assertIs(q({"A": "xx", "B": "zy"}), False)

    def test_spl_escapes_are_strict(self):
        self.assertEqual(parity.SPLParser.literal(r'"C:\\Windows\\"'), "C:\\Windows\\")
        with self.assertRaises(parity.ParseError):      # a single backslash is ambiguous in SPL
            parity.SPLParser.literal(r'"C:\Windows"')


class Prove(unittest.TestCase):
    RULE: ClassVar[dict] = {"detection": {"sel": {"Image|endswith": ["\\a.exe", "\\b.exe"], "CommandLine|contains": "x"},
                          "filter": {"User": "SYSTEM"}, "condition": "sel and not filter"}}

    def test_mutant_operators(self):
        kinds = sorted(k for _i, k, _d, _m, _meta in prove.mutants(self.RULE))
        self.assertEqual(kinds, ["drop-field", "drop-field", "drop-operand", "drop-operand",
                                 "drop-value", "drop-value"])

    def test_weak_suite_leaves_survivors_and_strong_suite_kills_all(self):
        weak = [("tp", {"Image": "C:\\a.exe", "CommandLine": "x"}, True)]
        survivors = [d for _i, _k, d, m, _meta in prove.mutants(self.RULE) if prove.killed_by(m, weak) is None]
        self.assertIn("sel: drop Image|endswith value '\\\\b.exe'", survivors)
        strong = weak + [("tp2", {"Image": "C:\\b.exe", "CommandLine": "x"}, True),
                         ("tn1", {"Image": "C:\\a.exe", "CommandLine": "y"}, False),
                         ("tn2", {"Image": "C:\\c.exe", "CommandLine": "x"}, False),
                         ("tn3", {"Image": "C:\\a.exe", "CommandLine": "x", "User": "SYSTEM"}, False)]
        self.assertTrue(all(prove.killed_by(m, strong) for _i, _k, _d, m, _meta in prove.mutants(self.RULE)))

    def test_condition_round_trip_preserves_semantics(self):
        for d in load_detections():
            det = d.rule["detection"]
            rebuilt = {**d.rule, "detection": {**det, "condition": prove.render(prove.parse_condition(det["condition"], det))}}
            for ev in d.tests("true_positive") + d.tests("true_negative"):
                self.assertEqual(matches(rebuilt, ev), matches(d.rule, ev), d.id)

    def test_every_rule_part_is_proven(self):
        for det, r in prove.prove().items():
            self.assertEqual(r["survivors"], [], det)
            self.assertEqual(r["stale"], [], det)


class Evidence(unittest.TestCase):
    """A simulated lab run: two steps fire, one step's detection is missing from the export."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        enc = find_detection("T1059.001").tests("true_positive")[0]
        run = find_detection("T1547.001").tests("true_positive")[0]
        events = [{**enc, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "LAB-WS01.lab.local",
                   "UtcTime": "2026-10-12 06:00:01.400"},
                  {**run, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "LAB-WS01.lab.local",
                   "UtcTime": "2026-10-12 06:00:07.900"},
                  {**enc, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "OTHER-HOST",
                   "UtcTime": "2026-10-12 06:00:02.000"}]                     # another machine: ignored
        self.steps = [
            {"technique": "T1059.001", "name": "enc", "detections": ["T1059.001_powershell_encoded_command"],
             "status": "executed", "host": "LAB-WS01", "user": "LAB\\lama", "marker": "rasd_00000001",
             "utc_start": "2026-10-12T06:00:00.0000000Z", "utc_end": "2026-10-12T06:00:01.0000000Z"},
            {"technique": "T1547.001", "name": "run key", "detections": ["T1547.001_registry_run_key_persistence"],
             "status": "executed", "host": "LAB-WS01", "utc_start": "2026-10-12T06:00:07.0000000Z",
             "utc_end": "2026-10-12T06:00:07.5000000Z"},
            {"technique": "T1569.002", "name": "service", "detections": ["T1569.002_suspicious_service_installation"],
             "status": "skipped", "reason": "not admin"}]
        self.results = self.tmp / "emulation-results.json"
        self.results.write_text("\ufeff" + json.dumps(self.steps), encoding="utf-8")       # BOM like PowerShell 5.1
        self.logs = self.tmp / "lab-export.jsonl"
        self.logs.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
        self.events = events

    def test_hits_respect_window_and_host(self):
        det = find_detection("T1059.001")
        hits = evidence.find_hits(det, self.steps[0], self.events, grace=120)
        self.assertEqual(len(hits), 1)
        late = {**self.steps[0], "utc_start": "2026-10-12T07:00:00Z", "utc_end": "2026-10-12T07:00:01Z"}
        self.assertEqual(evidence.find_hits(det, late, self.events, grace=120), [])

    def test_rendered_evidence_passes_the_validator(self):
        det = find_detection("T1059.001")
        hits = evidence.find_hits(det, self.steps[0], self.events, grace=120)
        folder = self.tmp / det.id
        folder.mkdir()
        step = {**self.steps[0], "cleanup": "verified", "artifacts": [{"path": "C:/r/scriptblock.json", "sha256": "c" * 64}]}
        alerts = evidence.find_alerts(det, step, [
            {"search_name": f"RASD - {det.title}", "_time": "2026-10-12T09:00:40.000+0300", "host": "LAB-WS01"},
            {"search_name": "Some other rule", "_time": "2026-10-12T06:00:10Z", "host": "LAB-WS01"}], grace=900)
        self.assertEqual(len(alerts), 1)
        (folder / "evidence.md").write_text(evidence.render(det, step, hits, alerts, {"lab-export.jsonl": "a" * 64},
                                                            "emulation-results.json", "b" * 64,
                                                            {"alerts.csv": "d" * 64}), encoding="utf-8")
        self.assertEqual(validate.evidence_errors(folder), [])
        import score
        front = score.evidence_front(folder)
        self.assertEqual(evidence.operational_score(front), {"Lab evidence": 35, "SIEM result": 25,
                                                             "Detection latency": 15, "DFIR evidence": 15, "Cleanup": 10})
        self.assertEqual(front["operational_score"], 100)
        without_siem = {**front, "siem": None, "cleanup": "manual"}
        self.assertEqual(sum(evidence.operational_score(without_siem).values()), 50)
        (folder / "evidence.md").write_text("# looks like evidence\nfired!\n", encoding="utf-8")
        self.assertTrue(validate.evidence_errors(folder))

    def test_cli_dry_run(self):
        before = sorted((ROOT / "detect" / "detections").glob("*/evidence.md"))
        cmd = [sys.executable, str(ROOT / "tools" / "evidence.py"), "--results", str(self.results),
               "--logs", str(self.logs), "--dry-run"]
        ok = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
        self.assertIn("FIRED", ok.stdout)
        self.steps[1]["detections"].append("T1685.005_security_log_cleared")          # expected, never logged
        self.results.write_text(json.dumps(self.steps), encoding="utf-8")
        miss = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(miss.returncode, 1)
        self.assertIn("MISSED", miss.stdout)
        self.assertEqual(sorted((ROOT / "detect" / "detections").glob("*/evidence.md")), before, "--dry-run must not write")


class EvidenceBinding(unittest.TestCase):
    """An event is evidence of THIS run only: right host (or client IP for DC-logged events) and token."""

    def test_dc_logged_events_need_the_hosts_own_address(self):
        det = find_detection("T1558.003")
        tp = next(e for e in det.tests("true_positive") if e["_case"] == "red: kerberoasting emulation")
        step = {"host": "LAB-WS01", "host_ips": ["10.10.10.21", "fe80::1"], "marker": "rasd_0badf00d",
                "detections": [det.id], "utc_start": "2026-10-12T06:00:00Z", "utc_end": "2026-10-12T06:00:02Z"}
        mine = {**tp, "Computer": "DC01.lab.local", "IpAddress": "::ffff:10.10.10.21",
                "TimeCreated": "2026-10-12T06:00:01Z", "Channel": "Security"}
        other = {**mine, "IpAddress": "::ffff:10.10.10.99"}
        hits = evidence.find_hits(det, step, [mine, other], grace=60)
        self.assertEqual(len(hits), 1)
        self.assertIn("client address 10.10.10.21", hits[0][2])
        self.assertEqual(evidence.find_hits(det, {**step, "host_ips": []}, [mine], grace=60), [])
        local_service = {"EventID": 7045, "Computer": "FS01"}                  # 7045 is logged where it happens
        self.assertFalse(evidence.on_host(local_service, step)[0])

    def test_bind_token_rejects_events_this_run_did_not_create(self):
        det = find_detection("T1059.001")
        tp = next(e for e in det.tests("true_positive") if e["_case"] == "red: powershell_encoded_command emulation")
        base = {"host": "LAB-WS01", "detections": [det.id], "utc_start": "2026-10-12T06:00:00Z",
                "utc_end": "2026-10-12T06:00:02Z", "bind": {det.id: "base64-utf16le:Write-Output '{marker}'"}}
        ev = {**tp, "Computer": "LAB-WS01.lab.local", "Channel": "Microsoft-Windows-Sysmon/Operational",
              "UtcTime": "2026-10-12 06:00:01.000"}
        self.assertEqual(len(evidence.find_hits(det, {**base, "marker": "rasd_1a2b3c4d"}, [ev], grace=60)), 1)
        self.assertEqual(evidence.find_hits(det, {**base, "marker": "rasd_ffffffff"}, [ev], grace=60), [])
        self.assertEqual(evidence.find_hits(det, {**base, "marker": ""}, [ev], grace=60), [])      # no marker, no binding

    def test_netbios_name_binds_workstation_fields(self):
        step = {"host": "lab-workstation-0001", "host_netbios": "LAB-WORKSTATION", "host_ips": []}
        ntlm = {"EventID": 4776, "Computer": "DC01.lab.local", "Workstation": "LAB-WORKSTATION"}
        self.assertTrue(evidence.on_host(ntlm, step)[0])
        self.assertTrue(evidence.on_host({"EventID": 1, "Computer": "LAB-WORKSTATION-0001.lab.local"}, step)[0])
        self.assertFalse(evidence.on_host({**ntlm, "Workstation": "OTHER-WS"}, step)[0])

    def test_remote_step_binds_target_events_only_with_the_token(self):
        det = find_detection("T1021.006")
        tp = next(e for e in det.tests("true_positive") if e["_case"] == "red: winrm_access_validation emulation")
        marker = "rasd_1a2b3c4d"
        step = {"host": "LAB-WS01", "host_ips": ["10.10.10.21"], "targets": ["LAB-SRV01"], "marker": marker,
                "detections": [det.id], "bind": {det.id: "{marker}"},
                "utc_start": "2026-10-12T06:00:00Z", "utc_end": "2026-10-12T06:00:03Z"}
        on_target = {**tp, "CommandLine": f'cmd.exe /c "echo LAB-SRV01 {marker}"', "Computer": "LAB-SRV01.lab.local",
                     "Channel": "Microsoft-Windows-Sysmon/Operational", "UtcTime": "2026-10-12 06:00:01.500"}
        hits = evidence.find_hits(det, step, [on_target], grace=60)
        self.assertEqual(len(hits), 1)
        self.assertIn("the step's lab target", hits[0][2])
        self.assertIn(marker, hits[0][2])
        other_run = {**on_target, "CommandLine": 'cmd.exe /c "echo LAB-SRV01 rasd_ffffffff"'}
        self.assertEqual(evidence.find_hits(det, step, [other_run], grace=60), [])
        other_host = {**on_target, "Computer": "LAB-SRV02.lab.local"}
        self.assertEqual(evidence.find_hits(det, step, [other_host], grace=60), [])
        self.assertEqual(evidence.find_hits(det, {**step, "bind": {}}, [on_target], grace=60), [],
                         "a target event without a token is not bound to the run")
        self.assertEqual(evidence.find_hits(det, {**step, "targets": []}, [on_target], grace=60), [])
        alert = {"_time": "2026-10-12T06:04:00Z", "ss_name": f"RASD - {det.id}", "alert_host": "LAB-SRV01"}
        self.assertEqual(len(evidence.find_alerts(det, step, [alert], grace=900)), 1)
        self.assertEqual(evidence.find_alerts(det, {**step, "targets": []}, [alert], grace=900), [])

    def test_runner_records_the_target_of_a_remote_step(self):
        text = (ROOT / "red" / "Invoke-RasdEmulation.ps1").read_text(encoding="utf-8")
        self.assertRegex(text, r"targets = @\(if \(\(Get-Parameters \$s\) -contains 'Target' -and \$Target\) \{ \$Target \}\)")

    def test_red_check_requires_the_mirrored_event_to_carry_the_token(self):
        dets = {d.id: d for d in load_detections()}
        test = next(t for t in red.load_tests() if t["id"] == "service_creation")
        self.assertEqual(red.check_test(test, dets), [])
        test["steps"][0]["bind"] = {"T1569.002_suspicious_service_installation": "R{hex}"}
        self.assertTrue(any("bind token" in e for e in red.check_test(test, dets)))
        test["steps"][0]["bind"] = {"T1569.002_suspicious_service_installation": "static"}
        self.assertTrue(any("{marker} or {hex}" in e for e in red.check_test(test, dets)))


class EvidenceRun(unittest.TestCase):
    """--run: a lab run's zip or folder read as one run, and refused when it does not add up."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        enc = find_detection("T1059.001").tests("true_positive")[0]
        self.run_dir = self.tmp / "lab-20261012-060000"
        (self.run_dir / "powershell_encoded_command").mkdir(parents=True)
        (self.run_dir / "lab-export.jsonl").write_text(json.dumps(
            {**enc, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "LAB-WS01.lab.local",
             "UtcTime": "2026-10-12 06:00:01.400"}) + "\n", encoding="utf-8")
        artifact = self.run_dir / "powershell_encoded_command" / "scriptblock-4104.json"
        artifact.write_text('{"records": 1}', encoding="utf-8")
        steps = [{"technique": "T1059.001", "test": "powershell_encoded_command", "step": "enc", "name": "enc",
                  "detections": ["T1059.001_powershell_encoded_command"], "status": "executed", "host": "LAB-WS01",
                  "marker": "rasd_00000001", "utc_start": "2026-10-12T06:00:00.0000000Z",
                  "utc_end": "2026-10-12T06:00:01.0000000Z", "cleanup": "verified",
                  "artifacts": [{"path": "C:\\RASD\\red\\results\\lab-20261012-060000\\powershell_encoded_command\\"
                                         "scriptblock-4104.json", "sha256": evidence.sha256(artifact)}]}]
        (self.run_dir / "emulation-results.json").write_text("\ufeff" + json.dumps(steps), encoding="utf-8")
        (self.run_dir / "lab-readiness.json").write_text(json.dumps([{"check": "Sysmon", "result": "PASS"}]),
                                                         encoding="utf-8")
        files = [p for p in sorted(self.run_dir.rglob("*")) if p.is_file()]
        (self.run_dir / evidence.MANIFEST).write_text(json.dumps({"files": [
            {"path": str(p.relative_to(self.run_dir)).replace("/", "\\"), "sha256": evidence.sha256(p)} for p in files]}),
            encoding="utf-8")
        self.zip = self.pack()
        (self.tmp / "siem-alerts.csv").write_text(
            "_time,ss_name,host,alert_hosts,result_count,first_event,last_event\n"
            "2026-10-12T06:00:40.000+00:00,RASD - T1059.001_powershell_encoded_command,LAB-WS01,LAB-WS01,1,"
            "1791784801,1791784801\n", encoding="utf-8")
        (self.tmp / "dc-export.jsonl").write_text("", encoding="utf-8")

    def pack(self, extra=()):
        """The zip as Invoke-RasdLabRun.ps1 packs it (Windows PowerShell 5.1 writes backslashes), and its .sha256."""
        zp = self.tmp / f"{self.run_dir.name}.zip"
        with zipfile.ZipFile(zp, "w") as z:
            for p in sorted(self.run_dir.rglob("*")):
                if p.is_file():
                    z.write(p, str(p.relative_to(self.run_dir)).replace("/", "\\"))
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)        # the duplicate-member case is deliberate
                for name, data in extra:
                    z.writestr(name, data)
        (self.tmp / f"{zp.name}.sha256").write_text(f"{evidence.sha256(zp)}  {zp.name}\n", encoding="utf-8")
        return zp

    def discover(self, *names):
        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work, ignore_errors=True)
        return evidence.discover([self.tmp / n for n in names], work)

    def refused(self, pattern, *names, strict=False):
        with self.assertRaisesRegex(evidence.RunError, pattern):
            self.discover_strict(*names) if strict else self.discover(*names)

    def discover_strict(self, *names):
        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work, ignore_errors=True)
        return evidence.discover([self.tmp / n for n in names], work, strict=True)

    def sidecar(self, name):
        f = self.tmp / name
        (self.tmp / f"{name}.sha256").write_text(f"{evidence.sha256(f)}  {name}\n", encoding="utf-8")

    def test_strict_accepts_a_run_whose_every_input_is_hashed_and_records_it(self):
        self.sidecar("dc-export.jsonl")
        self.sidecar("siem-alerts.csv")
        run = self.discover_strict(self.zip.name, "dc-export.jsonl", "siem-alerts.csv")
        self.assertEqual(run.archive["verification"], "strict")
        det = find_detection("T1059.001")
        step = evidence.load_results(run.results)[0]
        lab = next(p for p in run.logs if p.name == "lab-export.jsonl")
        hits = evidence.find_hits(det, step, load_jsonl(lab), grace=120)
        body = evidence.render(det, step, hits, [], {"lab-export.jsonl": evidence.sha256(lab)}, run.results.name,
                               evidence.sha256(run.results), {}, manifest=run.manifest, run=run.archive)
        self.assertIn("verification: strict", body)
        self.assertIn("--strict --dry-run", body)
        folder = self.discover_strict(self.run_dir.name)
        self.assertEqual(folder.archive["verification"], "strict")

    def test_strict_refuses_a_zip_without_its_sha256(self):
        (self.tmp / f"{self.zip.name}.sha256").unlink()
        self.assertEqual(self.discover(self.zip.name).archive["sha256_file"], "absent")
        self.refused("--strict: no .*sha256 beside the zip", self.zip.name, strict=True)

    def test_strict_refuses_a_run_without_a_manifest(self):
        (self.run_dir / evidence.MANIFEST).unlink()
        self.assertIsNone(self.discover(self.run_dir.name).manifest)
        self.refused("--strict: the run has no", self.run_dir.name, strict=True)

    def test_strict_refuses_an_unlisted_file_in_a_folder_run(self):
        (self.run_dir / "notes.txt").write_text("added later", encoding="utf-8")
        self.discover(self.run_dir.name)                                  # standard mode reads it, marked as added
        self.refused("--strict: files in the run folder", self.run_dir.name, strict=True)

    def test_strict_refuses_a_missing_artifact_and_an_export_without_its_sha256(self):
        self.refused("--strict: .*dc-export.jsonl was given beside the run without", self.zip.name, "dc-export.jsonl",
                     strict=True)
        (self.run_dir / "powershell_encoded_command" / "scriptblock-4104.json").unlink()
        files = [p for p in sorted(self.run_dir.rglob("*")) if p.is_file() and p.name != evidence.MANIFEST]
        (self.run_dir / evidence.MANIFEST).write_text(json.dumps({"files": [
            {"path": str(p.relative_to(self.run_dir)), "sha256": evidence.sha256(p)} for p in files]}), encoding="utf-8")
        self.discover(self.run_dir.name)
        self.refused("--strict: artifacts the runner recorded are not in the run", self.run_dir.name, strict=True)

    def test_an_export_whose_sha256_file_differs_is_refused_in_every_mode(self):
        (self.tmp / "dc-export.jsonl.sha256").write_text("0" * 64 + "  dc-export.jsonl\n", encoding="utf-8")
        self.refused("dc-export.jsonl: SHA-256 .* differs", self.zip.name, "dc-export.jsonl")

    def test_zip_and_the_exports_beside_it_are_read_as_one_run(self):
        run = self.discover(self.zip.name, "dc-export.jsonl", "siem-alerts.csv")
        self.assertEqual(run.results.name, "emulation-results.json")
        self.assertEqual(sorted(p.name for p in run.logs), ["dc-export.jsonl", "lab-export.jsonl"])
        self.assertEqual([p.name for p in run.siem], ["siem-alerts.csv"])
        self.assertEqual(sorted(run.manifest["verified"]), ["emulation-results.json", "lab-export.jsonl"])
        self.assertEqual(run.archive, {"file": self.zip.name, "sha256": evidence.sha256(self.zip),
                                       "sha256_file": "matched", "beside": ["dc-export.jsonl", "siem-alerts.csv"],
                                       "verification": "standard"})
        folder = self.discover(self.run_dir.name)
        self.assertEqual([p.name for p in folder.logs], ["lab-export.jsonl"])
        self.assertIsNone(folder.archive)

    def test_evidence_records_the_zip_and_how_to_rerun_it(self):
        run = self.discover(self.zip.name, "siem-alerts.csv")
        det = find_detection("T1059.001")
        step = evidence.load_results(run.results)[0]
        hits = evidence.find_hits(det, step, load_jsonl(run.logs[0]), grace=120)
        alerts = evidence.find_alerts(det, step, evidence.load_siem(run.siem[0]), grace=900)
        body = evidence.render(det, step, hits, alerts, {"lab-export.jsonl": evidence.sha256(run.logs[0])},
                               run.results.name, evidence.sha256(run.results),
                               {"siem-alerts.csv": evidence.sha256(run.siem[0])}, manifest=run.manifest, run=run.archive)
        folder = self.tmp / det.id
        folder.mkdir()
        (folder / "evidence.md").write_text(body, encoding="utf-8")
        self.assertEqual(validate.evidence_errors(folder), [])
        import score
        front = score.evidence_front(folder)
        self.assertEqual(front["inputs"]["run"], {"file": self.zip.name, "sha256": evidence.sha256(self.zip),
                                                  "sha256_file": "matched"})
        self.assertEqual(front["operational_score"], 100)
        self.assertIn(f"rasd evidence --run {self.zip.name} siem-alerts.csv --dry-run", body)

    def test_a_zip_changed_after_packing_is_refused(self):
        self.zip.write_bytes(self.zip.read_bytes() + b"\0")
        self.refused(r"differs from .*\.sha256", self.zip.name)

    def test_an_export_edited_after_the_run_is_refused(self):
        (self.run_dir / "lab-export.jsonl").write_text('{"EventID": 1}\n', encoding="utf-8")
        self.refused("lab-export.jsonl: SHA-256 differs", self.run_dir.name)

    def test_a_swapped_artifact_is_refused_without_a_manifest_too(self):
        (self.run_dir / evidence.MANIFEST).unlink()
        (self.run_dir / "powershell_encoded_command" / "scriptblock-4104.json").write_text("{}", encoding="utf-8")
        self.refused("artifact .* differs", self.run_dir.name)

    def test_zip_members_cannot_leave_the_run_folder(self):
        for name in ("..\\..\\evil.jsonl", "/etc/evil.jsonl", "C:\\Windows\\evil.jsonl"):
            with self.subTest(name=name):
                self.pack(extra=[(name, "{}")])
                self.refused("outside the run folder", self.zip.name)

    def test_one_run_at_a_time_with_its_telemetry(self):
        shutil.copytree(self.run_dir, self.tmp / "other")
        self.refused("2 files named emulation-results.json", self.run_dir.name, "other")
        self.refused("no emulation-results.json", "siem-alerts.csv")
        (self.run_dir / "lab-export.jsonl").unlink()
        self.refused("lab-export.jsonl: listed in lab-run-manifest.json but missing", self.run_dir.name)
        (self.run_dir / evidence.MANIFEST).unlink()
        self.refused("no telemetry export", self.run_dir.name)

    def test_a_zip_holds_only_what_the_run_packed(self):
        self.pack(extra=[("planted.jsonl", '{"EventID": 1}\n')])
        self.refused("does not list: planted.jsonl", self.zip.name)
        self.pack(extra=[("lab-export.jsonl", '{"EventID": 1}\n')])
        self.refused("appears twice", self.zip.name)

    def test_files_added_to_a_run_folder_are_labelled_and_not_verified(self):
        (self.run_dir / "dc-export.jsonl").write_text("", encoding="utf-8")
        run = self.discover(self.run_dir.name)
        self.assertIn(("telemetry", "dc-export.jsonl", "added to the run folder, not in the manifest"), run.lines)
        self.assertNotIn("dc-export.jsonl", run.manifest["verified"])

    def test_a_zip_without_its_sha256_is_read_and_says_so(self):
        (self.tmp / f"{self.zip.name}.sha256").unlink()
        run = self.discover(self.zip.name)
        self.assertEqual(run.archive["sha256_file"], "absent")
        self.assertTrue(any(kind == "zip" and "not compared" in note for kind, _, note in run.lines))
        (self.tmp / f"{self.zip.name}.sha256").write_text(f"{evidence.sha256(self.zip)}  {self.zip.name}\n",
                                                           encoding="utf-16")      # re-saved by Windows PowerShell
        self.assertEqual(self.discover(self.zip.name).archive["sha256_file"], "matched")

    def test_exports_saved_as_utf16_are_read(self):
        alerts = (self.tmp / "siem-alerts.csv").read_text(encoding="utf-8")
        (self.tmp / "siem-alerts.csv").write_text(alerts, encoding="utf-16")          # re-saved by Windows PowerShell
        (self.tmp / "dc-export.jsonl").write_text('{"EventID": 4769, "Channel": "Security"}\n', encoding="utf-16")
        cmd = [sys.executable, str(ROOT / "rasd.py"), "evidence", "--run", self.zip.name, "dc-export.jsonl",
               "siem-alerts.csv", "--dry-run"]
        out = subprocess.run(cmd, cwd=self.tmp, capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("SIEM alert after 40s", out.stdout)

    def test_an_empty_manifest_vouches_for_nothing(self):
        (self.run_dir / evidence.MANIFEST).write_text('{"files": []}', encoding="utf-8")
        self.refused("lists no files", self.run_dir.name)

    def test_broken_inputs_are_refused_cleanly(self):
        (self.run_dir / evidence.MANIFEST).write_text("{not json", encoding="utf-8")
        self.refused("lab-run-manifest.json: not valid JSON", self.run_dir.name)
        (self.run_dir / evidence.MANIFEST).write_text("[]", encoding="utf-8")
        self.refused("expected an object with a files list", self.run_dir.name)
        (self.run_dir / evidence.MANIFEST).unlink()
        (self.run_dir / "emulation-results.json").write_text('["not a step"]', encoding="utf-8")
        self.refused("expected the runner's list of steps", self.run_dir.name)

    def test_artifacts_are_matched_by_their_path_under_the_test_folder(self):
        self.assertEqual(evidence.artifact_key("C:\\RASD\\red\\results\\lab-1\\run_key\\sub\\x.json", {"run_key"}),
                         "run_key/sub/x.json")
        self.assertEqual(evidence.artifact_key("/home/lab/red/results/1/cron/x.txt", {"cron", "results"}), "cron/x.txt")

    def test_alert_exports_are_told_apart_from_telemetry(self):
        def write(name, text):
            (self.tmp / name).write_text(text, encoding="utf-8")
            return self.tmp / name
        self.assertEqual(evidence.export_kind(self.tmp / "siem-alerts.csv"), "siem")
        self.assertEqual(evidence.export_kind(write("alerts.jsonl", '{"_time": "t", "ss_name": "RASD - x"}\n')), "siem")
        self.assertEqual(evidence.export_kind(write("sentinel.json", '[{"TimeGenerated": "t", "AlertName": "x"}]')), "siem")
        self.assertEqual(evidence.export_kind(self.run_dir / "lab-export.jsonl"), "telemetry")
        self.assertEqual(evidence.export_kind(self.tmp / "dc-export.jsonl"), "telemetry")
        self.assertIsNone(evidence.export_kind(self.run_dir / "lab-readiness.json"))
        self.assertIsNone(evidence.export_kind(write("notes.csv", "a,b\n1,2\n")))

    def test_cli_reads_the_run_from_the_folder_it_runs_in(self):
        cmd = [sys.executable, str(ROOT / "rasd.py"), "evidence", "--run", self.zip.name, "dc-export.jsonl",
               "siem-alerts.csv", "--dry-run"]
        out = subprocess.run(cmd, cwd=self.tmp, capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("FIRED", out.stdout)
        self.assertIn(f"matches {self.zip.name}.sha256", out.stdout)
        both = subprocess.run([*cmd, "--results", "x.json"], cwd=self.tmp, capture_output=True, text=True)
        self.assertEqual(both.returncode, 2)
        self.assertIn("--run finds", both.stderr)


class SplunkApp(unittest.TestCase):
    """The lab's Splunk alerts are the tested rules, and their export feeds rasd evidence."""

    @classmethod
    def setUpClass(cls):
        import configparser
        cls.files = splunk_app.render(load_detections(), load_correlations())
        cls.saved = configparser.RawConfigParser(delimiters=("=",), comment_prefixes=("#",), interpolation=None,
                                                 strict=True)
        cls.saved.optionxform = str
        cls.saved.read_string(cls.files[splunk_app.OUT / "rasd" / "default" / "savedsearches.conf"])

    def test_one_scheduled_alert_per_detection_running_the_proven_query(self):
        for det in load_detections():
            name = f"RASD - {det.id}"
            self.assertIn(name, self.saved.sections())
            sec = self.saved[name]
            base = splunk_app.one_line(convert.convert(det.rule, "spl"))
            self.assertTrue(sec["search"].startswith(base + " | eval rasd_detection="), det.id)
            self.assertIn("| stats count as result_count", sec["search"])
            self.assertEqual(sec["enableSched"], "1")
            self.assertEqual((sec["counttype"], sec["relation"], sec["quantity"]), ("number of events", "greater than", "0"))
            sev = (det.contract.get("detection_logic") or {}).get("severity", det.level)
            self.assertEqual(sec["alert.severity"], str(splunk_app.SEVERITY[sev]))
        self.assertIn("index=rasd_alerts", self.saved["RASD - alert export"]["search"])
        self.assertIn("index=_audit action=alert_fired", self.saved["RASD - alert export (audit)"]["search"])
        self.assertIn("sourcetype=scheduler", self.saved["RASD - alert export (scheduler)"]["search"])
        for det in load_detections():
            sec = self.saved[f"RASD - {det.id}"]
            self.assertEqual(sec["action.logevent"], "1")
            self.assertEqual(sec["action.logevent.param.index"], "rasd_alerts")
            self.assertIn(f'detection="{det.id}"', sec["action.logevent.param.event"])
            self.assertIn('alert_host="$result.alert_host$"', sec["action.logevent.param.event"])
            self.assertIn('alert_hosts="$result.alert_hosts$"', sec["action.logevent.param.event"])
            self.assertIn('first_event="$result.first_event$"', sec["action.logevent.param.event"])

    def test_one_alert_per_correlation_runs_once_per_window_over_that_window(self):
        from correlation import to_spl
        corrs = load_correlations()
        self.assertTrue(corrs)
        for corr in corrs:
            sec = self.saved[f"RASD - {corr.id}"]
            span = corr.params.timespan
            self.assertTrue(sec["search"].startswith(splunk_app.one_line(to_spl(corr)) + " | addinfo | where "), corr.id)
            self.assertIn(f"window_start>=info_min_time AND window_start+{span}<=info_max_time AND "
                          f"window_start+{span}>info_max_time-{span} | eval rasd_detection=", sec["search"])
            self.assertEqual(sec["alert.digest_mode"], "0")            # one alert per window and group
            self.assertEqual(sec["realtime_schedule"], "0")            # a skipped run is caught up
            minutes, lag = span // 60, splunk_app.CORRELATION_LAG
            self.assertEqual(sec["dispatch.earliest_time"], f"-{2 * minutes + lag}m@m")
            self.assertEqual(sec["dispatch.latest_time"], f"-{lag}m@m")
            self.assertIn(f'detection="{corr.id}"', sec["action.logevent.param.event"])
            self.assertIn('alert_host="$result.alert_host$"', sec["action.logevent.param.event"])
        self.assertEqual(splunk_app.correlation_schedule(600), ("*/10 * * * *", "-23m@m", "-3m@m"))
        self.assertEqual(splunk_app.correlation_schedule(3600), ("0 * * * *", "-123m@m", "-3m@m"))
        self.assertEqual(splunk_app.correlation_schedule(7200), ("0 */2 * * *", "-243m@m", "-3m@m"))
        self.assertEqual(splunk_app.correlation_schedule(86400), ("0 0 * * *", "-2883m@m", "-3m@m"))
        for bad in (30, 480, 5400):
            with self.assertRaises(ValueError):
                splunk_app.correlation_schedule(bad)

    def test_correlation_runs_tile_time_in_any_time_zone(self):
        """Whatever the phase of the cron runs (a search head at UTC+3, +5:30, +5:45 ...), the
        window filter keeps each window in exactly one run, whole."""
        for span in (600, 3600, 7200):
            lag = splunk_app.CORRELATION_LAG * 60
            for phase in (0, 60, 1800, 2700, 3600 * 3 + 1800):           # cron fires at local times
                runs = [phase + k * span for k in range(1, 40)]
                seen = {}
                for t in runs:
                    lo, hi = t - lag - 2 * span, t - lag                 # info_min_time, info_max_time
                    for w in range((lo // span) * span, hi, span):       # windows in the range
                        if w >= lo and w + span <= hi and w + span > hi - span:
                            seen[w] = seen.get(w, 0) + 1
                inner = [w for w in seen if runs[2] < w < runs[-3]]
                self.assertTrue(inner)
                self.assertTrue(all(seen[w] == 1 for w in inner), (span, phase))
                self.assertEqual(sorted(inner), list(range(min(inner), max(inner) + 1, span)), (span, phase))

    def test_every_conf_file_parses_and_the_app_is_committed(self):
        import configparser
        for path, body in self.files.items():
            if path.suffix == ".conf":
                c = configparser.RawConfigParser(delimiters=("=",), comment_prefixes=("#",), interpolation=None, strict=True)
                c.read_string(body)
                self.assertTrue(c.sections(), path.name)
            self.assertEqual(path.read_text(encoding="utf-8"), body, f"{path} is stale - run: rasd build")

    def test_provider_name_extraction_matches_windows_xml(self):
        import re as _re
        props = self.files[splunk_app.OUT / "rasd" / "default" / "props.conf"]
        pcre = _re.search(r"EXTRACT-rasd_provider_name = (.+)", props).group(1)
        rx = _re.compile(pcre.replace("(?<", "(?P<"))
        xml = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Service Control Manager' Guid='{555908d1-a6d7-4695-8e1e-26931d2012f4}' EventSourceName='Service Control Manager'/><EventID Qualifiers='16384'>7045</EventID>"
        self.assertEqual(rx.search(xml).group("Provider_Name"), "Service Control Manager")

    def test_indexes_cover_every_index_the_queries_read(self):
        conf = self.files[splunk_app.OUT / "rasd" / "default" / "indexes.conf"]
        declared = set(re.findall(r"^\[([A-Za-z0-9_]+)\]$", conf, re.M))
        searches = " ".join(self.saved.get(s, "search") for s in self.saved.sections())
        self.assertLessEqual(set(re.findall(r"\bindex=([A-Za-z0-9_]+)", searches)) - {"_audit", "_internal"}, declared)
        self.assertLessEqual({"linux", "web", splunk_app.ALERT_INDEX}, declared)

    def test_correlation_alert_host_is_the_spl_column(self):
        for corr in load_correlations():
            search = self.saved.get(f"{splunk_app.ALERT_PREFIX}{corr.id}", "search")
            column = (splunk_app.MAPPINGS["spl"].get("fields") or {}).get(corr.params.group_by[0], corr.params.group_by[0])
            self.assertIn(f"alert_host='{column}'", search, corr.id)
            self.assertRegex(search, rf"stats .* by window_start {re.escape(column)}\b", corr.id)

    def test_linux_forwarder_sends_sysmon_and_the_access_log_to_the_queried_indexes(self):
        inputs = self.files[splunk_app.OUT / "rasd_forwarder_linux" / "default" / "inputs.conf"]
        self.assertRegex(inputs, r"\[journald://sysmon\]\nindex = linux\n")
        self.assertRegex(inputs, r"index = web\nsourcetype = access_combined\n")

    def test_alert_export_rows_are_matched_by_evidence(self):
        det = find_detection("T1059.001")
        step = {"host": "LAB-WS01", "utc_start": "2026-10-12T06:00:00Z", "utc_end": "2026-10-12T06:00:02Z"}
        rows = [{"_time": "2026-10-12T09:04:10.000+03:00", "ss_name": f"RASD - {det.id}", "severity": "4"},
                {"_time": "2026-10-12T09:04:10.000+03:00", "ss_name": "RASD - T1218.011_rundll32_suspicious_execution",
                 "severity": "5"}]
        alerts = evidence.find_alerts(det, step, rows, grace=900)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(round((alerts[0][0] - evidence.step_time(step, "utc_start")).total_seconds()), 250)
        logged = [{"_time": "2026-10-12T06:03:00.000+00:00", "ss_name": f"RASD - {det.id}", "host": "LAB-WS01"},
                  {"_time": "2026-10-12T06:03:00.000+00:00", "ss_name": f"RASD - {det.id}", "host": "OTHER-WS"},
                  {"_time": "2026-10-12T06:03:00.000+00:00", "ss_name": f"RASD - {det.id}", "alert_host": "LAB-WS01"}]
        self.assertEqual([evidence.first(a, evidence.SIEM_HOST) for _, a in evidence.find_alerts(det, step, logged, grace=900)], ["LAB-WS01", "LAB-WS01"])


    def test_alerts_summarising_other_events_are_not_this_runs_alerts(self):
        det = find_detection("T1059.001")
        step = {"host": "LAB-WS01", "utc_start": "2026-10-12T06:00:00Z", "utc_end": "2026-10-12T06:00:02Z"}
        name = f"RASD - {det.id}"
        mine = {"_time": "2026-10-12T06:04:00Z", "ss_name": name, "alert_host": "LAB-WS01",
                "first_event": "1791784801", "last_event": "1791784801"}          # 2026-10-12 06:00:01 UTC
        older = {**mine, "first_event": "1791777600", "last_event": "1791778200"}   # 04:00 - 04:10 UTC
        self.assertEqual(len(evidence.find_alerts(det, step, [mine], grace=900)), 1)
        self.assertEqual(evidence.find_alerts(det, step, [older], grace=900), [])

    def test_manifest_refuses_inputs_from_another_run(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        results, export = tmp / "emulation-results.json", tmp / "lab-export.jsonl"
        results.write_text("[]", encoding="utf-8")
        export.write_text("{}\n", encoding="utf-8")
        manifest = tmp / evidence.MANIFEST
        manifest.write_text(json.dumps({"files": [
            {"path": "emulation-results.json", "sha256": evidence.sha256(results)},
            {"path": "lab-export.jsonl", "sha256": evidence.sha256(export)}]}), encoding="utf-8")
        info, errors = evidence.verify_manifest(manifest, [results, export])
        self.assertEqual((errors, sorted(info["verified"])), ([], ["emulation-results.json", "lab-export.jsonl"]))
        export.write_text('{"edited": true}\n', encoding="utf-8")
        self.assertTrue(evidence.verify_manifest(manifest, [results, export])[1])

    def test_lab_powershell_scripts_are_hardened_for_large_runs(self):
        export = (ROOT / "red" / "Export-LabTelemetry.ps1").read_text(encoding="utf-8")
        readiness = (ROOT / "red" / "lab" / "Test-LabReadiness.ps1").read_text(encoding="utf-8")
        runner = (ROOT / "red" / "lab" / "Invoke-RasdLabRun.ps1").read_text(encoding="utf-8")
        self.assertIn("[System.IO.StreamWriter]::new", export)
        self.assertNotIn("$lines = [System.Collections.Generic.List[string]]::new()", export)
        self.assertIn("EventRecordID", export)
        self.assertIn("Resolve-ExecutablePath", readiness)
        self.assertIn("ProcessCreationIncludeCmdLine_Enabled", readiness)
        self.assertIn("[switch] $FixReadiness", runner)
        self.assertIn("lab-run-manifest.json", runner)

    def test_lab_sysmon_config_logs_what_the_rules_read(self):
        import xml.etree.ElementTree as ET
        # this repository's own configuration file
        root = ET.parse(ROOT / "red" / "lab" / "sysmon-rasd.xml").getroot()  # noqa: S314
        groups = {child.tag: child for rg in root.iter("RuleGroup") for child in rg}
        self.assertEqual(groups["ProcessCreate"].get("onmatch"), "exclude")              # every process
        self.assertEqual(len(groups["ProcessCreate"]), 0)
        self.assertTrue(any(f.text.endswith("lsass.exe") for f in groups["ProcessAccess"]))
        self.assertTrue(any("CurrentVersion\\Run" in f.text for f in groups["RegistryEvent"]))


class AttackV19(unittest.TestCase):
    def test_legacy_v18_ids_and_techniques_resolve_to_the_v19_detections(self):
        self.assertEqual(find_detection("T1070.001_event_log_clearing").id, "T1685.005_event_log_clearing")
        self.assertEqual(sorted(d.id for d in load_detections("T1070.001")),
                         ["T1685.005_event_log_clearing", "T1685.005_security_log_cleared", "T1685.005_system_log_cleared"])
        import run_tests
        self.assertTrue(run_tests.run("T1070.001"))
        self.assertEqual(sorted(parity.check("T1070.001")), sorted(d.id for d in load_detections("T1070.001")))

    def test_generated_queries_and_saved_searches_name_the_v18_technique(self):
        rule = find_detection("T1685.005_security_log_cleared").rule
        for backend in ("kql",):
            self.assertIn("ATT&CK v19.2 T1685.005, v18 T1070.001", convert.convert(rule, backend).splitlines()[0])
        self.assertEqual(convert.legacy_note(find_detection("T1059.001").rule), "")
        conf = splunk_app.saved_searches(load_detections())
        self.assertIn("(T1685.005; ATT&CK v18: T1070.001)", conf)

    def test_navigator_layer_is_v19_and_records_the_v18_id(self):
        layer = json.loads((ROOT / "detect" / "coverage" / "attack_navigator_layer.json").read_text(encoding="utf-8"))
        self.assertEqual(layer["versions"]["attack"], "19")
        t = next(x for x in layer["techniques"] if x["techniqueID"] == "T1685.005")
        self.assertIn({"name": "ATT&CK v18", "value": "T1070.001"}, t["metadata"])

    def test_no_file_names_an_id_v19_revoked_and_red_tests_use_v19_names(self):
        from common import ATTACK_ALIASES, attack_aliases
        revoked = attack_aliases()["revoked"]
        self.assertEqual(revoked.get("T1562.008"), "T1685.002")
        git = shutil.which("git")
        out = subprocess.run([git, "ls-files", "-z"], cwd=ROOT, capture_output=True, text=True) if git else None
        if out is None or out.returncode or not out.stdout:
            self.skipTest("needs git and a git checkout")
        retired = re.compile(r"\b(" + "|".join(map(re.escape, sorted(revoked, key=len, reverse=True))) + r")\b")
        skip = {ATTACK_ALIASES.relative_to(ROOT).as_posix(), "tests/test_tools.py"}
        found = []
        for name in out.stdout.split("\0"):
            if not name or name in skip or name.startswith("datasets/"):     # dataset paths are the sources' own names
                continue
            try:
                text = (ROOT / name).read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            found += [f"{name}: {m.group(1)} (now {revoked[m.group(1)]})" for m in retired.finditer(text)]
        self.assertEqual(found, [])
        mitre = {t["id"]: t["mitre"] for t in red.load_tests() if t.get("mitre")}
        self.assertEqual(mitre["event_log_clearing"]["technique_name"], "Disable or Modify Tools: Clear Windows Event Logs")
        self.assertEqual(mitre["event_log_clearing"]["tactics"], ["defense-impairment"])
        self.assertEqual(mitre["rundll32_execution"]["tactics"], ["stealth"])
        self.assertEqual(mitre["powershell_encoded_command"]["tactics"], ["execution"])   # T1027 stealth is a related technique


class PublicDatasets(unittest.TestCase):
    NS = "http://schemas.microsoft.com/win/2004/08/events/event"

    def test_catalog_is_valid_and_accounts_for_every_detection(self):
        cat = datasets.load_catalog()
        self.assertEqual(cat.errors, [])
        ids = set(datasets.known_ids())
        accounted = {r for ds in cat.datasets for r in [*ds.expect, *ds.quiet]} | set(cat.gaps)
        self.assertEqual(ids - accounted, set())
        for ds in cat.datasets:
            self.assertTrue(ds.link.startswith(ds.source.repo + "/blob/" + ds.source.commit + "/"), ds.id)
            self.assertNotIn(" ", ds.link, ds.id)

    def test_repository_results_are_current_and_extracts_fire_as_recorded(self):
        self.assertEqual(datasets.check(), [])

    def test_xml_reader_keeps_the_system_channel_and_reads_linux_events(self):
        win = (f"<Event xmlns='{self.NS}'><System><Provider Name='Microsoft-Windows-Eventlog'/><EventID>104</EventID>"
               "<TimeCreated SystemTime='2026-10-12T10:00:00.1234567Z'/><Channel>System</Channel><Computer>WS1</Computer></System>"
               "<UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>"
               "<SubjectUserName>bob</SubjectUserName><Channel>Security</Channel></LogFileCleared></UserData></Event>")
        ev = datasets.xml_event(win)
        self.assertEqual((ev["Channel"], ev["EventID"], ev["Provider_Name"]), ("System", 104, "Microsoft-Windows-Eventlog"))
        self.assertEqual(ev["Channel_Cleared"], "Security")
        self.assertEqual(ev["SubjectUserName"], "bob")
        linux = ("<Event><System><Provider Name='Linux-Sysmon'/><EventID>1</EventID><Channel>Linux-Sysmon/Operational</Channel>"
                 "</System><EventData><Data Name='Image'>/tmp/x</Data><Data Name='CommandLine'>./x</Data></EventData></Event>")
        ev = datasets.xml_event(linux)
        self.assertEqual(replay.route(ev), "linux/process_creation")
        self.assertIsNone(datasets.xml_event("<Event><System>"))
        loose = ("<Event><System><EventID>1</EventID><Channel>Microsoft-Windows-Sysmon/Operational</Channel></System><EventData>"
                 "<Data Name='CommandLine'>powershell -c \"iex $d 2>&1; <# note #> &amp; x\"</Data></EventData></Event>")
        self.assertEqual(datasets.xml_event(loose)["CommandLine"], 'powershell -c "iex $d 2>&1; <# note #> & x"')

    CLASSIC = (
        "02/11/2022 07:29:07 PM\nLogName=Security\nSourceName=Microsoft Windows security auditing.\nEventCode=4769\n"
        "EventType=0\nComputerName=dc1.lab.example\nTaskCategory=Kerberos Service Ticket Operations\nRecordNumber=4711\n"
        "Keywords=Audit Success\nMessage=A Kerberos service ticket was requested.\n\nAccount Information:\n"
        "\tAccount Name:\t\tanalyst@LAB.EXAMPLE\n\tAccount Domain:\t\tLAB.EXAMPLE\n\nService Information:\n"
        "\tService Name:\t\tsvc_sql\n\tService ID:\t\tLAB\\svc_sql\n\nNetwork Information:\n\tClient Address:\t\t::ffff:10.0.0.21\n"
        "\tClient Port:\t\t50121\n\nAdditional Information:\n\tTicket Options:\t\t0x40810000\n\tTicket Encryption Type:\t0x17\n"
        "\tFailure Code:\t\t0x0\n\tTransited Services:\t-\n\nTicket options, encryption types, and failure codes are defined in RFC 4120.\n"
        "02/11/2022 07:30:01 PM\nLogName=System\nSourceName=Microsoft-Windows-Service Control Manager\nEventCode=7045\n"
        "ComputerName=ws1.lab.example\nRecordNumber=812\nMessage=A service was installed in the system.\n\n"
        "Service Name:  PrintAssist\nService File Name:  cmd.exe /c C:\\Users\\Public\\a.bat\nService Type:  user mode service\n"
        "Service Start Type:  demand start\nService Account:  LocalSystem\n"
        "02/11/2022 07:31:00 PM\nLogName=Security\nSourceName=Microsoft Windows security auditing.\nEventCode=4688\n"
        "ComputerName=ws1.lab.example\nRecordNumber=900\nMessage=A new process has been created.\n\nCreator Subject:\n"
        "\tSecurity ID:\t\tLAB\\analyst\n\tAccount Name:\t\tanalyst\n\tAccount Domain:\t\tLAB\n\nTarget Subject:\n"
        "\tAccount Name:\t\t-\n\nProcess Information:\n\tNew Process Name:\tC:\\Windows\\System32\\rundll32.exe\n"
        "\tCreator Process Name:\tC:\\Windows\\System32\\cmd.exe\n"
        "\tProcess Command Line:\trundll32.exe C:\\Users\\Public\\a.dll,Start\n\nToken Elevation Type indicates the type of token.\n"
        "02/11/2022 07:32:00 PM\nLogName=System\nSourceName=Microsoft-Windows-Eventlog\nEventCode=104\nComputerName=ws1.lab.example\n"
        "RecordNumber=901\nMessage=The System log file was cleared.\n")

    def test_classic_reader_names_fields_like_the_xml_reader(self):
        rows = list(datasets.text_records("windows-classic", self.CLASSIC))
        self.assertEqual([r[0] for r in rows], [1, 2, 3, 4])
        kerb, svc, proc, cleared = (r[2] for r in rows)
        self.assertEqual((kerb["Channel"], kerb["EventID"], kerb["EventRecordID"], kerb["Computer"], kerb["TimeCreated"]),
                         ("Security", 4769, 4711, "dc1.lab.example", "2022-02-11T19:29:07Z"))
        self.assertEqual((kerb["TargetUserName"], kerb["ServiceName"], kerb["IpAddress"], kerb["TicketEncryptionType"],
                          kerb["Status"], kerb["Provider_Name"]),
                         ("analyst@LAB.EXAMPLE", "svc_sql", "::ffff:10.0.0.21", "0x17", "0x0", "Microsoft-Windows-Security-Auditing"))
        self.assertEqual((svc["Provider_Name"], svc["ServiceName"], svc["ImagePath"], svc["StartType"]),
                         ("Service Control Manager", "PrintAssist", "cmd.exe /c C:\\Users\\Public\\a.bat", "demand start"))
        self.assertEqual((proc["SubjectUserName"], proc["TargetUserName"], proc["NewProcessName"], proc["ParentProcessName"]),
                         ("analyst", "-", "C:\\Windows\\System32\\rundll32.exe", "C:\\Windows\\System32\\cmd.exe"))
        self.assertEqual((cleared["EventID"], cleared["Provider_Name"], cleared["Channel_Cleared"]), (104, "Microsoft-Windows-Eventlog", "System"))
        plan = datasets.build_plan()
        fired = {r[2]["EventID"]: datasets.verdicts(profiles.normalize(r[2], profiles.load("windows-security-4688")), plan)[1]
                 for r in rows}
        self.assertIn("T1558.003_kerberoasting_rc4_tgs", fired[4769])
        self.assertIn("T1569.002_suspicious_service_installation", fired[7045])
        self.assertIn("T1218.011_rundll32_suspicious_execution", fired[4688])
        self.assertTrue(any(r.endswith("_system_log_cleared") for r in fired[104]))
        self.assertIsNone(datasets.classic_event("not an event"))
        sysmon = (f"<Event xmlns='{self.NS}'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>13</EventID>"
                  "<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>ws1</Computer></System><EventData>"
                  "<Data Name='TargetObject'>HKU\\S-1-5-21\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\NextRun</Data>"
                  "<Data Name='Details'>powershell.exe -w hidden -c iwr</Data></EventData></Event>")
        script = self.CLASSIC.replace("\tProcess Command Line:\trundll32.exe C:\\Users\\Public\\a.dll,Start\n",
                                      "\tProcess Command Line:\tpowershell.exe & {$a = New-ScheduledTaskAction -Execute calc.exe\n"
                                      "Register-ScheduledTask T -Action $a}\n", 1)
        multi = [r[2] for r in datasets.text_records("windows-classic", script)][2]
        self.assertEqual(multi["CommandLine"], "powershell.exe & {$a = New-ScheduledTaskAction -Execute calc.exe\n"
                                               "Register-ScheduledTask T -Action $a}")
        mixed = self.CLASSIC.replace("02/11/2022 07:30:01 PM", sysmon + "\n02/11/2022 07:30:01 PM", 1)
        kinds = [r[2].get("Channel") for r in datasets.text_records("windows-classic", mixed)]
        self.assertEqual(kinds, ["Security", "Microsoft-Windows-Sysmon/Operational", "System", "Security", "System"])

    def test_classic_reader_keeps_a_whole_command_line_and_names_more_events(self):
        """A 4688 command line runs to the paragraph after it, blank lines included; a cleared log's name can
        have spaces; a label left empty is a label, not a section; 4776, 4648, 4689 and 4698 get XML names."""
        head = "02/11/2022 07:3{n}:00 PM\nLogName={log}\nSourceName={src}\nEventCode={code}\nComputerName=ws1\nRecordNumber=9{n}\n"
        sec = "Microsoft Windows security auditing."
        text = (head.format(n=1, log="Security", src=sec, code=4688)
                + "Message=A new process has been created.\n\nProcess Information:\n\tNew Process Name:\tC:\\Windows\\powershell.exe\n"
                "\tProcess Command Line:\tpowershell.exe & {$a = 1\n\nforeach ($x in $a) {\n    Write-Host: $x}}\n\n"
                "Token Elevation Type indicates the type of token that was assigned.\n\nType 1 is a full token.\n"
                + head.format(n=2, log="System", src="Microsoft-Windows-Eventlog", code=104)
                + "Message=The Windows PowerShell log file was cleared.\n"
                + head.format(n=3, log="System", src="Microsoft-Windows-Service Control Manager", code=7045)
                + "Message=A service was installed in the system.\n\nService Name:  Upd\nService File Name:  C:\\Temp\\u.exe\n"
                "Service Type:  user mode service\nService Start Type:  demand start\nService Account:\n"
                + head.format(n=4, log="Security", src=sec, code=4776)
                + "Message=The computer attempted to validate the credentials for an account.\n\n"
                "Authentication Package:\tMICROSOFT_AUTHENTICATION_PACKAGE_V1_0\nLogon Account:\tlab.user\nSource Workstation:\n"
                "Error Code:\t0xc000006a\n"
                + head.format(n=5, log="Security", src=sec, code=4648)
                + "Message=A logon was attempted using explicit credentials.\n\nSubject:\n\tAccount Name:\t\tWS1$\n\n"
                "Account Whose Credentials Were Used:\n\tAccount Name:\t\tadmin\n\tAccount Domain:\t\tLAB\n\nTarget Server:\n"
                "\tTarget Server Name:\tdc1\n\tAdditional Information:\tHTTP/dc1\n\nProcess Information:\n\tProcess ID:\t\t0x518\n"
                "\tProcess Name:\t\tC:\\Windows\\System32\\svchost.exe\n\nNetwork Information:\n\tNetwork Address:\t10.0.0.5\n"
                "\tPort:\t\t\t0\n\nThis event is generated when a process attempts to log on an account.\n"
                + head.format(n=6, log="Security", src=sec, code=4689)
                + "Message=A process has exited.\n\nProcess Information:\n\tProcess ID:\t0x145c\n\tProcess Name:\tC:\\x.exe\n"
                "\tExit Status:\t0x1\n"
                + head.format(n=7, log="Security", src=sec, code=4698)
                + "Message=A scheduled task was created.\n\nTask Information:\n\tTask Name: \t\t\\T1\n"
                "\tTask Content: \t\t<?xml version=\"1.0\"?>\n<Task>\n  <Actions><Exec><Command>cmd.exe</Command></Exec></Actions>\n"
                "</Task>\n")
        proc, cleared, svc, ntlm, explicit, exited, task = (r[2] for r in datasets.text_records("windows-classic", text))
        self.assertEqual(proc["CommandLine"], "powershell.exe & {$a = 1\n\nforeach ($x in $a) {\n    Write-Host: $x}}")
        self.assertEqual(cleared["Channel_Cleared"], "Windows PowerShell")
        self.assertEqual((svc["ImagePath"], svc["StartType"], svc["AccountName"]), ("C:\\Temp\\u.exe", "demand start", ""))
        self.assertEqual((ntlm["PackageName"], ntlm["TargetUserName"], ntlm["Workstation"], ntlm["Status"]),
                         ("MICROSOFT_AUTHENTICATION_PACKAGE_V1_0", "lab.user", "", "0xc000006a"))
        self.assertEqual((explicit["SubjectUserName"], explicit["TargetUserName"], explicit["TargetDomainName"],
                          explicit["TargetServerName"], explicit["TargetInfo"], explicit["ProcessName"], explicit["IpAddress"]),
                         ("WS1$", "admin", "LAB", "dc1", "HTTP/dc1", "C:\\Windows\\System32\\svchost.exe", "10.0.0.5"))
        self.assertEqual((exited["ProcessName"], exited["Status"]), ("C:\\x.exe", "0x1"))
        self.assertEqual(task["TaskName"], "\\T1")
        self.assertTrue(task["TaskContent"].startswith("<?xml") and task["TaskContent"].endswith("</Task>"))

    def test_an_also_entry_with_where_separates_the_harness_from_the_recorded_attack(self):
        plan = datasets.build_plan()
        ps = "T1059.001_powershell_encoded_command"
        blob = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
        line = ('{{"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Hostname": "ws1", "RecordNumber": {n}, '
                '"EventTime": "2026-10-12 10:00:0{n}", "Image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe", '
                '"CommandLine": "{cl}"}}')
        launcher = f"PowerShell -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -EncodedCommand {blob}"
        attack = f"powershell.exe -nop -w hidden -enc {blob}"
        sel = {"CommandLine": ["-NonInteractive -ExecutionPolicy Unrestricted -EncodedCommand"]}
        entry = {"kind": "harness", "where": sel, "reason": "the lab's automation"}

        def run(cmds, **kw):
            data = "\n".join(line.format(n=i, cl=c) for i, c in enumerate(cmds, 1)).encode()
            with tempfile.TemporaryDirectory() as tmp:
                ds = dataclasses.replace(self._dataset(Path(tmp), "e.json", data), **kw)
                result, hits = datasets.run_dataset(ds, plan, Path(tmp))
            return ds, result, hits
        ds, result, hits = run([launcher, attack, launcher], expect=[ps], also={ps: entry})
        self.assertEqual((result["alerts"][ps]["count"], result["alerts"][ps]["also"]), (3, {"count": 2, "unique": 2}))
        self.assertEqual({k: v for k, v in datasets.assess(ds, result).items() if v}, {})
        self.assertEqual([h.also for h in hits], [[ps], [], [ps]])
        rows = [datasets.extract_line(h, plan.keep, plan, profiles.load(ds.profile), ds) for h in hits]
        self.assertEqual([r["_rasd"].get("also") for r in rows], [[ps], None, [ps]])
        got = datasets.replay_extract(ds, rows, plan)
        self.assertEqual((got["drift"], got["also"]), ([], {ps: {"count": 2, "unique": 2}}))
        cat = datasets.Catalog({ds.source.id: ds.source}, [ds], {}, {})
        v = datasets.summary(cat, {"datasets": {ds.id: result}})[ps]
        self.assertEqual((v["alerts"], v["harness"], v["independent"]), (1, 2, [ds.id]))
        ds, result, _ = run([launcher, launcher], expect=[ps], also={ps: entry})
        self.assertEqual(datasets.assess(ds, result)["missed"], [ps])          # only the harness fired: the attack was missed
        ds, result, _ = run([launcher, attack], also={ps: entry})
        self.assertEqual(datasets.assess(ds, result)["unexplained"], {ps: 1})  # an alert the where does not explain
        ds, result, _ = run([attack], expect=[ps], also={ps: entry})
        self.assertEqual(datasets.assess(ds, result)["also_silent"], [ps])
        quiet = {ps: {"kind": "scope", "reason": "the attack runs plain commands"}}
        ds, result, _ = run([launcher], also={ps: entry}, quiet=quiet)
        self.assertEqual({k: v for k, v in datasets.assess(ds, result).items() if v}, {})   # quiet on the attack
        ds, result, _ = run([launcher, attack], also={ps: entry}, quiet=quiet)
        self.assertEqual(datasets.assess(ds, result)["quiet_fired"], [ps])
        ds, result, _ = run([attack, launcher], expect=[ps], also={ps: entry})
        span = result["alerts"][ps]["attack"]
        self.assertEqual((span["records"], span["first"]), ([1], result["alerts"][ps]["first"]))
        self.assertTrue(datasets.where_match({"CommandLine": launcher.upper()}, sel))
        self.assertFalse(datasets.where_match({"Image": "x"}, sel))
        doc = yaml.safe_load(datasets.CATALOG.read_text(encoding="utf-8"))
        split = next(d for d in doc["datasets"] if any(isinstance(v, dict) and v.get("where") and k in (d.get("expect") or [])
                                                       for k, v in (d.get("also") or {}).items()))
        rid = next(k for k, v in split["also"].items() if v.get("where"))

        def edited(change):
            new = copy.deepcopy(doc)
            change(next(d for d in new["datasets"] if d["id"] == split["id"])["also"])
            return yaml.safe_dump(new, sort_keys=False)
        cases = {"(a detection can be under also beside expect or quiet only with where)": edited(lambda a: a[rid].pop("where")),
                 "where maps field names": edited(lambda a: a[rid].update(where=[])),
                 "needs kind": edited(lambda a: a.update({rid: "harness"}))}            # a plain string: reported, no crash
        held = next(d for d in doc["datasets"] if d.get("holdout") and d.get("quiet"))
        qrid = next(iter(held["quiet"]))

        def held_split(_also):
            new = copy.deepcopy(doc)
            h = next(d for d in new["datasets"] if d["id"] == held["id"])
            h.setdefault("also", {})[qrid] = {"kind": "benign", "where": {"Image": "x"}, "reason": "explained after the replay"}
            return yaml.safe_dump(new, sort_keys=False)
        cases["goes under found, not under also"] = held_split(None)
        for expected, text in cases.items():
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "catalog.yml"
                path.write_text(text, encoding="utf-8")
                cat = datasets.load_catalog(path)
                datasets.fingerprints(cat)
                datasets.pages(cat, datasets.load_results() or {})          # renders, even from a catalog with errors
            self.assertTrue(any(expected in e for e in cat.errors), (expected, cat.errors))

    def test_an_evtx_member_is_checked_before_it_is_read_and_a_file_outside_lfs_has_its_own_url(self):
        member = b"ElfFile\x00" + bytes(64)
        seen = []

        def fake(path):
            seen.append(Path(path).read_bytes())
            yield 1, "ab" * 32, {"EventID": 1}
        with tempfile.TemporaryDirectory() as tmp:
            buf = Path(tmp) / "z.zip"
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr("logs\\Security.evtx", member)
            data = buf.read_bytes()
            good = self._dataset(Path(tmp), "cap.zip", data, member="logs\\Security.evtx", format="evtx",
                                 member_sha256=hashlib.sha256(member).hexdigest())
            with mock.patch.object(datasets, "evtx_records", fake):
                self.assertEqual([r[0] for r in datasets.records(good, Path(tmp))], [1])
                bad = dataclasses.replace(good, member_sha256="0" * 64)
                with self.assertRaises(datasets.RunError):
                    list(datasets.records(bad, Path(tmp)))
        self.assertEqual(seen, [member])
        lfs_src = dataclasses.replace(good.source, lfs=True, url="https://media.githubusercontent.com/media/x/y/{commit}/{path}")
        in_lfs = dataclasses.replace(good, source=lfs_src, path="a b/c.log")
        in_git = dataclasses.replace(in_lfs, lfs=False)
        self.assertEqual(in_lfs.url, "https://media.githubusercontent.com/media/x/y/" + "0" * 40 + "/a%20b/c.log")
        self.assertEqual(in_git.url, "https://raw.githubusercontent.com/x/y/" + "0" * 40 + "/a%20b/c.log")
        self.assertTrue(in_lfs.in_lfs and not in_git.in_lfs)
        with self.assertRaises(datasets.RunError):
            datasets.git_fetch(lfs_src, [in_lfs], Path("/nonexistent"))

    def test_xml_reader_refuses_a_dtd(self):
        with self.assertRaises(datasets.RunError):
            datasets.xml_event('<!DOCTYPE x [<!ENTITY a "aaaa">]><Event><System/></Event>')

    def test_evtx_hex_values_are_rendered_the_windows_way(self):
        class Hex32TypeNode:
            def __init__(self, data):
                self.data = data

            def hex(self):
                return self.data

        class Nodes:
            pass
        Nodes.Hex32TypeNode = Hex32TypeNode
        Nodes.Hex64TypeNode = type("Hex64TypeNode", (Hex32TypeNode,), {})
        datasets.windows_hex(Nodes)
        self.assertEqual(Hex32TypeNode(bytes([0xff, 0xff, 0x1f, 0x00])).string(), "0x1fffff")
        self.assertEqual(Hex32TypeNode(bytes([0x18, 0, 0, 0])).string(), "0x18")
        self.assertEqual(Hex32TypeNode(bytes(4)).string(), "0x0")
        with self.assertRaises(datasets.RunError):
            datasets.windows_hex(type("Old", (), {}))

    def _dataset(self, root: Path, path: str, data: bytes, **kw) -> "datasets.Dataset":
        src = datasets.Source("test-source", "Test", "https://github.com/x/y", "https://github.com/x/y", "0" * 40, "MIT", None,
                              None, False, True)
        f = root / "test-source" / path
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(data)
        return datasets.Dataset("test/x", src, path, kw.pop("sha256", hashlib.sha256(data).hexdigest()), len(data),
                                kw.pop("format", "nxlog-json"), "nxlog-windows", "T0000", "test", [], {}, {}, **kw)

    def test_no_field_value_is_kept_from_a_source_that_cannot_be_redistributed(self):
        """From a GPL file results.json keeps counts, times and record numbers: no host, account or address."""
        plan = datasets.build_plan()
        head = f"<Event xmlns='{self.NS}'><System>"
        events = [head + "<Provider Name='Microsoft-Windows-Eventlog'/><EventID>1102</EventID><TimeCreated "
                  "SystemTime='2026-10-12T10:00:00Z'/><Channel>Security</Channel><Computer>dc1.lab.example</Computer></System>"
                  "<UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'><SubjectUserName>"
                  "bob</SubjectUserName></LogFileCleared></UserData></Event>"]
        events += [head + f"<Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4771</EventID><TimeCreated SystemTime="
                   f"'2026-10-12T10:01:0{i}Z'/><Channel>Security</Channel><Computer>dc1.lab.example</Computer></System><EventData>"
                   f"<Data Name='TargetUserName'>user{i}</Data><Data Name='Status'>0x18</Data><Data Name='IpAddress'>10.0.0.9</Data>"
                   "</EventData></Event>" for i in range(5)]
        data = "\n".join(events).encode()
        spray, cleared = "T1110.003_password_spray_burst", "T1685.005_security_log_cleared"
        with tempfile.TemporaryDirectory() as tmp:
            ds = dataclasses.replace(self._dataset(Path(tmp), "sec.xml", data, format="windows-xml"), profile="sysmon-native")
            shared, _ = datasets.run_dataset(ds, plan, Path(tmp))
            self.assertEqual(shared["alerts"][cleared]["hosts"], ["dc1.lab.example"])
            self.assertEqual(shared["correlations"][spray][0]["group"], {"IpAddress": "10.0.0.9"})
            gpl = dataclasses.replace(ds, source=dataclasses.replace(ds.source, redistribute=False))
            kept, _ = datasets.run_dataset(gpl, plan, Path(tmp))
        self.assertEqual(kept["alerts"][cleared]["hosts"], [])
        self.assertNotIn("group", kept["correlations"][spray][0])
        self.assertEqual((kept["alerts"][cleared]["count"], kept["correlations"][spray][0]["metric"]), (1, 5))
        self.assertEqual(datasets.quoted_values(kept), [])
        self.assertEqual(len(datasets.quoted_values(shared)), 2)

    def test_the_leak_scan_finds_values_copied_from_a_file_that_cannot_be_redistributed(self):
        head = f"<Event xmlns='{self.NS}'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>10</EventID>"
        gpl = (head + "<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>ws-77q.corp.example</Computer></System>"
               "<EventData><Data Name='SourceImage'>C:\\Users\\Public\\x_tool77.exe</Data><Data Name='TargetImage'>"
               "C:\\Windows\\system32\\lsass.exe</Data><Data Name='CallTrace'>C:\\Windows\\SYSTEM32\\ntdll.dll+abc12|"
               "C:\\Windows\\System32\\KERNELBASE.dll+2d36e</Data></EventData></Event>")
        free = (head + "<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>srv-01.lab.example</Computer></System>"
                "<EventData><Data Name='SourceImage'>C:\\Windows\\system32\\svchost.exe</Data><Data Name='CallTrace'>"
                "C:\\Windows\\System32\\KERNELBASE.dll+2d36e</Data></EventData></Event>")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            open_ds = self._dataset(root, "free.xml", free.encode(), format="windows-xml")
            gpl_src = dataclasses.replace(open_ds.source, id="gpl-source", redistribute=False)
            gpl_ds = dataclasses.replace(self._dataset(root, "gpl.xml", gpl.encode(), format="windows-xml"), id="test/gpl",
                                         source=gpl_src)
            (root / "gpl-source").mkdir()
            (root / "test-source" / "gpl.xml").rename(root / "gpl-source" / "gpl.xml")
            cat = datasets.Catalog({"test-source": open_ds.source, "gpl-source": gpl_src}, [open_ds, gpl_ds], {}, {})
            files = {"copied.jsonl": json.dumps({"SourceImage": "C:\\Users\\Public\\x_tool77.exe"}) + "\n",
                     "host.md": "The host ws-77q.corp.example opened LSASS.\n",
                     "frame.yml": "CallTrace: 'C:\\Windows\\SYSTEM32\\ntdll.dll+abc12'\n",
                     "generic.md": "svchost.exe on srv-01.lab.example, frame C:\\Windows\\System32\\KERNELBASE.dll+2d36e, lsass.exe\n"}
            for name, text in files.items():
                (root / name).write_text(text, encoding="utf-8")
            with mock.patch.object(datasets, "ROOT", root), \
                    mock.patch.object(datasets, "_tracked_files", lambda: [root / n for n in files]):
                hits = datasets.leak_scan(cat, root)
        self.assertEqual(sorted({h.split(":")[0] for h in hits}), ["copied.jsonl", "frame.yml", "host.md"])
        self.assertTrue(any("x_tool77.exe" in h for h in hits) and any("ntdll.dll+abc12" in h for h in hits))

    def test_a_file_whose_hash_differs_from_the_catalog_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            ds = self._dataset(Path(tmp), "a.json", b'{"EventID": 1}\n', sha256="0" * 64)
            with self.assertRaises(datasets.RunError):
                list(datasets.records(ds, Path(tmp)))

    def test_a_zip_member_is_read_in_place_and_its_hash_checked(self):
        member = b'{"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational"}\n{"EventID": 2}\n'
        with tempfile.TemporaryDirectory() as tmp:
            buf = Path(tmp) / "z.zip"
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr("events.json", member)
            data = buf.read_bytes()
            good = self._dataset(Path(tmp), "set.zip", data, member="events.json",
                                 member_sha256=hashlib.sha256(member).hexdigest())
            rows = list(datasets.records(good, Path(tmp)))
            self.assertEqual([r[0] for r in rows], [1, 2])
            self.assertEqual(rows[0][2]["EventID"], 1)
            bad = self._dataset(Path(tmp), "set2.zip", data, member="events.json", member_sha256="f" * 64)
            with self.assertRaises(datasets.RunError):
                list(datasets.records(bad, Path(tmp)))
            missing = self._dataset(Path(tmp), "set3.zip", data, member="other.json", member_sha256="f" * 64)
            with self.assertRaises(datasets.RunError):
                list(datasets.records(missing, Path(tmp)))

    def test_an_extract_cuts_long_values_only_where_the_verdicts_stay(self):
        plan = datasets.build_plan()
        blob = "SQBmACgAJABQAFMAVgBFAFIAUwBpAG8AbgBUAEEAQgBsAEUALgBQAFMAVgBFAHIA" * 20
        raw = {"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
               "CommandLine": f"powershell.exe -noP -sta -w 1 -enc {blob}", "UtcTime": "2026-10-12 10:00:00.000", "Unrelated": "x"}
        h = datasets.Hit(7, "ab" * 32, raw, raw, [r for r, fn in plan.rules["process_creation"] if fn(raw)])
        self.assertIn("T1059.001_powershell_encoded_command", h.fires)
        line = datasets.extract_line(h, plan.keep, plan, None)
        self.assertNotIn("Unrelated", line)
        self.assertIn("characters cut", line["CommandLine"])
        self.assertEqual(line["_rasd"]["fires"], h.fires)
        padded = {**raw, "CommandLine": "powershell.exe" + " " * 300 + f" -enc {blob[:40]} " + " " * 300 + "-NoExit"}
        h2 = datasets.Hit(8, "cd" * 32, padded, padded, [r for r, fn in plan.rules["process_creation"] if fn(padded)])
        self.assertEqual(datasets.extract_line(h2, plan.keep, plan, None)["CommandLine"], padded["CommandLine"])

    def test_extract_drift_and_unexplained_alerts_are_reported(self):
        cat = datasets.load_catalog()
        plan = datasets.build_plan()
        ds = next(d for d in cat.datasets if d.extract is not None and d.extract.exists() and d.expect)
        rows = datasets.read_extract(ds.extract)
        rows[0] = {**rows[0], "_rasd": {**rows[0]["_rasd"], "fires": ["T1595.003_api_auth_probing"]}}
        self.assertTrue(datasets.replay_extract(ds, rows, plan)["drift"])
        result = {"alerts": {"T1059.004_linux_suspicious_shell_execution": {"count": 2}}, "correlations": {}}
        a = datasets.assess(ds, result)
        self.assertEqual(a["unexplained"], {"T1059.004_linux_suspicious_shell_execution": 2})
        self.assertEqual(a["missed"], ds.expect)

    def test_fingerprints_change_with_a_rule_but_not_with_its_prose(self):
        cat = datasets.load_catalog()
        before = datasets.fingerprints(cat)
        rule = ROOT / "detect" / "detections" / "T1685.005_security_log_cleared" / "rule.yml"
        text = rule.read_text(encoding="utf-8")
        try:
            rule.write_text(text.replace("falsepositives:", "falsepositives:\n  - prose only", 1), encoding="utf-8")
            self.assertEqual(datasets.stale_inputs(before, datasets.fingerprints(cat)), [])
            rule.write_text(text.replace("EventID: 1102", "EventID: 1100"), encoding="utf-8")
            self.assertEqual(datasets.stale_inputs(before, datasets.fingerprints(cat)), ["rule:T1685.005_security_log_cleared"])
        finally:
            rule.write_text(text, encoding="utf-8")

    def test_the_catalog_refuses_unknown_next_rules_kinds_overlaps_and_changed_rules(self):
        base = datasets.CATALOG.read_text(encoding="utf-8")
        later = "splunk/T1059.001/encoded_powershell/windows-sysmon"
        cases = {
            "names next rule no_such_rule": base.replace("next: netcat_exec", "next: no_such_rule", 1),
            "needs kind": base.replace("kind: scope", "kind: shrug", 1),
            "a gap names the next rule": base.replace("      next: netcat_exec\n", "", 1),
            "not an earlier dataset": base.replace("    splunk/T1059.001/encoded_powershell/explorer_spawns_windows-sysmon: 'the file",
                                                   f"    {later}: 'the file", 1),
            "changed_after_replay": base.replace("changed_after_replay:\n", "changed_after_replay:\n  T0000_nothing: x\n", 1),
        }
        for expected, text in cases.items():
            self.assertNotEqual(text, base, expected)
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "catalog.yml"
                path.write_text(text, encoding="utf-8")
                errors = datasets.load_catalog(path).errors
            self.assertTrue(any(expected in e for e in errors), (expected, errors))

    def test_held_out_files_keep_their_labels_and_their_misses(self):
        base = datasets.CATALOG.read_text(encoding="utf-8")
        entry = "  holdout: H05\n  expect:\n  - T1053.005_schtasks_suspicious_creation\n  - T1003.001_lsass_memory_access\n"
        self.assertIn(entry, base)
        relabelled = base.replace(entry, "  holdout: H05\n  expect:\n  - T1053.005_schtasks_suspicious_creation\n", 1)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "catalog.yml"
            path.write_text(relabelled, encoding="utf-8")
            errors = datasets.load_catalog(path).errors
        self.assertTrue(any("must be the labels of H05" in e for e in errors), errors)
        cat = datasets.load_catalog()
        held = next(ds for ds in cat.datasets if ds.holdout == "H05")
        lsass = "T1003.001_lsass_memory_access"
        quiet = dataclasses.replace(held, expect=["T1053.005_schtasks_suspicious_creation"], missed={},
                                    quiet={lsass: {"kind": "scope", "reason": "x"}}, found={lsass: "fired beyond the label"})
        result = {"alerts": {lsass: {"count": 2, "unique": 2}}, "correlations": {}, "overlap": {}}
        a = datasets.assess(quiet, result)
        self.assertEqual((a["quiet_fired"], a["unexplained"], a["missed"]), ([], {}, ["T1053.005_schtasks_suspicious_creation"]))
        missed = dataclasses.replace(held, missed={lsass: "stayed quiet on the first replay"})
        self.assertEqual(datasets.assess(missed, result)["holdout_changed"], [lsass])
        self.assertEqual(datasets.assess(dataclasses.replace(held, found={"T1059.001_powershell_encoded_command": "x"}),
                                         result)["found_silent"], ["T1059.001_powershell_encoded_command"])
        members = [ds for ds in cat.datasets if ds.holdout and ds.member]
        self.assertGreaterEqual(len(members), 2)
        swapped = dataclasses.replace(members[0], member_sha256=members[1].member_sha256)
        self.assertTrue(any(members[0].holdout in e for e in datasets._check_holdout_labels([swapped])))
        demoted = next(ds for ds in cat.datasets if ds.demoted_from)
        again = base.replace(f"  demoted_from: {demoted.demoted_from}\n", f"  holdout: {demoted.demoted_from}\n", 1)
        self.assertNotEqual(again, base)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "catalog.yml"
            path.write_text(again, encoding="utf-8")
            errors = datasets.load_catalog(path).errors
        self.assertTrue(any("was demoted and cannot be held out again" in e for e in errors), errors)
        s = datasets.summary(cat)
        self.assertEqual(len(s[lsass]["holdout"]["met"]), len(s[lsass]["holdout"]["expected"]))
        self.assertFalse(any(ds.holdout for ds in cat.datasets if ds.id in s[lsass]["expected"]))

    def test_records_are_counted_once_and_copies_from_an_earlier_file_are_not_new_evidence(self):
        plan = datasets.build_plan()
        ev = (f"<Event xmlns='{self.NS}'><System><Provider Name='Microsoft-Windows-Eventlog'/><EventID>1102</EventID>"
              "<EventRecordID>{n}</EventRecordID><TimeCreated SystemTime='2026-10-12T10:00:0{n}Z'/><Channel>Security</Channel>"
              "<Computer>dc1.lab.example</Computer></System><UserData><LogFileCleared xmlns='http://manifests.microsoft.com/"
              "win/2004/08/windows/eventlog'><SubjectUserName>{who}</SubjectUserName></LogFileCleared></UserData></Event>")
        first = "\n".join([ev.format(n=1, who="bob"), ev.format(n=1, who="bob"), ev.format(n=2, who="bob")]).encode()
        second = "\n".join([ev.format(n=1, who="bob"), ev.format(n=2, who="eve"), ev.format(n=3, who="bob")]).encode()
        cleared = "T1685.005_security_log_cleared"
        with tempfile.TemporaryDirectory() as tmp:
            a = dataclasses.replace(self._dataset(Path(tmp), "a.xml", first, format="windows-xml"), profile="sysmon-native")
            b = dataclasses.replace(self._dataset(Path(tmp), "b.xml", second, format="windows-xml"), id="test/y",
                                    profile="sysmon-native")
            ledger = datasets.Ledger()
            ra, _ = datasets.run_dataset(a, plan, Path(tmp), ledger)
            rb, hits = datasets.run_dataset(b, plan, Path(tmp), ledger)
        self.assertEqual((ra["events"], ra["duplicates"], ra["alerts"][cleared]["count"], ra["alerts"][cleared]["unique"]), (3, 1, 2, 2))
        self.assertEqual(rb["overlap"], {"test/x": {"same": 1, "edited": 1}})
        self.assertEqual((rb["alerts"][cleared]["count"], rb["alerts"][cleared]["unique"]), (3, 1))
        self.assertEqual(sorted(h.seen_in or "-" for h in hits), ["-", "test/x", "test/x"])
        self.assertEqual(datasets.assess(b, rb)["overlap_undeclared"], ["test/x"])
        declared = dataclasses.replace(b, overlap={"test/x": "the same records", "test/z": "gone"})
        self.assertEqual(datasets.assess(declared, rb, {"test/x", "test/y", "test/z"})["overlap_gone"], ["test/z"])

    def test_downloads_are_https_only_and_capped_at_the_catalog_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(datasets.RunError):
                datasets.http_fetch("http://example.com/x", Path(tmp) / "x", 10)

            class Big:
                def __init__(self):
                    self.left = 3

                def read(self, n):
                    self.left -= 1
                    return b"x" * 8 if self.left >= 0 else b""

                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    return False
            real = datasets.urllib.request.urlopen
            datasets.urllib.request.urlopen = lambda req, timeout=0: Big()
            try:
                with self.assertRaises(datasets.RunError):
                    datasets.http_fetch("https://example.com/x", Path(tmp) / "x", 10)
            finally:
                datasets.urllib.request.urlopen = real
            self.assertFalse((Path(tmp) / "x").exists())

    def test_a_download_cut_off_midway_resumes_where_it_stopped(self):
        data = bytes(range(256)) * 40
        calls = []

        class Resp:
            def __init__(self, body, status, cut):
                self.body, self.status, self.cut, self.sent = body, status, cut, False

            def read(self, n):
                if self.sent:
                    if self.cut:
                        raise datasets.http.client.IncompleteRead(b"", 100)
                    return b""
                self.sent = True
                return self.body

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake(req, timeout=0):
            rng = req.get_header("Range")
            calls.append(rng)
            if rng is None:
                return Resp(data[:4000], 200, cut=True)
            start = int(rng.split("=")[1].rstrip("-"))
            return Resp(data[start:], 206, cut=False)

        real = datasets.urllib.request.urlopen
        datasets.urllib.request.urlopen = fake
        try:
            with tempfile.TemporaryDirectory() as tmp:
                dest = Path(tmp) / "f.log"
                datasets.http_fetch("https://example.com/f.log", dest, len(data))
                self.assertEqual(dest.read_bytes(), data)
        finally:
            datasets.urllib.request.urlopen = real
        self.assertEqual(calls, [None, "bytes=4000-"])

    def test_parity_runs_the_queries_on_public_events(self):
        dets = load_detections()
        lsass = find_detection("T1003.001")
        public = datasets.public_events()
        labels = [label for label, _ in parity.corpus_for(lsass, dets, [], public)]
        self.assertTrue(any(label.startswith("public:") for label in labels))


class Profiles(unittest.TestCase):
    """Exports in other schemas reach the same rules - and native exports are never changed."""

    def fixtures(self):
        for path in sorted((ROOT / "samples" / "profiles").glob("*.jsonl")):
            yield path.stem, load_jsonl(path)

    def verdicts(self, ev: dict) -> list[str]:
        dets = load_detections()
        return sorted(d.id for d in dets if convert.logsource_key(d.rule) == replay.route(ev) and matches(d.rule, ev))

    def test_every_fixture_triggers_exactly_its_detections(self):
        seen = set()
        for name, events in self.fixtures():
            prof = profiles.load(name)
            seen.add(name)
            for ev in events:
                raw = {k: v for k, v in ev.items() if not k.startswith("_")}
                self.assertEqual(self.verdicts(profiles.normalize(raw, prof)), sorted(ev["_expect"]), f"{name}: {ev['_case']}")
        self.assertEqual(seen, set(profiles.names()) - {profiles.NATIVE}, "every shipped profile needs fixtures")

    def test_the_profile_does_the_work(self):
        for name, events in self.fixtures():
            expected = [ev for ev in events if ev["_expect"]]
            raw = [{k: v for k, v in ev.items() if not k.startswith("_")} for ev in expected]
            self.assertTrue(any(self.verdicts(r) != sorted(ev["_expect"]) for r, ev in zip(raw, expected, strict=True)),
                            f"{name}: the fixtures already match without the profile")

    def test_native_events_are_never_changed(self):
        dets = load_detections()
        for name in profiles.names():
            prof = profiles.load(name)
            for d in dets:
                for ev in d.tests("true_positive"):
                    self.assertTrue(matches(d.rule, profiles.normalize(ev, prof)), f"{name} broke {d.id}: {ev['_case']}")
                for ev in d.tests("true_negative"):
                    self.assertFalse(matches(d.rule, profiles.normalize(ev, prof)), f"{name} broke {d.id}: {ev['_case']}")

    def test_auto_detection_picks_the_export_schema(self):
        for name, events in self.fixtures():
            raw = [{k: v for k, v in ev.items() if not k.startswith("_")} for ev in events]
            best, _ = profiles.detect(raw)
            if name == "splunk-ta-windows":            # native names: native and the TA profile tie, native wins
                self.assertIn(best, (name, profiles.NATIVE))
            else:
                self.assertEqual(best, name)
        self.assertEqual(profiles.detect(load_jsonl(ROOT / "samples" / "doctor" / "ecs-export.jsonl"))[0], "elastic-ecs")

    def test_profiles_are_well_formed_and_documented(self):
        import yaml
        for name in profiles.names():
            prof = yaml.safe_load((profiles.PROFILES_DIR / f"{name}.yml").read_text(encoding="utf-8"))
            self.assertEqual(prof["name"], name)
            for key in ("description", "source", "docs", "covers"):
                self.assertTrue(prof.get(key), f"{name}: {key}")
            self.assertTrue(set(prof["covers"]) <= set(profiles.LOGSOURCES), name)
            self.assertTrue(set(prof.get("fields") or {}) <= {"common", *profiles.LOGSOURCES}, name)
        self.assertTrue(profiles.write_readme(check=True), "profiles/README.md is stale - run: rasd build")

    def test_a_4688_export_degrades_only_the_branches_that_need_originalfilename(self):
        import doctor
        raw = [{k: v for k, v in ev.items() if not k.startswith("_")}
               for ev in load_jsonl(ROOT / "samples" / "profiles" / "windows-security-4688.jsonl")]
        self.assertEqual(profiles.detect(raw)[0], "windows-security-4688")
        events, used = profiles.apply(raw, "auto")
        verdicts = {r["detection"]: r for r in doctor.diagnose(events, load_detections(), used)}
        renamed = [d.id for d in load_detections() if logsource_key(d.rule) == "process_creation"
                   and "OriginalFileName" in validate.rule_fields(d.rule["detection"])]
        self.assertGreaterEqual(len(renamed), 6)
        for det_id in renamed:                       # every rule with a renamed-binary branch, and only those
            self.assertEqual(verdicts[det_id]["verdict"], "DEGRADED", det_id)
            self.assertTrue(any("OriginalFileName" in i and "medium" in i for i in verdicts[det_id]["issues"]), det_id)
        self.assertEqual(verdicts["T1558.003_kerberoasting_rc4_tgs"]["verdict"], "READY")
        self.assertEqual(verdicts["T1547.001_registry_run_key_persistence"]["verdict"], "BLIND")

    def test_doctor_reads_an_ecs_export_through_its_profile(self):
        raw = load_jsonl(ROOT / "samples" / "doctor" / "ecs-export.jsonl")
        before = {r["detection"]: r["verdict"] for r in doctor.diagnose(raw, load_detections())}
        events, used = profiles.apply(raw, "auto")
        after = {r["detection"]: r for r in doctor.diagnose(events, load_detections(), used)}
        self.assertEqual(used, "elastic-ecs")
        self.assertEqual(before["T1059.001_powershell_encoded_command"], "BLIND")
        self.assertEqual(after["T1059.001_powershell_encoded_command"]["verdict"], "READY")
        mde = profiles.apply(raw, "mde-advanced-hunting")[0]
        lsass = next(r for r in doctor.diagnose(mde, load_detections(), "mde-advanced-hunting")
                     if r["detection"] == "T1003.001_lsass_memory_access")
        self.assertIn("profile has no record", lsass["issues"][0])


class CompiledEngine(unittest.TestCase):
    def test_compiled_rules_return_the_reference_verdicts(self):
        """compile_rule() == matches() on every corpus parity uses, for every rule and every rule mutant."""
        dets = load_detections()
        replay_events = load_jsonl(parity.REPLAY_CORPUS)
        compared = 0
        for d in dets:
            corpus = [ev for _, ev in parity.corpus_for(d, dets, replay_events)]
            for rule in [d.rule] + [m[3] for m in prove.mutants(d.rule)]:
                fn = compile_rule(rule)
                for ev in corpus:
                    self.assertEqual(fn(ev), matches(rule, ev), f"{d.id}: {json.dumps(ev)[:200]}")
                    compared += 1
        self.assertGreater(compared, 50000)

    def test_benchmark_reports_cost_and_agrees_with_the_interpreter(self):
        dets = load_detections()
        events = benchmark.generate(3000, dets)
        res = benchmark.benchmark(events, dets, repeat=1, compare=True)     # raises if alert counts differ
        self.assertEqual(res["events"], 3000)
        self.assertGreater(res["events_per_second"], 0)
        self.assertTrue(res["rules"] and res["regexes"])
        self.assertGreater(res["alerts"], 0)

    def test_stream_mode_gives_the_same_alerts_with_bounded_chunks(self):
        dets = load_detections()
        in_memory = benchmark.benchmark(benchmark.generate(3000, dets), dets, repeat=1)
        streamed = benchmark.stream(benchmark.iter_generated(3000, dets), dets, chunk_size=700, sample=150, compare=True)
        self.assertEqual(streamed["alerts"], in_memory["alerts"])
        self.assertEqual((streamed["events"], streamed["chunks"]), (3000, 5))
        self.assertEqual(streamed["sampled_events"], 5 * 150)
        self.assertTrue(streamed["rules"] and streamed["regexes"])
        self.assertTrue(all(r["values"] <= benchmark.RESERVOIR for r in streamed["regexes"]))


class RE2(unittest.TestCase):
    def test_flags_constructs_kql_cannot_run(self):
        self.assertEqual(validate.re2_issues(r"(?<!svc)host"), ["a lookaround"])
        self.assertEqual(validate.re2_issues(r"(a)\1"), ["a backreference"])
        self.assertEqual(validate.re2_issues(r"[\\/](AppData|Temp)[\\/]"), [])
        self.assertEqual(validate.re2_issues(r"[*+]+"), [])


class ReplayRisk(unittest.TestCase):
    def test_contract_risk_model_ranks_alerts(self):
        assets = replay.load_assets(str(ROOT / "samples" / "replay" / "assets.csv"))
        users = replay.load_users(str(ROOT / "samples" / "replay" / "users.csv"))
        events = load_jsonl(ROOT / "samples" / "replay" / "lab-day.jsonl")
        alerts, _ = replay.replay(events, load_detections(), assets, replay.RiskContext(assets, users))
        smbexec = next(a for a in alerts if a["technique"] == "T1569.002" and "COMSPEC" in a["summary"])
        psexec = next(a for a in alerts if a["technique"] == "T1569.002" and "PSEXESVC" in a["summary"])
        self.assertEqual(smbexec["risk"], 95)              # base 60 + remote execution 15 + critical host 20
        self.assertIn("+20 host is critical", smbexec["risk_factors"])
        self.assertEqual(psexec["risk"], 80)               # admin PsExec on a server: no remote-share path
        self.assertTrue(any("approved" in q for q in psexec["risk_questions"]))


class Chain(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = chain.Repo()

    def test_no_chain_item_is_missing(self):
        for t in self.repo.techniques():
            self.assertNotIn("missing", self.repo.checklist(t).values(), t)

    def test_primary_mappings_follow_attack_v19_and_v18_aliases_hold(self):
        self.assertEqual(chain.attack_alias_errors(self.repo), [])
        self.assertIn("T1685.005", self.repo.techniques())
        self.assertNotIn("T1070.001", self.repo.techniques())
        tactics = {t for d in self.repo.items for t in d.tactics}
        self.assertNotIn("defense-evasion", tactics)
        self.assertTrue({"stealth", "defense-impairment"} <= tactics)

    def test_alias_gate_catches_v18_tags_folders_and_tactics(self):
        from types import SimpleNamespace
        from common import Detection
        rule = {"title": "x", "tags": ["attack.defense-evasion", "attack.t1070.001"], "detection": {"condition": "s", "s": {"a": 1}}}
        det = Detection(ROOT / "detect" / "detections" / "T1070.001_old_copy", rule, {})
        fake = SimpleNamespace(by_id={self.repo.dets[0].id: self.repo.dets[0], "T1070.001_event_log_clearing": det},
                               items=[det], red=[{"platform": "windows", "id": "x", "mitre": {"technique": "T1070.001"}}])
        errs = "\n".join(chain.attack_alias_errors(fake))
        for text in ("is not a detection", "is still a detection folder", "tag attack.t1070.001 is the ATT&CK v18 ID",
                     "attack.defense-evasion is the v18 tactic", "named after the ATT&CK v18 technique",
                     "maps the ATT&CK v18 technique"):
            self.assertIn(text, errs)

    def test_operational_is_not_a_maturity_level(self):
        import yaml
        folder = ROOT / "detect" / "detections" / "T1059.001_powershell_encoded_command"
        c = yaml.safe_load((folder / "contract.yml").read_text(encoding="utf-8"))
        self.assertEqual(c["maturity"], "siem-ready")
        self.assertNotIn("operational", validate.MATURITY)
        self.assertEqual(validate.maturity_label("siem-ready"), "SIEM-Ready")

    def test_maturity_is_computed_and_over_claims_fail(self):
        det = self.repo.dets[0]
        self.assertEqual(self.repo.maturity(det), "siem-ready")      # no lab evidence yet
        original = det.contract["maturity"]
        try:
            det.contract["maturity"] = "reference"
            self.assertTrue(any("declares maturity 'reference'" in e for e in chain.gate_errors(self.repo)))
        finally:
            det.contract["maturity"] = original
        self.assertEqual(chain.gate_errors(self.repo), [])

    def test_pending_items_are_never_marked_done_without_evidence(self):
        for t in self.repo.techniques():
            c = self.repo.checklist(t)
            self.assertEqual(c["Evidence file"], "pending")
            self.assertEqual(c["Operational Score"], "pending")

    def test_backlog_holds_every_gap_and_only_gaps(self):
        self.assertEqual(chain.backlog_errors(self.repo), [])
        ranked = [g["technique"] for g, _ in chain.backlog_ranked(self.repo)]
        self.assertEqual(ranked, ["T1083", "T1505.003", "T1087.002", "T1606"])
        original = list(self.repo.backlog)
        try:
            self.repo.backlog = [g for g in original if g["red_test"] != "jwt_testing"]
            self.assertTrue(any("jwt_testing documents a coverage gap" in e for e in chain.backlog_errors(self.repo)))
            self.repo.backlog = [*original, {**original[0], "technique": "T1059.001"}]
            self.assertTrue(any("T1059.001 is covered by a detection" in e for e in chain.backlog_errors(self.repo)))
        finally:
            self.repo.backlog = original

    def test_backlog_actor_rows_cite_attack(self):
        for g in self.repo.backlog:
            for a in self.repo.actors_for(g["technique"]):
                self.assertRegex(a["source"], r"^https://attack\.mitre\.org/groups/G\d{4}/$")
                self.assertTrue(any(t.get("note") for t in a["techniques"] if t["id"] == g["technique"]), a["group"])


class Tune(unittest.TestCase):
    def test_risky_and_safe_tunings_are_told_apart(self):
        logs = tune.DEFAULT_LOGS
        rows = {r["id"]: r for r in tune.analyse(find_detection("T1569"), logs)}
        self.assertEqual(rows["psexec_service_name"]["verdict"], "RISKY")
        self.assertGreater(len(rows["psexec_service_name"]["hidden"]), 0)
        kerb = {r["id"]: r for r in tune.analyse(find_detection("T1558"), logs)}
        self.assertEqual(kerb["legacy_rc4_scanner"]["verdict"], "SAFE")
        self.assertEqual(kerb["legacy_rc4_scanner"]["removed"], 2)
        self.assertEqual(kerb["machine_accounts"]["verdict"], "APPLIED")

    def test_a_filter_the_engine_refuses_is_broken_not_risky(self):
        det = find_detection("T1021.006")
        original = tune.load_tuning
        doc = {"tunings": [{"id": "unc", "status": "proposed", "reason": "x" * 12,
                            "filter": {"CommandLine|contains": "\\\\share\\scripts\\"}}]}
        tune.load_tuning = lambda _det: doc
        try:
            row = tune.analyse(det, tune.DEFAULT_LOGS)[0]
        finally:
            tune.load_tuning = original
        self.assertEqual(row["verdict"], "BROKEN")
        self.assertTrue(any("refused" in p for p in row["problems"]))


class Red(unittest.TestCase):
    def setUp(self):
        self.dets = {d.id: d for d in load_detections()}
        self.corrs = {c.id: c for c in load_correlations()}
        self.test = next(t for t in red.load_tests() if t["id"] == "scheduled_task_creation")

    def test_repository_tests_are_valid(self):
        for t in red.load_tests():
            self.assertEqual(red.check_test(t, self.dets, self.corrs), [], t.get("id"))

    def test_correlation_links_are_executed(self):
        import copy
        spray = next(t for t in red.load_tests() if t["id"] == "password_spray_simulation")
        self.assertEqual(red.covers(spray), ["T1110.003_password_spray_burst"])
        bad = copy.deepcopy(spray)
        bad["sample_output"]["scenarios"][0]["scenario"] = "one below the threshold - four accounts"
        self.assertIn("does not fire", " | ".join(red.check_test(bad, self.dets, self.corrs)))
        bad["steps"][0]["correlations"] = ["T9999_no_such_correlation"]
        self.assertIn("unknown correlation", " | ".join(red.check_test(bad, self.dets, self.corrs)))
        gap = copy.deepcopy(spray)
        gap["gap"] = {"reason": "x", "planned": "y"}
        self.assertIn("remove `gap`", " | ".join(red.check_test(gap, self.dets, self.corrs)))

    def test_broken_links_are_caught(self):
        import copy
        bad = copy.deepcopy(self.test)
        bad["objective"] = ""
        bad["steps"][0]["detections"] = ["T9999_does_not_exist"]
        bad["sample_output"]["events"][0]["case"] = "not a true positive"
        errs = " | ".join(red.check_test(bad, self.dets))
        self.assertIn("missing 'objective'", errs)
        self.assertIn("unknown detection 'T9999_does_not_exist'", errs)
        self.assertIn("is not a true positive", errs)

    def test_placeholders_render_visibly(self):
        readme = red.render_all(self.test, self.dets)["README.md"]
        prose = readme.split("## Run")[0]
        self.assertNotIn(" <marker>", prose)
        self.assertIn("&lt;marker&gt;", prose)


class Links(unittest.TestCase):
    def test_every_relative_link_resolves(self):
        self.assertEqual(links.check(), [])

    def test_github_anchor_slugs(self):
        self.assertEqual(links.slug("Evasion & coverage gaps"), "evasion--coverage-gaps")
        self.assertEqual(links.slug("Maturity per detection"), "maturity-per-detection")


class DefenderAdvancedHunting(unittest.TestCase):
    """The optional Defender XDR backend: its extend and filter, parsed back, equal the engine."""

    PROCESS: ClassVar[list] = [
        {"Image": "C:\\Windows\\System32\\cmd.exe", "ParentImage": "C:\\Windows\\explorer.exe", "OriginalFileName": "Cmd.Exe",
         "CommandLine": "cmd.exe /c whoami", "ParentCommandLine": "C:\\Windows\\Explorer.EXE", "User": "LAB\\alice"},
        {"Image": "cmd.exe", "User": "SYSTEM", "ParentImage": ""},
        {"Image": "C:/Tools/x.exe", "User": "NT AUTHORITY\\SYSTEM", "ParentImage": "C:\\Program Files\\App\\app.exe"},
        {"Image": "C:\\Windows\\System32\\CMD.EXE", "User": "lab\\ALICE", "CommandLine": "CMD /C WHOAMI"},
        {},
    ]
    REGISTRY: ClassVar[list] = [
        {"TargetObject": "HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
         "Details": "C:\\Users\\Public\\u.exe", "Image": "C:\\Windows\\regedit.exe", "User": "LAB\\alice"},
        {"TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Agent",
         "Details": "C:\\Program Files\\Agent\\agent.exe", "Image": "C:\\Program Files\\Agent\\setup.exe", "User": "SYSTEM"},
        {"TargetObject": "HKCR\\exefile\\shell\\open\\command", "Details": "\"%1\" %*"},
        {},
    ]
    RULES: ClassVar[list] = [
        ("process_creation", {"Image": "C:\\Windows\\System32\\cmd.exe"}), ("process_creation", {"Image": "cmd.exe"}),
        ("process_creation", {"Image": "C:/Tools/x.exe"}), ("process_creation", {"ParentImage|endswith": "\\explorer.exe"}),
        ("process_creation", {"ParentImage": "C:\\Program Files\\App\\app.exe"}),
        ("process_creation", {"OriginalFileName": "cmd.exe"}), ("process_creation", {"CommandLine|contains": "whoami"}),
        ("process_creation", {"ParentCommandLine|contains": "explorer"}), ("process_creation", {"User": "SYSTEM"}),
        ("process_creation", {"User": "LAB\\alice"}), ("process_creation", {"User": "NT AUTHORITY\\SYSTEM"}),
        ("process_creation", {"Image": None}),
        ("registry_set", {"TargetObject|startswith": "HKU\\"}), ("registry_set", {"TargetObject|startswith": "HKLM\\"}),
        ("registry_set", {"TargetObject|startswith": "HKCR\\"}),
        ("registry_set", {"TargetObject": "HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"}),
        ("registry_set", {"TargetObject|endswith": "\\Run\\Agent"}), ("registry_set", {"Details|contains": "public"}),
        ("registry_set", {"Image|endswith": "\\regedit.exe"}), ("registry_set", {"User": "SYSTEM"}),
    ]

    @staticmethod
    def rule(source: str, selection: dict) -> dict:
        return {"title": "probe", "id": "00000000-0000-0000-0000-000000000000",
                "logsource": {"product": "windows", "category": source},
                "detection": {"sel": selection, "condition": "sel"}}

    def divergences(self) -> list[str]:
        out = []
        for source, selection in self.RULES:
            r = self.rule(source, selection)
            spec, query = parity.defender_spec(r), parity.compile_defender(r)
            probes = self.PROCESS if source == "process_creation" else self.REGISTRY
            fired = [matches(r, ev) for ev in probes]
            self.assertTrue(any(fired) and not all(fired), f"{selection}: the probes do not separate it")
            for i, ev in enumerate(probes):
                for full_path in (False, True):
                    got = query(parity.defender_row(ev, spec, full_path, parity.defender_action(r))) is True
                    if got != fired[i]:
                        out.append(f"{selection} probe {i + 1} full_path={full_path}: defender {got}, engine {fired[i]}")
        return out

    def test_every_mapped_field_is_rebuilt_exactly(self):
        self.assertEqual(self.divergences(), [])

    def test_the_table_filter_runs_too(self):
        r = self.rule("registry_set", {"TargetObject|endswith": "\\Run\\Agent"})
        query, spec = parity.compile_defender(r), parity.defender_spec(r)
        ev = next(e for e in self.REGISTRY if matches(r, e))
        self.assertIs(query(parity.defender_row(ev, spec, False, "RegistryValueSet")), True)
        self.assertIsNot(query(parity.defender_row(ev, spec, False, "RegistryKeyDeleted")), True)

    def test_rules_get_a_query_only_where_defender_has_a_table(self):
        for d in load_detections():
            if convert.logsource_key(d.rule) in convert.MAPPINGS[convert.DEFENDER]["logsources"]:
                self.assertIn("advanced hunting", convert.convert(d.rule, convert.DEFENDER))
            else:
                with self.assertRaisesRegex(Exception, "no table"):
                    convert.convert(d.rule, convert.DEFENDER)

    def test_deployed_defender_queries_agree_with_the_engine(self):
        report = parity.check()
        covered = {k: r for k, r in report.items() if r["mde"] is not None}
        self.assertGreaterEqual(len(covered), 7)
        for k, r in covered.items():
            self.assertEqual(r["mde"], [], k)
            self.assertEqual(r["mde_rows"], 2 * r["events"], k)

    def test_injected_generator_bugs_are_caught(self):
        original = convert.defender_expression

        def joined(kind):
            def bug(spec):
                if isinstance(spec, dict) and kind in spec:
                    return 'strcat({}, @"\\", {})'.format(*spec[kind])
                return original(spec)
            return bug

        bugs = {"path always joins folder and file": joined("path"),
                "account always joins domain and name": joined("account"),
                "hives left as Defender writes them": joined("registry")}
        for name, bug in bugs.items():
            convert.defender_expression = bug
            try:
                self.assertTrue(self.divergences(), f"not caught: {name}")
            finally:
                convert.defender_expression = original


class Packaging(unittest.TestCase):
    """`pip install -e .` gives a `rasd` command that runs this clone's tools."""

    def test_pyproject_declares_the_command_and_the_release_version(self):
        from common import VERSION
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertRegex(text, rf'(?m)^version = "{re.escape(VERSION)}"$')
        self.assertRegex(text, r'(?m)^rasd = "rasd:main"$')
        self.assertRegex(text, r'(?m)^py-modules = \["rasd"\]$')
        self.assertRegex(text, r'(?m)^requires-python = ">=3\.10"$')
        req = (ROOT / "requirements.txt").read_text(encoding="utf-8").split()
        for dep in req:
            self.assertIn(f'"{dep}"', text, "pyproject dependencies must match requirements.txt")

    def test_commands_run_from_the_folder_they_are_typed_in(self):
        rasd = [sys.executable, str(ROOT / "rasd.py")]
        rule = ROOT / "detect" / "detections" / "T1685.005_event_log_clearing" / "rule.yml"
        out = subprocess.run([*rasd, "convert", "--backend", "kql", "--rule", str(rule)], cwd=ROOT / "queries",
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("wevtutil", out.stdout)
        out = subprocess.run([*rasd, "explain", "T1685.005_event_log_clearing", "--tp", "1"],
                             cwd=ROOT / "detect" / "detections", capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)

    def test_command_outside_a_clone_says_how_to_install(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        shutil.copy(ROOT / "rasd.py", tmp / "rasd.py")
        out = subprocess.run([sys.executable, str(tmp / "rasd.py"), "lint"], capture_output=True, text=True)
        self.assertEqual(out.returncode, 2)
        self.assertIn("pip install -e .", out.stderr)


class Naming(unittest.TestCase):
    """One name per thing: the project is RASD and every run marker is rasd_ plus 8 hex characters."""

    # the project's earlier names: this guard is the only place they appear, built from parts so it does not match itself
    OLD = re.compile("|".join([r"purple[\s_-]?lab", "detection-as-code-" + "purple", "Purple" + "Emulation"]), re.I)
    MARKER = "^rasd_[0-9a-f]{8}$"

    def tracked_text(self):
        git = shutil.which("git")
        out = subprocess.run([git, "ls-files", "-z"], cwd=ROOT, capture_output=True, text=True) if git else None
        if out is None or out.returncode or not out.stdout:
            self.skipTest("needs git and a git checkout")
        for name in out.stdout.split("\0"):
            if not name or name.startswith("datasets/extracts/"):
                continue
            try:
                yield name, (ROOT / name).read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue

    def test_no_file_uses_an_old_project_name_even_inside_base64(self):
        import base64
        import binascii
        token = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
        found = []
        for name, text in self.tracked_text():
            found += [f"{name}: {m.group(0)}" for m in self.OLD.finditer(text)]
            for m in token.finditer(text):
                raw = m.group(0).rstrip("=")
                try:
                    data = base64.b64decode(raw[: len(raw) // 4 * 4], validate=True)
                except (binascii.Error, ValueError):
                    continue
                for enc in ("utf-16-le", "utf-8"):
                    decoded = data.decode(enc, errors="ignore")
                    if self.OLD.search(decoded):
                        found.append(f"{name}: base64 of {decoded[:60]!r}")
        self.assertEqual(found, [])

    def test_every_runner_and_script_checks_the_same_marker_format(self):
        from common import MARKER_RE
        sys.path.insert(0, str(ROOT / "red" / "web"))
        import rasd_web
        self.assertEqual(MARKER_RE.pattern, self.MARKER)
        self.assertEqual(rasd_web.MARKER_RE.pattern, self.MARKER)
        seen = 0
        for path in sorted((ROOT / "red").rglob("*")):
            if path.suffix not in (".ps1", ".sh", ".py") or not path.is_file():
                continue
            text = path.read_text(encoding="utf-8")
            for pattern in re.findall(r"ValidatePattern\('([^']*)'\)\]\s*\[string\]\s*\$Marker", text):
                self.assertEqual(pattern, self.MARKER, path)
                seen += 1
            for pattern in re.findall(r'\[\[ "\$marker" =~ (\S+) \]\]', text):
                self.assertEqual(pattern, self.MARKER, path)
                seen += 1
            for prefix in re.findall(r"""(?:\$Marker|marker) = ['"]([a-z]+_)['"] \+""", text):
                self.assertEqual(prefix, "rasd_", path)
                seen += 1
        self.assertGreater(seen, 40)

    def test_a_technique_has_one_name_and_tactics_come_from_one_list(self):
        import common
        import coverage
        self.assertIs(chain.TECHNIQUE_NAMES, common.TECHNIQUE_NAMES)
        self.assertEqual(coverage.TACTIC_ORDER, list(common.ATTACK_TACTICS))
        self.assertEqual(replay.TACTIC_ORDER, list(common.ATTACK_TACTICS))
        self.assertEqual(coverage.navigator_layer([])["versions"]["attack"], common.ATTACK_VERSION.split(".")[0])
        for tid, name in common.TECHNIQUE_NAMES.items():
            self.assertRegex(tid, r"^T\d{4}(\.\d{3})?$")
            self.assertEqual(name.count(": "), 1 if "." in tid else 0, f"{tid}: write it as ATT&CK does, Parent: Sub")
        test = next(t for t in red.load_tests() if t["id"] == "rundll32_execution")
        dets = {d.id: d for d in load_detections()}
        bad = copy.deepcopy(test)
        bad["mitre"]["technique_name"] = "System Binary Proxy Execution - Rundll32"
        bad["mitre"]["tactics"] = ["defence-evasion"]
        errs = " | ".join(red.check_test(bad, dets))
        version = common.ATTACK_VERSION
        self.assertIn(f'technique_name must be the ATT&CK v{version} name "System Binary Proxy Execution: Rundll32"', errs)
        self.assertIn(f"defence-evasion is not an ATT&CK v{version} tactic", errs)
        bad["mitre"]["technique"] = "T1218.010"
        self.assertIn("T1218.010 has no name in TECHNIQUE_NAMES", " | ".join(red.check_test(bad, dets)))
        self.assertEqual(common.attack_tag_errors(["attack.execution", "attack.t1059.001", "attack.g0007", "attack.s0002"]), [])
        errs = common.attack_tag_errors(["attack.defence-evasion", "attack.Execution", "attack.t1021.006", "attack.execution"])
        self.assertEqual(len(errs), 3, errs)
        self.assertIn("tag attack.execution is a tactic of none of the tagged techniques (T1021.006: lateral-movement)", errs)
        self.assertEqual(common.attack_tag_errors(["attack.t9999"]),
                         ["technique T9999 is not in the ATT&CK reference (TECHNIQUES in tools/common.py)"])
        bad = copy.deepcopy(test)
        bad["mitre"]["tactics"] = list(reversed(common.TECHNIQUE_TACTICS["T1218.011"])) + ["execution"]
        self.assertIn("mitre.tactics must be the tactics ATT&CK", " | ".join(red.check_test(bad, dets)))

    def test_links_to_a_detection_use_its_title_or_id_and_scenarios_name_their_technique(self):
        from common import TECHNIQUE_NAMES
        items = {d.folder.resolve(): (d.id, d.title) for d in load_detections()}
        items |= {c.folder.resolve(): (c.id, c.title) for c in load_correlations()}
        link = re.compile(r"\[([^\]\n]+)\]\(([^)\s#]+)(?:#[^)\s]*)?\)")
        wrong = []
        for name, text in self.tracked_text():
            if not name.endswith(".md"):
                continue
            for label, target in link.findall(text):
                dest = None if "://" in target else ((ROOT / name).parent / target).resolve()
                if dest in items and label.strip("`* ") not in items[dest]:
                    wrong.append(f"{name}: [{label}] -> {items[dest][0]}")
        self.assertEqual(wrong, [])
        for path in sorted((ROOT / "purple" / "scenarios").glob("*.md")):
            text = path.read_text(encoding="utf-8")
            tid = re.search(r"(?m)^technique: (\S+)$", text).group(1)
            self.assertRegex(text, rf"(?m)^# Purple Scenario: .+ \({re.escape(tid)} {re.escape(TECHNIQUE_NAMES[tid])}\)$",
                             path.name)


class SafetyAndConversion(unittest.TestCase):
    def test_web_tests_refuse_public_targets(self):
        sys.path.insert(0, str(ROOT / "red" / "web"))
        import rasd_web
        self.assertEqual(rasd_web.lab_target("http://127.0.0.1:3000/"), "http://127.0.0.1:3000")
        with self.assertRaises(rasd_web.Refused):
            rasd_web.lab_target("http://8.8.8.8")

    def test_python_runner_dry_run_plans_and_refuses_public_targets(self):
        run = [sys.executable, str(ROOT / "red" / "run_red.py"), "--lab-confirmed", "--dry-run"]
        plan = subprocess.run(run + ["--platform", "web", "linux", "--target", "http://127.0.0.1:3000"],
                              capture_output=True, text=True)
        self.assertEqual(plan.returncode, 0, plan.stderr)
        self.assertIn("cron_persistence", plan.stdout)
        self.assertIn("nothing was executed", plan.stdout)
        refused = subprocess.run(run + ["--test", "idor_testing", "--target", "http://8.8.8.8"], capture_output=True, text=True)
        self.assertEqual(refused.returncode, 2)
        self.assertIn("refused", refused.stdout)
        self.assertFalse((ROOT / "red" / "results").exists() and any(
            p.stat().st_mtime > __import__("time").time() - 5 for p in (ROOT / "red" / "results").iterdir()),
            "a dry run must not write results")

    def test_runner_requires_lab_confirmation(self):
        r = subprocess.run([sys.executable, str(ROOT / "red" / "run_red.py"), "--test", "suspicious_shell_execution"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertIn("--lab-confirmed", r.stderr)

    def test_lab_address_is_loopback_rfc1918_or_ula_only(self):
        import ipaddress
        sys.path.insert(0, str(ROOT / "red" / "web"))
        import rasd_web
        ok = ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "::1", "fd00::1", "::ffff:10.0.0.1"]
        bad = ["169.254.1.1", "192.0.2.1", "198.18.0.1", "100.64.0.1", "8.8.8.8", "fe80::1"]
        self.assertTrue(all(rasd_web.lab_address(ipaddress.ip_address(a)) for a in ok))
        self.assertFalse(any(rasd_web.lab_address(ipaddress.ip_address(a)) for a in bad))

    def test_every_set_cookie_header_is_kept(self):
        import http.server
        import threading
        sys.path.insert(0, str(ROOT / "red" / "web"))
        sys.path.insert(0, str(ROOT / "red" / "web" / "security_headers_testing"))
        import rasd_web
        import emulate_security_headers

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Set-Cookie", "a=securevalue; Path=/")
                self.send_header("Set-Cookie", "b=2; Secure; HttpOnly; SameSite=Lax")
                self.end_headers()

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)        # cleanups run last-in first-out: shutdown, then close
        self.addCleanup(server.shutdown)
        client = rasd_web.Client(f"http://127.0.0.1:{server.server_port}", "rasd_1a2b3c4d")
        _status, headers, _body = client.request("GET", "/")
        cookies = headers.get_all("Set-Cookie")
        self.assertEqual(len(cookies), 2)
        self.assertEqual(emulate_security_headers.cookie_attributes(cookies[0]), ("a", {"path"}))   # 'secure' in a value is no flag
        self.assertEqual(emulate_security_headers.cookie_attributes(cookies[1])[1], {"secure", "httponly", "samesite"})

    def test_web_client_never_follows_a_redirect_or_reaches_an_unchecked_host(self):
        import http.server
        import threading
        sys.path.insert(0, str(ROOT / "red" / "web"))
        import rasd_web

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "http://8.8.8.8/stolen")     # a lab app redirecting to the internet
                self.end_headers()

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        client = rasd_web.Client(f"http://127.0.0.1:{server.server_port}", "rasd_1a2b3c4d")
        status, headers, _body = client.request("GET", "/")
        self.assertEqual(status, 302)                                    # reported, not followed
        self.assertEqual(headers.get("Location"), "http://8.8.8.8/stolen")
        with self.assertRaises(rasd_web.Refused):                        # a name lab_target never checked
            rasd_web.pinned_addresses("unchecked.example")
        with self.assertRaises(rasd_web.Refused):                        # a client cannot be built for a public target
            rasd_web.Client("http://8.8.8.8", "rasd_1a2b3c4d")

    def test_hunt_copies_of_a_rule_regex_stay_in_sync(self):
        import re as _re
        rule_rx = find_detection("T1059.001").rule["detection"]["selection_enc"]["CommandLine|re"]
        kql = (ROOT / "queries" / "hunts" / "powershell_encoded_with_network_or_child.kql").read_text(encoding="utf-8")
        spl = (ROOT / "queries" / "hunts" / "powershell_encoded_with_network_or_child.spl").read_text(encoding="utf-8")
        self.assertEqual(_re.search(r'matches regex @"((?:[^"]|"")*)"', kql).group(1).replace('""', '"'), rule_rx)
        self.assertEqual(_re.search(r'\| regex CommandLine="((?:[^"\\]|\\.)*)"', spl).group(1).replace('\\"', '"'), rule_rx)

    def test_off_hours_uses_local_time(self):
        ev = {"UtcTime": "2026-10-12 17:30:00.000"}                      # 17:30 UTC = 20:30 at UTC+3
        self.assertFalse(replay.RiskContext().resolve("outside_business_hours", ev, "h"))
        self.assertTrue(replay.RiskContext(utc_offset=3).resolve("outside_business_hours", ev, "h"))

    def test_spl_negation_is_null_safe_and_positive_side_untouched(self):
        rule = {"logsource": {"category": "process_creation"},
                "detection": {"sel": {"Image|endswith": "\\a.exe"}, "f": {"ParentImage|endswith": "\\b.exe"},
                              "condition": "sel and not f"}}
        spl = convert.convert(rule, "spl")
        self.assertIn("match('Image'", spl)
        self.assertIn("NOT (match(coalesce('ParentImage', \"\")", spl)


class LinuxTelemetry(unittest.TestCase):
    """Sysmon for Linux: the exporter's output routes to linux/process_creation and the rules fire on it."""
    LINE = ('Oct 13 10:00:00 lab-lnx01 sysmon: <Event><System><Provider Name="Linux-Sysmon" '
            'Guid="{ff032593-a8d3-4f13-b0d6-01fc615a0f97}"/><EventID>1</EventID><Version>5</Version>'
            '<TimeCreated SystemTime="2026-10-13T10:00:00.123456789Z"/><Channel>Linux-Sysmon/Operational</Channel>'
            '<Computer>lab-lnx01</Computer></System><EventData><Data Name="RuleName">-</Data>'
            '<Data Name="UtcTime">2026-10-13 10:00:00.120</Data><Data Name="ProcessId">2481</Data>'
            '<Data Name="Image">/usr/bin/crontab</Data><Data Name="CommandLine">crontab -</Data>'
            '<Data Name="ParentImage">/usr/bin/bash</Data><Data Name="User">labuser</Data></EventData></Event>')

    def setUp(self):
        sys.path.insert(0, str(ROOT / "red" / "linux"))
        import export_sysmon_linux
        self.ex = export_sysmon_linux

    def test_syslog_line_becomes_a_routed_event(self):
        evs = list(self.ex.read_events([self.LINE, "Oct 13 10:00:01 lab-lnx01 cron[1]: unrelated"],
                                       self.ex.parse_since("2026-10-13T09:00:00Z"), {1}))
        self.assertEqual(len(evs), 1)
        ev = evs[0]
        self.assertEqual((ev["EventID"], ev["Channel"], ev["Computer"], ev["Image"]),
                         (1, "Linux-Sysmon/Operational", "lab-lnx01", "/usr/bin/crontab"))
        self.assertEqual(replay.route(ev), "linux/process_creation")
        self.assertTrue(matches(find_detection("T1053.003").rule, ev))
        self.assertFalse(matches(find_detection("T1059.001").rule, ev))      # a Windows rule never reads it

    def test_window_and_event_ids_filter(self):
        since = self.ex.parse_since("2026-10-13T11:00:00Z")
        self.assertEqual(list(self.ex.read_events([self.LINE], since, {1})), [])
        self.assertEqual(list(self.ex.read_events([self.LINE], self.ex.parse_since("2026-10-13T09:00:00Z"), {11})), [])

    def test_windows_sysmon_still_routes_to_windows(self):
        self.assertEqual(replay.route({"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1}), "process_creation")
        self.assertEqual(replay.route({"EventID": 1, "Image": "C:\\Windows\\System32\\cmd.exe"}), "process_creation")
        self.assertEqual(replay.route({"EventID": 1, "Image": "/usr/bin/dash"}), "linux/process_creation")
        self.assertEqual(convert.logsource_key({"logsource": {"product": "linux", "category": "process_creation"}}),
                         "linux/process_creation")
        self.assertEqual(convert.logsource_key({"logsource": {"product": "windows", "category": "process_creation"}}),
                         "process_creation")


class WebTelemetry(unittest.TestCase):
    """Access logs: the exporter's output routes to webserver and the web correlations fire on a lab run."""
    PATHS: ClassVar[list] = ["/rest/basket/1", "/api/Cards", "/api/Users", "/api/Addresss", "/rest/wallet/balance",
             "/rest/user/authentication-details"]

    def setUp(self):
        sys.path.insert(0, str(ROOT / "red" / "web"))
        import export_access_log
        self.ex = export_access_log

    def line(self, second, path, status, agent="RASD-Red/rasd_1a2b3c4d"):
        return (f'127.0.0.1 - - [13/Oct/2026:10:01:{second:02d} +0000] "GET {path} HTTP/1.1" {status} 31 "-" "{agent}"')

    def test_combined_line_becomes_a_routed_event(self):
        ev = self.ex.parse_line(self.line(0, "/api/Cards?x=1", 401))
        self.assertEqual((ev["c-ip"], ev["cs-method"], ev["cs-uri-stem"], ev["cs-uri-query"], ev["sc-status"]),
                         ("127.0.0.1", "GET", "/api/Cards", "x=1", "401"))
        self.assertEqual(ev["TimeCreated"], "2026-10-13T10:01:00Z")
        self.assertEqual(replay.route(ev), "webserver")
        self.assertIsNone(self.ex.parse_line("not an access log line"))

    def test_lab_run_fires_the_api_probing_correlation(self):
        from correlation import evaluate
        lines = [self.line(i // 3, p, 401) for i, p in enumerate(q for q in self.PATHS for _ in range(3))]
        lines.append(self.line(30, "/api/Products", 200, agent="Mozilla/5.0"))
        evs = list(self.ex.read_events(lines, self.ex.parse_since("2026-10-13T10:00:00Z"), "rasd_1a2b3c4d"))
        self.assertEqual(len(evs), 18)                                   # the marker keeps only the run's requests
        corr = next(c for c in load_correlations() if c.id == "T1595.003_api_auth_probing")
        alerts = evaluate(corr, evs)
        self.assertEqual(len(alerts), 1)
        self.assertEqual((alerts[0]["value_count"], alerts[0]["group"]), (6, {"c-ip": "127.0.0.1"}))

    def test_loopback_target_binds_web_evidence(self):
        sys.path.insert(0, str(ROOT / "red"))
        import run_red
        self.assertTrue(run_red.target_is_loopback("http://127.0.0.1:3000"))
        step = {"host": "lab-ws01", "host_ips": ["10.0.0.21", "127.0.0.1", "::1"]}
        self.assertTrue(evidence.is_host("127.0.0.1", step))
        self.assertIn("c-ip", evidence.CLIENT_FIELDS)


class Banner(unittest.TestCase):
    def test_plain_render_and_svg(self):
        text = banner.render(color=False)
        self.assertIn("Attack-to-Defense Validation Framework", text)
        self.assertIn("Red → Detect → DFIR → Intel → Purple", text)
        self.assertNotIn("\033[", text)
        svg = banner.svg()
        self.assertTrue(svg.startswith("<svg") and svg.rstrip().endswith("</svg>"))


if __name__ == "__main__":
    unittest.main()
