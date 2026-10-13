"""Tests for the RASD toolchain: fuzzer, replay, doctor, explain, linter, banner (python -m unittest)."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

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
import validate  # noqa: E402
from common import find_detection, load_detections, load_jsonl  # noqa: E402
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


class Doctor(unittest.TestCase):
    def test_ecs_export_gets_mapping_fixes(self):
        res = {r["detection"]: r for r in doctor.diagnose(load_jsonl(ROOT / "samples" / "doctor" / "ecs-export.jsonl"), load_detections())}
        r = res["T1059.001_powershell_encoded_command"]
        self.assertEqual(r["verdict"], "BLIND")
        self.assertIn("add 'CommandLine: [process.command_line]' for process_creation to a profile in mappings/ "
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
    RULE = {"detection": {"sel": {"Image|endswith": ["\\a.exe", "\\b.exe"], "CommandLine|contains": "x"},
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
             "status": "executed", "host": "LAB-WS01", "user": "LAB\\lama", "marker": "purplelab_t",
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
        self.steps[1]["detections"].append("T1070.001_security_log_cleared")          # expected, never logged
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
        step = {"host": "LAB-WS01", "host_ips": ["10.10.10.21", "fe80::1"], "marker": "purplelab_0badf00d",
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
        self.assertEqual(len(evidence.find_hits(det, {**base, "marker": "purplelab_1a2b3c4d"}, [ev], grace=60)), 1)
        self.assertEqual(evidence.find_hits(det, {**base, "marker": "purplelab_ffffffff"}, [ev], grace=60), [])
        self.assertEqual(evidence.find_hits(det, {**base, "marker": ""}, [ev], grace=60), [])      # no marker, no binding

    def test_netbios_name_binds_workstation_fields(self):
        step = {"host": "lab-workstation-0001", "host_netbios": "LAB-WORKSTATION", "host_ips": []}
        ntlm = {"EventID": 4776, "Computer": "DC01.lab.local", "Workstation": "LAB-WORKSTATION"}
        self.assertTrue(evidence.on_host(ntlm, step)[0])
        self.assertTrue(evidence.on_host({"EventID": 1, "Computer": "LAB-WORKSTATION-0001.lab.local"}, step)[0])
        self.assertFalse(evidence.on_host({**ntlm, "Workstation": "OTHER-WS"}, step)[0])

    def test_red_check_requires_the_mirrored_event_to_carry_the_token(self):
        dets = {d.id: d for d in load_detections()}
        test = next(t for t in red.load_tests() if t["id"] == "service_creation")
        self.assertEqual(red.check_test(test, dets), [])
        test["steps"][0]["bind"] = {"T1569.002_suspicious_service_installation": "R{hex}"}
        self.assertTrue(any("bind token" in e for e in red.check_test(test, dets)))
        test["steps"][0]["bind"] = {"T1569.002_suspicious_service_installation": "static"}
        self.assertTrue(any("{marker} or {hex}" in e for e in red.check_test(test, dets)))


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
            self.assertEqual(path.read_text(encoding="utf-8"), body, f"{path} is stale - run: python rasd.py build")

    def test_provider_name_extraction_matches_windows_xml(self):
        import re as _re
        props = self.files[splunk_app.OUT / "rasd" / "default" / "props.conf"]
        pcre = _re.search(r"EXTRACT-rasd_provider_name = (.+)", props).group(1)
        rx = _re.compile(pcre.replace("(?<", "(?P<"))
        xml = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Service Control Manager' Guid='{555908d1-a6d7-4695-8e1e-26931d2012f4}' EventSourceName='Service Control Manager'/><EventID Qualifiers='16384'>7045</EventID>"
        self.assertEqual(rx.search(xml).group("Provider_Name"), "Service Control Manager")

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
        root = ET.parse(ROOT / "red" / "lab" / "sysmon-rasd.xml").getroot()
        groups = {child.tag: child for rg in root.iter("RuleGroup") for child in rg}
        self.assertEqual(groups["ProcessCreate"].get("onmatch"), "exclude")              # every process
        self.assertEqual(len(groups["ProcessCreate"]), 0)
        self.assertTrue(any(f.text.endswith("lsass.exe") for f in groups["ProcessAccess"]))
        self.assertTrue(any("CurrentVersion\\Run" in f.text for f in groups["RegistryEvent"]))


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
            self.assertTrue(any(self.verdicts(r) != sorted(ev["_expect"]) for r, ev in zip(raw, expected)),
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
        self.assertTrue(profiles.write_readme(check=True), "mappings/README.md is stale - run: python rasd.py build")

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
            self.assertEqual(c["Operational score"], "pending")


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
        client = rasd_web.Client(f"http://127.0.0.1:{server.server_port}", "purplelab_1a2b3c4d")
        _status, headers, _body = client.request("GET", "/")
        cookies = headers.get_all("Set-Cookie")
        self.assertEqual(len(cookies), 2)
        self.assertEqual(emulate_security_headers.cookie_attributes(cookies[0]), ("a", {"path"}))   # 'secure' in a value is no flag
        self.assertEqual(emulate_security_headers.cookie_attributes(cookies[1])[1], {"secure", "httponly", "samesite"})

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
