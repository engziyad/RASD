"""RASD-Health: is every detection still being fed?"""
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import health  # noqa: E402
import splunk_app  # noqa: E402
from common import load_detections  # noqa: E402
from convert import MAPPINGS  # noqa: E402
from correlation import load_correlations  # noqa: E402

SYSMON, SECURITY = "Microsoft-Windows-Sysmon/Operational", "Security"
TUESDAY = datetime(2026, 11, 3, 6, 0, 0)
FRIDAY = TUESDAY + timedelta(days=3)

PROCESS = health.Need("D_process", "a process rule", "process_creation", (), ("Image", "CommandLine", "OriginalFileName"), {},
                      frozenset({"Image", "CommandLine"}), 300, "RASD - D_process")
LOGON = health.Need("D_logon", "a logon rule", "windows/security", ("4625", "4771"), ("TargetUserName", "SubStatus"),
                    {"SubStatus": frozenset({"4625"})}, frozenset({"TargetUserName", "SubStatus"}), 300, "RASD - D_logon")
CLEARED = health.Need("D_cleared", "a log-clear rule", "windows/security", ("1102",), ("EventID",), {}, frozenset({"EventID"}), 300,
                      "RASD - D_cleared")
COUNTED = health.Need("D_counted", "a correlation", "windows/security", ("4625",), ("TargetUserName",), {},
                      frozenset({"TargetUserName"}), 180, "RASD - D_counted")
WANTED = [PROCESS, LOGON, CLEARED, COUNTED]


def iso(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def process(t: datetime, host: str, lag: float | None = None, **fields) -> dict:
    ev = {"TimeCreated": iso(t), "Channel": SYSMON, "Computer": f"{host}.corp.lab", "EventID": 1, "Image": "C:\\Windows\\System32\\cmd.exe",
          "OriginalFileName": "Cmd.Exe", "CommandLine": "cmd.exe /c echo ok", **fields}
    return ev if lag is None else {**ev, "IngestionTime": iso(t + timedelta(seconds=lag))}


def security(t: datetime, host: str, eid: int, lag: float | None = None, **fields) -> dict:
    ev = {"TimeCreated": iso(t), "Channel": SECURITY, "Computer": f"{host}.corp.lab", "EventID": eid, "TargetUserName": "amal", **fields}
    if eid == 4625:
        ev.setdefault("SubStatus", "0xc000006a")
    return ev if lag is None else {**ev, "IngestionTime": iso(t + timedelta(seconds=lag))}


def stretch(start: datetime, end: datetime, minutes: int, make, hours: tuple[int, int] = (0, 24), weekdays: bool = False) -> list[dict]:
    """One event every so many minutes between two moments, inside the given hours of the day."""
    out, t = [], start
    while t < end:
        if hours[0] <= t.hour < hours[1] and not (weekdays and t.weekday() >= 5):
            out.append(make(t))
        t += timedelta(minutes=minutes)
    return out


def office(start: datetime, end: datetime, hosts=("ws01", "ws02"), minutes: int = 10, **fields) -> list[dict]:
    return [e for h in hosts for e in stretch(start, end, minutes, lambda t, h=h: process(t, h, **fields), (8, 18))]


def verdict(base_events, cur_events, need=PROCESS, scheduler=None, until=None) -> health.Verdict:
    base = health.measure(base_events, WANTED, until=FRIDAY)
    cur = health.measure(cur_events, WANTED, until=until)
    return health.judge(need, base, cur, scheduler)


def checks(v: health.Verdict) -> list[tuple[str, str]]:
    return [(f.check, f.level) for f in v.findings if f.level != "note"]


class WhatTheLibraryReads(unittest.TestCase):
    def test_every_detection_and_correlation_has_a_need(self):
        wanted = health.needs()
        ids = [d.id for d in load_detections()] + [c.id for c in load_correlations()]
        self.assertEqual(sorted(n.detection for n in wanted), sorted(ids))
        by_id = {n.detection: n for n in wanted}
        self.assertEqual(by_id["T1003.001_lsass_memory_access"].feeds, ("process_access",))
        self.assertEqual(by_id["T1558.003_kerberoasting_rc4_tgs"].feeds, ("windows/security#4769",))
        self.assertEqual(by_id["T1078.002_honey_account_authentication"].ids, ("4624", "4625", "4768", "4771", "4776"))
        self.assertEqual(by_id["T1059.001_powershell_encoded_command"].search, "RASD - T1059.001_powershell_encoded_command")

    def test_the_wait_is_the_one_the_splunk_app_schedules(self):
        by_id = {n.detection: n for n in health.needs()}
        self.assertEqual(splunk_app.WINDOW_END, "-5m@m")
        self.assertEqual(by_id["T1059.001_powershell_encoded_command"].allowance, 300)
        self.assertEqual(by_id["T1110.003_password_spray_burst"].allowance, splunk_app.CORRELATION_LAG * 60)

    def test_a_field_belongs_to_the_event_ids_it_is_read_with(self):
        self.assertTrue(LOGON.reads("windows/security#4625", "SubStatus"))
        self.assertFalse(LOGON.reads("windows/security#4771", "SubStatus"))
        self.assertEqual(health.feed_fields([LOGON]), {"windows/security#4625": ["TargetUserName", "SubStatus"],
                                                       "windows/security#4771": ["TargetUserName"]})


class Measuring(unittest.TestCase):
    def test_an_export_is_counted_by_what_the_rules_read(self):
        events = [process(TUESDAY, "WS01"), process(TUESDAY + timedelta(hours=1), "WS01", CommandLine=""),
                  security(TUESDAY, "DC01", 4625), security(TUESDAY, "DC01", 4624),
                  {"TimeCreated": iso(TUESDAY), "Channel": "Application", "Computer": "WS01.corp.lab", "EventID": 1000},
                  {"Channel": SYSMON, "Computer": "WS01.corp.lab", "EventID": 1}]
        m = health.measure(events, WANTED)
        self.assertEqual((m.events, m.undated, sorted(m.hosts)), (5, 1, ["dc01", "ws01"]))
        self.assertEqual(sorted(m.feeds), ["process_creation", "windows/security#4625"])
        feed = m.feeds["process_creation"]
        self.assertEqual((feed.events, feed.present["Image"], feed.present["CommandLine"]), (2, 2, 1))
        self.assertEqual(feed.hosts["ws01"].hours, {TUESDAY.weekday() * 24 + 6: 1, TUESDAY.weekday() * 24 + 7: 1})
        self.assertEqual(sorted(m.carriers), ["application", "microsoft-windows-sysmon/operational", "security"])
        self.assertEqual(m.carriers["security"]["dc01"].events, 2, "the channel carries every event, read by a rule or not")

    def test_times_are_read_as_text_or_as_seconds(self):
        self.assertEqual(health.to_time("2026-11-03T06:00:00Z"), TUESDAY)
        self.assertEqual(health.to_time(1793685600), TUESDAY)
        self.assertEqual(health.to_time("1793685600.5"), TUESDAY + timedelta(milliseconds=500))
        for bad in (None, "", "soon", True, [1]):
            self.assertIsNone(health.to_time(bad))

    def test_until_moves_the_end_of_an_export_that_was_taken_later(self):
        m = health.measure([process(TUESDAY, "ws01")], WANTED, until=TUESDAY + timedelta(hours=5))
        self.assertEqual(m.hours, 5)
        self.assertEqual(health.measure([process(TUESDAY, "ws01")], WANTED, until=TUESDAY - timedelta(hours=1)).end, TUESDAY)

    def test_a_short_baseline_is_read_by_hour_of_day_and_a_long_one_by_hour_of_week(self):
        monday = datetime(2026, 11, 2)
        events = stretch(monday, monday + timedelta(days=14), 10, lambda t: process(t, "ws01"), (9, 17), weekdays=True)
        base = health.measure(events, WANTED, until=monday + timedelta(days=14))
        flow = base.feeds["process_creation"].hosts["ws01"]
        saturday = monday + timedelta(days=19)
        self.assertEqual(health.expected(flow, base, saturday, saturday + timedelta(days=1)), 0)
        self.assertAlmostEqual(health.expected(flow, base, saturday + timedelta(days=2), saturday + timedelta(days=3)), 48)
        self.assertAlmostEqual(health.expected(flow, base, saturday + timedelta(days=2, hours=9, minutes=30),
                                               saturday + timedelta(days=2, hours=10)), 3)
        short = health.measure([e for e in events if e["TimeCreated"] < iso(monday + timedelta(days=3))], WANTED,
                               until=monday + timedelta(days=3))
        self.assertAlmostEqual(health.expected(short.feeds["process_creation"].hosts["ws01"], short, saturday,
                                               saturday + timedelta(days=1)), 48, msg="three days cannot know what a Saturday is")

    def test_the_baseline_profile_keeps_what_the_judge_needs_and_no_event(self):
        events = office(TUESDAY, FRIDAY, lag=5) + stretch(TUESDAY, FRIDAY, 30, lambda t: security(t, "dc01", 4625, lag=9))
        m = health.measure(events, WANTED, until=FRIDAY)
        doc = health.to_baseline(m)
        text = json.dumps(doc)
        self.assertNotIn("cmd.exe /c echo ok", text)
        self.assertNotIn("amal", text)
        again = health.from_baseline(json.loads(text))
        self.assertEqual(health.to_baseline(again), doc)
        today = office(FRIDAY, FRIDAY + timedelta(days=1), hosts=("ws01",))
        cur = health.measure(today, WANTED)
        self.assertEqual(checks(health.judge(PROCESS, again, cur)), checks(health.judge(PROCESS, m, cur)))
        self.assertEqual(doc["lag"]["security|dc01"], {"n": 144, "p50": 9.0, "p95": 9.0})

    def test_a_file_that_is_not_a_baseline_is_refused(self):
        for doc in ({}, {"rasd_health_baseline": 2}, {"rasd_health_baseline": 1}, {"rasd_health_baseline": 1, "start": "x", "end": "y", "events": 1},
                    {"rasd_health_baseline": 1, "start": iso(TUESDAY), "end": iso(FRIDAY), "events": 1,
                     "feeds": {"process_creation": {"events": 1, "hosts": {"a": {"events": 1, "hours": {"999": 1}}}}}}):
            with self.assertRaises(health.HealthError, msg=doc):
                health.from_baseline(doc)


class Verdicts(unittest.TestCase):
    def setUp(self):
        self.base = office(TUESDAY, FRIDAY)
        self.day = FRIDAY + timedelta(days=1)

    def test_a_day_like_the_baseline_is_healthy(self):
        v = verdict(self.base, office(FRIDAY, self.day))
        self.assertEqual((v.verdict, v.findings), ("healthy", []))

    def test_a_host_that_stops_in_working_hours_is_silent_and_one_asleep_at_night_is_not(self):
        stops = FRIDAY + timedelta(hours=5)                                       # 11:00
        today = office(FRIDAY, self.day, hosts=("ws01",)) + office(FRIDAY, stops, hosts=("ws02",))
        today.append(security(FRIDAY + timedelta(hours=9), "ws02", 4624))        # still up: its Security log arrives
        v = verdict(self.base, today)
        self.assertEqual((v.verdict, checks(v)), ("degraded", [("silent", "degraded")]))
        self.assertIn("1 of 2 hosts silent (ws02 still sends other events, and none of this kind since 2026-11-06 10:50)",
                      v.findings[0].text)
        self.assertIn("about 42 events", v.findings[0].text)
        evening = office(FRIDAY, FRIDAY + timedelta(hours=12))                    # exported at 23:00, after everyone left
        self.assertEqual(verdict(self.base, evening, until=FRIDAY + timedelta(hours=17)).verdict, "healthy")

    def test_a_host_that_sends_nothing_at_all_is_told_apart_from_a_log_that_stopped(self):
        v = verdict(self.base, office(FRIDAY, self.day, hosts=("ws01",)))
        self.assertIn("ws02 sends nothing at all", v.findings[0].text)
        self.assertEqual(v.findings[0].fix, "the host is down or its forwarder stopped")

    def test_every_host_silent_is_blind(self):
        today = [security(FRIDAY + timedelta(hours=h), "ws01", 4624) for h in range(24)]
        v = verdict(self.base, today)
        self.assertEqual((v.verdict, checks(v)), ("blind", [("silent", "blind")]))
        self.assertIn("every host that sent it is silent", v.findings[0].text)

    def test_an_export_too_short_to_tell_says_nothing(self):
        early = office(FRIDAY, FRIDAY + timedelta(hours=4), hosts=("ws01",))      # 06:00 to 10:00: ws02 would have sent 12
        self.assertEqual(verdict(self.base, early).verdict, "healthy")

    def test_volume_that_falls_on_hosts_still_sending_is_degraded(self):
        v = verdict(self.base, office(FRIDAY, self.day, minutes=60))
        self.assertEqual((v.verdict, checks(v)), ("degraded", [("volume", "degraded")]))
        self.assertIn("20 events where the baseline saw about 108 over the same hours (19%)", v.findings[0].text,
                      "the export spans 08:00 to 17:00: nine hours of two hosts at six an hour")
        self.assertEqual(verdict(self.base, office(FRIDAY, self.day, minutes=30)).verdict, "healthy", "a third is not a quarter")

    def test_a_field_the_rule_cannot_work_without_is_blind_when_lost_and_names_its_new_name(self):
        renamed = [{k: v for k, v in e.items() if k != "CommandLine"} | {"process.command_line": e["CommandLine"]}
                   for e in office(FRIDAY, self.day)]
        v = verdict(self.base, renamed)
        self.assertEqual((v.verdict, checks(v)), ("blind", [("fields", "blind")]))
        self.assertIn("the same events now carry process.command_line", v.findings[0].text)
        self.assertEqual(v.findings[0].fix, "map process.command_line to CommandLine (a profile in profiles/, or a field alias in the SIEM)")

    def test_a_field_the_rule_can_work_without_degrades_it(self):
        dropped = [{k: v for k, v in e.items() if k != "OriginalFileName"} for e in office(FRIDAY, self.day)]
        v = verdict(self.base, dropped)
        self.assertEqual((v.verdict, checks(v)), ("degraded", [("fields", "degraded")]))
        self.assertNotIn("now carry", v.findings[0].text)

    def test_a_field_filled_less_often_is_degraded(self):
        today = office(FRIDAY, self.day)
        for e in today[::3]:
            e["CommandLine"] = ""
        v = verdict(self.base, today)
        self.assertEqual(checks(v), [("fields", "degraded")])
        self.assertIn("filled in 67% of events (the baseline: 100%)", v.findings[0].text)
        for e in today[::3]:
            e["CommandLine"] = "x"
        for e in today[::10]:
            e["CommandLine"] = ""
        self.assertEqual(verdict(self.base, today).verdict, "healthy", "ten points are within what a pipeline does on its own")

    def test_command_lines_cut_at_one_length_are_degraded(self):
        long = "powershell.exe -enc " + "A" * 1500
        today = office(FRIDAY, self.day)
        for e in today[::5]:
            e["CommandLine"] = long[:1024]
        v = verdict(self.base, today)
        self.assertEqual(checks(v), [("truncation", "degraded")])
        self.assertIn("cut at 1024 characters", v.findings[0].text)
        cut_before = self.base[:]
        for e in cut_before[::5]:
            e["CommandLine"] = long[:1024]
        self.assertEqual(verdict(cut_before, today).verdict, "healthy", "a limit the baseline already had is not news")

    def test_events_that_arrive_after_the_search_has_looked(self):
        base = office(TUESDAY, FRIDAY, lag=8)
        late = office(FRIDAY, self.day, hosts=("ws01",), lag=8) + office(FRIDAY, self.day, hosts=("ws02",), lag=1500)
        v = verdict(base, late)
        self.assertEqual((v.verdict, checks(v)), ("degraded", [("delay", "degraded")]))
        self.assertIn("microsoft-windows-sysmon/operational from ws02: 100% of its events", v.findings[0].text)
        self.assertIn("95% within 25 min; the baseline: 8 s", v.findings[0].text)
        v = verdict(base, office(FRIDAY, self.day, lag=1500))
        self.assertEqual((v.verdict, [c for c, _l in checks(v)]), ("blind", ["delay", "delay"]), "no host's events are read in time")
        self.assertEqual(verdict(base, office(FRIDAY, self.day, lag=290)).verdict, "healthy", "inside the wait")

    def test_a_correlation_waits_less_than_a_single_event_rule(self):
        base = stretch(TUESDAY, FRIDAY, 30, lambda t: security(t, "dc01", 4625, lag=5))
        today = stretch(FRIDAY, self.day, 30, lambda t: security(t, "dc01", 4625, lag=240))
        self.assertEqual(verdict(base, today, COUNTED).verdict, "blind")
        self.assertEqual([c for c in checks(verdict(base, today, LOGON)) if c[0] == "delay"], [])

    def test_a_rare_event_is_judged_by_the_channel_that_carries_it(self):
        base = stretch(TUESDAY, FRIDAY, 20, lambda t: security(t, "dc01", 4624)) + [security(TUESDAY + timedelta(hours=30), "dc01", 4771)]
        alive = stretch(FRIDAY, self.day, 20, lambda t: security(t, "dc01", 4624))
        v = verdict(base, alive, LOGON)
        self.assertEqual((v.verdict, checks(v)), ("healthy", []))
        self.assertTrue(any("too rare to judge by its own volume (1 in the baseline); judged by its channel, security" in f.text
                            for f in v.findings))
        stopped = stretch(FRIDAY, FRIDAY + timedelta(hours=3), 20, lambda t: security(t, "dc01", 4624))
        stopped += office(FRIDAY, self.day, hosts=("dc01",))
        v = verdict(base, stopped, LOGON, until=self.day)
        self.assertEqual(v.verdict, "blind")
        self.assertIn("windows/security event 4771: every host that sent it is silent (dc01 still sends other events", v.findings[-1].text)

    def test_an_event_never_seen_is_judged_by_its_log_sources_channel(self):
        base = stretch(TUESDAY, FRIDAY, 20, lambda t: security(t, "dc01", 4625)) + stretch(TUESDAY, FRIDAY, 20,
                                                                                         lambda t: security(t, "ws01", 4624))
        today = stretch(FRIDAY, self.day, 20, lambda t: security(t, "dc01", 4625))
        v = verdict(base, today, CLEARED)
        self.assertEqual((v.verdict, checks(v)), ("degraded", [("silent", "degraded")]))
        self.assertIn("windows/security event 1102: 1 of 2 hosts silent (ws01 sends nothing at all)", v.findings[1].text)
        self.assertIn("never seen in the baseline; judged by its channel, security (2 hosts)", v.findings[0].text)
        v = verdict(self.base, office(FRIDAY, self.day), CLEARED)
        self.assertEqual(v.verdict, "unknown")
        self.assertIn("nothing to compare (rasd doctor says whether it is collected at all)", v.findings[0].text)

    def test_a_rule_with_several_event_ids_is_blind_only_when_all_of_them_are(self):
        base = (stretch(TUESDAY, FRIDAY, 20, lambda t: security(t, "dc01", 4625))
                + stretch(TUESDAY, FRIDAY, 20, lambda t: security(t, "dc01", 4771)))
        one = stretch(FRIDAY, self.day, 20, lambda t: security(t, "dc01", 4625))
        v = verdict(base, one, LOGON)
        self.assertEqual((v.verdict, checks(v)), ("degraded", [("silent", "blind")]))
        none = stretch(FRIDAY, self.day, 20, lambda t: security(t, "dc01", 4624))
        self.assertEqual(verdict(base, none, LOGON).verdict, "blind")

    def test_the_scheduler_record_names_searches_that_did_not_look(self):
        today = office(FRIDAY, self.day)
        def runs(ok: int, bad: int) -> dict:
            return {"RASD - D_process": {"runs": ok + bad, "bad": bad, "reasons": Counter({"maxconcurrent": bad})}}

        self.assertEqual(verdict(self.base, today, scheduler=runs(100, 0)).verdict, "healthy")
        self.assertEqual(verdict(self.base, today, scheduler=runs(97, 3)).verdict, "healthy")
        v = verdict(self.base, today, scheduler=runs(80, 20))
        self.assertEqual((v.verdict, checks(v)), ("degraded", [("schedule", "degraded")]))
        self.assertIn("20 of 100 scheduled runs did not complete (maxconcurrent)", v.findings[0].text)
        self.assertEqual(verdict(self.base, today, scheduler=runs(40, 60)).verdict, "blind")
        v = verdict(self.base, today, scheduler={})
        self.assertEqual((v.verdict, checks(v)), ("blind", [("schedule", "blind")]))
        self.assertIn("no run of 'RASD - D_process'", v.findings[0].text)

    def test_the_scheduler_record_is_read_as_json_lines_or_csv(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "runs.jsonl").write_text("".join(json.dumps(r) + "\n" for r in [
            {"savedsearch_name": "RASD - a", "status": "success"}, {"savedsearch_name": "RASD - a", "status": "skipped", "reason": "busy"},
            {"savedsearch_name": "RASD - a", "status": "continued"}, {"status": "success"}, {"savedsearch_name": "RASD - b"}]),
            encoding="utf-8")
        got = health.read_scheduler(tmp / "runs.jsonl")
        self.assertEqual(sorted(got), ["RASD - a"])
        self.assertEqual((got["RASD - a"]["runs"], got["RASD - a"]["bad"], dict(got["RASD - a"]["reasons"])), (3, 1, {"busy": 1}))
        (tmp / "health.csv").write_text("SentinelResourceName,Status,Description\nRASD - a,Success,\nRASD - a,Failure,query timed out\n",
                                        encoding="utf-8")
        got = health.read_scheduler(tmp / "health.csv")
        self.assertEqual((got["RASD - a"]["runs"], got["RASD - a"]["bad"], dict(got["RASD - a"]["reasons"])),
                         (2, 1, {"query timed out": 1}))
        with self.assertRaises(health.HealthError):
            health.read_scheduler(tmp / "missing.jsonl")

    def test_each_cause_is_listed_once_with_everything_it_takes_with_it(self):
        base = health.measure(self.base, WANTED, until=FRIDAY)
        cur = health.measure(office(FRIDAY, self.day, hosts=("ws01",)), WANTED)
        twin = health.Need("D_twin", "t", "process_creation", (), ("Image",), {}, frozenset({"Image"}), 300, "RASD - D_twin")
        verdicts = health.assess(base, cur, [PROCESS, twin, CLEARED])
        self.assertEqual([v.detection for v in verdicts], ["D_process", "D_twin", "D_cleared"], "the worst first")
        broke = health.causes(verdicts)
        self.assertEqual(len(broke), 1)
        self.assertEqual(broke[0][1], [("D_process", "degraded"), ("D_twin", "degraded")])
        doc = health.to_json(base, cur, verdicts)
        self.assertEqual(doc["summary"], {"degraded": 2, "unknown": 1})
        self.assertEqual(doc["detections"][0]["findings"][0]["check"], "silent")


class Sample(unittest.TestCase):
    """samples/health: three ordinary days, then a day the pipeline breaks in five quiet ways."""

    @classmethod
    def setUpClass(cls):
        cls.base, cls.cur, verdicts = health.sample_verdicts()
        cls.verdicts = {v.detection: v for v in verdicts}

    def by(self, check: str) -> list[str]:
        return sorted(d for d, v in self.verdicts.items() if any(f.check == check for f in v.findings))

    def test_the_sample_is_what_its_generator_writes(self):
        spec = importlib.util.spec_from_file_location("health_sample", health.SAMPLE / "generate.py")
        gen = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gen)
        before, today, runs = gen.build()
        hint = "run: python samples/health/generate.py"
        self.assertEqual(gen.lines(today), health.SAMPLE_TODAY.read_text(encoding="utf-8"), hint)
        self.assertEqual(gen.lines(runs), health.SAMPLE_SCHEDULER.read_text(encoding="utf-8"), hint)
        self.assertEqual(gen.baseline_text(before), health.SAMPLE_BASELINE.read_text(encoding="utf-8"), hint)
        self.assertEqual(gen.lines(gen.build()[1]), gen.lines(today), "the same file twice")

    def test_every_break_is_found_and_named_by_what_it_blinds(self):
        tally = {}
        for v in self.verdicts.values():
            tally[v.verdict] = tally.get(v.verdict, 0) + 1
        self.assertEqual(tally, {"blind": 4, "degraded": 13, "healthy": 4, "unknown": 1})
        self.assertEqual(self.verdicts["T1003.001_lsass_memory_access"].verdict, "blind")
        self.assertIn("process_access: every host that sent it is silent", self.verdicts["T1003.001_lsass_memory_access"].findings[0].text)
        for linux in ("T1053.003_crontab_noninteractive_install", "T1059.004_linux_suspicious_shell_execution"):
            self.assertEqual(self.verdicts[linux].verdict, "blind")
            self.assertIn("now carry command_line", self.verdicts[linux].findings[0].text)
        self.assertEqual(self.by("truncation"), sorted(n.detection for n in health.needs() if n.source == "process_creation"))
        self.assertIn("ws03 still sends other events, and none of this kind since 2026-11-06 10:",
                      self.verdicts["T1059.001_powershell_encoded_command"].findings[0].text)
        self.assertEqual(self.by("delay"), ["T1078.002_honey_account_authentication", "T1110.003_password_spray_burst",
                                            "T1558.003_honey_spn_ticket_request", "T1558.003_kerberoasting_rc4_tgs",
                                            "T1558.003_kerberoasting_volume"])
        self.assertTrue(all("security from dc01" in f.text for d in self.by("delay") for f in self.verdicts[d].findings
                            if f.check == "delay"))
        self.assertEqual(self.by("schedule"), ["T1190_object_id_enumeration", "T1552.001_honey_file_access"])
        self.assertEqual(self.verdicts["T1190_object_id_enumeration"].verdict, "blind")
        self.assertEqual(self.verdicts["T1046_decoy_service_interaction"].verdict, "unknown")
        self.assertEqual(self.verdicts["T1595.003_api_auth_probing"].findings, [])

    def test_the_numbers_the_pages_quote(self):
        counts = health.sample_counts()
        self.assertEqual((counts["blind"], counts["degraded"], counts["healthy"], counts["unknown"]), (4, 13, 4, 1))
        self.assertEqual(counts["checks"], ["silent", "fields", "truncation", "delay", "schedule"])
        self.assertEqual((counts["watchdogs"], counts["detections"]), (5, len(health.needs())))


def balanced(text: str) -> bool:
    """Brackets close in order and quotes pair up, outside quoted text."""
    pairs, stack, quote = {")": "(", "]": "["}, [], ""
    for ch in text:
        if quote:
            quote = "" if ch == quote else quote
        elif ch in "\"'":
            quote = ch
        elif ch in "([":
            stack.append(ch)
        elif ch in pairs and (not stack or stack.pop() != pairs[ch]):
            return False
    return not stack and not quote


class Watchdogs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wanted = health.needs()
        cls.spl = health.spl_watchdogs(cls.wanted)
        cls.kql = health.kql_watchdogs(cls.wanted)

    def test_the_generated_files_match_the_library(self):
        self.assertEqual(health.check(self.wanted), [])
        self.assertEqual(sorted(p.name for p in (health.OUT / "spl").iterdir()), sorted(f"{c}.spl" for c in health.WATCHDOGS))
        self.assertEqual(sorted(p.name for p in (health.OUT / "kql").iterdir()), sorted(f"{c}.kql" for c in health.WATCHDOGS))

    def test_a_stale_or_stray_file_fails_the_check(self):
        extra = health.OUT / "spl" / "by-hand.spl"
        extra.write_text("index=main", encoding="utf-8")
        self.addCleanup(extra.unlink)
        self.assertEqual(health.check(self.wanted), ["queries/health/spl/by-hand.spl is not a generated watchdog - remove it"])

    def test_every_search_is_well_formed(self):
        for name, text in {**{f"{k}.spl": v for k, v in self.spl.items()}, **{f"{k}.kql": v for k, v in self.kql.items()}}.items():
            self.assertTrue(balanced(text.replace("@'Name=\"", "@'Name=").replace("\">([^<]*)<'", ">([^<]*)<'")), name)
            self.assertNotIn("None", text, name)
            self.assertNotRegex(text, r"\{[a-z_]+\}", name)
        for name, text in self.spl.items():
            self.assertTrue(text.startswith(("| tstats ", "| multisearch", "(", "index=")), name)
        for name, text in self.kql.items():
            self.assertTrue(text.startswith(("union\n", "SentinelHealth\n")), name)

    def test_every_event_the_rules_read_is_watched_and_every_row_names_its_detections(self):
        feeds = health.feed_detections(self.wanted)
        sources = {f.partition("#")[0] for f in feeds}
        for text in (self.spl["volume"], self.spl["fields"]):
            for source in sources:
                self.assertIn(f'feed="{source}', text)
            for feed, detections in feeds.items():
                self.assertIn(f'feed=="{feed}", "', text)
                self.assertIn(", ".join(detections), self.spl["volume"])
        for text in (self.kql["volume"], self.kql["fields"]):
            for source in sources:
                self.assertRegex(text, rf'feed = (strcat\()?"{re.escape(source)}')
        every = {n.detection for n in self.wanted}
        for text in (self.spl["silent"], self.spl["delay"], self.spl["volume"], self.kql["silent"], self.kql["volume"]):
            self.assertEqual({d for d in every if d in text}, every)
        self.assertEqual({d for d in every if d in self.kql["delay"]}, every - {"T1046_decoy_service_interaction"} | {
            "T1046_decoy_service_interaction"}, "the decoy's records are named in the case, though no leg can time them")

    def test_event_ids_and_fields_are_the_ones_the_rules_read(self):
        ids = sorted({i for n in self.wanted if n.source == "windows/security" for i in n.ids}, key=int)
        self.assertIn(f'source="XmlWinEventLog:Security" EventCode IN ({", ".join(ids)})', self.spl["volume"])
        self.assertIn(f"SecurityEvent | where (TimeGenerated > ago(24h) or TimeGenerated between (ago(8d) .. ago(7d))) and EventID in "
                      f"({', '.join(ids)})", self.kql["volume"])
        self.assertIn('feed=="windows/security#4769", "EventCode,ServiceName,TicketEncryptionType,Status,IpAddress"', self.spl["fields"])
        self.assertIn('feed=="webserver", "clientip,method,uri_path,status"', self.spl["fields"])
        self.assertIn("count(TicketEncryptionType) as TicketEncryptionType", self.spl["fields"])
        self.assertIn('field = pack_array("c-ip", "cs-method", "cs-uri-stem", "sc-status"), filled = pack_array(cIP_, csMethod_, '
                      "csUriStem_, scStatus_)", self.kql["fields"])
        self.assertIn("extract(@'Name=\"TicketEncryptionType\">([^<]*)<', 1, EventData)", self.kql["fields"],
                      "fields the Security table has no column for are read the way the detections read them")

    def test_the_channels_are_the_log_sources_without_their_event_id(self):
        carriers = health.spl_carriers(self.wanted)
        self.assertEqual(sorted(name for name, _c, _d in carriers),
                         ["Decoy records", "Security log", "Sysmon", "Sysmon for Linux", "System log", "Web access log"])
        sysmon = next(c for c in carriers if c[0] == "Sysmon")
        self.assertEqual(sysmon[1], 'index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"')
        self.assertEqual(len(sysmon[2]), sum(1 for n in self.wanted if n.source in ("process_creation", "process_access", "registry_set")))
        for _name, clause, _dets in carriers:
            self.assertNotRegex(clause, r"Event(Code|ID)=")
            self.assertIn(f"({clause})", self.spl["silent"])
        named = {c["name"] for c in health.kql_carriers(self.wanted)}
        self.assertEqual(named, {name for name, _c, _d in carriers})
        self.assertEqual(set((MAPPINGS["health"]["carriers"]).values()), named)

    def test_the_delay_watchdog_uses_the_wait_of_the_schedule_and_the_time_of_indexing(self):
        self.assertIn("count(eval(lag > 300)) as late", self.spl["delay"])
        self.assertIn("_index_earliest=-60m@m _index_latest=@m", self.spl["delay"])
        self.assertIn("late = countif(lag > 5m)", self.kql["delay"])
        self.assertIn("ingestion_time() > ago(1h)", self.kql["delay"])
        self.assertNotIn("OpenCanary", self.kql["delay"], "a table behind a function has no ingestion time to read")

    def test_the_delay_watchdog_does_not_judge_a_channel_in_the_hour_splunk_first_hears_from_it(self):
        spl = self.spl["delay"]
        self.assertIn("| tstats min(_indextime) as first_heard where (", spl)
        self.assertIn('first_heard < relative_time(now(), "-60m@m")', spl,
                      "what a new host sends first is its backlog: late by days, and no fault of the pipeline")
        counted = spl.index("count(eval(lag > 300)) as late")
        self.assertLess(counted, spl.index("| append [| tstats"), "the events are counted where they are, before anything is joined to them")
        self.assertLess(spl.index("first_heard < relative_time"), spl.index("| where late_pct >= 1"))
        self.assertEqual(spl.count("earliest=-7d@d latest=+1d@d"), 2, "the first time heard is looked for over the same days as the events")
        self.assertNotIn("$", spl)

    def test_the_schedule_watchdog_watches_the_alerts_and_not_itself(self):
        self.assertIn('savedsearch_name="RASD - T*"', self.spl["schedule"])
        self.assertNotIn("RASD Health", self.spl["schedule"])
        self.assertIn('SentinelResourceName startswith "RASD - T"', self.kql["schedule"])

    def test_the_schedule_watchdog_reads_up_to_now_and_waits_out_a_splunk_that_has_just_started(self):
        spl = self.spl["schedule"]
        self.assertIn("earliest=-24h latest=now", spl)
        self.assertNotIn("@h", spl, "a window that ends at the last full hour holds no run on a Splunk started after it")
        longest = max(n.period for n in self.wanted)
        self.assertIn("| rest /services/server/info splunk_server=local | eval uptime=now() - startup_time", spl)
        self.assertIn(f"(succeeded == 0 AND (runs > 0 OR coalesce(uptime, 86400) >= {longest + 300}))", spl,
                      "a search that ran and never succeeded is named at once; one without a run only when it has had its slot")
        self.assertNotIn("$", spl, "Splunk reads a dollar sign in a saved search as the start of a token")
        self.assertEqual(health.WATCHDOGS["schedule"][1], "32 * * * *")

    def test_every_search_knows_how_often_it_runs(self):
        periods = {n.detection: n.period for n in self.wanted}
        for det in load_detections():
            self.assertEqual(periods[det.id], 300, det.id)
        for corr in load_correlations():
            self.assertEqual(periods[corr.id], corr.params.timespan, corr.id)
            cron = splunk_app.correlation_schedule(corr.params.timespan)[0]
            self.assertTrue(cron.startswith(f"*/{corr.params.timespan // 60} ") or corr.params.timespan >= 3600, cron)

    def test_the_field_watchdog_reads_the_last_day_up_to_now(self):
        self.assertIn("earliest=-24h latest=now", self.spl["fields"])
        self.assertNotIn("@h", self.spl["fields"], "the events of the last hour are the ones a fresh fault is in")
        self.assertIn("earliest=-24h@h latest=@h", self.spl["volume"], "a day and the same day a week earlier, hour for hour")
        self.assertIn("earliest=-8d@h latest=-7d@h", self.spl["volume"])

    def test_the_splunk_app_schedules_the_five_watchdogs(self):
        import configparser
        files = splunk_app.render(load_detections(), load_correlations())
        saved = configparser.RawConfigParser(delimiters=("=",), comment_prefixes=("#",), interpolation=None, strict=True)
        saved.optionxform = str
        saved.read_string(files[splunk_app.OUT / "rasd" / "default" / "savedsearches.conf"])
        names = [s for s in saved.sections() if s.startswith(health.HEALTH_PREFIX)]
        self.assertEqual(names, [f"RASD Health - {c}" for c in health.WATCHDOGS])
        for check, (_every, cron, _what) in health.WATCHDOGS.items():
            sec = saved[f"RASD Health - {check}"]
            self.assertEqual(sec["search"], splunk_app.one_line(self.spl[check]))
            self.assertEqual((sec["enableSched"], sec["cron_schedule"], sec["action.logevent.param.sourcetype"]), ("1", cron, "rasd:health"))
            self.assertIn('blinds="$result.blinds$"', sec["action.logevent.param.event"])
        self.assertNotIn("rasd:health", saved["RASD - alert export"]["search"])
        self.assertIn('sourcetype="rasd:alert"', saved["RASD - alert export"]["search"], "a health row is never exported as an alert")
        self.assertIn("## Health watchdogs", files[splunk_app.OUT / "README.md"])

    def test_the_page_says_what_was_and_was_not_run(self):
        text = health.PAGE.read_text(encoding="utf-8")
        self.assertIn("**Not yet run on a live SIEM.**", text)
        self.assertIn("**4 detections are blind and 13 degraded**", text)
        for check in health.WATCHDOGS:
            self.assertIn(f"[`{check}.spl`](spl/{check}.spl)", text)


class CommandLine(unittest.TestCase):
    def run_rasd(self, *args):
        return subprocess.run([sys.executable, str(ROOT / "tools" / "health.py"), *args], capture_output=True, text=True,
                              encoding="utf-8", env={"PYTHONUTF8": "1", "NO_COLOR": "1", "PATH": ""})

    def test_the_sample_runs_and_strict_fails_on_it(self):
        r = self.run_rasd("--sample")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("What broke, and what it takes with it", r.stdout)
        self.assertIn("4 blind · 13 degraded · 4 healthy · 1 unknown", r.stdout)
        self.assertIn("BLIND T1003.001_lsass_memory_access", r.stdout)
        self.assertEqual(self.run_rasd("--sample", "--strict").returncode, 1)
        self.assertIn("too rare to judge by its own volume", self.run_rasd("--sample", "--detail").stdout)

    def test_a_baseline_is_saved_from_one_export_and_judges_the_next(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "week.jsonl").write_text("".join(json.dumps(e) + "\n" for e in office(TUESDAY, FRIDAY)), encoding="utf-8")
        (tmp / "today.jsonl").write_text("".join(json.dumps(e) + "\n" for e in office(FRIDAY, FRIDAY + timedelta(days=1), hosts=("ws01",))),
                                         encoding="utf-8")
        r = self.run_rasd(str(tmp / "week.jsonl"), "--save-baseline", str(tmp / "base.json"), "--until", "2026-11-06T06:00:00Z")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("baseline of 2.9 d: 360 events from 2 hosts", r.stdout)
        for baseline in ("base.json", "week.jsonl"):
            r = self.run_rasd(str(tmp / "today.jsonl"), "--baseline", str(tmp / baseline), "--json", str(tmp / "out.json"),
                              "--filter", "T1059.001")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("ws02 sends nothing at all", r.stdout)
            doc = json.loads((tmp / "out.json").read_text(encoding="utf-8"))
            self.assertEqual((doc["rasd_health"], doc["summary"]), (1, {"degraded": 1}))
            self.assertEqual(doc["detections"][0]["detection"], "T1059.001_powershell_encoded_command")

    def test_inputs_that_cannot_be_what_they_are_given_as_are_refused(self):
        self.assertNotEqual(self.run_rasd("nowhere.jsonl", "--baseline", str(health.SAMPLE_BASELINE)).returncode, 0)
        r = self.run_rasd(str(health.SAMPLE_BASELINE), "--baseline", str(health.SAMPLE_BASELINE))
        self.assertEqual(r.returncode, 2)
        self.assertIn("a saved baseline goes after --baseline", r.stderr)
        self.assertEqual(self.run_rasd(str(health.SAMPLE_TODAY)).returncode, 2)
        self.assertEqual(self.run_rasd(str(health.SAMPLE_TODAY), "--baseline", str(health.SAMPLE_BASELINE), "--until", "soon").returncode, 2)
        self.assertEqual(self.run_rasd("--write", str(health.SAMPLE_TODAY)).returncode, 2)

    def test_check_passes_on_the_repository(self):
        r = self.run_rasd("--check")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("every detection is watched", r.stdout)


if __name__ == "__main__":
    unittest.main()
