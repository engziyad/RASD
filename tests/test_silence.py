"""Tests for RASD-Silence (tools/silence.py): the proof on small hand-built exports, the shipped model, the sample fleet."""
import copy
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from itertools import pairwise
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import silence as sil  # noqa: E402
import survivability  # noqa: E402

T0 = datetime(2026, 1, 5, 8, 0, 0)
SYSMON, SECURITY, SYSTEM = "Microsoft-Windows-Sysmon/Operational", "Security", "System"
LSASS_READ = {"SourceImage": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MsMpEng.exe",
              "TargetImage": "C:\\Windows\\System32\\lsass.exe", "GrantedAccess": "0x1410"}
PROCESS = {"Image": "C:\\Windows\\System32\\svchost.exe", "CommandLine": "C:\\Windows\\System32\\svchost.exe -k netsvcs -p",
           "ParentImage": "C:\\Windows\\System32\\services.exe", "User": "NT AUTHORITY\\SYSTEM", "OriginalFileName": "svchost.exe"}
EVENTLOG, KERNEL, POWER = "EventLog", "Microsoft-Windows-Kernel-General", "Microsoft-Windows-Kernel-Power"
SERVICE, SYSTEM_CLEARED, LSASS = ("T1569.002_suspicious_service_installation", "T1685.005_system_log_cleared",
                                  "T1003.001_lsass_memory_access")
RASD = (sys.executable, str(ROOT / "rasd.py"), "silence")


def ev(minute: float, channel: str, eid: int, number: int | None = None, host: str = "H1", **fields) -> dict:
    t = T0 + timedelta(minutes=minute)
    out = {"TimeCreated": t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z", "Channel": channel,
           "EventID": eid, "Computer": host, **fields}
    if number is not None:
        out["EventRecordID"] = number
    return out


def steady(channel: str, n: int, *, start: float = 0, step: float = 5, first: int | None = 1000, host: str = "H1",
           eid: int = 7036, **fields) -> list[dict]:
    """n records, one every `step` minutes, numbered one after the other (first=None: no record numbers)."""
    return [ev(start + i * step, channel, eid, None if first is None else first + i, host, **fields) for i in range(n)]


def numbered(events: list[dict], first: int = 1000, by_time: bool = True) -> list[dict]:
    """The events numbered in the order they were written: by time, or as listed."""
    for n, e in enumerate(sorted(events, key=lambda e: e["TimeCreated"]) if by_time else events):
        e["EventRecordID"] = first + n
    return events


def sensors(events: list[dict], assets: dict | None = None) -> dict:
    fleet = sil.Fleet(events, sil.load_model(), assets)
    out = {key: sil.sense(fleet, key[0], key[1], {}) for key in sorted(fleet.streams)}
    sil.settle(fleet, out)
    return out


def pair(res: dict, detection: str, host: str = "H1") -> dict:
    return next(r for r in res["pairs"] if r["detection"] == detection and r["host"] == host)


class Order(unittest.TestCase):
    def order(self, events: list[dict]) -> tuple:
        fleet = sil.Fleet(events, sil.load_model())
        return next(iter(fleet.ordered.values()))

    def test_consecutive_numbers_give_the_sequence_grade(self):
        recs, mode, note, setbacks = self.order(steady(SYSTEM, 40))
        self.assertEqual((mode, note, len(recs), setbacks), ("sequence", "", 40, set()))

    def test_an_export_that_skips_records_is_judged_by_rhythm_and_says_why(self):
        events = [ev(i * 5, SYSTEM, 7036, 1000 + 3 * i) for i in range(40)]       # a pipeline that ships one event id in three
        _recs, mode, note, _ = self.order(events)
        self.assertEqual(mode, "rhythm")
        self.assertIn("skips records", note)

    def test_records_without_numbers_are_judged_by_rhythm(self):
        _recs, mode, note, _ = self.order(steady(SYSTEM, 40, first=None))
        self.assertEqual((mode, note), ("rhythm", "the export carries no record numbers"))

    def test_the_same_record_exported_twice_counts_once(self):
        events = steady(SYSTEM, 40)
        recs, mode, _note, _ = self.order(events + events[10:15])
        self.assertEqual((mode, len(recs)), ("sequence", 40))

    def test_one_number_on_two_different_records_is_not_trusted(self):
        events = steady(SYSTEM, 40) + [ev(900, SYSTEM, 7036, 1010)]               # number 1010 again, hours later
        _recs, mode, note, _ = self.order(events)
        self.assertEqual(mode, "rhythm")
        self.assertIn("carried by two different records", note)

    def test_a_record_stamped_with_an_old_clock_keeps_its_place(self):
        """Windows stamps the record of a wake with the clock of the moment the host fell asleep."""
        events = steady(SYSTEM, 40)
        events[20]["TimeCreated"] = events[2]["TimeCreated"]                      # written twentieth, stamped an hour and a half back
        recs, mode, _note, setbacks = self.order(events)
        self.assertEqual((mode, setbacks), ("sequence", set()))
        self.assertEqual([r.rid for r in recs], list(range(1000, 1040)))
        self.assertEqual(recs[20].time, recs[19].time, "it was written after the nineteenth, whatever its own clock says")
        self.assertTrue(all(b.time >= a.time for a, b in pairwise(recs)))

    def test_a_clock_that_stays_behind_was_set_back(self):
        events = steady(SYSTEM, 20) + steady(SYSTEM, 20, start=-600, first=1020)   # from the 21st on, ten hours earlier
        _recs, mode, _note, setbacks = self.order(events)
        self.assertEqual((mode, setbacks), ("sequence", {20}))

    def test_other_names_of_the_record_number_are_read(self):
        model = sil.load_model()
        self.assertEqual(sil.record_id({"RecordNumber": "77"}, model.fields), 77)
        self.assertEqual(sil.record_id({"winlog": {"record_id": 78}}, model.fields), 78)
        self.assertIsNone(sil.record_id({"EventRecordID": True}, model.fields))
        self.assertIsNone(sil.record_id({"EventID": 1}, model.fields))


class Rhythm(unittest.TestCase):
    def test_too_few_gaps_say_nothing(self):
        self.assertIsNone(sil.rhythm([timedelta(minutes=5)] * (sil.MIN_GAPS - 1)))

    def test_the_bound_is_three_times_the_rare_gap_and_never_under_the_floor(self):
        self.assertEqual(sil.rhythm([timedelta(seconds=20)] * 200), sil.QUIET_FLOOR)
        self.assertEqual(sil.rhythm([timedelta(minutes=10)] * 200), timedelta(minutes=30))

    def test_one_long_quiet_does_not_hide_itself(self):
        gaps = [timedelta(minutes=10)] * 40 + [timedelta(hours=6)]
        self.assertEqual(sil.rhythm(gaps), timedelta(minutes=30), "the six hours must be judged against the others, not set the bound")

    def test_gaps_a_channel_has_often_set_its_bound(self):
        gaps = [timedelta(minutes=10)] * 60 + [timedelta(hours=6)] * 20      # a channel that sleeps every night
        self.assertEqual(sil.rhythm(gaps), timedelta(hours=18))


class Breaks(unittest.TestCase):
    def test_steady_records_have_no_break(self):
        s = sensors(steady(SYSTEM, 40))[("h1", "system")]
        self.assertEqual((s.mode, len(s.runs), s.holes), ("sequence", 1, []))
        self.assertEqual(s.bound, timedelta(minutes=15))

    def test_a_missing_number_breaks_the_run_and_is_counted(self):
        events = steady(SYSTEM, 30) + steady(SYSTEM, 20, start=150, first=1037)          # 1030 to 1036 are not there
        s = sensors(events)[("h1", "system")]
        self.assertEqual(len(s.runs), 2)
        h = s.holes[0]
        self.assertEqual((h.kind, h.missing, h.severity), ("missing", 7, "high"))
        self.assertIn("7 records missing between #1029 and #1037, and no record says why", h.detail)

    def test_a_record_a_time_filter_left_out_at_the_head_is_not_an_alarm(self):
        """An export cut by time leaves out the record of a wake, which is stamped before the window."""
        events = [ev(0, SYSTEM, 6013, 1000), *steady(SYSTEM, 40, start=0.1, first=1002)]
        h = sensors(events)[("h1", "system")].holes[0]
        self.assertEqual((h.kind, h.missing, h.severity), ("missing", 1, "low"))
        self.assertIn("at the head of the export: a time filter leaves out a record stamped before the window", h.detail)

    def test_a_clear_that_lost_nothing_is_not_a_break(self):
        events = steady(SECURITY, 20, eid=4624) + [ev(96, SECURITY, 1102, 1020)] + steady(SECURITY, 20, start=100, first=1021, eid=4624)
        s = sensors(events)[("h1", "security")]
        self.assertEqual((len(s.runs), s.holes), (1, []), "every record before the clear had left the host: the count is whole")

    def test_a_clear_that_took_records_is_a_break_that_names_it(self):
        events = steady(SECURITY, 30, eid=4624) + [ev(146, SECURITY, 1102, 1035)] + steady(SECURITY, 20, start=150, first=1036, eid=4624)
        h = sensors(events)[("h1", "security")].holes[0]
        self.assertEqual((h.kind, h.missing, h.severity, h.cuts), ("cleared", 5, "high", ["security_cleared"]))
        self.assertIn("5 records gone between #1029 and #1035: the channel was cleared", h.detail)

    def test_without_numbers_a_clear_always_breaks_and_says_what_cannot_be_known(self):
        events = (steady(SECURITY, 20, eid=4624, first=None) + [ev(96, SECURITY, 1102)]
                  + steady(SECURITY, 20, start=100, eid=4624, first=None))
        h = sensors(events)[("h1", "security")].holes[0]
        self.assertEqual((h.kind, h.missing), ("cleared", 0))
        self.assertIn("without record numbers nothing shows what was lost", h.detail)

    def test_a_clear_of_another_channel_is_read_from_the_system_log(self):
        sysmon = steady(SYSMON, 30, eid=3) + steady(SYSMON, 20, start=150, first=1041, eid=3)        # 11 records gone
        system = numbered(steady(SYSTEM, 50, first=None) + [ev(147.5, SYSTEM, 104, Provider_Name="Microsoft-Windows-Eventlog",
                                                               Channel_Cleared=SYSMON)], first=5000)
        got = sensors(sysmon + system)
        h = got[("h1", SYSMON.lower())].holes[0]
        self.assertEqual((h.kind, h.missing, h.cuts), ("cleared", 11, ["channel_cleared"]))
        self.assertEqual(got[("h1", "system")].holes, [], "the System log itself was not emptied")

    def night(self, clean: bool) -> list[dict]:
        """A host that stops for the night: with the records of a shutdown, or with only the records of the start."""
        stop = [ev(172, SYSTEM, 6006, Provider_Name=EVENTLOG), ev(172.1, SYSTEM, 13, Provider_Name=KERNEL)] if clean else []
        boot = [ev(600, SYSTEM, 12, Provider_Name=KERNEL), ev(600.1, SYSTEM, 6009, Provider_Name=EVENTLOG),
                ev(600.2, SYSTEM, 6005, Provider_Name=EVENTLOG)]
        if not clean:
            boot.insert(0, ev(599.9, SYSTEM, 6008, Provider_Name=EVENTLOG))
        return numbered(steady(SYSTEM, 35) + stop + boot + steady(SYSTEM, 35, start=602), by_time=False)

    def test_a_shutdown_and_the_next_start_are_time_off_not_a_break(self):
        s = sensors(self.night(clean=True))[("h1", "system")]
        self.assertEqual([(h.kind, h.severity) for h in s.holes], [("down", "low")])
        self.assertIn("shut down for 7 h 07 min", s.holes[0].detail)
        res = sil.assess(self.night(clean=True))
        row = pair(res, SERVICE)
        self.assertEqual((row["verdict"], row["grade"], row["coverage"]), ("attested", "sequence", 1.0))
        self.assertAlmostEqual(row["down_seconds"], 7 * 3600 + 8 * 60, delta=60)
        self.assertEqual(res["breaks"], [])
        self.assertEqual([(d["host"], d["what"]) for d in res["down"]], [("H1", "shut down")])

    def test_boot_records_written_out_of_their_own_order_are_one_stretch(self):
        """As Windows writes them: the Event Log service's own records first, the kernel's earlier ones after."""
        restart = [ev(172, SYSTEM, 6006, Provider_Name=EVENTLOG),
                   ev(172.53, SYSTEM, 6009, Provider_Name=EVENTLOG), ev(172.53, SYSTEM, 6005, Provider_Name=EVENTLOG),
                   ev(172.53, SYSTEM, 6013, Provider_Name=EVENTLOG),
                   ev(172.13, SYSTEM, 13, Provider_Name=KERNEL), ev(172.28, SYSTEM, 12, Provider_Name=KERNEL),
                   *[ev(172.28, SYSTEM, n, Provider_Name="Microsoft-Windows-Kernel-Boot") for n in (153, 18, 32, 20, 27, 30)],
                   ev(172.4, SYSTEM, 172, Provider_Name=POWER)]
        s = sensors(numbered(steady(SYSTEM, 35) + restart + steady(SYSTEM, 35, start=174), by_time=False))[("h1", "system")]
        self.assertEqual([(h.kind, round(h.seconds)) for h in s.holes], [("down", 32)], "one restart, however its records are stamped")
        self.assertEqual(len(s.runs), 2)

    def test_a_sleep_is_time_off_though_its_wake_record_carries_the_old_clock(self):
        nap = [ev(172, SYSTEM, 42, Provider_Name=POWER), ev(172.03, SYSTEM, 107, Provider_Name=POWER),      # 107: stamped as it fell asleep
               ev(600, SYSTEM, 1, Provider_Name=KERNEL), ev(600.02, SYSTEM, 131, Provider_Name=POWER),
               ev(600.07, SYSTEM, 1, Provider_Name="Microsoft-Windows-Power-Troubleshooter")]
        events = numbered(steady(SYSTEM, 35) + nap + steady(SYSTEM, 35, start=602), by_time=False)
        s = sensors(events)[("h1", "system")]
        self.assertEqual([(h.kind, h.severity) for h in s.holes], [("down", "low")])
        self.assertIn("asleep for 7 h 07 min", s.holes[0].detail)
        res = sil.assess(events)
        self.assertEqual((pair(res, SERVICE)["coverage"], res["breaks"]), (1.0, []))
        self.assertEqual([d["what"] for d in res["down"]], ["asleep"])

    def test_a_nap_too_short_to_matter_cuts_nothing(self):
        nap = [ev(172, SYSTEM, 42, Provider_Name=POWER), ev(172.03, SYSTEM, 107, Provider_Name=POWER),
               ev(172.3, SYSTEM, 1, Provider_Name=KERNEL), ev(172.33, SYSTEM, 1, Provider_Name="Microsoft-Windows-Power-Troubleshooter")]
        s = sensors(numbered(steady(SYSTEM, 35) + nap + steady(SYSTEM, 35, start=175), by_time=False))[("h1", "system")]
        self.assertEqual((s.holes, len(s.runs)), ([], 1), "a pause of seconds after a sleep record is not a stretch off")

    def test_a_start_with_no_stop_before_it_is_a_break(self):
        s = sensors(self.night(clean=False))[("h1", "system")]
        h = s.holes[0]
        self.assertEqual((h.kind, h.severity, h.opened), ("stopped", "medium", "start"))
        self.assertIn("no record for 7 h 09 min, then the previous shutdown was unexpected and the Event Log service started, "
                      "and no record of a stop before it", h.detail)
        row = pair(sil.assess(self.night(clean=False)), SERVICE)
        self.assertEqual(row["verdict"], "attested")
        self.assertLess(row["coverage"], 0.5)

    def test_a_stretch_off_that_another_host_contradicts_is_a_grave_break(self):
        dc = [ev(m, SECURITY, 4624, 9000 + i, host="DC", TargetUserName="amal", LogonType="3", WorkstationName="H1")
              for i, m in enumerate((250, 320, 400, 480))]
        for clean in (True, False):
            h = sensors(self.night(clean=clean) + copy.deepcopy(dc))[("h1", "system")].holes[0]
            self.assertEqual((h.kind, h.severity), ("stopped", "high"), "the records say off, a domain controller says otherwise")
            self.assertIn("DC recorded 4 events naming it meanwhile", h.life)

    def test_with_whole_numbers_a_long_quiet_is_not_a_break(self):
        """An idle host writes nothing for hours. Nothing was taken out, and no record says the sensor stopped."""
        events = steady(SECURITY, 40, eid=4624) + steady(SECURITY, 40, start=600, first=1040, eid=4624)
        s = sensors(events)[("h1", "security")]
        self.assertEqual((s.mode, s.holes, len(s.runs)), ("sequence", [], 1))

    def test_quiet_within_the_channels_own_rhythm_is_not_a_break(self):
        events = steady(SYSTEM, 20, first=None) + steady(SYSTEM, 20, start=107, first=None)          # one gap of 12 minutes
        self.assertEqual(sensors(events)[("h1", "system")].holes, [])

    def test_without_numbers_quiet_beyond_the_rhythm_is_a_break_and_graver_when_someone_saw_the_host(self):
        events = steady(SECURITY, 20, eid=4624, first=None) + steady(SECURITY, 20, start=300, first=None, eid=4624)
        h = sensors(events)[("h1", "security")].holes[0]
        self.assertEqual((h.kind, h.missing, h.severity, h.life), ("quiet", 0, "medium", ""))
        self.assertIn("no record for 3 h 25 min, against gaps of at most 15 min", h.detail)
        dc = [ev(m, SECURITY, 4769, 9000 + i, host="DC", ServiceName="svc_sql", IpAddress="::ffff:10.0.0.7", Status="0x0",
                 TicketEncryptionType="0x12") for i, m in enumerate((150, 200, 250))]
        h = sensors(events + dc, assets={"10.0.0.7": {"ip": "10.0.0.7", "host": "H1.corp.lab", "role": "workstation"}})[
            ("h1", "security")].holes[0]
        self.assertEqual(h.severity, "high")
        self.assertEqual(h.life, "DC recorded 3 events naming it meanwhile")

    def test_a_logon_that_names_its_client_twice_is_one_sighting(self):
        events = steady(SECURITY, 20, eid=4624, first=None) + steady(SECURITY, 20, start=300, first=None, eid=4624)
        dc = [ev(200, SECURITY, 4624, 9000, host="DC", WorkstationName="H1", IpAddress="10.0.0.7", LogonType="3")]
        h = sensors(events + dc, assets={"10.0.0.7": {"ip": "10.0.0.7", "host": "H1", "role": "workstation"}})[("h1", "security")].holes[0]
        self.assertEqual(h.life, "DC recorded 1 event naming it meanwhile")

    def test_a_sensor_stopped_while_the_host_kept_writing_elsewhere(self):
        sysmon = (steady(SYSMON, 34, eid=3) + [ev(167, SYSMON, 4, 1034, State="Stopped"), ev(300, SYSMON, 4, 1035, State="Started")]
                  + steady(SYSMON, 34, start=301, first=1036, eid=3))
        got = sensors(sysmon + steady(SYSTEM, 95, first=5000))
        h = got[("h1", SYSMON.lower())].holes[0]
        self.assertEqual((h.kind, h.severity, h.cuts), ("stopped", "high", ["sysmon_state_stopped", "sysmon_state_started"]))
        self.assertIn("the Sysmon service stopped; no record for 2 h 13 min, then the Sysmon service started", h.detail)
        self.assertRegex(h.life, r"the host wrote \d+ records to System meanwhile")
        self.assertEqual(got[("h1", "system")].holes, [])

    def test_channels_that_went_quiet_together_do_not_vouch_for_each_other(self):
        events = (steady(SYSMON, 34, eid=3, first=None) + steady(SYSMON, 34, start=400, first=None, eid=3)
                  + steady(SYSTEM, 34, first=None, start=3) + steady(SYSTEM, 34, start=395, first=None))
        got = sensors(events)
        self.assertEqual([(h.kind, h.life) for s in got.values() for h in s.holes], [("quiet", ""), ("quiet", "")])

    def test_a_channel_that_does_not_come_back_is_a_break_to_the_end_of_the_window(self):
        events = steady(SYSMON, 34, eid=3) + steady(SYSTEM, 120, first=5000)              # System goes on for ten hours
        s = sensors(events)[("h1", SYSMON.lower())]
        h = s.holes[-1]
        self.assertEqual((h.kind, h.edge), ("quiet", "trail"))
        self.assertIn("no record after", h.detail)
        self.assertRegex(h.life, r"the host wrote \d+ records to System meanwhile")

    def test_a_clock_set_back_is_a_break(self):
        events = steady(SYSTEM, 30) + steady(SYSTEM, 30, start=-600, first=1030)
        h = sensors(events)[("h1", "system")].holes[0]
        self.assertEqual((h.kind, h.severity), ("restarted", "high"))
        self.assertIn("the record order and the clock disagree between #1029 and #1030", h.detail)

    def test_a_log_whose_numbers_start_again_is_a_break(self):
        """A log file deleted and recreated numbers its records from the start."""
        events = steady(SYSTEM, 40) + steady(SYSTEM, 40, start=200, first=1000)
        s = sensors(events)[("h1", "system")]
        self.assertEqual(s.mode, "rhythm")
        self.assertIn("carried by two different records", s.note)
        h = s.holes[0]
        self.assertEqual((h.kind, h.severity, len(s.holes)), ("restarted", "high", 1))
        self.assertIn("the record order and the clock disagree between #1039 and #1000", h.detail)

    def test_a_logger_restarted_within_seconds_is_one_short_stretch(self):
        """The stop is answered by the start five seconds later: the quiet minutes after it are not part of it."""
        events = numbered(steady(SYSTEM, 35) + [ev(172, SYSTEM, 6006, Provider_Name=EVENTLOG), ev(172.08, SYSTEM, 6005, Provider_Name=EVENTLOG)]
                          + steady(SYSTEM, 35, start=176), by_time=False)
        s = sensors(events)[("h1", "system")]
        self.assertEqual([(h.kind, h.severity, round(h.seconds)) for h in s.holes], [("stopped", "medium", 5)])
        self.assertIn("the Event Log service stopped; no record for 5 s, then the Event Log service started", s.holes[0].detail)

    def test_the_stop_of_every_channel_is_one_break(self):
        events = self.night(clean=False) + steady(SECURITY, 35, eid=4624, first=3000) + steady(SECURITY, 35, start=602, first=3035, eid=4624)
        res = sil.assess(events)
        self.assertEqual(len(res["breaks"]), 1)
        self.assertEqual(sorted(res["breaks"][0]["channels"]), ["Security", "System"])
        self.assertIn("no record of a stop before it", res["breaks"][0]["detail"])


class Verdicts(unittest.TestCase):
    def test_quiet_between_proofs_is_attested_and_says_how_it_knows(self):
        res = sil.assess(steady(SYSTEM, 40))
        row = pair(res, SERVICE)
        self.assertEqual((row["verdict"], row["grade"], row["coverage"], row["sensors"]), ("attested", "sequence", 1.0, ["System"]))
        self.assertEqual(pair(res, SYSTEM_CLEARED)["verdict"], "attested")
        self.assertIn("nothing confirms its fields survive this pipeline", row["caveats"][0])
        self.assertEqual(pair(sil.assess(steady(SYSTEM, 40, first=None)), SERVICE)["grade"], "rhythm")

    def test_an_alert_is_fired_whatever_the_records_around_it(self):
        events = numbered(steady(SYSTEM, 40) + [ev(51, SYSTEM, 7045, None, Provider_Name="Service Control Manager",
                                                   ServiceName="PSEXESVC", ImagePath="%SystemRoot%\\PSEXESVC.exe")])
        res = sil.assess(events)
        row = pair(res, SERVICE)
        self.assertEqual((row["verdict"], row["alerts"]), ("fired", 1))
        self.assertEqual(res["counts"]["fired"], 1)

    def test_a_rule_that_needs_a_setting_is_unattested_until_a_record_of_its_kind_shows_it_on(self):
        quiet = steady(SYSMON, 40, eid=1, **PROCESS)
        row = pair(sil.assess(quiet), LSASS)
        self.assertEqual((row["verdict"], row["reason"]), ("unattested", "no_proof"))
        self.assertIn("no Sysmon 10 (ProcessAccess) is in it: nothing shows the sensor was set to write one", row["why"])
        shown = numbered(quiet + [ev(52, SYSMON, 10, None, **LSASS_READ)])
        row = pair(sil.assess(shown), LSASS)
        self.assertEqual((row["verdict"], row["coverage"]), ("attested", 1.0), "one record of the kind proves the whole run")

    def test_a_change_of_settings_asks_for_a_new_proof(self):
        events = numbered(steady(SYSMON, 20, eid=3) + [ev(52, SYSMON, 10, None, **LSASS_READ),
                                                        ev(97, SYSMON, 16, None, Configuration="new.xml")]
                          + steady(SYSMON, 20, start=100, eid=3))
        row = pair(sil.assess(events), LSASS)
        self.assertEqual(row["verdict"], "attested")
        self.assertAlmostEqual(row["coverage"], 97 / 195, places=2)
        self.assertEqual([h["kind"] for h in row["holes"]], ["unproven"])
        self.assertIn("nothing shows the sensor was set to write one", row["holes"][0]["detail"])

    def test_a_field_the_rule_reads_and_the_events_lack_is_blind(self):
        bare = {k: v for k, v in PROCESS.items() if k != "CommandLine"}
        row = pair(sil.assess(steady(SYSMON, 40, eid=1, **bare)), "T1059.001_powershell_encoded_command")
        self.assertEqual((row["verdict"], row["reason"]), ("unattested", "blind"))
        self.assertIn("CommandLine", row["why"])

    def test_a_host_without_the_channel_is_unattested_and_told_what_to_forward(self):
        res = sil.assess(steady(SECURITY, 40, eid=4624))
        row = pair(res, SERVICE)
        self.assertEqual((row["verdict"], row["reason"]), ("unattested", "no_record"))
        self.assertIn("no record of the System channel", row["why"])
        self.assertEqual(res["detections"][SERVICE]["enable"], "Forward the System channel")

    def test_a_rule_an_observer_records_counts_only_the_observers(self):
        res = sil.assess(steady(SYSTEM, 40))
        rows = [r for r in res["pairs"] if r["detection"] == "T1558.003_kerberoasting_rc4_tgs"]
        self.assertEqual([(r["host"], r["reason"]) for r in rows], [(None, "no_observer")])
        dc = steady(SECURITY, 40, host="DC", eid=4769, ServiceName="svc_sql", TicketEncryptionType="0x12", Status="0x0",
                    IpAddress="::ffff:10.0.0.7")
        rows = [r for r in sil.assess(steady(SYSTEM, 40) + dc)["pairs"] if r["detection"] == "T1558.003_kerberoasting_rc4_tgs"]
        self.assertEqual([(r["host"], r["verdict"]) for r in rows], [("DC", "attested")])

    def test_the_window_the_host_and_the_detections_can_be_narrowed(self):
        events = steady(SYSTEM, 30) + steady(SYSTEM, 20, start=150, first=1037) + steady(SYSTEM, 50, host="H2", first=7000)
        res = sil.assess(events, start=T0, end=T0 + timedelta(minutes=120), filter_="T1569", only_host="h1")
        self.assertEqual([r["detection"] for r in res["pairs"]], [SERVICE])
        self.assertEqual((res["hosts"], res["breaks"]), (["H1"], []), "the missing numbers lie after the window")
        self.assertEqual(pair(res, SERVICE)["coverage"], 1.0)
        whole = sil.assess(events, filter_="T1569")
        self.assertEqual({r["host"] for r in whole["pairs"]}, {"H1", "H2"})
        self.assertEqual([b["kind"] for b in whole["breaks"]], ["missing"])
        with self.assertRaises(sil.SilenceError):
            sil.assess(events, only_host="nobody")
        with self.assertRaises(sil.SilenceError):
            sil.assess(events, start=T0 + timedelta(hours=2), end=T0)
        with self.assertRaises(sil.SilenceError):
            sil.assess([{"EventID": 1}])
        with self.assertRaises(sil.SilenceError) as one:
            sil.assess([ev(0, SYSTEM, 7036, 1)])
        self.assertIn("a stretch needs two records at different times", str(one.exception))

    def test_a_window_the_records_do_not_reach_is_not_attested(self):
        before = sil.assess(steady(SYSTEM, 60), start=T0 - timedelta(hours=20), end=T0 - timedelta(hours=8), filter_="T1569")
        row = pair(before, SERVICE)
        self.assertEqual((row["verdict"], row["attested_seconds"]), ("unattested", 0.0))
        self.assertEqual([(b["detail"], b["seconds"]) for b in before["breaks"]], [("no record of the channel inside the window", 12 * 3600.0)])
        wider = sil.assess(steady(SYSTEM, 60), start=T0 - timedelta(hours=8), end=T0 + timedelta(hours=16), filter_="T1569")
        row = pair(wider, SERVICE)
        self.assertEqual(row["verdict"], "attested")
        self.assertAlmostEqual(row["coverage"], (59 * 5) / (24 * 60), places=3)
        self.assertEqual(sorted(b["edge"] for b in wider["breaks"]), ["lead", "trail"])

    def test_a_record_without_a_time_is_counted_and_left_out(self):
        res = sil.assess([*steady(SYSTEM, 40), {"Channel": SYSTEM, "EventID": 7036, "Computer": "H1"}])
        self.assertEqual((res["records"], res["undated"]), (41, 1))

    def test_what_the_quiet_covers_is_read_from_the_behaviour_spec(self):
        res = sil.assess(steady(SYSTEM, 40))
        spec = res["detections"]["T1059.001_powershell_encoded_command"]["behaviour"]
        self.assertTrue(spec["spec"])
        self.assertGreater(spec["fires"], 0)
        self.assertIn("Quoted parts inside an argument", spec["gaps"])
        self.assertIn("slip past", sil.scope_text(spec))
        self.assertFalse(res["detections"][SERVICE]["behaviour"]["spec"])
        self.assertIn("no behaviour spec", sil.scope_text(res["detections"][SERVICE]["behaviour"]))
        self.assertEqual(sil.scope_text({"spec": True, "fires": 1, "gaps": ["x"], "exclusions": 0}),
                         "1 variant proven on every event · 1 documented variant slips past")


class ShippedModel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.trace = survivability.load_model()
        cls.doc = yaml.safe_load(sil.MODEL.read_text(encoding="utf-8"))

    def problems(self, edit) -> str:
        doc = copy.deepcopy(self.doc)
        edit(doc)
        return " | ".join(sil.check(sil.build_model(doc), self.trace))

    def test_the_model_agrees_with_trace_the_rules_and_the_engine(self):
        self.assertEqual(sil.check(sil.load_model(), self.trace), [])
        self.assertEqual(sil.cut_events_fire(sil.load_model()), [])

    def test_every_record_a_detection_reads_has_a_witness(self):
        model = sil.load_model()
        self.assertEqual({fp.reads for fp in self.trace.footprints.values()} - set(model.witnesses), set())
        self.assertIn("no witness for sysmon_10", self.problems(lambda d: d["witnesses"].pop("sysmon_10")))

    def test_a_witness_must_be_an_artifact_trace_knows_and_a_channel_proof_needs_a_channel(self):
        self.assertIn("witness ghost is not an artifact", self.problems(lambda d: d["witnesses"].update(ghost={"proof": "event"})))
        self.assertIn("a channel proof needs a store with a channel",
                      self.problems(lambda d: d["witnesses"]["dc_4769"].update(proof="channel")))
        self.assertIn("proof must be one of", self.problems(lambda d: d["witnesses"]["sysmon_1"].update(proof="hope")))

    def test_a_cut_is_held_to_the_rule_that_reads_it(self):
        def unread(d):
            next(c for c in d["cuts"] if c["id"] == "security_cleared").pop("detection")

        def wrong(d):
            next(c for c in d["cuts"] if c["id"] == "audit_policy_changed")["detection"] = "T1685.005_security_log_cleared"

        def unlike(d):
            next(c for c in d["cuts"] if c["id"] == "event_log_stopped")["event"]["EventID"] = 6005
        self.assertIn("a rule now reads this record: name it in `detection`", self.problems(unread))
        self.assertIn("the sample event fires no rule, the model says ['T1685.005_security_log_cleared']", self.problems(wrong))
        self.assertIn("the sample event is not a record that `record` describes", self.problems(unlike))
        self.assertIn("erasure vanish is not in dfir/trace/model.yml",
                      self.problems(lambda d: d["cuts"][0].update(erasures=["vanish"])))
        self.assertIn("edge must be one of", self.problems(lambda d: d["cuts"][0].update(edge="maybe")))
        self.assertIn("`record` must name at least a Channel and an EventID", self.problems(lambda d: d["cuts"][0].update(record={})))

    def test_a_certificate_must_say_what_it_does_not_say(self):
        self.assertIn("limits is empty", self.problems(lambda d: d.update(limits=[])))
        self.assertIn("claim is empty", self.problems(lambda d: d.update(claim="")))

    def test_a_yaml_key_read_as_a_boolean_is_not_used(self):
        """`on:` is True in YAML 1.1: a cut that named its record under it would match nothing."""
        self.assertTrue(all(isinstance(k, str) for c in self.doc["cuts"] for k in c))
        self.assertTrue(all(c.record for c in sil.load_model().cuts))

    def test_the_wake_is_not_read_from_the_record_stamped_with_the_old_clock(self):
        sleep = next(d for d in sil.load_model().down if d.id == "sleep")
        self.assertEqual((sleep.start["EventID"], sleep.end["Provider_Name"]), (42, "Microsoft-Windows-Power-Troubleshooter"))


class SampleFleet(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.res = sil.sample_result()

    def test_the_sample_is_what_its_generator_writes(self):
        spec = importlib.util.spec_from_file_location("silence_fleet", sil.SAMPLE / "generate.py")
        gen = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gen)
        text = "".join(json.dumps(e, separators=(",", ":")) + "\n" for e in gen.build())
        self.assertEqual(text, sil.SAMPLE_EXPORT.read_text(encoding="utf-8"), "run: python samples/silence/generate.py")
        self.assertEqual(text, "".join(json.dumps(e, separators=(",", ":")) + "\n" for e in gen.build()), "the same file twice")

    def test_the_quiet_hosts_are_attested_whole_by_sequence(self):
        for host in ("DC01.corp.lab", "WS01.corp.lab", "WS06.corp.lab"):
            row = pair(self.res, SERVICE, host)
            self.assertEqual((row["verdict"], row["grade"], row["coverage"]), ("attested", "sequence", 1.0), host)
        self.assertEqual(pair(self.res, SERVICE, "SRV-FS01.corp.lab")["grade"], "rhythm", "its pipeline drops the record number")

    def test_the_intrusion_breaks_the_quiet(self):
        fired = sorted((r["detection"], r["host"]) for r in self.res["pairs"] if r["verdict"] == "fired")
        self.assertEqual(fired, [("T1003.001_lsass_memory_access", "WS02.corp.lab"), ("T1059.001_powershell_encoded_command", "WS02.corp.lab"),
                                 ("T1218.011_rundll32_suspicious_execution", "WS02.corp.lab"),
                                 ("T1547.001_registry_run_key_persistence", "WS02.corp.lab"),
                                 ("T1685.005_system_log_cleared", "WS03.corp.lab")])

    def test_each_way_the_quiet_stops_being_evidence_is_found(self):
        by_host = {b["host"]: b for b in self.res["breaks"]}
        self.assertEqual(sorted(by_host), ["WS03.corp.lab", "WS04.corp.lab", "WS05.corp.lab"])
        cleared, cut, blind = by_host["WS03.corp.lab"], by_host["WS04.corp.lab"], by_host["WS05.corp.lab"]
        self.assertEqual((cleared["kind"], cleared["channels"], cleared["cuts"]), ("cleared", [SYSMON], ["channel_cleared"]))
        self.assertGreater(cleared["missing"], 0)
        self.assertEqual((cut["kind"], cut["channels"], cut["cuts"]), ("missing", [SECURITY], []))
        self.assertGreater(cut["missing"], 20)
        self.assertEqual((blind["kind"], sorted(blind["channels"])), ("stopped", [SYSMON, SECURITY, SYSTEM]))
        self.assertIn("no record of a stop before it", blind["detail"])
        self.assertEqual(blind["life"], "DC01.corp.lab recorded 4 events naming it meanwhile")
        self.assertEqual({b["severity"] for b in self.res["breaks"]}, {"high"})
        self.assertLess(pair(self.res, LSASS, "WS05.corp.lab")["coverage"], 0.9)
        self.assertLess(pair(self.res, "T1685.005_security_log_cleared", "WS04.corp.lab")["coverage"], 1.0)

    def test_the_night_off_is_not_held_against_the_host(self):
        self.assertEqual([(d["host"], d["what"]) for d in self.res["down"]], [("WS01.corp.lab", "shut down")])
        row = pair(self.res, LSASS, "WS01.corp.lab")
        self.assertEqual(row["coverage"], 1.0)
        self.assertGreater(row["down_seconds"], 11 * 3600)

    def test_the_blind_spots_say_what_to_turn_on(self):
        row = pair(self.res, LSASS, "WS06.corp.lab")
        self.assertEqual((row["verdict"], row["reason"]), ("unattested", "no_proof"))
        row = pair(self.res, LSASS, "SRV-FS01.corp.lab")
        self.assertEqual((row["verdict"], row["reason"]), ("unattested", "no_record"))
        self.assertIn("ProcessAccess rule for lsass.exe", self.res["detections"][LSASS]["enable"])

    def test_the_counts_add_up(self):
        c = self.res["counts"]
        self.assertEqual(c["pairs"], c["attested"] + c["fired"] + c["unattested"])
        self.assertEqual(c["attested"], c["sequence"] + c["rhythm"])
        self.assertGreater(c["rhythm"], 0)
        self.assertEqual(c["pairs"], len(self.res["pairs"]))
        for r in self.res["pairs"]:
            self.assertLessEqual(r["attested_seconds"], r["watched_seconds"] + 1e-6, r)

    def test_the_results_page_is_current(self):
        page = sil.README.read_text(encoding="utf-8")
        self.assertEqual(sil.with_block(page, sil.render(self.res)), page, "run: rasd build")

    def test_the_page_draws_every_sensor_inside_the_window_and_escapes_what_it_prints(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        res = copy.deepcopy(self.res)
        res["breaks"][0]["detail"] = "<script>alert(1)</script>"
        sil.write_html(str(tmp / "deep" / "page.html"), res, [{"name": "a&b.jsonl", "records": 1, "sha256": "ab" * 32}])
        page = (tmp / "deep" / "page.html").read_text(encoding="utf-8")
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertIn("a&amp;b.jsonl", page)
        import re
        lefts = [float(x) for x in re.findall(r'style="left:([0-9.]+)%', page)]
        widths = [float(x) for x in re.findall(r'%;width:([0-9.]+)%', page)]
        self.assertTrue(lefts and all(0 <= x <= 100 for x in lefts))
        self.assertTrue(all(0 <= x <= 100 for x in widths))
        self.assertEqual(page.count('<section class="card">'), len(self.res["hosts"]))

    def test_the_certificate_states_the_claim_the_inputs_and_the_limits(self):
        text = sil.certificate(self.res, [{"name": "fleet.jsonl", "records": self.res["records"], "sha256": "ab" * 32}])
        for part in ("# Certificate of silence", "## The claim", self.res["claim"], "`" + "ab" * 32 + "`", "### The quiet is broken",
                     "### Attested", "### Quiet that proves nothing", "## Breaks in the record",
                     "## Documented variants a quiet rule does not cover", "## What this certificate does not say",
                     "rasd silence fleet.jsonl"):
            self.assertIn(part, text)
        for limit in self.res["limits"]:
            self.assertIn(limit.split(".")[0][:60], text)


class CommandLine(unittest.TestCase):
    def run_rasd(self, *argv: str, cwd: Path = ROOT) -> subprocess.CompletedProcess:
        return subprocess.run([*RASD, *argv], cwd=cwd, capture_output=True, text=True, encoding="utf-8",
                              env={**os.environ, "NO_BANNER": "1", "NO_COLOR": "1"})

    def test_an_export_gives_the_report_the_certificate_and_the_json(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        shutil.copy(sil.SAMPLE_EXPORT, tmp / "fleet.jsonl")
        shutil.copy(sil.SAMPLE_ASSETS, tmp / "assets.csv")
        out = self.run_rasd("fleet.jsonl", "--assets", "assets.csv", "--certificate", "out/silence.md", "--json", "out/silence.json",
                            "--html", "out/silence.html", cwd=tmp)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        for part in ("The quiet is broken", "Quiet that is evidence", "Quiet that proves nothing", "Breaks in the record",
                     "not counted: WS01.corp.lab shut down"):
            self.assertIn(part, out.stdout)
        doc = json.loads((tmp / "out" / "silence.json").read_text(encoding="utf-8"))
        self.assertEqual((doc["format"], doc["inputs"][0]["name"], len(doc["inputs"][0]["sha256"])), (1, "fleet.jsonl", 64))
        cert = (tmp / "out" / "silence.md").read_bytes()
        self.assertIn(b"# Certificate of silence", cert)
        self.assertNotIn(b"\r\n", cert)
        self.assertIn("rasd silence fleet.jsonl --assets assets.csv", cert.decode("utf-8"))
        self.assertIn("| `assets.csv` | 8 |", cert.decode("utf-8"), "every input is named with its hash")
        page = (tmp / "out" / "silence.html").read_text(encoding="utf-8")
        for part in ("<title>RASD-Silence</title>", "The record, sensor by sensor", "WS05.corp.lab", 'class="off"', 'class="high"',
                     'class="hit"', "no record of a stop before it", "What this does not say"):
            self.assertIn(part, page)

    def test_check_passes_on_the_shipped_model_and_page(self):
        out = self.run_rasd("--check")
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("silence model consistent", out.stdout)

    def test_a_missing_export_and_a_bad_time_are_said_plainly(self):
        out = self.run_rasd("nowhere.jsonl")
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("nowhere.jsonl: no such file", out.stderr)
        out = self.run_rasd(str(sil.SAMPLE_EXPORT), "--from", "yesterday")
        self.assertIn("--from yesterday: not a time", out.stderr)

    def test_with_no_export_and_no_windows_it_says_what_to_pass(self):
        with mock.patch.object(sil, "wevtutil", return_value=None), mock.patch.object(sys, "argv", ["silence.py"]), \
                self.assertRaises(sil.SilenceError) as caught:
            sil.main()
        self.assertIn("rasd silence EXPORT.jsonl reads an export", str(caught.exception))

    def test_this_host_is_read_through_wevtutil_and_each_channel_says_what_happened(self):
        def record(number: int, minute: int) -> str:
            return ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
                    "<Provider Name='Service Control Manager'/><EventID Qualifiers='16384'>7036</EventID>"
                    f"<TimeCreated SystemTime='2026-01-05T08:{minute:02d}:00.0000000Z'/><EventRecordID>{number}</EventRecordID>"
                    "<Channel>System</Channel><Computer>HOME-PC</Computer></System>"
                    "<EventData><Data Name='param1'>Windows Update</Data></EventData></Event>")
        asked = []

        def fake(cmd, stdout, stderr, **_kw):
            channel, query = cmd[2], cmd[-1]
            asked.append((channel, query))
            if channel == "System":
                # the first record of the window by time, then everything from its number on
                rows = [record(500, 0)] if "timediff" in query else [record(500 + i, i) for i in range(40)]
                stdout.write(("\ufeff" + "".join(rows)).encode("utf-16-le"))
                return SimpleNamespace(returncode=0)
            if channel == "Security":
                stderr.write("Access is denied.".encode("utf-16-le"))
                return SimpleNamespace(returncode=5)
            return SimpleNamespace(returncode=15007)
        with mock.patch.object(sil, "wevtutil", return_value="wevtutil"), mock.patch.object(sil.subprocess, "run", fake):
            events, notes = sil.collect(7)
        self.assertEqual((len(events), events[0]["EventRecordID"], events[0]["Computer"]), (40, 500, "HOME-PC"))
        self.assertIn(("System", "/q:*[System[(EventRecordID >= 500)]]"), asked, "by number, so a record with an old clock is not left out")
        states = {n["channel"]: n["state"] for n in notes}
        self.assertEqual(states["System"], "read")
        self.assertIn("not readable without elevation", states["Security"])
        self.assertIn("does not exist on this host", states[SYSMON])
        res = sil.assess(events)
        row = pair(res, SERVICE, "HOME-PC")
        self.assertEqual((row["verdict"], row["grade"]), ("attested", "sequence"))
        self.assertEqual(pair(res, "T1685.005_security_log_cleared", "HOME-PC")["reason"], "no_record")
        text = sil.certificate(res, [], notes)
        self.assertIn("| Security (this host) | 0 | not readable without elevation", text)

    def test_reading_this_host_without_wevtutil_is_refused(self):
        with mock.patch.object(sil, "wevtutil", return_value=None), self.assertRaises(sil.SilenceError):
            sil.collect(1)


if __name__ == "__main__":
    unittest.main()
