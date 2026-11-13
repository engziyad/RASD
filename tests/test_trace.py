"""Tests for RASD-Trace (tools/survivability.py): the search on small hand-built models, and the shipped model."""
import contextlib
import copy
import io
import sys
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import survivability as sv  # noqa: E402

T = sv.TECHNIQUE


def world(erasures: list[dict], writes: tuple[str, ...] = (), forwarded: tuple[str, ...] = ("log",)) -> sv.Model:
    """One detection that reads `rec` from a forwarded log, with optional extra artifacts and the given erasures."""
    model = {
        "position": "an administrator on the host",
        "questions": {"alert": "", "ran": "", "when": "", "who": "", "how": ""},
        "baseline": {"forwarder_inputs": "", "forwarded": {s: s for s in forwarded}},
        "stores": {"log": {"name": "Log", "reach": "host", "collect": 1}, "disk": {"name": "Disk", "reach": "host", "collect": 2},
                   "other": {"name": "Other log", "reach": "host", "collect": 1}, "far": {"name": "Far", "reach": "remote", "collect": 3}},
        "artifacts": {
            "rec": {"name": "Record", "store": "log", "answers": ["ran", "when", "who", "how"], "basis": "vendor", "source": "https://x"},
            "file": {"name": "File", "store": "disk", "answers": ["ran", "when"], "basis": "vendor", "source": "https://x"},
            "note": {"name": "Note", "store": "other", "answers": ["ran"], "basis": "vendor", "source": "https://x"},
            "extra": {"name": "Extra", "store": "log", "answers": ["how"], "optional": "a policy", "basis": "vendor", "source": "https://x"},
            "away": {"name": "Away", "store": "far", "answers": ["ran", "who"], "basis": "vendor", "source": "https://x"},
        },
        "erasures": erasures,
    }
    prints = {"footprints": {"D": {"reads": "rec", "writes": [{"artifact": a} for a in writes]}}}
    return sv.build_model(model, prints)


CLEAR_SEEN = {"id": "clear", "name": "Clear", "destroys": ["log"], "basis": "vendor",
              "traces": [{"artifact": "rec", "at": "effect", "detection": "R", "event": {"EventID": 1}}]}
CLEAR_QUIET = {"id": "clear", "name": "Clear", "destroys": ["log"], "basis": "vendor", "traces": []}
WIPE_DISK = {"id": "wipe", "name": "Wipe", "destroys": ["disk"], "basis": "vendor", "traces": []}
BLIND_QUIET = {"id": "blind", "name": "Blind", "blinds": ["log"], "basis": "vendor",
               "traces": [{"artifact": "note", "at": "start", "event": {"EventID": 4}}]}
UNPLUG = {"id": "unplug", "name": "Unplug", "stops_forwarding": True, "basis": "vendor",
          "traces": [{"artifact": "rec", "at": "start", "detection": "R", "event": {"EventID": 1}}]}


class Search(unittest.TestCase):
    def verdicts(self, m: sv.Model, **kw) -> dict:
        return {q: (r["verdict"], r["quiet"] and r["quiet"][0]) for q, r in sv.survivability(m, m.footprints["D"], **kw).items()}

    def test_a_forwarded_record_is_out_of_reach_of_actions_that_only_destroy(self):
        m = world([CLEAR_QUIET, WIPE_DISK], writes=("file",))
        self.assertEqual(set(self.verdicts(m).values()), {("out of reach", None)})

    def test_blinding_before_the_technique_removes_the_alert_and_the_copy(self):
        m = world([BLIND_QUIET])
        v = self.verdicts(m)
        self.assertEqual(v["alert"], ("exposed", 1))
        self.assertEqual(v["how"], ("exposed", 1))
        self.assertEqual(sv.survivability(m, m.footprints["D"])["alert"]["quiet"][1], ["blind", T])

    def test_every_witness_has_to_go_before_an_answer_does(self):
        m = world([BLIND_QUIET, WIPE_DISK], writes=("file",))
        v = self.verdicts(m)
        self.assertEqual(v["how"], ("exposed", 1), "only the record answers how")
        self.assertEqual(v["ran"], ("exposed", 2), "the file still answers ran until the disk is wiped")

    def test_a_trace_a_rule_reads_makes_the_answer_evident(self):
        blind_seen = {**BLIND_QUIET, "traces": [{"artifact": "rec", "at": "start", "detection": "R", "event": {"EventID": 1}}]}
        m = world([blind_seen])
        v = self.verdicts(m)
        self.assertEqual(v["ran"], ("evident", None))
        self.assertEqual(sv.survivability(m, m.footprints["D"])["ran"]["erase"][0], 1)

    def test_a_start_trace_is_written_before_its_own_blinding_takes_effect(self):
        blind = {"id": "blind", "name": "Blind", "blinds": ["log"], "basis": "vendor",
                 "traces": [{"artifact": "rec", "at": "start", "detection": "R", "event": {"EventID": 1}}]}
        late = copy.deepcopy(blind)
        late["traces"][0]["at"] = "effect"
        self.assertEqual(self.verdicts(world([blind]))["alert"], ("evident", None))
        self.assertEqual(self.verdicts(world([late]))["alert"], ("exposed", 1), "an effect trace in the blinded store is never written")

    def test_still_written_records_survive_the_blinding(self):
        late = {"id": "blind", "name": "Blind", "blinds": ["log"], "still_written": ["rec"], "basis": "vendor",
                "traces": [{"artifact": "rec", "at": "effect", "detection": "R", "event": {"EventID": 1}}]}
        m = world([late])
        self.assertEqual(set(self.verdicts(m).values()), {("out of reach", None)}, "the record the rule reads is written anyway")

    def test_the_forwarder_does_not_ship_the_record_of_its_own_stop(self):
        m = world([UNPLUG])
        self.assertEqual(self.verdicts(m)["alert"], ("exposed", 1))
        self.assertEqual(self.verdicts(m)["ran"], ("out of reach", None), "the record stays on the host and nothing here clears it")

    def test_stopping_the_forwarder_silences_later_traces(self):
        m = world([UNPLUG, CLEAR_SEEN])
        v = self.verdicts(m)
        self.assertEqual(v["ran"], ("exposed", 2))
        self.assertEqual(sv.survivability(m, m.footprints["D"])["ran"]["quiet"][1], ["unplug", T, "clear"])

    def test_a_record_written_elsewhere_cannot_be_removed(self):
        m = world([BLIND_QUIET, CLEAR_QUIET], writes=("away",))
        v = self.verdicts(m)
        self.assertEqual(v["ran"], ("out of reach", None))
        self.assertEqual(v["who"], ("out of reach", None))
        self.assertEqual(v["how"], ("exposed", 1), "the remote record does not answer how")

    def test_an_optional_artifact_counts_only_when_enabled(self):
        m = world([BLIND_QUIET], writes=("extra",))
        self.assertNotIn("extra", sv.run_technique(m, m.footprints["D"], sv.START, frozenset())[3])
        self.assertIn("extra", sv.run_technique(m, m.footprints["D"], sv.START, frozenset({"extra"}))[3])

    def test_a_host_that_forwards_nothing_has_a_depth(self):
        m = world([CLEAR_SEEN, WIPE_DISK], writes=("file",))
        self.assertEqual(sv.host_depth(m)["D"], {"ran": 2, "when": 2, "who": 1, "how": 1})

    def test_residue_tells_host_from_siem(self):
        own = {"id": "clear", "name": "Clear", "destroys": ["log"], "basis": "vendor",
               "traces": [{"artifact": "rec", "at": "start"}, {"artifact": "rec", "at": "effect"}, {"artifact": "file", "at": "start"}]}
        m = world([own])
        rows = sv.residue(m, m.footprints["D"], [T, "clear"])
        self.assertEqual([(r["host"], r["siem"]) for r in rows], [(False, True), (True, True), (True, False)],
                         "the start record is cleared with the log it sits in and has already left; the effect record stays")

    def test_closure_supposes_the_rule_that_blocks_the_most_sequences(self):
        other = {"id": "other", "name": "Other", "blinds": ["log"], "basis": "vendor",
                 "traces": [{"artifact": "note", "at": "start", "event": {"EventID": 4}}]}
        m = world([BLIND_QUIET, other], forwarded=("log", "other"))
        steps = sv.closure(m)
        self.assertEqual([s["rule"] for s in steps], ["note"])
        self.assertEqual(steps[-1]["exposed_after"], 0, "one rule on the artifact both actions leave closes both")

    def test_closure_stops_when_nothing_readable_is_left(self):
        m = world([BLIND_QUIET])
        self.assertEqual(sv.closure(m), [], "the trace sits in a store that is not forwarded: no SIEM rule could read it")
        self.assertEqual(self.verdicts(m)["alert"], ("exposed", 1))


class Shipped(unittest.TestCase):
    """The model in dfir/trace agrees with the rules, the forwarder inputs and the engine, and its page is current."""

    @classmethod
    def setUpClass(cls):
        cls.m = sv.load_model()
        cls.raw = yaml.safe_load(sv.MODEL.read_text(encoding="utf-8"))
        cls.prints = yaml.safe_load(sv.FOOTPRINTS.read_text(encoding="utf-8"))

    def test_model_is_consistent(self):
        self.assertEqual(sv.check(self.m), [])

    def test_a_trace_that_names_the_wrong_rule_is_refused(self):
        raw = copy.deepcopy(self.raw)
        clear = next(e for e in raw["erasures"] if e["id"] == "clear_security_log")
        next(t for t in clear["traces"] if t["artifact"] == "security_1102")["detection"] = "T1685.005_system_log_cleared"
        errs = sv.check(sv.build_model(raw, self.prints))
        self.assertTrue(any("fires ['T1685.005_security_log_cleared']" in e for e in errs), errs)

    def test_a_trace_a_rule_reads_cannot_be_called_unread(self):
        raw = copy.deepcopy(self.raw)
        clear = next(e for e in raw["erasures"] if e["id"] == "clear_sysmon_log")
        del next(t for t in clear["traces"] if t["artifact"] == "system_104")["detection"]
        errs = sv.check(sv.build_model(raw, self.prints))
        self.assertTrue(any("a rule now reads this trace" in e for e in errs), errs)

    def test_forwarded_channels_follow_the_forwarder_inputs(self):
        raw = copy.deepcopy(self.raw)
        raw["baseline"]["forwarded"]["winrm_log"] = "Microsoft-Windows-WinRM/Operational"
        errs = sv.check(sv.build_model(raw, self.prints))
        self.assertTrue(any("baseline.forwarded" in e for e in errs), errs)

    def test_a_footprint_must_read_the_rules_log_source(self):
        prints = copy.deepcopy(self.prints)
        prints["footprints"]["T1003.001_lsass_memory_access"]["reads"] = "sysmon_1"
        errs = sv.check(sv.build_model(self.raw, prints))
        self.assertTrue(any("the rule reads process_access" in e for e in errs), errs)

    def test_every_detection_is_accounted_for(self):
        prints = copy.deepcopy(self.prints)
        del prints["not_modelled"]["T1190_object_id_enumeration"]
        errs = sv.check(sv.build_model(self.raw, prints))
        self.assertTrue(any("T1190_object_id_enumeration has neither a footprint nor a reason" in e for e in errs), errs)

    def test_records_on_other_machines_are_out_of_reach(self):
        res = sv.survivability(self.m, self.m.footprints["T1558.003_honey_spn_ticket_request"])
        self.assertEqual({r["verdict"] for r in res.values()}, {"out of reach"})

    def test_the_log_clears_are_seen_while_the_forwarder_ships(self):
        fp = self.m.footprints["T1059.001_powershell_encoded_command"]
        state = sv.run_technique(self.m, fp, sv.START, frozenset())
        for action in ("clear_security_log", "clear_system_log", "clear_sysmon_log", "clear_powershell_logs"):
            self.assertTrue(sv.run_erasure(self.m, self.m.erasures[action], state, frozenset(), frozenset())[6], action)

    def test_page_is_current(self):
        text = sv.README.read_text(encoding="utf-8")
        self.assertEqual(sv.with_block(text, sv.render(self.m, sv.compute(self.m))), text)

    def test_lost_stores_leave_the_host_artifacts(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            sv.print_detection(self.m, "T1059.001_powershell_encoded_command", {"sysmon_log", "security_log", "siem"})
        text = out.getvalue()
        self.assertIn("Prefetch file of the executable", text)
        self.assertNotIn("SIEM copy", text)
        self.assertNotIn("[Sysmon operational log]", text)
        with contextlib.redirect_stdout(io.StringIO()) as lsass:
            sv.print_detection(self.m, "T1003.001_lsass_memory_access", {"sysmon_log", "siem"})
        self.assertIn("no witness left", lsass.getvalue())


if __name__ == "__main__":
    unittest.main()
