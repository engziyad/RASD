"""Tests for RASD-Blindpath (tools/blindpath.py): the model, the proof behind every verdict, the plan, the reports."""
import contextlib
import copy
import functools
import io
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from itertools import combinations
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import blindpath as bp  # noqa: E402
import silence as sil  # noqa: E402
import survivability  # noqa: E402
from common import load_detections  # noqa: E402
from correlation import evaluate, load_correlations  # noqa: E402
from replay import load_assets, replay, route  # noqa: E402
from sigma_engine import matches  # noqa: E402

RASD = (sys.executable, str(ROOT / "rasd.py"), "blindpath")
DC, FS, WS1, WS6 = "DC01.corp.lab", "SRV-FS01.corp.lab", "WS01.corp.lab", "WS06.corp.lab"
ENCODED, RUNDLL, LSASS = "T1059.001_powershell_encoded_command", "T1218.011_rundll32_suspicious_execution", "T1003.001_lsass_memory_access"
CLEARING, CLEARED, WINRM = "T1685.005_event_log_clearing", "T1685.005_security_log_cleared", "T1021.006_wsmprovhost_suspicious_child"
RC4, VOLUME, SPRAY = "T1558.003_kerberoasting_rc4_tgs", "T1558.003_kerberoasting_volume", "T1110.003_password_spray_burst"
SEEING = ("attested", "fired")


@functools.lru_cache(maxsize=1)
def sample() -> SimpleNamespace:
    model, book = bp.load_model(), bp.book()
    quiet = sil.sample_result()
    assets = load_assets(str(sil.SAMPLE_ASSETS))
    return SimpleNamespace(model=model, book=book, quiet=quiet, assets=assets, res=bp.assess(quiet, model, assets=assets),
                           ways=bp.all_ways(model, book), trace=survivability.load_model())


def cell(res: dict, host: str, stage: str) -> dict:
    return next(c for c in res["cells"] if c["host"] == host and c["stage"] == stage)


def step(res: dict, host: str, ident: str) -> dict:
    stage = res["steps"][ident]["stage"]
    return next(s for s in cell(res, host, stage)["steps"] if s["step"] == ident)


def changed(quiet: dict, rows: dict[tuple[str, str], str]) -> dict:
    """The answer of rasd silence with some detection-host pairs turned dark ('dark') or made to record ('live')."""
    out = copy.deepcopy(quiet)
    for r in out["pairs"]:
        to = rows.get((r["detection"], r["host"]))
        if to == "dark":
            r.update(verdict="unattested", reason="no_record", why="no record of it from this host is in the export", fix=None)
        elif to == "live":
            r.update(verdict="attested", reason=None, why=None, fix=None)
    return out


def recording(quiet: dict, rule: str, host: str, local: bool) -> bool:
    """Read from the pairs of rasd silence alone: does anything show this rule can see an act on this host?"""
    rows = [r for r in quiet["pairs"] if r["detection"] == rule and r["host"] is not None and (not local or r["host"] == host)]
    return any(r["verdict"] in SEEING or r["reason"] not in bp.DARK for r in rows)


class ModelFile(unittest.TestCase):
    def setUp(self):
        self.s = sample()

    def test_the_shipped_model_agrees_with_the_repository(self):
        self.assertEqual(bp.check(self.s.model, self.s.book), [])

    def test_every_detection_is_an_observer_or_a_tripwire(self):
        placed = {o for st in self.s.model.steps for o in st.observers} | {t.detection for t in self.s.model.tripwires}
        self.assertEqual(placed, set(self.s.book.targets))

    def test_a_detection_with_no_place_fails_the_check(self):
        m = copy.deepcopy(self.s.model)
        m.steps = [st for st in m.steps if st.id != "run_key"]
        errs = bp.check(m, self.s.book)
        self.assertTrue(any("T1547.001_registry_run_key_persistence" in e and "is not placed" in e for e in errs), errs)

    def test_a_documented_variant_with_no_place_fails_the_check(self):
        m = copy.deepcopy(self.s.model)
        del m.ways[(ENCODED, "White space inside the Base64 text")]
        errs = bp.check(m, self.s.book)
        self.assertTrue(any("White space inside the Base64 text" in e and "not placed under `ways`" in e for e in errs), errs)

    def test_a_variant_no_spec_documents_fails_the_check(self):
        m = copy.deepcopy(self.s.model)
        m.ways[(ENCODED, "A variant nobody wrote")] = bp.Choice("intruder", "", "")
        self.assertTrue(any("A variant nobody wrote" in e for e in bp.check(m, self.s.book)))

    def test_the_tripwires_are_the_decoy_detections(self):
        m = copy.deepcopy(self.s.model)
        gone = m.tripwires.pop()
        m.apart[gone.detection] = "moved"
        self.assertTrue(any("deceive/decoys.yml" in e for e in bp.check(m, self.s.book)))

    def test_a_step_watches_rules_of_its_own_technique(self):
        m = copy.deepcopy(self.s.model)
        m.steps = [bp.Step(st.id, st.stage, st.title, "T9999", st.observers) if st.id == "run_key" else st for st in m.steps]
        self.assertTrue(any("is not a rule for T9999" in e for e in bp.check(m, self.s.book)))

    def test_a_variant_the_intruder_does_not_choose_needs_its_reason(self):
        m = copy.deepcopy(self.s.model)
        m.ways[(LSASS, "Memory read access written in decimal")] = bp.Choice("environment", "", "")
        self.assertTrue(any("needs its `why`" in e for e in bp.check(m, self.s.book)))

    def test_a_file_of_the_wrong_shape_is_refused(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "model.yml").write_text("- a list\n", encoding="utf-8", newline="\n")
        with self.assertRaises(bp.BlindpathError):
            bp.load_model(tmp / "model.yml")
        (tmp / "model.yml").write_text("stages: {a: 1}\n", encoding="utf-8", newline="\n")
        with self.assertRaises(bp.BlindpathError):
            bp.load_model(tmp / "model.yml")
        with self.assertRaises(bp.BlindpathError):
            bp.load_model(tmp / "nowhere.yml")

    def test_something_written_twice_is_said(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        text = bp.MODEL.read_text(encoding="utf-8").replace("  - id: cover\n", "  - id: cover\n    title: Again\n  - id: cover\n", 1)
        (tmp / "model.yml").write_text(text, encoding="utf-8", newline="\n")
        self.assertIn("stage `cover` is written twice", bp.check(bp.load_model(tmp / "model.yml"), self.s.book))


class Witnesses(unittest.TestCase):
    """Every way around is a sequence of events; what the tool says of it is asked of the engine again."""

    def setUp(self):
        self.s = sample()
        self.flat = [w for group in self.s.ways.values() for w in group]
        self.dets, self.corrs = list(load_detections()), list(load_correlations())

    def test_the_alerts_of_every_way_are_what_the_engine_raises(self):
        self.assertGreater(len(self.flat), 15)
        for w in self.flat:
            alerts, _stats = replay(w.events, self.dets, {}, corrs=self.corrs)
            self.assertEqual(tuple(sorted({a["rule"] for a in alerts})), w.fired, w.label)

    def test_a_documented_variant_stays_in_its_variant_and_slips_its_own_rule(self):
        rules = {d.id: d.rule for d in self.dets} | {c.id: c.base for c in self.corrs}
        for w in self.flat:
            if w.kind == "pace":
                continue
            spec = self.s.book.specs[w.detection]
            variant = next(v for v in spec.variants if v.name == w.variant)
            self.assertEqual(variant.expect, "bypass")
            for ev in w.events:
                self.assertTrue(bp.in_variant(ev, variant), w.label)
                self.assertFalse(matches(rules[w.detection], ev), w.label)
            self.assertNotIn(w.detection, w.fired)

    def test_every_event_routes_to_the_log_source_of_its_rule(self):
        for w in self.flat:
            for ev in w.events:
                self.assertEqual(route(ev), self.s.book.targets[w.detection].logsource, w.label)

    def test_a_pace_is_exactly_one_under_the_count(self):
        paces = [w for w in self.flat if w.kind == "pace"]
        self.assertTrue(paces)
        for w in paces:
            corr = next(c for c in self.corrs if c.id == w.detection)
            p, count = corr.params, bp.need(corr)
            self.assertEqual(evaluate(corr, w.events), [], w.label)
            self.assertEqual(len(w.events), bp.PACED_WINDOWS * (count - 1))
            if p.counted:
                self.assertEqual(len({ev[p.counted] for ev in w.events}), len(w.events), "every counted value is its own")
            one_more = [dict(ev, TimeCreated=w.events[0]["TimeCreated"]) for ev in w.events[:count]]
            self.assertTrue(evaluate(corr, one_more), f"{count} in one window must alert")
            self.assertIsNone(w.atom, "no rule change closes a pace")

    def test_the_windows_of_a_pace_are_two_lengths_apart(self):
        from replay import parse_time
        for w in (w for w in self.flat if w.kind == "pace"):
            corr = next(c for c in self.corrs if c.id == w.detection)
            times = sorted(parse_time(ev) for ev in w.events)
            per = bp.need(corr) - 1
            for a, b in zip(times[per - 1::per], times[per::per], strict=False):
                self.assertGreater((b - a).total_seconds(), corr.params.timespan, "a sliding window holds one burst only")

    def test_a_variant_the_environment_decides_is_never_walked(self):
        walked = {(w.detection, w.variant) for w in self.flat}
        decided = [k for k, c in self.s.model.ways.items() if c.by == "environment"]
        self.assertIn((LSASS, "Memory read access written in decimal"), decided)
        for key in decided:
            self.assertNotIn(key, walked)
        for key, c in self.s.model.ways.items():
            if c.by == "intruder":
                self.assertIn(key, walked)

    def test_what_a_variant_needs_travels_with_its_witness(self):
        w = next(w for w in self.flat if w.variant == "MsMpEng.exe directly in the Platform folder")
        self.assertIn("tamper protection", w.needs)
        self.assertEqual(w.atom, ("rule", LSASS, w.variant))

    def test_a_variant_with_no_fix_in_its_spec_cannot_be_closed(self):
        w = next(w for w in self.flat if w.variant == "Cmdlet name built at run time")
        self.assertEqual((w.fix, w.atom), ("", None))

    def test_the_roasting_witness_stands_in_the_exclusion_of_the_other_observer(self):
        w = next(w for w in self.s.ways["kerberoast"] if not w.fired)
        self.assertEqual((w.kind, w.detection, w.inside), ("pace", VOLUME, (f"{RC4}: AES tickets",)))
        fired = [w.fired for w in self.s.ways["kerberoast"] if w.fired]
        self.assertIn((RC4,), fired, "the same pace with RC4 tickets is caught by the single-event rule")

    def test_an_event_that_cannot_be_routed_is_not_a_witness(self):
        t = self.s.book.targets[ENCODED]
        self.assertIsNone(bp.dress({"Channel": "Application", "EventID": 1, "Image": "x"}, t))
        dressed = bp.dress({"Image": "C:\\x.exe", "CommandLine": "x", "_case": "label"}, t)
        self.assertEqual((dressed["Channel"], dressed["EventID"], "_case" in dressed), (t.channel_name, 1, False))


class SampleFleet(unittest.TestCase):
    def setUp(self):
        self.s = sample()
        self.res = self.s.res

    def test_the_routes(self):
        c = self.res["counts"]
        self.assertEqual((c["routes"], c["routes_unseen"], c["routes_seen"]), (12, 6, 6))
        self.assertEqual(c["first_sight"], {"3": {"routes": 6, "on_tests": 6}})
        self.assertEqual(self.res["ends"], "the roles of the assets file")
        self.assertEqual((len(self.res["origins"]), self.res["targets"]), (6, [DC, FS]))
        for g in self.res["routes"]:
            self.assertEqual(g["verdict"], "unseen" if g["targets"] == [FS] else "seen", g)
            self.assertEqual(g["seen_at"], None if g["targets"] == [FS] else 3)
        self.assertEqual(sum(g["count"] for g in self.res["routes"]), 12)

    def test_the_summary_says_what_the_first_sight_rests_on(self):
        self.assertEqual(bp.summary_line(self.res), "12 routes from 6 origins to 2 targets: 6 unseen end to end, 6 first seen at leg 3 "
                                                    "(Move into the target, on rules with no behaviour spec)")

    def test_the_map(self):
        expect = {(WS1, "entry"): "-", (WS1, "execution"): "open 1/2", (WS1, "persistence"): "open 1/3",
                  (WS1, "credentials"): "open 3/3", (WS1, "movement"): "held*", (WS1, "cover"): "held",
                  (FS, "execution"): "open 2/2", (FS, "persistence"): "open 3/3", (FS, "movement"): "open 1/2", (FS, "cover"): "held",
                  (DC, "movement"): "held*"}
        for (host, stage), text in expect.items():
            self.assertEqual(bp.cell_text(cell(self.res, host, stage)), text, (host, stage))

    def test_a_host_with_no_sysmon_is_dark_and_one_with_it_needs_a_witness(self):
        self.assertEqual((step(self.res, FS, "encoded_powershell")["by"], step(self.res, WS1, "encoded_powershell")["by"]),
                         ("dark", "witness"))
        self.assertEqual((step(self.res, WS6, "lsass_read")["by"], step(self.res, WS1, "lsass_read")["by"]), ("dark", "witness"))
        self.assertIn("tamper protection", step(self.res, WS1, "lsass_read")["needs"])
        self.assertEqual(len(step(self.res, WS1, "encoded_powershell")["ways"]), 4)

    def test_a_way_with_no_condition_is_shown_before_one_with(self):
        chosen = self.res["ways"][step(self.res, WS1, "encoded_powershell")["way"] - 1]
        self.assertEqual((chosen["needs"], chosen["fired"]), ("", []))

    def test_two_records_of_one_act_hold_where_one_rule_is_slipped(self):
        got = step(self.res, WS1, "clear_security_log")
        self.assertEqual(got["verdict"], "seen")
        self.assertIn("two records of the one act", got["note"])
        self.assertTrue(any(not w.fired for w in self.s.ways["clear_security_log"]), "the command-line rule alone is slipped")
        alone = step(self.res, FS, "clear_security_log")
        self.assertEqual((alone["verdict"], [r["rule"] for r in alone["rests"]]), ("seen", [CLEARED]))

    def test_a_hold_says_whether_it_is_proven(self):
        self.assertTrue(cell(self.res, WS1, "cover")["proven"])
        self.assertFalse(cell(self.res, WS1, "movement")["proven"])
        self.assertEqual(self.res["counts"]["held_on_tests"], 7)

    def test_the_plan(self):
        rungs = self.res["ladder"]
        self.assertEqual([(r["count"], r["side"], r["same_as"], r["exact"]) for r in rungs],
                         [(4, "every origin", None, True), (4, "every origin", 1, True), (1, "every target", None, True),
                          (1, "every target", 3, True)])
        self.assertEqual({c["rule"] for c in rungs[0]["changes"]}, {ENCODED})
        self.assertEqual([(c["kind"], c["host"], c["reads"]) for c in rungs[2]["changes"]], [("sensor", FS, "Sysmon 1 (ProcessCreate)")])
        self.assertEqual(len(rungs[1]["cannot"]), 2)
        self.assertTrue(all("paced under a threshold" in x for x in rungs[1]["cannot"]))

    def test_the_tripwires_are_shown_and_not_counted(self):
        state = {t["detection"]: (t["state"], t["armed"]) for t in self.res["tripwires"]}
        self.assertEqual(state["T1558.003_honey_spn_ticket_request"], ("armed", [DC]))
        self.assertEqual(state["T1046_decoy_service_interaction"], ("not in this export", []))
        self.assertEqual(step(self.res, WS1, "kerberoast")["verdict"], "unseen", "an armed honey SPN does not make roasting seen")

    def test_the_summary_for_the_metrics_pages(self):
        s = bp.sample_summary()
        self.assertEqual((s["steps"], s["stages"], s["legs"], s["hosts"], s["routes"], s["routes_unseen"], s["plan"], s["plan_leg"]),
                         (16, 6, 4, 8, 12, 6, 1, 3))


class Proofs(unittest.TestCase):
    """Every unseen verdict derived a second time, from the pairs of rasd silence and the engine alone."""

    def setUp(self):
        self.s = sample()
        self.dets, self.corrs = list(load_detections()), list(load_correlations())
        reach = {t.id: t for t in sil.targets(sil.load_model(), self.s.trace)}
        self.local = {i: t.reach == "host" or t.artifact is None for i, t in reach.items()}
        self.reads = {i: (self.s.trace.footprints[i].reads if i in self.s.trace.footprints else t.logsource) for i, t in reach.items()}

    def proven(self, quiet: dict, res: dict) -> int:
        n = 0
        for c in res["cells"]:
            for st in c["steps"]:
                if st["verdict"] != "unseen":
                    continue
                n += 1
                host, observers = c["host"], res["steps"][st["step"]]["observers"]
                live = [o for o in observers if recording(quiet, o, host, self.local[o])]
                if st["by"] == "dark":
                    self.assertEqual(live, [], (host, st["step"]))
                    continue
                w = res["ways"][st["way"] - 1]
                alerts, _stats = replay(w["events"], self.dets, {}, corrs=self.corrs)
                seeing = [a["rule"] for a in alerts if recording(quiet, a["rule"], host, self.local[a["rule"]])]
                self.assertEqual(seeing, [], (host, st["step"], w["label"]))
                self.assertEqual(len({self.reads[o] for o in live}), 1, "the witness answers for one kind of record")
                self.assertEqual(self.reads[w["rule"]], self.reads[live[0]], "and it is that record")
        return n

    def test_every_unseen_behaviour_of_the_sample_fleet_has_its_proof(self):
        self.assertEqual(self.proven(self.s.quiet, self.s.res), self.s.res["counts"]["unseen"])
        self.assertEqual(self.s.res["counts"]["unseen"], 44)

    def test_the_same_on_fleets_changed_at_random(self):
        rng = random.Random(20261115)
        pairs = [(r["detection"], r["host"]) for r in self.s.quiet["pairs"] if r["host"]]
        for _ in range(12):
            flips = {p: rng.choice(("dark", "live")) for p in rng.sample(pairs, 25)}
            quiet = changed(self.s.quiet, flips)
            self.assertGreater(self.proven(quiet, bp.assess(quiet, self.s.model, assets=self.s.assets)), 0)

    def test_every_seen_behaviour_has_a_rule_that_can_see_it(self):
        for c in self.s.res["cells"]:
            for st in c["steps"]:
                if st["verdict"] == "seen":
                    self.assertTrue(st["rests"], (c["host"], st["step"]))
                    for r in st["rests"]:
                        self.assertTrue(recording(self.s.quiet, r["rule"], c["host"], self.local[r["rule"]]))


class ChangedFleets(unittest.TestCase):
    def setUp(self):
        self.s = sample()

    def assess(self, rows: dict, **kw) -> dict:
        return bp.assess(changed(self.s.quiet, rows), self.s.model, assets=self.s.assets, **kw)

    def test_sysmon_on_the_file_server_ends_the_unseen_routes(self):
        sysmon = [t.id for t in self.s.book.targets.values() if t.artifact == "sysmon_1"]
        res = self.assess({(rule, FS): "live" for rule in sysmon})
        self.assertEqual(res["counts"]["routes_unseen"], 0)
        self.assertEqual(bp.cell_text(cell(res, FS, "movement")), "held*")
        self.assertEqual(step(res, FS, "encoded_powershell")["by"], "witness", "a sensor turned on meets the same four variants")

    def test_a_security_log_that_is_not_collected_opens_the_clearing(self):
        res = self.assess({(CLEARED, WS1): "dark"})
        got = step(res, WS1, "clear_security_log")
        self.assertEqual((got["verdict"], got["by"]), ("unseen", "witness"))
        self.assertEqual(res["ways"][got["way"] - 1]["rule"], CLEARING)
        self.assertEqual(step(res, DC, "clear_security_log")["verdict"], "seen", "and only on that host")

    def test_a_domain_controller_that_sends_no_ticket_record_is_dark_for_everyone(self):
        res = self.assess({(RC4, DC): "dark", (VOLUME, DC): "dark"})
        for host in (WS1, FS):
            self.assertEqual(step(res, host, "kerberoast")["by"], "dark")

    def test_a_dark_single_event_rule_lets_the_rc4_pace_through(self):
        res = self.assess({(RC4, DC): "dark"})
        got = step(res, WS1, "kerberoast")
        self.assertEqual(got["by"], "witness")
        self.assertGreater(len(got["ways"]), 1, "the pace with RC4 tickets alerts only a rule with no sensor here")

    def test_a_sensor_whose_quiet_is_not_attested_still_counts_as_recording(self):
        quiet = copy.deepcopy(self.s.quiet)
        for r in quiet["pairs"]:
            if (r["detection"], r["host"]) == (WINRM, DC):
                r.update(verdict="unattested", reason="no_stretch", why="too few records")
        res = bp.assess(quiet, self.s.model, assets=self.s.assets)
        self.assertEqual(step(res, DC, "winrm_command")["verdict"], "seen")
        self.assertIn({"rule": WINRM, "host": DC, "why": "too few records"}, res["caveats"])

    def test_a_stage_with_no_sensor_anywhere_is_unwatched_and_cannot_be_planned(self):
        quiet = copy.deepcopy(self.s.quiet)
        quiet["pairs"] = [r for r in quiet["pairs"] if r["detection"] not in (ENCODED, RUNDLL)]
        res = bp.assess(quiet, self.s.model, assets=self.s.assets)
        self.assertEqual(bp.cell_text(cell(res, WS1, "execution")), "-")
        first, third = res["ladder"][0], res["ladder"][2]
        self.assertFalse(first["reachable"])
        self.assertIn("Run code: no behaviour of this stage has a sensor in the export", first["open"])
        self.assertEqual(bp.rung_text(first)[0], "not reachable")
        self.assertTrue(third["reachable"])

    def test_one_host_is_walked_alone(self):
        quiet = copy.deepcopy(self.s.quiet)
        quiet["hosts"] = [WS1]
        quiet["pairs"] = [r for r in quiet["pairs"] if r["host"] == WS1]
        res = bp.assess(quiet, self.s.model)
        self.assertTrue(res["single"])
        self.assertEqual((res["origins"], res["targets"], res["counts"]["routes"]), ([WS1], [WS1], 1))
        self.assertEqual(res["ends"], "one host: the walk on this host alone")
        self.assertEqual(step(res, WS1, "encoded_powershell")["by"], "witness")
        self.assertEqual(res["routes"][0]["seen_at"], 3)
        self.assertIn("On this host alone the walk is first seen at leg 3", bp.summary_line(res))
        self.assertEqual(next(r["side"] for r in res["ladder"] if r["reachable"]), "this host")

    def test_without_an_assets_file_the_hosts_that_record_for_others_are_the_targets(self):
        res = bp.assess(self.s.quiet, self.s.model)
        self.assertEqual(res["targets"], [DC, FS])
        self.assertEqual(len(res["origins"]), 6)
        self.assertIn("no assets file", res["ends"])

    def test_the_ends_can_be_named(self):
        res = bp.assess(self.s.quiet, self.s.model, assets=self.s.assets, origins=["ws01"], targets=[DC])
        self.assertEqual((res["origins"], res["targets"], res["counts"]["routes"], res["ends"]), ([WS1], [DC], 1, "named on the command line"))
        with self.assertRaises(bp.BlindpathError) as caught:
            bp.assess(self.s.quiet, self.s.model, origins=["nowhere"])
        self.assertIn("--origin nowhere: no host of the export answers to it", str(caught.exception))

    def test_hosts_that_are_both_ends_are_not_routed_to_themselves(self):
        hosts = [DC, FS, WS1]
        res = bp.assess(self.s.quiet, self.s.model, origins=hosts, targets=hosts)
        self.assertEqual(res["counts"]["routes"], 6)
        for r in res["ladder"]:
            self.assertTrue(r["reachable"])


class OneWayOnly(unittest.TestCase):
    """A sensor turned on or a variant closed never makes anything less seen."""

    def test_on_fleets_and_changes_drawn_at_random(self):
        s = sample()
        rng = random.Random(1115)
        pairs = [(r["detection"], r["host"]) for r in s.quiet["pairs"] if r["host"]]
        rule_atoms = sorted({w.atom for group in s.ways.values() for w in group if w.atom})
        order = {"unseen": 0, "absent": 1, "seen": 2}
        for _ in range(10):
            quiet = changed(s.quiet, {p: rng.choice(("dark", "live")) for p in rng.sample(pairs, 30)})
            fleet = bp.Fleet(quiet, s.book)
            sensors = sorted({fleet.atom(r["detection"], fleet.read(r["detection"], r)) for r in quiet["pairs"]
                              if r["host"] and fleet.read(r["detection"], r).state == "dark"})
            origins, targets, _how = bp.ends(fleet, s.model, s.assets, [], [])
            before_cells, before = bp.walk(fleet, s.model, s.ways, origins, targets, False)
            fixes = frozenset(rng.sample(rule_atoms, 5) + rng.sample(sensors, min(4, len(sensors))))
            after_cells, after = bp.walk(fleet, s.model, s.ways, origins, targets, False, fixes)
            for key, c in before_cells.items():
                was = {st["step"]: st["verdict"] for st in c["steps"]}
                for st in after_cells[key]["steps"]:
                    self.assertGreaterEqual(order[st["verdict"]], order[was[st["step"]]], (key, st["step"]))
            self.assertLessEqual(sum(g["count"] for g in after if g["verdict"] == "unseen"),
                                 sum(g["count"] for g in before if g["verdict"] == "unseen"))


class Plan(unittest.TestCase):
    def brute(self, demands: list[list[frozenset]]) -> int | None:
        if any(not d for d in demands):
            return None
        atoms = sorted({a for d in demands for o in d for a in o})
        for size in range(len(atoms) + 1):
            for chosen in combinations(atoms, size):
                if all(any(o <= set(chosen) for o in d) for d in demands):
                    return size
        return None

    def test_the_smallest_union_on_small_cases(self):
        a, b, c, d = (("rule", x, "") for x in "abcd")
        f = frozenset
        self.assertEqual(bp.cheapest([[f([a]), f([b, c])], [f([b])], [f([c]), f([a, b])]]), (f([a, b]), True))
        self.assertEqual(bp.cheapest([[f()], [f([d])]]), (f([d]), True))
        self.assertEqual(bp.cheapest([]), (f(), True))
        self.assertIsNone(bp.cheapest([[f([a])], []]))

    def test_the_smallest_union_against_every_subset(self):
        rng = random.Random(7)
        atoms = [("rule", f"r{i}", "") for i in range(6)] + [("sensor", f"h{i}", "s") for i in range(3)]
        for _ in range(300):
            demands = [[frozenset(rng.sample(atoms, rng.randint(1, 3))) for _ in range(rng.randint(1, 3))] for _ in range(rng.randint(1, 6))]
            got = bp.cheapest(demands)
            self.assertIsNotNone(got)
            union, exact = got
            self.assertTrue(exact)
            self.assertEqual(len(union), self.brute(demands), demands)
            self.assertTrue(all(any(o <= union for o in d) for d in demands))

    def test_a_search_that_runs_out_says_so(self):
        atoms = [("rule", f"r{i}", "") for i in range(12)]
        demands = [[frozenset([atoms[i], atoms[(i + j) % 12]]) for j in (1, 2, 3)] for i in range(12)]
        with mock.patch.object(bp, "SEARCH_BUDGET", 5):
            union, exact = bp.cheapest(demands)
        self.assertFalse(exact)
        self.assertTrue(all(any(o <= union for o in d) for d in demands), "what it found still answers every demand")

    def test_no_smaller_set_of_changes_does_what_the_plan_does(self):
        s = sample()
        fleet = bp.Fleet(s.quiet, s.book)
        origins, targets = s.res["origins"], s.res["targets"]
        rules = sorted({w.atom for group in s.ways.values() for w in group if w.atom})
        sensors = sorted({fleet.atom(r["detection"], fleet.read(r["detection"], r)) for r in s.quiet["pairs"]
                          if r["host"] and fleet.read(r["detection"], r).state == "dark"})
        universe = rules + sensors
        self.assertGreater(len(universe), 15)

        def seen_by(fixes: frozenset, leg: int) -> bool:
            _cells, groups = bp.walk(fleet, s.model, s.ways, origins, targets, False, fixes)
            return all(g["seen_at"] is not None and g["seen_at"] <= leg for g in groups)

        for rung in s.res["ladder"]:
            plan = frozenset(tuple(a) for a in rung["atoms"])
            self.assertTrue(plan <= set(universe))
            self.assertTrue(seen_by(plan, rung["leg"]), rung["leg"])
            for size in range(rung["count"]):
                for fewer in combinations(universe, size):
                    self.assertFalse(seen_by(frozenset(fewer), rung["leg"]), (rung["leg"], fewer))

    def test_a_later_leg_never_takes_more(self):
        counts = [r["count"] for r in sample().res["ladder"]]
        self.assertEqual(counts, sorted(counts, reverse=True))

    def test_plans_on_fleets_changed_at_random_hold_and_never_grow(self):
        """assess walks the model again with every plan in place and refuses one that leaves a route unseen."""
        s = sample()
        rng = random.Random(42)
        pairs = [(r["detection"], r["host"]) for r in s.quiet["pairs"] if r["host"]]
        for trial in range(10):
            quiet = changed(s.quiet, {p: rng.choice(("dark", "live")) for p in rng.sample(pairs, 40)})
            res = bp.assess(quiet, s.model, assets=s.assets if trial % 2 else None)
            rungs = [r for r in res["ladder"] if r["reachable"]]
            self.assertTrue(rungs)
            self.assertTrue(all(r["exact"] for r in rungs))
            self.assertEqual([r["count"] for r in rungs], sorted((r["count"] for r in rungs), reverse=True))

    def test_six_hundred_hosts_are_walked_and_planned(self):
        s = sample()
        big = copy.deepcopy(s.quiet)
        rows = [r for r in s.quiet["pairs"] if r["host"] == WS1]
        for i in range(600):
            big["hosts"].append(f"PC{i:04d}.corp.lab")
            big["pairs"] += [{**r, "host": f"PC{i:04d}.corp.lab"} for r in rows]
        res = bp.assess(big, s.model)
        self.assertEqual((len(res["origins"]), res["counts"]["routes"]), (606, 1212))
        self.assertEqual([r["count"] for r in res["ladder"]], [4, 4, 1, 1])
        self.assertLessEqual(len(res["routes"]), 8, "routes whose legs read the same are one group")


class WhatEachChangeBuys(unittest.TestCase):
    def test_the_ranking_on_the_sample_fleet(self):
        rows = sample().res["leverage"]
        self.assertEqual([(r["kind"], r["changes"], r["legs_held"], r["routes_seen"], r["every_route_by"]) for r in rows],
                         [("rule", 4, 7, 6, 1), ("sensor", 1, 1, 6, 3), ("rule", 4, 7, 0, None)])
        self.assertIn(ENCODED, rows[0]["what"])
        self.assertEqual(rows[1]["what"], "SRV-FS01.corp.lab: turn on Sysmon 1 (ProcessCreate)")

    def test_every_row_is_what_a_full_walk_gives(self):
        s = sample()
        fleet = bp.Fleet(s.quiet, s.book)
        origins, targets = s.res["origins"], s.res["targets"]
        before_cells, before = bp.walk(fleet, s.model, s.ways, origins, targets, False)
        unseen = sum(g["count"] for g in before if g["verdict"] == "unseen")
        for r in s.res["leverage"]:
            fixes = frozenset(tuple(a) for a in r["atoms"])
            cells, groups = bp.walk(fleet, s.model, s.ways, origins, targets, False, fixes)
            held = sum(1 for key, c in cells.items() if c["verdict"] == "held" and before_cells[key]["verdict"] == "open")
            seen = unseen - sum(g["count"] for g in groups if g["verdict"] == "unseen")
            self.assertEqual((held, seen), (r["legs_held"], r["routes_seen"]), r["what"])

    def test_a_change_that_buys_nothing_alone_is_not_listed(self):
        listed = " ".join(r["what"] for r in sample().res["leverage"])
        self.assertNotIn(LSASS, listed)
        self.assertNotIn("WS06", listed)

    def test_on_fleets_changed_at_random_no_row_claims_more_than_a_walk_gives(self):
        s = sample()
        rng = random.Random(77)
        pairs = [(r["detection"], r["host"]) for r in s.quiet["pairs"] if r["host"]]
        for _ in range(6):
            quiet = changed(s.quiet, {p: rng.choice(("dark", "live")) for p in rng.sample(pairs, 35)})
            res = bp.assess(quiet, s.model, assets=s.assets)
            fleet = bp.Fleet(quiet, s.book)
            before_cells, before = bp.walk(fleet, s.model, s.ways, res["origins"], res["targets"], False)
            unseen = sum(g["count"] for g in before if g["verdict"] == "unseen")
            for r in res["leverage"]:
                cells, groups = bp.walk(fleet, s.model, s.ways, res["origins"], res["targets"], False,
                                        frozenset(tuple(a) for a in r["atoms"]))
                held = sum(1 for key, c in cells.items() if c["verdict"] == "held" and before_cells[key]["verdict"] == "open")
                self.assertEqual((held, unseen - sum(g["count"] for g in groups if g["verdict"] == "unseen")),
                                 (r["legs_held"], r["routes_seen"]), r["what"])


class Baseline(unittest.TestCase):
    def setUp(self):
        self.s = sample()
        sysmon = [t.id for t in self.s.book.targets.values() if t.artifact == "sysmon_1"]
        self.fixed = bp.assess(changed(self.s.quiet, {(rule, FS): "live" for rule in sysmon}), self.s.model, assets=self.s.assets)
        self.titles = {st["id"]: st["title"] for st in self.s.res["stages"]}

    def test_an_answer_against_itself_changed_nothing(self):
        d = bp.since(self.s.res, json.loads(json.dumps(self.s.res)))
        self.assertFalse(d["worse"])
        self.assertEqual(bp.since_lines(d, self.s.res["steps"], self.titles),
                         ["nothing changed: every route, leg and behaviour reads as it did"])

    def test_a_sensor_turned_on_reads_as_better(self):
        d = bp.since(self.fixed, self.s.res)
        self.assertFalse(d["worse"])
        self.assertEqual((len(d["routes_better"]), len(d["routes_worse"]), d["legs_opened"]), (6, 0, []))
        self.assertIn({"host": FS, "stage": "movement", "was": "open", "now": "held"}, d["legs_held"])
        self.assertIn({"origin": WS1, "target": FS, "was": None, "now": 3}, d["routes_better"])

    def test_a_sensor_lost_reads_as_worse(self):
        d = bp.since(self.s.res, self.fixed)
        self.assertTrue(d["worse"])
        self.assertEqual(len(d["routes_worse"]), 6)
        lines = bp.since_lines(d, self.s.res["steps"], self.titles)
        self.assertEqual(lines[0], f"worse: {WS1} → {FS} was seen at leg 3, now unseen end to end")
        self.assertIn(f"worse: Move in on {FS} was held, now open", lines)
        self.assertIn(f"now unseen: Run a command on the target through WinRM on {FS}", lines)

    def test_hosts_that_come_and_go_are_named_and_not_judged(self):
        old = json.loads(json.dumps(self.s.res))
        old["hosts"] = [h for h in old["hosts"] if h != WS6] + ["OLD01.corp.lab"]
        d = bp.since(self.s.res, old)
        self.assertEqual((d["hosts_new"], d["hosts_gone"]), ([WS6], ["OLD01.corp.lab"]))

    def test_a_file_that_is_not_an_answer_is_refused(self):
        for bad in ({"format": 0}, {"format": 1}, [], "text"):
            with self.assertRaises(bp.BlindpathError):
                bp.since(self.s.res, bad)

    def test_many_changes_are_counted_not_listed_without_end(self):
        d = bp.since(self.s.res, self.fixed)
        lines = bp.since_lines(d, self.s.res["steps"], self.titles, most=2)
        self.assertIn("and 4 more", lines)


class Reports(unittest.TestCase):
    def setUp(self):
        self.s = sample()
        self.res = self.s.res

    def test_the_results_page_is_current(self):
        text = bp.README.read_text(encoding="utf-8")
        self.assertEqual(bp.with_block(text, bp.render(self.res)), text, "run: rasd build")
        with self.assertRaises(bp.BlindpathError):
            bp.with_block("no markers here", "x")

    def test_the_certificate_states_the_claim_the_inputs_the_proofs_and_the_limits(self):
        text = bp.certificate(self.res, [{"name": "fleet.jsonl", "records": self.res["records"], "sha256": "ab" * 32}])
        for part in ("# Certificate of the unseen route", "## The claim", self.res["claim"], "`" + "ab" * 32 + "`", "### The map",
                     "### Routes", "**unseen end to end**", "### Unseen, and the proof", "### The plan", "### What each hold rests on",
                     "### What each change buys alone", "### Tripwires", "### Variants the intruder does not choose",
                     "## The witnesses", "```json",
                     "## What this certificate does not say", "rasd blindpath fleet.jsonl", self.res["position"]):
            self.assertIn(part, text)
        for limit in self.res["limits"]:
            self.assertIn(limit, text)
        used = [w for w in self.res["ways"] if w["used"]]
        self.assertEqual(text.count("```json"), len(used))
        for w in used:
            self.assertIn(json.dumps(w["events"][0], ensure_ascii=False, sort_keys=True), text)

    def test_the_page_escapes_what_it_shows(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        res = copy.deepcopy(self.res)
        res["limits"][0] = "<script>alert(1)</script>"
        res["roles"][WS1] = "<b>role</b>"
        bp.write_html(str(tmp / "deep" / "page.html"), res, [{"name": "a&b.jsonl", "records": 1, "sha256": "ab" * 32}])
        page = (tmp / "deep" / "page.html").read_text(encoding="utf-8")
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertIn("&lt;b&gt;role&lt;/b&gt;", page)
        self.assertIn("a&amp;b.jsonl", page)
        self.assertEqual(page.count('<section class="card">'), len(self.res["routes"]))
        self.assertEqual(page.count('class="cell '), len(self.res["hosts"]) * len(self.res["stages"]))

    def test_the_report_names_every_route_and_the_plan(self):
        said = io.StringIO()
        with contextlib.redirect_stdout(said):
            bp.print_report(self.res)
        for part in ("12 routes from 6 origins to 2 targets", "UNSEEN", "SEEN", "The plan", "leg 3 Move into the target",
                     "turn on Sysmon 1 (ProcessCreate)", "What each change buys alone", "every route seen by leg 1", "Tripwires",
                     "Held means no way around is known here"):
            self.assertIn(part, said.getvalue())

    def test_the_result_is_json(self):
        doc = json.loads(json.dumps(self.res))
        self.assertEqual((doc["format"], doc["rules"], doc["correlations"]), (1, 18, 4))
        self.assertEqual([w["id"] for w in doc["ways"]], list(range(1, len(doc["ways"]) + 1)))


class CommandLine(unittest.TestCase):
    def run_rasd(self, *argv: str, cwd: Path = ROOT) -> subprocess.CompletedProcess:
        return subprocess.run([*RASD, *argv], cwd=cwd, capture_output=True, text=True, encoding="utf-8",
                              env={**os.environ, "NO_BANNER": "1", "NO_COLOR": "1"})

    def folder(self) -> Path:
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        shutil.copy(sil.SAMPLE_EXPORT, tmp / "fleet.jsonl")
        shutil.copy(sil.SAMPLE_ASSETS, tmp / "assets.csv")
        return tmp

    def test_an_export_gives_the_report_the_certificate_the_page_and_the_json(self):
        tmp = self.folder()
        out = self.run_rasd("fleet.jsonl", "--assets", "assets.csv", "--certificate", "out/route.md", "--json", "out/route.json",
                            "--html", "out/route.html", cwd=tmp)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        for part in ("the route through the green cells", "6 unseen end to end", "The map", "Witnesses the engine replayed", "The plan"):
            self.assertIn(part, out.stdout)
        doc = json.loads((tmp / "out" / "route.json").read_text(encoding="utf-8"))
        self.assertEqual((doc["format"], doc["inputs"][0]["name"], len(doc["inputs"][0]["sha256"])), (1, "fleet.jsonl", 64))
        cert = (tmp / "out" / "route.md").read_bytes()
        self.assertIn(b"# Certificate of the unseen route", cert)
        self.assertNotIn(b"\r\n", cert)
        self.assertIn("rasd blindpath fleet.jsonl --assets assets.csv", cert.decode("utf-8"))
        self.assertIn("| `assets.csv` | 8 |", cert.decode("utf-8"), "every input is named with its hash")
        page = (tmp / "out" / "route.html").read_text(encoding="utf-8")
        for part in ("<title>RASD-Blindpath</title>", "The map", "SRV-FS01.corp.lab", 'class="cell open"', 'class="cell tests"',
                     "unseen end to end", "What this does not say"):
            self.assertIn(part, page)

    def test_strict_stops_a_pipeline_on_an_unseen_route_only(self):
        tmp = self.folder()
        self.assertEqual(self.run_rasd("fleet.jsonl", "--assets", "assets.csv", "--strict", cwd=tmp).returncode, 1)
        out = self.run_rasd("fleet.jsonl", "--assets", "assets.csv", "--target", "DC01", "--strict", cwd=tmp)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("6 routes from 6 origins to 1 target: 0 unseen end to end", out.stdout)

    def test_a_baseline_says_what_changed_and_stops_a_pipeline_when_it_got_worse(self):
        tmp = self.folder()
        self.assertEqual(self.run_rasd("fleet.jsonl", "--assets", "assets.csv", "--json", "base.json", cwd=tmp).returncode, 0)
        same = self.run_rasd("fleet.jsonl", "--assets", "assets.csv", "--baseline", "base.json", cwd=tmp)
        self.assertEqual(same.returncode, 0, same.stdout + same.stderr)
        self.assertIn("nothing changed: every route, leg and behaviour reads as it did", same.stdout)
        doc = json.loads((tmp / "base.json").read_text(encoding="utf-8"))
        for g in doc["routes"]:
            if g["verdict"] == "unseen":
                g.update(verdict="seen", seen_at=3)
        (tmp / "better.json").write_text(json.dumps(doc), encoding="utf-8", newline="\n")
        out = self.run_rasd("fleet.jsonl", "--assets", "assets.csv", "--baseline", "better.json", "--certificate", "c.md",
                            "--html", "p.html", "--json", "now.json", cwd=tmp)
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
        self.assertIn(f"worse: {WS1} → {FS} was seen at leg 3, now unseen end to end", out.stdout)
        cert = (tmp / "c.md").read_text(encoding="utf-8")
        self.assertIn("## Since the baseline", cert)
        self.assertIn("--baseline better.json", cert)
        self.assertIn("| `better.json` |", cert, "the baseline is an input, named with its hash")
        self.assertIn("<h2>Since the baseline</h2>", (tmp / "p.html").read_text(encoding="utf-8"))
        self.assertTrue(json.loads((tmp / "now.json").read_text(encoding="utf-8"))["since"]["worse"])
        self.assertIn("nowhere.json: no such file", self.run_rasd("fleet.jsonl", "--baseline", "nowhere.json", cwd=tmp).stderr)
        self.assertIn("not JSON", self.run_rasd("fleet.jsonl", "--baseline", "assets.csv", cwd=tmp).stderr)
        (tmp / "other.json").write_text('{"format": 1, "rows": []}', encoding="utf-8", newline="\n")
        self.assertIn("not a rasd blindpath --json answer", self.run_rasd("fleet.jsonl", "--baseline", "other.json", cwd=tmp).stderr)

    def test_the_witnesses_are_written_as_events_the_engine_replays_in_silence(self):
        tmp = self.folder()
        out = self.run_rasd("fleet.jsonl", "--assets", "assets.csv", "--witnesses", "w/witnesses.jsonl", cwd=tmp)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        raw = (tmp / "w" / "witnesses.jsonl").read_bytes()
        self.assertNotIn(b"\r\n", raw)
        events = [json.loads(line) for line in raw.decode("utf-8").splitlines()]
        used = [w for w in sample().res["ways"] if w["used"]]
        self.assertEqual(len(events), sum(len(w["events"]) for w in used))
        self.assertEqual({ev["_witness"] for ev in events}, {f"W{w['id']}" for w in used})
        self.assertTrue(all(ev["_step"] in sample().res["steps"] for ev in events))
        alerts, _stats = replay(events, list(load_detections()), {}, corrs=list(load_correlations()))
        self.assertEqual(alerts, [], "what the certificate calls unseen raises nothing when it is replayed")

    def test_check_passes_on_the_shipped_model_and_page(self):
        out = self.run_rasd("--check")
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("blindpath model consistent", out.stdout)

    def test_a_missing_file_an_unknown_host_and_a_bad_time_are_said_plainly(self):
        out = self.run_rasd("nowhere.jsonl")
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("nowhere.jsonl: no such file", out.stderr)
        out = self.run_rasd(str(sil.SAMPLE_EXPORT), "--assets", "nowhere.csv")
        self.assertIn("nowhere.csv: no such file", out.stderr)
        out = self.run_rasd(str(sil.SAMPLE_EXPORT), "--target", "MAIL01")
        self.assertIn("--target MAIL01: no host of the export answers to it", out.stderr)
        out = self.run_rasd(str(sil.SAMPLE_EXPORT), "--from", "yesterday")
        self.assertIn("--from yesterday: not a time", out.stderr)

    def test_with_no_export_and_no_windows_it_says_what_it_reads(self):
        with mock.patch.object(sil, "wevtutil", return_value=None), mock.patch.object(sys, "argv", ["blindpath.py"]), \
                self.assertRaises(bp.BlindpathError) as caught:
            bp.main()
        self.assertIn("rasd blindpath EXPORT.jsonl reads an export", str(caught.exception))

    def test_this_host_is_read_and_its_certificate_is_written_beside_the_answer(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        from common import load_jsonl
        events = [e for e in load_jsonl(sil.SAMPLE_EXPORT) if e.get("Computer") == WS1]
        notes = [{"channel": "Security", "records": len(events), "state": "read"}]
        said = io.StringIO()
        here = os.getcwd()
        self.addCleanup(os.chdir, here)
        os.chdir(tmp)
        with mock.patch.object(sil, "wevtutil", return_value="wevtutil.exe"), mock.patch.object(sil, "collect", return_value=(events, notes)), \
                mock.patch.object(sys, "argv", ["blindpath.py", "--yes"]), contextlib.redirect_stdout(said):
            self.assertEqual(bp.main(), 0)
        self.assertIn("It reads only; nothing on this host is changed, nothing is run and nothing leaves it.", said.getvalue())
        self.assertIn("On this host alone the walk", said.getvalue())
        written = sorted(p.name for p in tmp.iterdir())
        self.assertEqual([n[:20] for n in written], ["rasd-blindpath-WS01-", "rasd-blindpath-WS01-"])
        self.assertEqual([Path(n).suffix for n in written], [".html", ".md"])
        self.assertIn("Security (this host)", (tmp / written[1]).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
