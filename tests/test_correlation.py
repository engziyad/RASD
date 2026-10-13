"""Tests for Sigma correlation detections: engine semantics, SIEM conversion, proofs (python -m unittest)."""
import copy
import json
import random
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import correlate  # noqa: E402
import doctor  # noqa: E402
import evidence  # noqa: E402
import replay  # noqa: E402
import validate  # noqa: E402
from common import load_jsonl  # noqa: E402
from correlation import (CorrelationError, Correlation, alert_signature, check_guarantee, evaluate,  # noqa: E402
                         expand_scenarios, guaranteed_burst, iso, load_correlations, param_mutants,
                         timespan_seconds, to_kql, to_spl)

SPRAY = "T1110.003_password_spray_burst"
ROAST = "T1558.003_kerberoasting_volume"


def spray():
    return next(c for c in load_correlations() if c.id == SPRAY)


def failure(user: str, at: str, ip: str = "::ffff:10.0.0.21", **extra) -> dict:
    ev = {"Channel": "Security", "EventID": 4771, "Computer": "LAB-DC01.lab.local", "TargetUserName": user,
          "Status": "0x18", "IpAddress": ip, "TimeCreated": at}
    ev.update(extra)
    return ev


class Semantics(unittest.TestCase):
    def test_timespans_align_in_every_siem_and_can_be_scheduled(self):
        for good, seconds in (("10m", 600), ("15m", 900), ("1h", 3600), ("2h", 7200), ("8h", 28800), ("1d", 86400)):
            self.assertEqual(timespan_seconds(good), seconds)
        for bad in ("7m", "8m", "90m", "30s", "45s", "5h", "90s5", "10 minutes", "0m"):
            with self.assertRaises(CorrelationError, msg=bad):
                timespan_seconds(bad)

    def test_unsupported_rules_are_rejected(self):
        c = spray()
        for change in ({"type": "temporal"}, {"condition": {"gte": 5}}, {"condition": {"gte": "5", "field": "x"}},
                       {"condition": {"gte": 5, "lt": 9, "field": "TargetUserName"}}, {"group-by": ["Ip Address"]}):
            broken = copy.deepcopy(c)
            broken.rule["correlation"].update(change)
            with self.assertRaises(CorrelationError, msg=str(change)):
                broken.params

    def test_windows_are_aligned_to_the_clock(self):
        c = spray()
        # five accounts between 10:05 and 10:09 are one window; the same five from 10:08 to 10:12 are two
        inside = [failure(f"u{i}", f"2026-10-12T10:0{5 + i}:00Z") for i in range(5)]
        across = [failure(f"u{i}", iso(datetime(2026, 10, 12, 10, 8) + timedelta(minutes=i))) for i in range(5)]
        self.assertEqual(len(evaluate(c, inside)), 1)
        self.assertEqual(evaluate(c, inside)[0]["window_start"], datetime(2026, 10, 12, 10, 0))
        self.assertEqual(evaluate(c, across), [])

    def test_missing_or_empty_values_are_ignored_and_addresses_are_normalised(self):
        c = spray()
        evs = [failure(f"u{i}", f"2026-10-12T10:02:0{i}Z") for i in range(4)]
        self.assertEqual(evaluate(c, evs + [failure("", "2026-10-12T10:02:05Z")]), [])          # empty account
        no_ip = failure("u9", "2026-10-12T10:02:06Z")
        del no_ip["IpAddress"]
        self.assertEqual(evaluate(c, evs + [no_ip]), [])                                          # no client
        plain = failure("u9", "2026-10-12T10:02:07Z", ip="10.0.0.21")
        alerts = evaluate(c, evs + [plain])                                                       # ::ffff: or not
        self.assertEqual([(a["group"], a["value_count"]) for a in alerts], [({"IpAddress": "10.0.0.21"}, 5)])

    def test_distinct_accounts_not_events_and_the_crossing_event(self):
        c = spray()
        retries = [failure("omar", f"2026-10-12T10:02:{s:02d}Z") for s in range(0, 50, 5)]
        self.assertEqual(evaluate(c, retries), [])
        burst = [failure(f"u{i}", f"2026-10-12T10:02:0{i}Z") for i in range(7)]
        a = evaluate(c, list(reversed(burst)))[0]                                                 # order does not matter
        self.assertEqual((a["value_count"], a["event_count"]), (7, 7))
        self.assertEqual(a["crossed_at"], datetime(2026, 10, 12, 10, 2, 4))                      # the 5th account

    def test_a_condition_that_needs_the_whole_window_is_timed_at_its_end(self):
        c = spray()
        p = c.params.__class__(**{**c.params.__dict__, "op": "lte", "threshold": 2})
        a = evaluate(c, [failure("u1", "2026-10-12T10:02:00Z"), failure("u2", "2026-10-12T10:03:00Z")], p)[0]
        self.assertEqual(a["crossed_at"], datetime(2026, 10, 12, 10, 10))

    def test_scenario_expansion(self):
        doc = {"defaults": {"EventID": 4771, "Status": "0x18", "UtcTime": "2020-01-01 00:00:00.000"},
               "scenarios": [{"name": "s", "expect": "fire", "start": "2026-10-12T10:00:00Z",
                              "events": [{"at": 10, "every": 2.5, "count": 3, "Status": None,
                                          "set": {"TargetUserName": "lab.user{n:02d}"}}]}]}
        evs = expand_scenarios(doc)[0]["events"]
        self.assertEqual([e["TargetUserName"] for e in evs], ["lab.user01", "lab.user02", "lab.user03"])
        self.assertEqual([e["TimeCreated"] for e in evs],
                         ["2026-10-12T10:00:10.000Z", "2026-10-12T10:00:12.500Z", "2026-10-12T10:00:15.000Z"])
        self.assertTrue(all("Status" not in e and "UtcTime" not in e and e["EventID"] == 4771 for e in evs))


class Proofs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = correlate.check(queries=True)

    def test_every_correlation_is_proven(self):
        self.assertEqual(set(self.report), {SPRAY, ROAST})
        for cid, r in self.report.items():
            self.assertEqual(correlate.failures(r), [], cid)

    def test_every_parameter_mutant_flips_a_scenario_verdict(self):
        for cid, r in self.report.items():
            mutants = r["correlation_mutants"]["mutants"]
            self.assertEqual({m["id"] for m in mutants},
                             {"threshold:+1", "threshold:-1", "timespan:x2", "timespan:/2", "group-by:-IpAddress",
                              "type:event_count", "normalize:-IpAddress"}, cid)
            for m in mutants:
                self.assertTrue(m["killed_by"] and m["verdict_flip"], f"{cid} {m['id']}")

    def test_aggregation_parity_covers_the_rule_and_every_mutant(self):
        for cid, r in self.report.items():
            ap = r["aggregation_parity"]
            self.assertEqual(ap["parameter_sets"], 8, cid)
            self.assertGreaterEqual(ap["sequences"], 150, cid)
            self.assertGreater(ap["alerts"], 100, cid)
            self.assertEqual((ap["spl"], ap["kql"], ap["errors"]), ([], [], []), cid)

    def test_burst_guarantee_is_2t_minus_1_and_tight(self):
        for cid, r in self.report.items():
            g = r["guarantee"]
            self.assertEqual(g["burst"], 9, cid)
            self.assertEqual(g["failures"], [], cid)
            self.assertTrue(g["tight"], cid)
        p = spray().params
        self.assertEqual(guaranteed_burst(p), 9)
        self.assertEqual(guaranteed_burst(p.__class__(**{**p.__dict__, "op": "gt"})), 11)
        self.assertIsNone(guaranteed_burst(p.__class__(**{**p.__dict__, "op": "lte"})))

    def test_guarantee_holds_at_random_alignments(self):
        c, rng = spray(), random.Random(7)
        template = {k: v for k, v in c.tests("true_positive")[0].items() if k != "_case"}
        day = datetime(2026, 3, 9)
        for _ in range(200):
            offset, spread = rng.uniform(0, 600), rng.uniform(0, 599)
            times = sorted(offset + rng.uniform(0, spread) for _ in range(9))
            evs = [{**template, "TargetUserName": f"r{i}", "TimeCreated": iso(day + timedelta(seconds=t))}
                   for i, t in enumerate(times)]
            self.assertTrue(evaluate(c, evs), (offset, spread))

    def test_generated_queries_are_committed(self):
        for c in load_correlations():
            for path, text in correlate.query_files(c).items():
                self.assertEqual(path.read_text(encoding="utf-8"), text, path)


class ConverterBugs(unittest.TestCase):
    """Aggregation parity has teeth: each classic converter bug makes the parsed query disagree."""

    @classmethod
    def setUpClass(cls):
        cls.c = spray()
        cls.seqs = [sc["events"] for sc in cls.c.scenarios()] + list(correlate.random_sequences(cls.c, cls.c.params))

    def diverges(self, backend: str, text: str) -> bool:
        try:
            model = (correlate.SPLModel if backend == "spl" else correlate.KQLModel)(text, self.c)
        except correlate.ParseError:
            return True                                    # a query the model refuses is a failure too
        return any(sorted(model.run(s)) != sorted(alert_signature(a) for a in evaluate(self.c, s)) for s in self.seqs)

    def test_injected_bugs_are_caught(self):
        spl, kql = to_spl(self.c), to_kql(self.c)
        drop = lambda text, start: "\n".join(l for l in text.split("\n") if not l.startswith(start))
        bugs = {
            "SPL without normalisation": ("spl", drop(spl, "| eval IpAddress")),
            "SPL without the not-null filter": ("spl", drop(spl, "| where isnotnull")),
            "SPL without the empty-string test": ("spl", spl.replace(" AND 'IpAddress'!=\"\"", "")),
            "SPL with 5-minute windows": ("spl", spl.replace("span=600s", "span=300s")),
            "SPL counting events as value_count": ("spl", spl.replace("dc(TargetUserName) as value_count",
                                                                       "count as value_count")),
            "SPL threshold off by one": ("spl", spl.replace("value_count>=5", "value_count>=4")),
            "SPL grouping by window only": ("spl", spl.replace("by window_start IpAddress", "by window_start")),
            "SPL binning _time in place": ("spl", spl.replace("| bin span=600s _time AS window_start",
                                                              "| bin span=600s _time")),
            "KQL without isnotempty": ("kql", drop(kql, "| where isnotempty")),
            "KQL without normalisation": ("kql", "\n".join(l for l in kql.split("\n") if "replace_regex" not in l)),
            "KQL with 20-minute windows": ("kql", kql.replace("600s", "1200s")),
            "KQL > instead of >=": ("kql", kql.replace("value_count >= 5", "value_count > 5")),
            "KQL grouping by the counted field": ("kql", kql.replace("600s), IpAddress", "600s), TargetUserName")),
            "KQL reading IpAddress without EventData": ("kql", drop(kql, "| extend IpAddress = coalesce")),
        }
        for name, (backend, text) in bugs.items():
            self.assertTrue(self.diverges(backend, text), name)
        self.assertFalse(self.diverges("spl", spl))
        self.assertFalse(self.diverges("kql", kql))

    def test_mutant_queries_differ_from_the_rule(self):
        p = self.c.params
        texts = {to_spl(self.c, mp) for _id, _d, mp in param_mutants(p)} | {to_spl(self.c, p)}
        self.assertEqual(len(texts), 8)


class Structure(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        shutil.copytree(spray().folder, self.tmp / SPRAY)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def load(self) -> Correlation:
        import yaml
        f = self.tmp / SPRAY
        return Correlation(f, yaml.safe_load((f / "correlation.yml").read_text()), yaml.safe_load((f / "base.yml").read_text()),
                           yaml.safe_load((f / "contract.yml").read_text()))

    def test_broken_folders_are_reported(self):
        c = self.load()
        self.assertEqual(correlate.structure_errors(c, {})[0], [])
        c.rule["correlation"]["rules"] = ["something_else"]
        c.rule["correlation"].pop("generate")
        c.contract["data_contract"]["required_fields"].remove("IpAddress")
        c.contract["detection_logic"]["type"] = "single-event"
        errs = " | ".join(correlate.structure_errors(c, {})[0])
        for expected in ("must list exactly the base rule's name", "generate: false",
                         "detection_logic.type must be 'correlation'", "not in the data contract: ['IpAddress']"):
            self.assertIn(expected, errs)

    def test_a_correlation_without_a_silent_scenario_is_rejected(self):
        path = self.tmp / SPRAY / "tests" / "scenarios.yml"
        import yaml
        doc = yaml.safe_load(path.read_text())
        doc["scenarios"] = [s for s in doc["scenarios"] if s["expect"] == "fire"]
        path.write_text(yaml.safe_dump(doc))
        self.assertIn("one that stays silent", " | ".join(correlate.structure_errors(self.load(), {})[0]))


class Integration(unittest.TestCase):
    def test_replay_puts_the_spray_on_the_intrusion_storyline(self):
        events = load_jsonl(ROOT / "samples" / "replay" / "lab-day.jsonl")
        assets = replay.load_assets(str(ROOT / "samples" / "replay" / "assets.csv"))
        alerts, _ = replay.replay(events, [], assets, corrs=load_correlations())
        self.assertEqual([(a["rule"], a["entity"]) for a in alerts], [(SPRAY, "WS07.corp.lab")])
        self.assertEqual(alerts[0]["correlation"]["metric"], 9)               # 7 Kerberos + 2 NTLM, one client
        from common import load_detections
        full, _ = replay.replay(events, load_detections(), assets, corrs=load_correlations())
        story = replay.storylines(full, 60)
        self.assertEqual(len(story), 1)
        self.assertIn(SPRAY, {a["rule"] for a in story[0]["steps"]})

    def test_evidence_binds_the_spray_to_the_run_host_only(self):
        c = spray()
        step = {"technique": "T1110.003", "test": "password_spray_simulation", "step": "spray", "name": "spray",
                "correlations": [SPRAY], "status": "executed", "host": "LAB-WS01.lab.local", "host_netbios": "LAB-WS01",
                "host_ips": ["10.0.0.21"], "marker": "purplelab_1a2b3c4d", "utc_start": "2026-10-12T10:02:00Z",
                "utc_end": "2026-10-12T10:02:09Z", "cleanup": "verified"}
        mine = [failure(f"lab.user{i}", f"2026-10-12T10:02:0{i}.5Z") for i in range(9)]
        other = [failure(f"x{i}", f"2026-10-12T10:02:0{i}.7Z", ip="::ffff:10.0.0.99") for i in range(8)]
        self.assertEqual(evidence.expected_correlations(step, load_correlations()), [c])
        self.assertEqual(evidence.expected_correlations({**step, "correlations": []}, load_correlations()), [])
        bound, fired = evidence.correlation_hits(c, step, mine + other, 120)
        self.assertEqual([(a["group"]["IpAddress"], a["metric"]) for a in fired], [("10.0.0.21", 9)])
        self.assertEqual(len(evidence.counted_events(c, fired[0], bound)), 9)
        _bound, fired_other_only = evidence.correlation_hits(c, step, other, 120)
        self.assertEqual(fired_other_only, [])
        # another client spraying AT the emulation host (which logs the 4625s) is not this run's spray,
        # and a group that sorts first ("10.0.0.100") never displaces the run's own alert
        at_host = [failure(f"y{i}", f"2026-10-12T10:02:0{i}.1Z", ip="10.0.0.100", EventID=4625, SubStatus="0xc000006a",
                           Computer="LAB-WS01.lab.local") for i in range(6)]
        self.assertEqual(evidence.correlation_hits(c, step, at_host, 120)[1], [])
        self.assertEqual([a["group"]["IpAddress"] for a in evidence.correlation_hits(c, step, at_host + mine, 120)[1]],
                         ["10.0.0.21"])
        siem = [{"_time": "2026-10-12T10:13:05Z", "ss_name": f"RASD - {SPRAY}", "host": "10.0.0.99"},
                {"_time": "2026-10-12T10:13:05Z", "ss_name": f"RASD - {SPRAY}", "host": "10.0.0.21"}]
        found = evidence.find_correlation_alerts(c, step, siem, 900)
        self.assertEqual([a["host"] for _t, a in found], ["10.0.0.21"])
        tmp = Path(tempfile.mkdtemp()) / SPRAY
        tmp.mkdir()
        try:
            body = evidence.render_correlation(c, step, bound, fired[0], found, {"dc.jsonl": "a" * 64}, "r.json", "b" * 64,
                                               {"alerts.csv": "c" * 64})
            (tmp / "evidence.md").write_text(body, encoding="utf-8")
            self.assertEqual(validate.evidence_errors(tmp), [])
            self.assertIn("threshold_reached: '2026-10-12T10:02:04.500Z'", body)
        finally:
            shutil.rmtree(tmp.parent)

    def test_evidence_binding_holds_for_every_group_by_shape(self):
        c = spray()
        step = {"host": "LAB-WS01.lab.local", "host_netbios": "LAB-WS01", "host_ips": ["10.0.0.21"],
                "utc_start": "2026-10-12T10:02:00Z", "utc_end": "2026-10-12T10:02:09Z"}
        foreign = [failure(f"y{i}", f"2026-10-12T10:02:0{i}.1Z", ip="10.0.0.100", EventID=4625, SubStatus="0xc000006a",
                           Computer="LAB-WS01.lab.local") for i in range(6)]          # aimed AT the host
        mine = [failure(f"u{i}", f"2026-10-12T10:02:0{i}.5Z") for i in range(9)]
        at_server = [failure(f"t{i}", f"2026-10-12T10:02:0{i}.3Z", ip="10.0.0.21", EventID=4625,
                             SubStatus="0xc000006a", Computer="LAB-SRV01.lab.local") for i in range(6)]

        def shaped(group_by):
            other = copy.deepcopy(c)
            other.rule["correlation"]["group-by"] = group_by
            return other
        hits = lambda corr, evs: [(a["group"], a["metric"]) for a in evidence.correlation_hits(corr, step, evs, 120)[1]]
        self.assertEqual(hits(shaped(["Computer", "IpAddress"]), foreign), [])     # client field must be the host
        self.assertEqual(hits(shaped([]), foreign), [])                            # activity must come from the host
        self.assertEqual(hits(shaped([]), mine), [({}, 9)])
        self.assertEqual(hits(shaped(["Computer"]), at_server), [({"Computer": "LAB-SRV01.lab.local"}, 6)])
        self.assertEqual(hits(shaped(["Computer"]), foreign), [])

    def test_doctor_counts_a_field_only_over_its_own_events(self):
        evs = [failure(f"u{i}", "2026-10-12T10:02:00Z") for i in range(9)]
        evs.append({"Channel": "Security", "EventID": 4625, "TargetUserName": "v", "SubStatus": "0xc000006a",
                    "Status": "0xc000006d", "IpAddress": "10.0.0.21", "TimeCreated": "2026-10-12T10:02:00Z"})
        from types import SimpleNamespace
        c = spray()
        res = doctor.diagnose(evs, [SimpleNamespace(id=c.id, rule=c.base, contract=c.contract)])[0]
        self.assertEqual(res["verdict"], "READY")                 # SubStatus is a 4625 field, not a 4771 one
        self.assertEqual(res["coverage"]["SubStatus"], 100.0)



class NearMiss(unittest.TestCase):
    """Near misses are proven by witnesses; impossible and trivial flips never count."""

    @classmethod
    def setUpClass(cls):
        import nearmiss
        cls.nm = nearmiss
        cls.events = load_jsonl(ROOT / "samples" / "replay" / "lab-day.jsonl")
        cls.report = nearmiss.analyse(cls.events)

    def test_every_boundary_has_a_witness_the_engine_confirms(self):
        from common import load_detections
        from sigma_engine import compile_rule
        rules = {d.id: d.rule for d in load_detections()}
        rules.update({f"{c.id} (base)": c.base for c in load_correlations()})
        checked = 0
        for det, r in self.report["detections"].items():
            fires = compile_rule(rules[det])
            for b in r.get("boundaries", []):
                w = b["witness"]
                twin = self.nm.Boundary.edit(b["example"], w["field"], w["to"])
                self.assertFalse(fires(b["example"]), det)
                self.assertTrue(fires(twin), f"{det}: {b['condition']}")
                changed = {k for k in set(b["example"]) | set(twin) if b["example"].get(k) != twin.get(k)}
                self.assertLessEqual(len(changed), 1, f"{det}: a witness edits exactly one field")
                checked += 1
        self.assertGreaterEqual(checked, 8)

    def test_impossible_and_trivial_flips_do_not_count(self):
        lsass = self.report["detections"]["T1003.001_lsass_memory_access"]["boundaries"]
        self.assertFalse(any("lolbin_exception" in b["condition"] for b in lsass),
                         "a path cannot end in both MsMpEng.exe and rundll32.exe")
        self.assertEqual(self.report["detections"]["T1070.001_security_log_cleared"]["near_misses"], 0,
                         "a Security event shares nothing needed with the 1102 rule")
        rc4 = self.report["detections"]["T1558.003_kerberoasting_rc4_tgs"]["boundaries"][0]
        self.assertEqual((rc4["witness"]["from"], rc4["witness"]["to"]), ("0x12", "0x17"))

    def test_every_loaded_boundary_is_pinned_and_unpinned_ones_are_reported(self):
        self.assertEqual(self.nm.unpinned(self.report), [])
        from common import Detection, find_detection
        det = find_detection("T1558.003_kerberoasting_rc4_tgs")
        tmp = Path(tempfile.mkdtemp())
        try:
            (tmp / "tests").mkdir()
            shutil.copy(det.folder / "tests" / "true_positive.jsonl", tmp / "tests")
            bare = Detection(tmp, det.rule, det.contract)               # same rule, no true negatives
            r = self.nm.analyse_detection(bare, self.events)
            self.assertTrue(r["boundaries"] and all(b["pinned_by"] is None for b in r["boundaries"]))
        finally:
            shutil.rmtree(tmp)

    def test_a_burst_split_by_a_window_boundary_is_reported(self):
        c = spray()
        at = lambda m: iso(datetime(2026, 10, 12, 10, 7) + timedelta(minutes=m))
        split = [failure(f"s{i}", at(i if i < 3 else i + 1), ip="::ffff:10.0.0.50") for i in range(6)]    # 3 + 3 at 10:10
        caught = [failure(f"c{i}", f"2026-10-12T11:02:0{i}Z", ip="10.0.0.60") for i in range(6)]
        r = self.nm.analyse_correlation(c, split + caught, [])
        self.assertEqual(r["alerting"], 1)
        self.assertEqual([(b["group"], b["metric"]) for b in r["split_bursts"]], [("10.0.0.50", 6)])
        self.assertEqual(self.report["correlations"][SPRAY]["split_bursts"], [])
        # a sustained spray whose middle window alerted is caught, not split: 3 late, 6 in 10:10-10:20, 3 early
        times = ["10:08:20", "10:09:00", "10:09:40"] + [f"10:1{i}:00" for i in range(6)] + ["10:20:30", "10:21:00", "10:21:30"]
        sustained = [failure(f"z{i}", f"2026-10-12T{t}Z", ip="10.0.0.70") for i, t in enumerate(times)]
        r = self.nm.analyse_correlation(c, sustained, [])
        self.assertEqual((r["alerting"], r["split_bursts"]), (1, []))

    def test_correlation_headroom_and_defence_in_depth(self):
        spray, roast = self.report["correlations"][SPRAY], self.report["correlations"][ROAST]
        self.assertEqual((spray["alerting"], spray["max_quiet"], spray["headroom"]), (1, 1, 4))
        self.assertEqual((roast["alerting"], roast["max_quiet"], roast["headroom"]), (0, 4, 1))
        self.assertEqual([n["caught_by"] for n in roast["near_misses"]], [["T1558.003_kerberoasting_rc4_tgs"]])


if __name__ == "__main__":
    unittest.main()
