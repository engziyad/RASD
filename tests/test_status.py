"""The Decision layer: one record per detection, one verdict, and every page and command reading the same record."""
import io
import json
import re
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import date, timedelta
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests"))

import advise  # noqa: E402
import datasets  # noqa: E402
import status  # noqa: E402
from test_tools import shared_repo  # noqa: E402


def record(checks, evidence=None, level="medium", blocker=None, foundation=None):
    rec = status.Record(id="T0000_example", kind="rule", technique="T0000", title="Example", level=level,
                        folder="detect/detections/T0000_example", blocker=blocker,
                        foundation=foundation or {"tests": 8, "contract": ["Sysmon Event ID 1"]}, evidence=evidence)
    rec.checks = [status.Check(stage, layer, state, detail) for stage, layer, state, detail in checks]
    return rec


CODE = [("Tests", "code", "passed", "8 true positives and 8 true negatives, all pass"),
        ("Mutations", "code", "passed", "every value proven"),
        ("Evasion fuzzer", "code", "passed", "resistance 100%"),
        ("Query parity", "code", "passed", "KQL and SPL return the rule's verdict"),
        ("Exact automaton", "code", "passed", "compiled")]
FIRED = ("Lab run", "lab", "passed", "fired on lab-ws01 at 2026-11-21 03:02 UTC")
ALERT = ("Live SIEM", "siem", "passed", "Splunk Enterprise 10.4.5 raised `RASD - T0000_example` 7 min after the step")
CLEAN = ("Cleanup", "lab", "passed", "the step undid what it did, and the run checked it")
QUIET = ("Telemetry health", "health", "unknown", "production: unknown")
EVIDENCE = {"file": "x/evidence.md", "run_utc": "2026-11-21T03:02:00Z", "operational_parts": {"DFIR evidence": 15}}


class Verdicts(unittest.TestCase):
    """The rules of `judge`, in their order: what fails wins, and code checks never verify."""

    def judged(self, checks, as_of=date(2026, 11, 21), **kw):
        rec = record(checks, **kw)
        status.judge(rec, as_of)
        return rec

    def test_a_thousand_passing_code_checks_never_verify_a_detection(self):
        many = CODE * 200
        rec = self.judged(many + [("Lab run", "lab", "pending", "no kept lab run has run its step yet"), QUIET])
        self.assertEqual(rec.verdict, "Unverified")
        self.assertEqual(rec.next_key, "lab")
        rec = self.judged(many + [("Lab run", "lab", "blocked", "its step needs a lab domain"), QUIET], blocker="domain")
        self.assertEqual((rec.verdict, rec.next_key), ("Blocked", "domain"))

    def test_verified_needs_the_lab_step_the_siem_alert_and_the_cleanup(self):
        self.assertEqual(self.judged(CODE + [FIRED, ALERT, CLEAN, QUIET], evidence=EVIDENCE).verdict, "Verified")
        no_alert = self.judged(CODE + [FIRED, ("Live SIEM", "siem", "missing", "no SIEM beside it"), CLEAN, QUIET],
                               evidence=EVIDENCE)
        self.assertEqual((no_alert.verdict, no_alert.next_key), ("Partially Verified", "siem"))
        dirty = self.judged(CODE + [FIRED, ALERT, ("Cleanup", "lab", "missing", "cleanup: not recorded"), QUIET],
                            evidence=EVIDENCE)
        self.assertEqual((dirty.verdict, dirty.next_key), ("Partially Verified", "cleanup"))

    def test_a_failure_wins_over_everything_else(self):
        broken = [("Query parity", "code", "failed", "a generated query and the rule disagree")]
        rec = self.judged(CODE[:3] + broken + [FIRED, ALERT, CLEAN, QUIET], evidence=EVIDENCE)
        self.assertEqual(rec.verdict, "Failed")
        self.assertTrue(rec.critical, "a failure is always critical")
        silent = self.judged(CODE + [FIRED, ("Live SIEM", "siem", "failed", "the SIEM raised no alert"), CLEAN, QUIET],
                             evidence=EVIDENCE)
        self.assertEqual((silent.verdict, silent.next_key), ("Failed", "fix:Live SIEM"))

    def test_degraded_is_for_a_detection_proven_once_and_blocked_stays_blocked(self):
        sick = ("Telemetry health", "health", "degraded", "production: blind; process_access is silent")
        proven = self.judged(CODE + [FIRED, ALERT, CLEAN, sick], evidence=EVIDENCE)
        self.assertEqual((proven.verdict, proven.next_key), ("Degraded", "health"))
        unproven = self.judged(CODE + [("Lab run", "lab", "blocked", "its step is opt-in"), sick], blocker="opt-in")
        self.assertEqual(unproven.verdict, "Blocked")
        self.assertTrue(unproven.critical)
        self.assertIn("health", [a["key"] for a in unproven.also])
        self.assertTrue(any(g.startswith("Telemetry health") for g in unproven.gaps))

    def test_lab_evidence_goes_stale_after_the_window(self):
        checks = CODE + [FIRED, ALERT, CLEAN, QUIET]
        run = date(2026, 11, 21)
        self.assertEqual(self.judged(checks, as_of=run + timedelta(days=status.FRESH_DAYS), evidence=EVIDENCE).verdict,
                         "Verified")
        stale = self.judged(checks, as_of=run + timedelta(days=status.FRESH_DAYS + 1), evidence=EVIDENCE)
        self.assertEqual((stale.verdict, stale.next_key), ("Stale", "stale"))
        self.assertTrue(stale.critical)

    def test_an_incomplete_foundation_is_unknown(self):
        rec = self.judged([("Tests", "code", "attention", "0 true positives and 0 true negatives, all pass"), QUIET],
                          foundation={"tests": 0, "contract": []})
        self.assertEqual(rec.verdict, "Unknown")

    def test_critical_follows_the_level_and_the_noise(self):
        blocked = [*CODE, ("Lab run", "lab", "blocked", "its step needs a lab domain"), QUIET]
        self.assertFalse(self.judged(blocked, level="medium", blocker="domain").critical)
        self.assertTrue(self.judged(blocked, level="high", blocker="domain").critical)
        noisy = ("False positives", "noise", "attention", "1 alert in the lab with no step asking for it")
        rec = self.judged(CODE + [FIRED, ALERT, CLEAN, QUIET, noisy], level="high", evidence=EVIDENCE)
        self.assertEqual(rec.verdict, "Verified")
        self.assertTrue(rec.critical)
        self.assertEqual(rec.next_key, "noise", "a Verified detection's next action is its open gap")

    def test_the_blocker_quotes_only_what_the_run_recorded(self):
        said = ('could not look up svc_x in AD (Exception calling "FindOne" with "0" argument(s): "The specified domain '
                'either does not exist or could not be contacted. ")')
        pattern, kind = next((p, k) for p, k in status.BLOCKERS if re.search(p, said, re.I))
        self.assertEqual(kind, "domain")
        self.assertEqual(status._quote(said, pattern), "The specified domain either does not exist or could not be contacted")


class Record(unittest.TestCase):
    """The record of this repository, against the evidence it holds."""

    @classmethod
    def setUpClass(cls):
        cls.repo = shared_repo()
        cls.doc = cls.repo.status
        cls.by_id = {r["id"]: r for r in cls.doc["detections"]}

    def stage(self, rec, name):
        return next((c for c in rec["checks"] if c["stage"] == name), None)

    def test_one_record_per_detection_and_one_verdict_each(self):
        self.assertEqual(sorted(self.by_id), sorted(d.id for d in self.repo.items))
        self.assertEqual(sum(self.doc["counts"].values()), len(self.repo.items))
        for rec in self.doc["detections"]:
            self.assertIn(rec["verdict"], status.STATES, rec["id"])
            self.assertTrue(rec["why"], rec["id"])
            if rec["verdict"] != "Verified":
                self.assertTrue(rec["next"], f"{rec['id']}: every detection short of Verified has a next action")

    def test_verified_is_exactly_the_evidence_that_fired_with_an_alert_and_a_verified_cleanup(self):
        for d in self.repo.items:
            ev = self.repo.evidence[d.id]
            proven = bool(ev and ev.get("result") == "fired" and int((ev.get("siem") or {}).get("alerts") or 0) >= 1
                          and ev.get("cleanup") == "verified")
            self.assertEqual(self.by_id[d.id]["verdict"] == "Verified", proven, d.id)
            if not ev:
                self.assertNotIn(self.by_id[d.id]["verdict"], ("Verified", "Partially Verified", "Stale", "Degraded"), d.id)

    def test_code_checks_and_live_checks_are_apart(self):
        for rec in self.doc["detections"]:
            layers = [c["layer"] for c in rec["checks"]]
            code = [i for i, layer in enumerate(layers) if layer in status.CODE_LAYERS]
            live = [i for i, layer in enumerate(layers) if layer in status.LIVE_LAYERS]
            self.assertTrue(code and live, rec["id"])
            self.assertLess(max(code), min(live), f"{rec['id']}: the code checks come first, then the live ones")

    def test_every_stage_names_a_file_that_exists(self):
        for rec in self.doc["detections"]:
            for c in rec["checks"]:
                if c["proof"]:
                    self.assertTrue((ROOT / c["proof"]).exists(), f"{rec['id']} · {c['stage']}: {c['proof']}")

    def test_a_blocker_is_what_the_kept_run_recorded(self):
        ctx = status.context()
        for rec in self.doc["detections"]:
            if rec["verdict"] != "Blocked":
                continue
            seen = ctx.steps.get(rec["id"], [])
            if not seen:
                self.assertIn(rec["blocker"], ("no step", "opt-in", "domain"), rec["id"])
                continue
            label, step = seen[-1]
            said = str(step.get("reason") or step.get("error") or "")
            self.assertIn(label, rec["why"], rec["id"])
            if said.startswith("opt-in"):
                self.assertEqual(rec["blocker"], "opt-in", rec["id"])
            elif "-Spn" in said or "-UserList" in said or "domain" in said:
                self.assertEqual(rec["blocker"], "domain", rec["id"])

    def test_no_component_contradicts_another(self):
        self.assertEqual([c for r in self.doc["detections"] for c in r["conflicts"]], [])
        self.assertEqual(self.doc["pages"], [])

    def test_the_next_actions_name_each_detection_they_move_on(self):
        steps = status.next_actions(self.doc)
        texts = [t for t, _ids in steps]
        self.assertEqual(len(texts), len(set(texts)), "each action once")
        for text, ids in steps:
            for det in ids:
                rec = self.by_id[det]
                self.assertIn(text, [rec["next"], *(a["text"] for a in rec["also"])], det)
        waiting = [r for r in self.doc["detections"] if r["verdict"] != "Verified"]
        if waiting:
            first = steps[0][1]
            self.assertTrue(set(first) & {r["id"] for r in waiting}, "the first action moves a detection to a better verdict")

    def test_the_counsel_reads_the_same_blockers(self):
        findings = [f for f in advise.counsel(self.repo) if f.id.startswith("evidence.wave.")]
        for f in findings:
            key = f.data["wave"]
            for det in f.data["detections"]:
                self.assertFalse(self.repo.evidence[det], det)
                self.assertEqual(self.by_id[det]["next_key"] if self.by_id[det]["next_key"] in advise.LAB_NEEDS else "lab",
                                 key, det)
                self.assertIn(self.by_id[det]["next"], f.action, det)

    def test_the_public_data_pages_read_the_lab_row_from_the_evidence(self):
        for d in self.repo.items:
            cell = datasets.lab_cell(d.id, "../../../")
            ev = self.repo.evidence[d.id]
            if ev and ev.get("result") == "fired":
                self.assertIn(f"fired on its attack step in a lab on {str(ev['run_utc'])[:10]}", cell, d.id)
            else:
                self.assertTrue(cell.startswith("pending"), d.id)
        fired = sum(1 for d in self.repo.items if (self.repo.evidence[d.id] or {}).get("result") == "fired")
        self.assertEqual(datasets.lab_count(), fired)


class OneRecordEverywhere(unittest.TestCase):
    """The record, its page, the front page and the command say the same thing."""

    @classmethod
    def setUpClass(cls):
        cls.doc = shared_repo().status

    def test_the_committed_record_and_pages_are_this_build(self):
        for path, text in status.files(self.doc).items():
            self.assertEqual(path.read_text(encoding="utf-8"), text, f"{path.relative_to(ROOT)}: run rasd build")

    def test_the_command_prints_what_the_page_and_the_front_page_show(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(status.main([]), 0)
        printed = out.getvalue()
        page = status.page(self.doc)
        front = (ROOT / "README.md").read_text(encoding="utf-8")
        for question, answer, _where in status.answers(self.doc):
            self.assertIn(question, printed)
            self.assertIn(answer, printed)
            self.assertIn(status._cell(answer), page)
        for _question, answer, _where in status.answers(self.doc, up="", page_link="status/README.md"):
            self.assertIn(status._cell(answer), front)
        for verdict, n in self.doc["counts"].items():
            if n:
                self.assertRegex(printed, rf"{verdict}\s+{n}\b")
                self.assertIn(f"| **{verdict}** | {n} |", page)
        self.assertIn(status.sentence(self.doc, "status/README.md"), front)

    def test_one_detection_view_is_the_record(self):
        rec = next(r for r in self.doc["detections"] if r["verdict"] != "Verified")
        out = io.StringIO()
        with redirect_stdout(out):
            status.main(["--detection", rec["id"]])
        text = out.getvalue()
        self.assertIn(rec["why"], text)
        self.assertIn(rec["next"], text)
        for c in rec["checks"]:
            self.assertIn(c["detail"], text)
        out = io.StringIO()
        with redirect_stdout(out):
            status.main(["--detection", rec["id"], "--json"])
        self.assertEqual(json.loads(out.getvalue()), rec)

    def test_check_fails_on_a_conflict_or_a_stale_record(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        conflicted = json.loads(json.dumps(self.doc))
        conflicted["detections"][0]["conflicts"] = ["its contract claims reference, and the repository proves tested"]
        out = io.StringIO()
        with mock.patch.object(status, "build", return_value=conflicted), redirect_stdout(out):
            self.assertEqual(status.main(["--check"]), 1)
        self.assertIn("conflict: ", out.getvalue())
        stale = tmp / "status.json"
        stale.write_text("{}", encoding="utf-8")
        out = io.StringIO()
        with mock.patch.object(status, "files", return_value={stale: "{\"rasd_status\": 1}"}), redirect_stdout(out):
            self.assertEqual(status.main(["--check"]), 1)
        self.assertIn("out of date", out.getvalue())

    def test_a_page_that_states_a_lab_result_the_record_does_not_hold_is_a_conflict(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "docs").mkdir()
        folder = tmp / "detect" / "detections" / "T0000_example"
        folder.mkdir(parents=True)
        (folder / "public_evidence.md").write_text("| Validated (lab evidence) | pending ([evidence plan](x)) |\n",
                                                  encoding="utf-8")
        (tmp / "docs" / "PUBLIC_DATA_VALIDATION.md").write_text(
            "**Validated (lab evidence): 0 of 1** ([status](../status/README.md))", encoding="utf-8")
        doc = {"detections": [{"id": "T0000_example", "folder": "detect/detections/T0000_example",
                               "evidence": {"run_utc": "2026-11-21"},
                               "checks": [{"stage": "Lab run", "state": "passed"}]}]}
        with mock.patch.object(status, "ROOT", tmp):
            found = status.page_claims(doc)
        self.assertEqual(len(found), 2, found)
        self.assertTrue(any("says its lab evidence is pending" in f for f in found))
        self.assertTrue(any("says 0 of 1 detections have lab evidence" in f for f in found))


class ProductionHealth(unittest.TestCase):
    """`rasd status --health` reads what `rasd health --json` wrote, and degrades only what a lab once proved."""

    @classmethod
    def setUpClass(cls):
        import health
        cls.repo = shared_repo()
        cls.tmp = Path(tempfile.mkdtemp())
        cls.file = cls.tmp / "health.json"
        with mock.patch.object(sys, "argv", ["health", "--sample", "--json", str(cls.file)]), redirect_stdout(io.StringIO()):
            health.main()
        cls.doc = status.build(cls.repo, health_file=cls.file)
        cls.health = json.loads(cls.file.read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_degraded_follows_the_health_verdict_of_proven_detections(self):
        verdicts = {r["detection"]: r["verdict"] for r in self.health["detections"]}
        plain = {r["id"]: r for r in self.repo.status["detections"]}
        for rec in self.doc["detections"]:
            sick = verdicts.get(rec["id"]) in ("blind", "degraded")
            proven = plain[rec["id"]]["verdict"] == "Verified"
            if sick and proven:
                self.assertEqual(rec["verdict"], "Degraded", rec["id"])
            else:
                self.assertEqual(rec["verdict"], plain[rec["id"]]["verdict"], rec["id"])
            if sick:
                self.assertTrue(rec["critical"], rec["id"])
        self.assertEqual(self.doc["production_health"], self.file.name)

    def test_a_file_that_is_not_health_json_is_refused(self):
        bad = self.tmp / "other.json"
        bad.write_text(json.dumps({"detections": []}), encoding="utf-8")
        with self.assertRaises(SystemExit):
            status.production_health(bad)


if __name__ == "__main__":
    unittest.main()
