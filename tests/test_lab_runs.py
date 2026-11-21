"""Lab runs kept in the repository (purple/lab_runs): evidence that is recomputed, not trusted."""
import hashlib
import io
import json
import shutil
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import evidence  # noqa: E402
import validate  # noqa: E402
from common import find_detection  # noqa: E402

DETECTION = "T1059.001_powershell_encoded_command"


class KeptRuns(unittest.TestCase):
    """One lab run, kept twice over: as the strict zip a Windows lab packs, and as a folder with an export beside it."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.store = self.tmp / "lab_runs"
        self.library = self.tmp / "library" / DETECTION
        self.library.mkdir(parents=True)
        self.entries = [(DETECTION, self.library)]
        self.event = {**find_detection("T1059.001").tests("true_positive")[0],
                      "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "LAB-WS01.lab.local",
                      "UtcTime": "2026-10-12 06:00:01.400"}

    def step(self, start="2026-10-12T06:00:00.0000000Z", end="2026-10-12T06:00:01.0000000Z", artifacts=()):
        return {"technique": "T1059.001", "test": "powershell_encoded_command", "step": "enc", "name": "enc",
                "detections": [DETECTION], "status": "executed", "host": "LAB-WS01", "marker": "rasd_00000001",
                "utc_start": start, "utc_end": end, "cleanup": "verified", "artifacts": list(artifacts)}

    def folder_run(self, name="lab-linux", event=None, **step):
        """A run as red/run_red.py leaves it: a folder with the results, and the export beside it."""
        base = Path(tempfile.mkdtemp(dir=self.tmp))
        (base / name).mkdir(parents=True)
        (base / name / "emulation-results.json").write_text(json.dumps([self.step(**step)]), encoding="utf-8")
        export = base / "export.jsonl"
        export.write_text(json.dumps(event or self.event) + "\n", encoding="utf-8")
        (base / "export.jsonl.sha256").write_text(f"{evidence.sha256(export)}  export.jsonl\n", encoding="utf-8")
        return [base / name, export]

    def zip_run(self, name="lab-windows"):
        """A run as Invoke-RasdLabRun.ps1 packs it: manifest inside, .sha256 beside."""
        base = Path(tempfile.mkdtemp(dir=self.tmp))
        run_dir = base / "run"
        run_dir.mkdir(parents=True)
        (run_dir / "lab-export.jsonl").write_text(json.dumps(self.event) + "\n", encoding="utf-8")
        (run_dir / "emulation-results.json").write_text(json.dumps([self.step()]), encoding="utf-8")
        files = [p for p in sorted(run_dir.rglob("*")) if p.is_file()]
        (run_dir / evidence.MANIFEST).write_text(json.dumps({"files": [
            {"path": p.name, "sha256": evidence.sha256(p)} for p in files]}), encoding="utf-8")
        zp = base / f"{name}.zip"
        with zipfile.ZipFile(zp, "w") as z:
            for p in sorted(run_dir.rglob("*")):
                z.write(p, p.name)
        (base / f"{zp.name}.sha256").write_text(f"{evidence.sha256(zp)}  {zp.name}\n", encoding="utf-8")
        return [zp]

    def keep(self, paths, run="hosted-1", strict=False, note="made for the test", **options):
        return evidence.keep(run, paths, strict=strict, note=note, options=options, store=self.store)

    def standing(self):
        return evidence.standing(self.store, self.entries)

    def write_evidence(self):
        st = self.standing()
        _label, text = st.stale[DETECTION]
        (self.library / "evidence.md").write_text(text, encoding="utf-8", newline="\n")
        return text

    def quiet(self, fn, *args):
        out = io.StringIO()
        with redirect_stdout(out):
            code = fn(*args)
        return code, out.getvalue()

    def test_keep_copies_the_run_with_its_hash_files_and_records_how_it_was_read(self):
        dest = self.keep(self.zip_run(), strict=True)
        self.assertEqual(sorted(p.name for p in dest.iterdir()), ["lab-windows.zip", "lab-windows.zip.sha256"])
        dest = self.keep(self.folder_run(), grace=300)
        self.assertEqual(sorted(p.name for p in dest.iterdir()), ["export.jsonl", "export.jsonl.sha256", "lab-linux"])
        doc = yaml.safe_load((self.store / "hosted-1" / "run.yml").read_text(encoding="utf-8"))
        self.assertEqual(doc, {"rasd_lab_run": 1, "note": "made for the test", "parts": [
            {"name": "lab-linux", "run": ["lab-linux", "export.jsonl"], "grace": 300},
            {"name": "lab-windows", "run": ["lab-windows.zip"], "strict": True}]})
        parts, notes, problems = evidence.kept_parts(self.store)
        self.assertEqual([(p.label, p.strict, p.options) for p in parts],
                         [("hosted-1/lab-linux", False, {"grace": 300}), ("hosted-1/lab-windows", True, {})])
        self.assertEqual((notes, problems), ({"hosted-1": "made for the test"}, []))

    def test_a_part_kept_again_replaces_its_first_copy(self):
        self.keep(self.folder_run())
        again = self.folder_run(name="lab-linux")
        (again[0] / "notes.txt").write_text("second run", encoding="utf-8")
        dest = self.keep(again, note=None)
        self.assertTrue((dest / "lab-linux" / "notes.txt").exists())
        doc = yaml.safe_load((self.store / "hosted-1" / "run.yml").read_text(encoding="utf-8"))
        self.assertEqual([p["name"] for p in doc["parts"]], ["lab-linux"])
        self.assertEqual(doc["note"], "made for the test", "a note is kept until another one replaces it")

    def test_a_name_that_could_leave_the_store_is_refused(self):
        for name in ("../outside", "Hosted", "", "a/b", ".hidden"):
            with self.assertRaises(evidence.RunError, msg=name):
                self.keep(self.folder_run(name=f"run-{abs(hash(name))}"), run=name)

    def test_evidence_of_a_kept_run_is_what_the_run_gives_today(self):
        self.keep(self.zip_run(), strict=True)
        st = self.standing()
        self.assertEqual((st.current, list(st.stale), st.absent), ({}, [DETECTION], {DETECTION}),
                         "a run that fires a detection with no evidence.md is not in step with the library")
        text = self.write_evidence()
        self.assertEqual(validate.evidence_errors(self.library), [])
        self.assertIn("verification: strict", text)
        st = self.standing()
        self.assertEqual(st.current, {DETECTION: "hosted-1/lab-windows"})
        self.assertEqual((st.stale, st.broken, st.unkept, st.unused, st.problems), ({}, {}, [], [], []))

    def test_an_edited_evidence_file_is_stale_and_refresh_restores_it(self):
        self.keep(self.folder_run())
        text = self.write_evidence()
        (self.library / "evidence.md").write_text(text.replace("matched_events: 1", "matched_events: 7"), encoding="utf-8")
        self.assertEqual(validate.evidence_errors(self.library), [], "the edit is one the validator alone cannot see")
        st = self.standing()
        self.assertEqual((list(st.stale), st.absent), ([DETECTION], set()))
        code, out = self.quiet(evidence.check, self.store, self.entries)
        self.assertEqual(code, 1)
        self.assertIn("is not what the kept run gives today", out)
        code, out = self.quiet(evidence.refresh, self.store, self.entries)
        self.assertEqual(code, 0, out)
        self.assertEqual((self.library / "evidence.md").read_text(encoding="utf-8"), text)

    def test_a_rule_that_no_longer_fires_on_its_run_loses_the_evidence(self):
        self.keep(self.folder_run())
        self.write_evidence()
        export = self.store / "hosted-1" / "lab-linux" / "export.jsonl"
        quiet = {**self.event, "CommandLine": "powershell.exe -NoProfile -File C:\\lab\\inventory.ps1"}
        export.write_text(json.dumps(quiet) + "\n", encoding="utf-8")
        (export.parent / "export.jsonl.sha256").write_text(f"{evidence.sha256(export)}  export.jsonl\n", encoding="utf-8")
        st = self.standing()
        self.assertEqual(st.broken, {DETECTION: "hosted-1/lab-linux"})
        code, out = self.quiet(evidence.check, self.store, self.entries)
        self.assertEqual(code, 1)
        self.assertIn("no longer fires on that run", out)

    def test_a_kept_file_changed_after_the_run_is_a_problem_not_evidence(self):
        self.keep(self.zip_run(), strict=True)
        self.write_evidence()
        zp = self.store / "hosted-1" / "lab-windows" / "lab-windows.zip"
        with zipfile.ZipFile(zp, "a") as z:
            z.writestr("added-later.txt", "x")
        st = self.standing()
        self.assertEqual(st.current, {})
        self.assertTrue(any("hosted-1/lab-windows" in p and "sha256" in p.lower() for p in st.problems), st.problems)
        self.assertEqual(st.broken, {}, "a run that cannot be read is reported once, as the run's problem")
        self.assertEqual(self.quiet(evidence.check, self.store, self.entries)[0], 1)

    def test_an_export_edited_in_the_store_is_refused_by_its_hash_file(self):
        self.keep(self.folder_run())
        self.write_evidence()
        export = self.store / "hosted-1" / "lab-linux" / "export.jsonl"
        export.write_text(export.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        st = self.standing()
        self.assertTrue(any("export.jsonl" in p and "differs" in p for p in st.problems), st.problems)

    def test_the_latest_run_that_fires_a_detection_is_the_one_that_stands(self):
        self.keep(self.folder_run())
        first = self.write_evidence()
        later = {**self.event, "UtcTime": "2026-10-13 06:00:01.400"}
        self.keep(self.folder_run(name="lab-linux", event=later, start="2026-10-13T06:00:00.0000000Z",
                                  end="2026-10-13T06:00:01.0000000Z"), run="hosted-2")
        st = self.standing()
        self.assertEqual(st.stale[DETECTION][0], "hosted-2/lab-linux")
        self.assertEqual(st.unused, ["hosted-1/lab-linux"], "the run nothing comes from any more is to be removed")
        second = self.write_evidence()
        self.assertNotEqual(first, second)
        shutil.rmtree(self.store / "hosted-1")
        st = self.standing()
        self.assertEqual((st.current, st.unused), ({DETECTION: "hosted-2/lab-linux"}, []))

    def test_prune_removes_only_what_a_later_run_made_redundant(self):
        self.keep(self.folder_run())
        self.keep(self.zip_run(), strict=True, run="hosted-1")
        later = {**self.event, "UtcTime": "2026-10-13 06:00:01.400"}
        self.keep(self.folder_run(name="lab-linux", event=later, start="2026-10-13T06:00:00.0000000Z",
                                  end="2026-10-13T06:00:01.0000000Z"), run="hosted-2")
        self.write_evidence()
        self.assertEqual(self.standing().unused, ["hosted-1/lab-linux", "hosted-1/lab-windows"])
        code, out = self.quiet(evidence.check, self.store, self.entries)
        self.assertEqual(code, 1)
        self.assertIn("rasd evidence --prune", out)
        code, out = self.quiet(evidence.prune, self.store, self.entries)
        self.assertEqual(code, 0, out)
        self.assertIn("removed", out)
        self.assertFalse((self.store / "hosted-1").exists(), "a run with no part left goes with its last part")
        self.assertTrue((self.store / "hosted-2" / "lab-linux").is_dir())
        self.assertEqual(self.quiet(evidence.check, self.store, self.entries)[0], 0)
        code, out = self.quiet(evidence.prune, self.store, self.entries)
        self.assertIn("nothing to remove", out)

    def test_prune_keeps_the_parts_of_a_run_that_still_carry_evidence(self):
        self.keep(self.zip_run(), strict=True)
        self.keep(self.folder_run(event={**self.event, "CommandLine": "powershell.exe -File x.ps1"}))
        self.write_evidence()
        self.assertEqual(self.standing().unused, ["hosted-1/lab-linux"])
        self.quiet(evidence.prune, self.store, self.entries)
        doc = yaml.safe_load((self.store / "hosted-1" / "run.yml").read_text(encoding="utf-8"))
        self.assertEqual([p["name"] for p in doc["parts"]], ["lab-windows"])
        self.assertFalse((self.store / "hosted-1" / "lab-linux").exists())
        self.assertEqual(self.quiet(evidence.check, self.store, self.entries)[0], 0)

    def test_prune_never_removes_a_run_it_cannot_read(self):
        self.keep(self.folder_run())
        self.write_evidence()
        export = self.store / "hosted-1" / "lab-linux" / "export.jsonl"
        export.write_text(export.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        self.assertTrue(self.standing().problems)
        self.quiet(evidence.prune, self.store, self.entries)
        self.assertTrue(export.exists())

    def test_an_artifact_is_recorded_by_its_file_name_whichever_machine_reads_the_run(self):
        body = b'{"decoded": "Write-Output rasd"}'
        digest = hashlib.sha256(body).hexdigest()
        on_the_lab = "C:\\Lab\\red\\results\\20261012-060000\\powershell_encoded_command\\decoded.json"
        paths = self.folder_run(artifacts=[{"path": on_the_lab, "sha256": digest}])
        (paths[0] / "powershell_encoded_command").mkdir()
        (paths[0] / "powershell_encoded_command" / "decoded.json").write_bytes(body)
        self.keep(paths)
        text = self.write_evidence()
        self.assertEqual(evidence.front_of(text)["artifacts"], [{"file": "decoded.json", "sha256": digest}])
        self.assertNotIn("C:\\Lab", text, "the lab machine's folders stay out of the evidence")
        self.assertEqual(validate.evidence_errors(self.library), [])
        for lab_path, name in ((on_the_lab, "decoded.json"), ("/home/lab/red/results/run/cron_persistence/crontab.txt", "crontab.txt"),
                               ("decoded.json", "decoded.json"), ("", ""), (None, "")):
            self.assertEqual(evidence.lab_file_name(lab_path), name)
        (self.library / "evidence.md").write_text(text.replace("- file: decoded.json", "- file: C:\\Lab\\decoded.json"), encoding="utf-8")
        self.assertTrue(any("recorded by its file name" in e for e in validate.evidence_errors(self.library)))

    def siem_files(self, base: Path, alert_at="2026-10-12T06:07:30.000Z", host="LAB-WS01", version="10.4.5"):
        """What red/lab/splunk_lab.py leaves beside a run: the alerts the SIEM raised, and which SIEM it was."""
        alerts = base / "siem-alerts.csv"
        alerts.write_text("_time,ss_name,host,alert_hosts,result_count,first_event,last_event\n"
                          f"{alert_at},RASD - {DETECTION},{host},{host},1,1791784801.400,1791784801.400\n", encoding="utf-8")
        about = base / "siem.json"
        about.write_text(json.dumps({"product": "Splunk Enterprise", "version": version, "build": "de9225ad9740", "licence": "Trial",
                                     "apps": {"rasd": "1.7.0", "rasd_fields": "1.7.0"}, "vendor_addons": [], "indexes": ["linux"]}),
                         encoding="utf-8")
        for f in (alerts, about):
            (base / f"{f.name}.sha256").write_text(f"{evidence.sha256(f)}  {f.name}\n", encoding="utf-8")
        return [alerts, about]

    def test_the_alert_of_a_live_siem_and_which_siem_it_was_are_part_of_the_kept_run(self):
        paths = self.folder_run()
        paths += self.siem_files(paths[1].parent)
        dest = self.keep(paths)
        self.assertEqual(sorted(p.name for p in dest.iterdir()),
                         ["export.jsonl", "export.jsonl.sha256", "lab-linux", "siem-alerts.csv", "siem-alerts.csv.sha256",
                          "siem.json", "siem.json.sha256"])
        text = self.write_evidence()
        front = evidence.front_of(text)
        self.assertEqual(front["siem"]["alerts"], 1)
        self.assertEqual(front["siem"]["latency_seconds"], 450.0)
        self.assertEqual(front["siem"]["platform"], "Splunk Enterprise 10.4.5 (build de9225ad9740), Trial licence; "
                                                    "apps: rasd 1.7.0, rasd_fields 1.7.0; vendor add-ons: none")
        self.assertIn("| SIEM | Splunk Enterprise 10.4.5 (build de9225ad9740), Trial licence;", text)
        self.assertEqual([i["file"] for i in front["inputs"]["siem"]], ["siem-alerts.csv", "siem.json"])
        score = evidence.operational_score(front)
        self.assertEqual((score["SIEM result"], score["Detection latency"]), (25, 5))
        self.assertEqual(validate.evidence_errors(self.library), [])
        self.assertEqual(self.quiet(evidence.refresh, self.store, self.entries)[0], 0)
        self.assertIn("byte for byte", self.quiet(evidence.check, self.store, self.entries)[1])
        # the SIEM's description is an input like the others: change it and the evidence is no longer what the run gives
        about = dest / "siem.json"
        about.write_text(about.read_text(encoding="utf-8").replace("10.4.5", "9.9.9"), encoding="utf-8")
        st = self.standing()
        self.assertTrue(st.stale or st.problems, "a changed input is seen")

    def searches_record(self, base: Path, refused: int = 0) -> Path:
        """What red/lab/splunk_lab.py searches leaves: what the lab's SIEM said of every saved search of the app."""
        names = [f"RASD - {DETECTION}", "RASD - alert export",
                 *(f"RASD Health - {c}" for c in ("delay", "fields", "schedule", "silent", "volume"))]
        rows = [{"name": n, "ok": i >= refused, "state": "DONE" if i >= refused else "FAILED", "results": 0, "events_scanned": 12,
                 "messages": [], "scheduled": "*/5 * * * *"} for i, n in enumerate(names)]
        record = base / "siem-searches.json"
        record.write_text(json.dumps({"window": "-60m", "searches": rows}), encoding="utf-8")
        (base / f"{record.name}.sha256").write_text(f"{evidence.sha256(record)}  {record.name}\n", encoding="utf-8")
        return record

    def test_what_the_siem_said_of_every_saved_search_is_kept_with_the_run_and_is_no_input_of_the_evidence(self):
        paths = self.folder_run()
        paths += self.siem_files(paths[1].parent)
        without = self.keep(paths)
        plain = self.write_evidence()
        self.assertEqual(evidence.part_siem(evidence.kept_parts(self.store)[0][0])[1], None)
        shutil.rmtree(without.parent)
        dest = self.keep([*paths, self.searches_record(paths[1].parent)])
        self.assertTrue((dest / "siem-searches.json").is_file() and (dest / "siem-searches.json.sha256").is_file())
        self.assertEqual(self.standing().current, {DETECTION: "hosted-1/lab-linux"}, "the record changes no byte of the evidence")
        self.assertEqual([i["file"] for i in evidence.front_of(plain)["inputs"]["siem"]], ["siem-alerts.csv", "siem.json"])
        part = evidence.kept_parts(self.store)[0][0]
        about, ran = evidence.part_siem(part)
        self.assertEqual((about["version"], ran), ("10.4.5", (7, 7, 5, 5)))
        self.assertEqual(evidence.siem_cell(part, 1, [DETECTION], [DETECTION]),
                         "Splunk Enterprise 10.4.5: alert raised for 1 of 1; 7/7 saved searches ran to the end")
        self.assertEqual(self.quiet(evidence.refresh, self.store, self.entries)[0], 0)
        self.assertEqual(self.quiet(evidence.check, self.store, self.entries)[0], 0)
        # the record is kept as the lab wrote it: one that was edited afterwards refuses the run
        record = dest / "siem-searches.json"
        record.write_text(record.read_text(encoding="utf-8").replace('"results": 0', '"results": 3', 1), encoding="utf-8")
        st = self.standing()
        self.assertTrue(any("siem-searches.json" in p and "differs" in p for p in st.problems), st.problems)

    def test_a_search_the_siem_refused_is_counted_and_a_file_of_another_name_is_no_record(self):
        record = self.searches_record(self.tmp, refused=2)
        self.assertEqual(evidence.siem_searches(record), (5, 7, 5, 5))
        other = self.tmp / "searches.json"
        other.write_text(record.read_text(encoding="utf-8"), encoding="utf-8")
        self.assertIsNone(evidence.siem_searches(other))
        for body in ("{}", '{"searches": []}', '{"searches": [{"ok": true}]}', "not json"):
            record.write_text(body, encoding="utf-8")
            self.assertIsNone(evidence.siem_searches(record), body)

    def test_the_page_of_kept_runs_says_which_siem_stood_beside_each_part(self):
        paths = self.folder_run()
        paths += [*self.siem_files(paths[1].parent), self.searches_record(paths[1].parent)]
        self.keep(paths)
        self.write_evidence()
        text = evidence.page(self.store, self.entries)
        self.assertIn("| Part | Read as | Files | Size | Evidence it carries | Live SIEM |", text)
        self.assertIn("| Splunk Enterprise 10.4.5: alert raised for 1 of 1; 7/7 saved searches ran to the end |", text)
        shutil.rmtree(self.store)
        (self.library / "evidence.md").unlink()
        self.keep(self.folder_run())
        self.write_evidence()
        row = next(line for line in evidence.page(self.store, self.entries).splitlines() if line.startswith("| `lab-linux`"))
        self.assertTrue(row.endswith("| - |"), row)

    def test_the_pages_say_of_a_live_siem_what_the_kept_runs_hold_and_no_more(self):
        import chain
        import health
        import splunk_app
        self.keep(self.folder_run())
        self.write_evidence()
        for text in (health.live_line(self.store, self.entries), " ".join(health.live_block(self.store, self.entries)),
                     splunk_app.live_section(self.store, self.entries)):
            self.assertRegex(text, r"[Nn]ot yet run on a live (SIEM|Splunk)", "a run kept without a SIEM says nothing of one")
        self.assertEqual(chain.live_siem_line(0, 1, self.store, self.entries), "0 of 1 evidence files carry an alert raised by a live SIEM")
        shutil.rmtree(self.store)
        (self.library / "evidence.md").unlink()
        paths = self.folder_run()
        paths += [*self.siem_files(paths[1].parent), self.searches_record(paths[1].parent)]
        self.keep(paths)
        self.write_evidence()
        live = evidence.live_siem(self.store, self.entries)
        self.assertEqual(live, {"runs": ["hosted-1"], "hosts": 1, "platforms": ["Splunk Enterprise 10.4.5"], "apps": ["rasd", "rasd_fields"],
                                "addons": [], "evidence": 1, "alerted": 1, "unasked": {}, "searches": [(7, 7)], "health": [(5, 5)]})
        self.assertEqual(health.live_line(self.store, self.entries),
                         "generated, and the SPL ones ran to the end on Splunk Enterprise 10.4.5 beside 1 lab host in the kept lab run")
        block = "\n".join(health.live_block(self.store, self.entries))
        self.assertIn("**Run on a live Splunk, in the lab.**", block)
        self.assertIn("It does not show a watchdog catching its fault.", block)
        self.assertIn("| Watchdog | `hosted-1/lab-linux` |", block)
        for check in health.WATCHDOGS:
            self.assertIn(f"| **{check}** | ran: 0 rows |", block)
        section = splunk_app.live_section(self.store, self.entries)
        self.assertIn("ran on Splunk Enterprise 10.4.5 beside 1 lab host, with `rasd_fields` and no vendor add-on", section)
        self.assertIn("raised the alert of 1 of the 1 detections whose attack step ran there", section)
        self.assertIn("every saved search of the `rasd` app (7 of them) ran to the end on each host", section)
        self.assertIn("Not shown by a kept run: the same searches over the fields of the vendor add-ons", section)
        self.assertEqual(chain.live_siem_line(1, 1, self.store, self.entries),
                         "1 of 1 evidence files carry an alert raised by a live SIEM: Splunk Enterprise 10.4.5 beside 1 lab host, "
                         "its own scheduler, the RASD apps and no vendor add-on")
        # a search the SIEM refused is said, not averaged away
        shutil.rmtree(self.store)
        paths = self.folder_run()
        paths += [*self.siem_files(paths[1].parent), self.searches_record(paths[1].parent, refused=3)]
        self.keep(paths)
        self.assertIn("3 saved search run(s) did not reach the end", splunk_app.live_section(self.store, self.entries))
        self.assertIn("1 SPL run(s) did not reach the end", health.live_line(self.store, self.entries))
        self.assertIn("| **delay** | **refused** |", "\n".join(health.live_block(self.store, self.entries)))

    def test_an_alert_no_step_asked_for_is_counted_and_shown_with_the_run(self):
        other = "T1003.001_lsass_memory_access"
        entries = [*self.entries, (other, self.tmp / "no-evidence-here")]
        paths = self.folder_run()
        alerts, about = self.siem_files(paths[1].parent)
        with alerts.open("a", encoding="utf-8") as f:
            for at in ("2026-10-12T06:05:01.000Z", "2026-10-12T06:10:01.000Z"):
                f.write(f"{at},RASD - {other},LAB-WS01,LAB-WS01,1,1791784801.400,1791784801.400\n")
            f.write("2026-10-12T06:05:02.000Z,Some other search,LAB-WS01,LAB-WS01,1,1791784801.400,1791784801.400\n")
        (alerts.parent / "siem-alerts.csv.sha256").write_text(f"{evidence.sha256(alerts)}  siem-alerts.csv\n", encoding="utf-8")
        self.keep([*paths, alerts, about])
        self.write_evidence()
        part = evidence.kept_parts(self.store)[0][0]
        self.assertEqual(evidence.unasked_alerts(part, [DETECTION], [DETECTION, other]), {other: 2},
                         "a search that is not a detection of the library is nobody's false positive")
        self.assertEqual(evidence.live_siem(self.store, entries)["unasked"], {other: 2})
        self.assertEqual(evidence.live_siem(self.store, entries)["alerted"], 1)
        row = next(line for line in evidence.page(self.store, entries).splitlines() if line.startswith("| `lab-linux`"))
        self.assertIn(f"alert raised for 1 of 1; alerts no step asked for: `{other}` (2) |", row)
        import chain
        import splunk_app
        self.assertIn(f"It also raised alerts that no step of the run asked for: `{other}` (2). On a host where nobody ran that attack, "
                      "each is a false positive to explain or a rule to tune. Not shown by a kept run:",
                      splunk_app.live_section(self.store, entries))
        self.assertTrue(chain.live_siem_line(1, 1, self.store, entries).endswith(
            "no vendor add-on · 1 detection also alerted there with no step asking for it ([which](purple/lab_runs/README.md))"))

    def test_an_alert_of_another_host_or_another_hour_is_not_this_run_s(self):
        for kwargs in ({"host": "OTHER-PC"}, {"alert_at": "2026-10-12T07:30:00.000Z"}):
            (self.library / "evidence.md").unlink(missing_ok=True)
            paths = self.folder_run()
            paths += self.siem_files(paths[1].parent, **kwargs)
            self.keep(paths)
            front = evidence.front_of(self.standing().stale[DETECTION][1])
            self.assertIsNone(front["siem"], kwargs)
            self.assertEqual(evidence.operational_score(front)["SIEM result"], 0)

    def test_a_json_file_that_is_not_a_siem_s_description_is_not_read_as_one(self):
        for body in ('{"product": "x"}', '{"product": "x", "version": "1"}', '[{"product": "x", "version": "1", "apps": {}}]', "not json"):
            f = self.tmp / "other.json"
            f.write_text(body, encoding="utf-8")
            self.assertIsNone(evidence.siem_platform(f), body)
        self.assertIsNone(evidence.siem_platform(self.tmp / "missing.json"))

    def test_evidence_whose_run_stayed_with_its_lab_is_listed_and_left_alone(self):
        self.keep(self.folder_run())
        text = self.write_evidence()
        shutil.rmtree(self.store)
        st = self.standing()
        self.assertEqual((st.unkept, st.current, st.problems), ([DETECTION], {}, []))
        evidence.write_output(self.store / evidence.STORE_PAGE, evidence.page(self.store, self.entries))
        code, out = self.quiet(evidence.check, self.store, self.entries)
        self.assertEqual(code, 0, out)
        self.assertIn("taken as written", out)
        self.assertEqual((self.library / "evidence.md").read_text(encoding="utf-8"), text)

    def test_the_store_refuses_records_it_did_not_write(self):
        self.keep(self.folder_run())
        (self.store / "hosted-1" / "stray").mkdir()
        (self.store / "by-hand").mkdir()
        (self.store / "broken").mkdir()
        (self.store / "broken" / "run.yml").write_text("rasd_lab_run: 1\nparts:\n- name: x\n  run: [../../etc]\n", encoding="utf-8")
        _parts, _notes, problems = evidence.kept_parts(self.store)
        self.assertEqual(len(problems), 3, problems)
        self.assertTrue(any("hosted-1/stray" in p for p in problems))
        self.assertTrue(any(p.startswith("by-hand:") for p in problems))
        self.assertTrue(any("broken/run.yml" in p for p in problems))

    def test_the_page_lists_each_part_and_the_evidence_it_carries(self):
        self.keep(self.zip_run(), strict=True)
        self.keep(self.folder_run(event={**self.event, "CommandLine": "powershell.exe -File x.ps1"}))
        self.write_evidence()
        text = evidence.page(self.store, self.entries)
        self.assertIn("## hosted-1", text)
        self.assertIn("made for the test", text)
        row = next(line for line in text.splitlines() if line.startswith("| `lab-windows`"))
        self.assertIn("| strict | 2 |", row)
        self.assertIn(f"1: [{DETECTION}](", row)
        self.assertIn("| `lab-linux` | standard |", text)
        self.assertIn("/hosted-1/lab-windows/lab-windows.zip --strict --dry-run", text)
        self.assertIn("None: every `evidence.md` in the library comes from a run above.", text)
        code, out = self.quiet(evidence.check, self.store, self.entries)
        self.assertEqual(code, 1)
        self.assertIn("README.md is out of date", out)
        self.assertIn("hosted-1/lab-linux: kept, and no evidence.md comes from it", out)

    def test_dry_run_never_renders_and_collect_never_writes(self):
        run = self.folder_run()
        results = run[0] / "emulation-results.json"
        bodies: dict = {}
        with redirect_stdout(io.StringIO()):
            code = evidence.evaluate(results, [run[1]], [], grace=120, siem_grace=900, dry_run=True, profile_name=None,
                                     manifest=None, collect=bodies)
        self.assertEqual(code, 0)
        self.assertEqual(list(bodies), [DETECTION])
        self.assertFalse((find_detection("T1059.001").folder / "evidence.md.tmp").exists())


class RepositoryStore(unittest.TestCase):
    """The store this repository ships."""

    def test_every_evidence_file_of_a_kept_run_is_what_the_run_gives_today(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = evidence.check()
        self.assertEqual(code, 0, out.getvalue())

    def test_raw_runs_are_never_normalised_and_never_ignored(self):
        attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
        self.assertIn("purple/lab_runs/** -text", attributes)
        ignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        self.assertIn("!/purple/lab_runs/**", ignore)
        self.assertGreater(ignore.index("!/purple/lab_runs/**"), ignore.index("lab-*.zip"),
                           "the exception has to come after the patterns it lifts")


if __name__ == "__main__":
    unittest.main()
