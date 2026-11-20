"""The lab kit as it runs on machines that exist for one run: the workflow's own limits, and the faults
the first real runs found, each held in place here."""
import re
import sys
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import health  # noqa: E402
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
