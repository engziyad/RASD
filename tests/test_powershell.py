"""PowerShell, executed: the lab scripts' logic run under pwsh and checked against the rules.

Nothing here touches a Windows host. The exporter's XML flattening, the readiness helpers and
the runners' plan modes are pure PowerShell, so they run on any OS where pwsh exists - the
GitHub runners included. Each test is skipped when pwsh is not installed; set RASD_PWSH to
point at a pwsh binary that is not on PATH.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

from common import carries_token, find_detection, load_detections  # noqa: E402
from convert import logsource_key  # noqa: E402
from replay import route  # noqa: E402
from sigma_engine import matches  # noqa: E402

PWSH = os.environ.get("RASD_PWSH") or shutil.which("pwsh")
NS = "http://schemas.microsoft.com/win/2004/08/events/event"

# Event XML as Get-WinEvent's ToXml() returns it (trimmed to the fields that matter)
SYSMON_1 = f"""<Event xmlns='{NS}'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{{5770385f-c22a-43e0-bf4c-06f5698ffbd9}}'/>
<EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords>
<TimeCreated SystemTime='2026-10-12T06:00:01.1234567Z'/><EventRecordID>48211</EventRecordID>
<Correlation/><Execution ProcessID='3152' ThreadID='4012'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel>
<Computer>LAB-WS01.lab.local</Computer><Security UserID='S-1-5-18'/></System><EventData>
<Data Name='RuleName'>-</Data><Data Name='UtcTime'>2026-10-12 06:00:01.120</Data>
<Data Name='ProcessGuid'>{{7d3f2a10-1c2b-670a-5a01-000000000a00}}</Data><Data Name='ProcessId'>7444</Data>
<Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
<Data Name='OriginalFileName'>PowerShell.EXE</Data>
<Data Name='CommandLine'>"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -NoProfile -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAHAAdQByAHAAbABlAGwAYQBiAF8AMQBhADIAYgAzAGMANABkACcA</Data>
<Data Name='User'>LAB\\labuser</Data><Data Name='ParentProcessId'>6120</Data>
<Data Name='ParentImage'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data></EventData></Event>"""

SYSTEM_104 = f"""<Event xmlns='{NS}'><System><Provider Name='Microsoft-Windows-Eventlog' Guid='{{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}}'/>
<EventID>104</EventID><Level>4</Level><Task>104</Task><TimeCreated SystemTime='2026-10-12T06:00:05.0000000Z'/>
<EventRecordID>9921</EventRecordID><Correlation/><Execution ProcessID='1204' ThreadID='5560'/><Channel>System</Channel>
<Computer>LAB-WS01.lab.local</Computer></System><UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>
<SubjectUserName>labuser</SubjectUserName><SubjectDomainName>LAB</SubjectDomainName><Channel>R1a2b3c4d</Channel><BackupPath></BackupPath>
</LogFileCleared></UserData></Event>"""

SECURITY_4769 = f"""<Event xmlns='{NS}'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{{54849625-5478-4994-a5ba-3e3b0328c30d}}'/>
<EventID>4769</EventID><Level>0</Level><Task>14337</Task><Keywords>0x8020000000000000</Keywords>
<TimeCreated SystemTime='2026-10-12T06:01:00.5000000Z'/><EventRecordID>771234</EventRecordID>
<Correlation ActivityID='{{a1b2c3d4-0000-0000-0000-000000000001}}'/><Execution ProcessID='716' ThreadID='2280'/><Channel>Security</Channel>
<Computer>LAB-DC01.lab.local</Computer></System><EventData><Data Name='TargetUserName'>labuser@LAB.LOCAL</Data>
<Data Name='TargetDomainName'>LAB.LOCAL</Data><Data Name='ServiceName'>svc_sql</Data><Data Name='TicketOptions'>0x40810000</Data>
<Data Name='TicketEncryptionType'>0x17</Data><Data Name='IpAddress'>::ffff:10.0.0.21</Data><Data Name='IpPort'>49831</Data>
<Data Name='Status'>0x0</Data></EventData></Event>"""

SYSTEM_7045 = f"""<Event xmlns='{NS}'><System><Provider Name='Service Control Manager' Guid='{{555908d1-a6d7-4695-8e1e-26931d2012f4}}' EventSourceName='Service Control Manager'/>
<EventID Qualifiers='16384'>7045</EventID><Level>4</Level><TimeCreated SystemTime='2026-10-12T06:02:00.0000000Z'/>
<EventRecordID>9930</EventRecordID><Correlation/><Execution ProcessID='812' ThreadID='4420'/><Channel>System</Channel>
<Computer>LAB-WS01.lab.local</Computer></System><EventData><Data Name='ServiceName'>purplelab_1a2b3c4d</Data>
<Data Name='ImagePath'>cmd.exe /c echo purplelab_1a2b3c4d</Data><Data Name='ServiceType'>user mode service</Data>
<Data Name='StartType'>demand start</Data><Data Name='AccountName'>LocalSystem</Data></EventData></Event>"""

# an EventData field named like a core key must not replace it
CLASH = f"""<Event xmlns='{NS}'><System><Provider Name='Contoso-App'/><EventID>1000</EventID>
<TimeCreated SystemTime='2026-10-12T06:03:00.0000000Z'/><Computer>LAB-WS01.lab.local</Computer></System>
<EventData><Data Name='Computer'>SPOOFED</Data><Data Name='Channel'>Fake</Data></EventData></Event>"""

HARNESS = r"""
param([string] $Exporter, [string] $Cases)
. $Exporter
foreach ($c in (Get-Content -LiteralPath $Cases -Raw | ConvertFrom-Json)) {
    $record = ConvertFrom-EventXml -Xml $c.xml -Channel $c.channel
    $record | ConvertTo-Json -Compress -Depth 4
}
"""


def run_pwsh(*args, cwd=ROOT, timeout=120):
    return subprocess.run([PWSH, "-NoLogo", "-NoProfile", "-NonInteractive", *args], cwd=cwd,
                          capture_output=True, text=True, timeout=timeout)


@unittest.skipUnless(PWSH, "pwsh not installed (set RASD_PWSH)")
class PowerShellScripts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def export(self, cases: list[tuple[str, str]]) -> list[dict]:
        """Run the exporter's own ConvertFrom-EventXml, exactly as it writes each JSONL line."""
        harness, data = self.tmp / "harness.ps1", self.tmp / "cases.json"
        harness.write_text(HARNESS, encoding="utf-8")
        data.write_text(json.dumps([{"xml": x, "channel": c} for x, c in cases]), encoding="utf-8")
        r = run_pwsh("-File", str(harness), "-Exporter", str(ROOT / "red" / "Export-LabTelemetry.ps1"),
                     "-Cases", str(data))
        self.assertEqual(r.returncode, 0, r.stderr)
        return [json.loads(line) for line in r.stdout.splitlines() if line.strip()]

    def test_every_script_parses(self):
        script = ("$bad = 0; foreach ($f in Get-ChildItem -Path red -Recurse -Filter *.ps1) { $t = $null; $e = $null; "
                  "[void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$t, [ref]$e); "
                  "foreach ($x in $e) { Write-Output \"$($f.Name):$($x.Extent.StartLineNumber): $($x.Message)\"; $bad++ } }; "
                  "exit $bad")
        r = run_pwsh("-Command", script)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_exported_events_keep_the_rule_field_names_and_fire_the_rules(self):
        sysmon, cleared, tgs, service = self.export([
            (SYSMON_1, "Microsoft-Windows-Sysmon/Operational"), (SYSTEM_104, "System"),
            (SECURITY_4769, "Security"), (SYSTEM_7045, "System")])
        # Sysmon's own ProcessId / UtcTime survive, with their exact casing; record metadata is System_*
        self.assertEqual(sysmon["ProcessId"], "7444")
        self.assertNotIn("ProcessID", sysmon)
        self.assertEqual(sysmon["System_ProcessID"], "3152")
        self.assertEqual(sysmon["UtcTime"], "2026-10-12 06:00:01.120")
        self.assertEqual(sysmon["TimeCreated"], "2026-10-12T06:00:01.1234567Z")
        self.assertEqual((sysmon["EventID"], sysmon["EventRecordID"]), (1, 48211))
        self.assertEqual((cleared["Channel"], cleared["Channel_Cleared"]), ("System", "R1a2b3c4d"))
        self.assertEqual(tgs["System_ActivityID"], "{a1b2c3d4-0000-0000-0000-000000000001}")
        # ... and each exported line is what the matching rule needs
        expected = {"T1059.001_powershell_encoded_command": sysmon, "T1070.001_system_log_cleared": cleared,
                    "T1558.003_kerberoasting_rc4_tgs": tgs, "T1569.002_suspicious_service_installation": service}
        for det_id, ev in expected.items():
            det = find_detection(det_id)
            self.assertEqual(route(ev), logsource_key(det.rule), det_id)
            self.assertTrue(matches(det.rule, ev), det_id)
        for d in load_detections():
            if d.id not in expected:
                self.assertFalse(any(route(ev) == logsource_key(d.rule) and matches(d.rule, ev)
                                     for ev in expected.values()), d.id)
        # the bind tokens of the red tests are carried by the exported events
        self.assertTrue(carries_token(sysmon, "base64-utf16le:Write-Output '{marker}'", "purplelab_1a2b3c4d"))
        self.assertTrue(carries_token(cleared, "R{hex}", "purplelab_1a2b3c4d"))
        self.assertTrue(carries_token(service, "{marker}", "purplelab_1a2b3c4d"))

    def test_eventdata_cannot_replace_core_fields(self):
        (ev,) = self.export([(CLASH, "Application")])
        self.assertEqual((ev["Computer"], ev["Channel"]), ("LAB-WS01.lab.local", "Application"))
        self.assertEqual((ev["Computer_EventData"], ev["Channel_EventData"]), ("SPOOFED", "Fake"))

    def test_readiness_resolves_service_executables(self):
        script = (f". '{ROOT / 'red' / 'lab' / 'Test-LabReadiness.ps1'}'; "
                  "Resolve-ExecutablePath '\"C:\\Program Files\\Sysmon\\Sysmon64.exe\" -c'; "
                  "Resolve-ExecutablePath 'C:\\Program Files\\Sysmon\\Sysmon64.exe'; "
                  "Resolve-ExecutablePath 'C:\\Windows\\Sysmon64.exe -m'")
        r = run_pwsh("-Command", script)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.split(), ["C:\\Program", "Files\\Sysmon\\Sysmon64.exe",
                                            "C:\\Program", "Files\\Sysmon\\Sysmon64.exe", "C:\\Windows\\Sysmon64.exe"])

    def test_windows_runner_lists_and_plans_every_test(self):
        tests = sorted(p.parent.name for p in (ROOT / "red").glob("*/*/test.json")
                       if p.parent.parent.name in ("windows", "active_directory"))
        listed = run_pwsh("-File", str(ROOT / "red" / "Invoke-PurpleEmulation.ps1"), "-List")
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertEqual(sorted(line.split()[0] for line in listed.stdout.splitlines() if line.strip()), tests)
        plan = run_pwsh("-File", str(ROOT / "red" / "Invoke-PurpleEmulation.ps1"), "-Technique", "All",
                        "-LabConfirmed", "-DryRun")
        self.assertEqual(plan.returncode, 0, plan.stderr)
        self.assertIn("skip (opt-in: add -IncludeCredentialAccess)", plan.stdout)
        self.assertIn("skip (missing parameter: -Spn)", plan.stdout)
        refused = run_pwsh("-File", str(ROOT / "red" / "Invoke-PurpleEmulation.ps1"), "-Technique", "All")
        self.assertNotEqual(refused.returncode, 0)

    def test_lab_run_dry_run_plans_without_running(self):
        r = run_pwsh("-File", str(ROOT / "red" / "lab" / "Invoke-RasdLabRun.ps1"), "-LabConfirmed", "-DryRun",
                     "-FixReadiness")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("readiness check (red\\lab\\Test-LabReadiness.ps1 -Fix)", r.stdout)
        self.assertIn("service_creation", r.stdout)
        self.assertFalse(any((ROOT / "red" / "results").glob("lab-*")) if (ROOT / "red" / "results").exists() else False)


if __name__ == "__main__":
    unittest.main()
