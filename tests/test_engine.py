"""Unit tests for the Sigma engine and converter themselves (python -m unittest)."""
import sys
import unittest
from typing import ClassVar
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
from sigma_engine import SigmaError, matches
from convert import convert


def rule(detection, category="process_creation"):
    return {"title": "t", "id": "x", "logsource": {"product": "windows", "category": category},
            "detection": detection}


class EngineModifiers(unittest.TestCase):
    def test_contains_case_insensitive(self):
        r = rule({"s": {"CommandLine|contains": "MIMIKATZ"}, "condition": "s"})
        self.assertTrue(matches(r, {"CommandLine": "run mimikatz.exe"}))

    def test_cased(self):
        r = rule({"s": {"CommandLine|contains|cased": "ABC"}, "condition": "s"})
        self.assertFalse(matches(r, {"CommandLine": "abc"}))

    def test_startswith_endswith(self):
        r = rule({"s": {"Image|startswith": "C:\\Users\\", "Image|endswith": ".exe"}, "condition": "s"})
        self.assertTrue(matches(r, {"Image": "C:\\Users\\a\\x.exe"}))
        self.assertFalse(matches(r, {"Image": "C:\\Windows\\x.exe"}))

    def test_all_modifier(self):
        r = rule({"s": {"CommandLine|contains|all": ["a", "b"]}, "condition": "s"})
        self.assertTrue(matches(r, {"CommandLine": "a b"}))
        self.assertFalse(matches(r, {"CommandLine": "a"}))

    def test_wildcard(self):
        r = rule({"s": {"Image": "*\\cmd.exe"}, "condition": "s"})
        self.assertTrue(matches(r, {"Image": "C:\\Windows\\System32\\cmd.exe"}))

    def test_null_and_exists(self):
        r = rule({"s": {"ParentImage": None}, "condition": "s"})
        self.assertTrue(matches(r, {"Image": "x"}))
        r = rule({"s": {"ParentImage|exists": True}, "condition": "s"})
        self.assertFalse(matches(r, {"Image": "x"}))

    def test_numeric_equality(self):
        r = rule({"s": {"EventID": 4769}, "condition": "s"})
        self.assertTrue(matches(r, {"EventID": "4769"}))

    def test_missing_field_does_not_match(self):
        r = rule({"s": {"CommandLine|contains": "x"}, "condition": "s"})
        self.assertFalse(matches(r, {}))

    def test_regex_follows_the_sigma_spec(self):
        """|re is case-sensitive unless the pattern says (?i) or the rule uses re|i."""
        plain = rule({"s": {"CommandLine|re": "-enc"}, "condition": "s"})
        self.assertFalse(matches(plain, {"CommandLine": "powershell -ENC x"}))
        inline = rule({"s": {"CommandLine|re": "(?i)-enc"}, "condition": "s"})
        self.assertTrue(matches(inline, {"CommandLine": "powershell -ENC x"}))
        sub = rule({"s": {"CommandLine|re|i": "-enc"}, "condition": "s"})
        self.assertTrue(matches(sub, {"CommandLine": "powershell -ENC x"}))
        with self.assertRaises(SigmaError):
            matches(rule({"s": {"CommandLine|contains|i": "x"}, "condition": "s"}), {"CommandLine": "x"})


class EngineConditions(unittest.TestCase):
    det: ClassVar[dict] = {"a": {"X": "1"}, "b": {"Y": "1"}, "f_1": {"Z": "1"}, "f_2": {"W": "1"}}

    def eval(self, cond, ev):
        return matches(rule({**self.det, "condition": cond}), ev)

    def test_precedence_and_binds_tighter(self):
        self.assertTrue(self.eval("a or b and f_1", {"X": "1"}))
        self.assertFalse(self.eval("(a or b) and f_1", {"X": "1"}))

    def test_not_and_quantifiers(self):
        self.assertTrue(self.eval("a and not 1 of f_*", {"X": "1"}))
        self.assertFalse(self.eval("a and not 1 of f_*", {"X": "1", "W": "1"}))
        self.assertTrue(self.eval("all of f_*", {"Z": "1", "W": "1"}))
        self.assertTrue(self.eval("1 of them", {"Y": "1"}))

    def test_errors(self):
        with self.assertRaises(SigmaError):
            self.eval("a and missing", {})
        with self.assertRaises(SigmaError):
            self.eval("(a or b", {})
        with self.assertRaises(SigmaError):
            matches(rule({"s": {"X|base64offset": "a"}, "condition": "s"}), {"X": "a"})


class Converter(unittest.TestCase):
    def test_kql_and_spl_render(self):
        r = rule({"sel": {"Image|endswith": "\\rundll32.exe"}, "f": {"User": "SYSTEM"},
                  "condition": "sel and not f"})
        kql = convert(r, "kql")
        spl = convert(r, "spl")
        self.assertIn('Image endswith @"\\rundll32.exe"', kql)
        self.assertIn("not(", kql)
        self.assertIn("NOT (", spl)
        self.assertIn("EventCode=1", spl)

    def test_spl_is_raw_search(self):
        r = rule({"sel": {"Image|endswith": "\\powershell.exe"}, "condition": "sel"})
        spl = convert(r, "spl")
        self.assertNotIn("```", spl)
        self.assertTrue(spl.startswith("index="))

    def test_regex_flags_merge_into_one_group(self):
        """KQL (RE2) and SPL (PCRE) receive the rule's own flags, never a second (?i) group."""
        r = rule({"s": {"CommandLine|re|i": "(?i)-enc"}, "t": {"CommandLine|re": "ABC"}, "condition": "s or t"})
        for backend in ("kql", "spl"):
            q = convert(r, backend)
            self.assertIn("(?i)-enc", q)
            self.assertNotIn("(?i)(?i)", q)
            self.assertNotIn("(?i)ABC", q)

    def test_kql_reads_missing_columns_from_eventdata(self):
        r = {"title": "t", "id": "x", "logsource": {"product": "windows", "service": "system"},
             "detection": {"s": {"Provider_Name": "Service Control Manager", "EventID": 7045,
                                 "ImagePath|contains": "cmd"}, "condition": "s"}}
        kql = convert(r, "kql")
        self.assertIn('| extend ImagePath = coalesce(tostring(column_ifexists("ImagePath", "")), '
                      "extract(@'Name=\"ImagePath\">([^<]*)<', 1, EventData))", kql)
        self.assertNotIn("extend Source", kql)          # native columns are left alone
        self.assertNotIn("extend EventID", kql)
        self.assertNotIn("extend", convert(rule({"s": {"Image|endswith": "x"}, "condition": "s"}), "kql"))

    def test_generated_spl_files_are_raw(self):
        out = Path(__file__).resolve().parent.parent / "queries" / "spl"
        for f in out.glob("*.spl"):
            self.assertTrue(f.read_text(encoding="utf-8").startswith("index="), f.name)


if __name__ == "__main__":
    unittest.main()
