"""The Sigma subset RASD supports is proven, the rest is refused, and the page says so (python -m unittest)."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import sigma_support  # noqa: E402
from convert import convert  # noqa: E402
from sigma_engine import SigmaError, compile_rule, conditions, matches  # noqa: E402


class SigmaSupport(unittest.TestCase):
    def test_every_supported_construct_is_identical_in_engine_spl_and_kql(self):
        self.assertEqual(sigma_support.prove_supported(), [])

    def test_every_unsupported_construct_is_refused_everywhere(self):
        self.assertEqual(sigma_support.prove_refused(), [])

    def test_the_page_is_current(self):
        self.assertEqual(sigma_support.OUT.read_text(encoding="utf-8"), sigma_support.render(),
                         "docs/SIGMA_SUPPORT.md is stale - run: rasd build")

    def test_refusals_explain_what_to_write_instead(self):
        rule = sigma_support.rule({"sel": {"CommandLine|contains": "x"}, "condition": "sel | count() by User > 5"})
        with self.assertRaisesRegex(SigmaError, "correlation rule"):
            matches(rule, {})
        rule = sigma_support.rule({"sel": {"CommandLine|contains": "x"}, "timeframe": "5m", "condition": "sel"})
        with self.assertRaisesRegex(SigmaError, "correlation rule"):
            compile_rule(rule)
        rule = sigma_support.rule({"sel": {"CommandLine|windash|contains": "-enc"}, "condition": "sel"})
        for backend in ("spl", "kql"):
            with self.assertRaisesRegex(SigmaError, "windash"):
                convert(rule, backend)

    def test_values_sigma_reads_differently_are_refused_everywhere(self):
        for value, key, reason in (("\\\\server\\share", "ImagePath|contains", "single backslashes"),
                                   ("C:\\Users\\*", "Image", "single backslashes"),
                                   ("who*mi", "CommandLine|startswith", "wildcard inside")):
            r = sigma_support.rule({"sel": {key: value}, "condition": "sel"})
            for fn in (lambda r=r: matches(r, {}), lambda r=r: compile_rule(r), lambda r=r: convert(r, "spl"),
                       lambda r=r: convert(r, "kql")):
                with self.subTest(value=value), self.assertRaisesRegex(SigmaError, reason):
                    fn()
        r = sigma_support.rule({"sel": {"ImagePath|contains": "\\127.0.0.1\\"}, "condition": "sel"})
        self.assertTrue(matches(r, {"ImagePath": "\\\\127.0.0.1\\C$\\x.exe"}), "a single backslash finds a UNC path")

    def test_keywords_with_wildcards_or_escapes_are_refused(self):
        for word in ("who*mi", "cm?", "a\\\\b"):
            r = sigma_support.rule({"keywords": [word], "condition": "keywords"})
            with self.subTest(word=word):
                with self.assertRaisesRegex(SigmaError, "Keyword"):
                    matches(r, {"CommandLine": "x"})
                with self.assertRaisesRegex(SigmaError, "Keyword"):
                    compile_rule(r)
        self.assertTrue(matches(sigma_support.rule({"keywords": ["C:\\Windows"], "condition": "keywords"}),
                                {"Image": "c:\\windows\\x.exe"}))

    def test_condition_lists_are_or(self):
        det = {"a": {"X": "1"}, "b": {"Y": "1"}, "condition": ["a", "b"]}
        self.assertEqual(conditions(det), ["a", "b"])
        rule = sigma_support.rule(det)
        self.assertTrue(matches(rule, {"Y": "1"}))
        self.assertFalse(matches(rule, {"Z": "1"}))

    def test_probes_separate_every_construct(self):
        for name, _meaning, det in sigma_support.SUPPORTED:
            fired = sum(matches(sigma_support.rule(det), ev) for ev in sigma_support.PROBES)
            self.assertTrue(0 < fired < len(sigma_support.PROBES), name)


if __name__ == "__main__":
    unittest.main()
