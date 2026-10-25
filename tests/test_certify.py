"""certify's automata accept exactly what the engine accepts, and its proofs hold (python -m unittest)."""
import itertools
import random
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import automata as fa  # noqa: E402
import certify  # noqa: E402
from benchmark import generate  # noqa: E402
from common import load_detections, load_jsonl  # noqa: E402
from correlation import load_correlations  # noqa: E402
from fuzz import variants  # noqa: E402
from mutation_test import generic_mutations, technique_mutations  # noqa: E402
from sigma_engine import _match_single, matches  # noqa: E402


def dfa(pattern, flags=0, search=True, lowered=False):
    return fa.compile_regex(pattern, flags, search, lowered).dfa()


def engine(pattern, flags, search):
    rx = re.compile(pattern, flags)
    return (lambda s: rx.search(s) is not None) if search else (lambda s: rx.fullmatch(s) is not None)


class Alphabet(unittest.TestCase):
    def test_the_universe_is_every_code_point(self):
        text = fa.universe_text()
        self.assertEqual(len(text), 0x110000)
        self.assertEqual([ord(text[i]) for i in (0, 0xD800, 0x10FFFF)], [0, 0xD800, 0x10FFFF])

    def test_word_boundary_uses_the_engines_word_characters(self):
        # every code point between two NULs (never word characters): \b fires before it exactly when it is \w
        text = "\0" + "\0".join(fa.universe_text()) + "\0"
        before = {m.start() // 2 for m in re.finditer(r"\b", text) if m.start() % 2 == 1}
        word = fa.word_chars()
        self.assertEqual(before, {cp for cp in range(0x110000) if cp in word})

    def test_lowercase_depends_on_context_only_for_capital_sigma(self):
        # str.lower() is a fixed map per character except Final_Sigma; certify models it as a
        # homomorphism and refuses a lowered value that tells small sigma from final sigma apart. Each code point is
        # lowered next to cased letters on either side, NUL-separated so contexts never touch.
        chars = [chr(cp) for cp in range(0x110000) if cp != 0x3A3]
        for left, right in (("A", ""), ("", "A"), ("A", "A")):
            text = "".join(left + ch + right + "\0" for ch in chars)
            expected = "".join(left.lower() + ch.lower() + right.lower() + "\0" for ch in chars)
            self.assertTrue(text.lower() == expected, f"context {left!r}...{right!r}")
        self.assertEqual(("A" + "\u03a3").lower(), "a\u03c2")
        self.assertEqual(("\u03a3" + "A").lower(), "\u03c3a")

    def test_classes_split_exactly_where_some_set_splits(self):
        sets = [fa.scan("[a-z]", re.I), fa.scan(r"\d"), fa.CharSet.points([0x130])]
        ab = fa.Alphabet(sets)
        rng = random.Random(3)
        for k in range(ab.size):
            members = [ab.member(k, rng) for _ in range(50)] + [ab.rep[k]]
            sig = {tuple(cp in s for s in sets) for cp in members}
            self.assertEqual(len(sig), 1)
        self.assertEqual(sum(ab.weight), 0x110000)

    def test_charset_algebra(self):
        a, b = fa.CharSet((0, 10, 20, 30)), fa.CharSet((5, 25))
        self.assertEqual((a | b).bounds, (0, 30))
        self.assertEqual((a & b).bounds, (5, 10, 20, 25))
        self.assertEqual((a - b).bounds, (0, 5, 25, 30))
        self.assertEqual(len(a), 20)


class Patterns(unittest.TestCase):
    def exhaustive(self, pattern, flags=0, search=True, alphabet="a \nZ_é", n=5):
        d, ref = dfa(pattern, flags, search), engine(pattern, flags, search)
        for size in range(n + 1):
            for chars in itertools.product(alphabet, repeat=size):
                s = "".join(chars)
                self.assertEqual(d.run(s), ref(s), f"{pattern!r} flags={flags} search={search} on {s!r}")

    def test_anchors_and_boundaries_follow_the_engine(self):
        for p in (r"^a", r"a$", r"\Aa", r"a\Z", r"\ba", r"a\b", r"\b", r"^$", r"$\n", r"a$\n?", r"(^|\s)a(\s|$)",
                  r"\b\w+\b", r"a\b\s", r"^\s*$"):
            for flags in (0, re.M, re.I | re.M):
                for search in (True, False):
                    self.exhaustive(p, flags, search)

    def test_dot_classes_and_repeats_follow_the_engine(self):
        for p in (r".", r"a.b", r"[^a]", r"[\s\S]", r"\W", r"\D+", r"a{2,3}", r"(?:a|\s){2,}", r"a*?Z", r"(a|Z)?_",
                  r"(?i)z", r"[a-zé]+", r"(?s:.)", r"(?i:A)a"):
            for flags in (0, re.S, re.I):
                self.exhaustive(p, flags, True, n=4)

    def test_case_folding_quirks_are_measured(self):
        self.assertTrue(dfa("(?i)k").run("K"))                  # Kelvin sign under IGNORECASE
        self.assertTrue(dfa("(?i)i").run("İ") and dfa("(?i)i").run("ı"))
        self.assertTrue(dfa("(?i)s").run("ſ"))                  # long s
        lowered = dfa(re.escape("i̇"), 0, True, True)            # 'İ'.lower() is two characters
        self.assertTrue(lowered.run("xİx"))
        self.assertEqual(lowered.run("İ"), "i̇" in "İ".lower())
        self.assertTrue(dfa("k", 0, True, True).run("K"))        # str.lower(KELVIN SIGN) == 'k'
        self.assertFalse(dfa("s", 0, True, True).run("ſ"))       # but long s stays itself

    def test_unsupported_constructs_are_refused(self):
        for p in (r"(a)\1", r"(?=a)", r"(?!a)", r"(?<=a)b", r"(?<!a)b", r"\B", r"(?a)\w", r"(a*)*", r"(?:a?)+",
                  r"a{1001}", r"(?(1)a|b)"):
            with self.assertRaises(fa.AutomataError, msg=p):
                dfa(p)
        if sys.version_info >= (3, 11):
            for p in (r"(?>a)", r"a++"):
                with self.assertRaises(fa.AutomataError, msg=p):
                    dfa(p)
        with self.assertRaises(fa.AutomataError):
            dfa("\u03c3", 0, True, True)                         # small sigma versus final sigma: Final_Sigma

    def test_minimal_automata_are_canonical(self):
        for a, b in ((r"a|b", r"[ab]"), (r"(ab)*", r"(?:ab)*"), (r"x{2,3}", r"xxx?"), (r"\d", r"[\d]"),
                     (r"(?i)abc", r"[aA][bB][cC]")):
            da, db = dfa(a, 0, False), dfa(b, 0, False)
            ab = fa.joint([da.alphabet, db.alphabet])
            self.assertIsNone(fa.equivalent(da.lift(ab), db.lift(ab)), f"{a} vs {b}")
        da, db = dfa(r"(?i)abc", 0, False), dfa(r"abc", 0, False)
        ab = fa.joint([da.alphabet, db.alphabet])
        word = fa.equivalent(da.lift(ab), db.lift(ab))
        text = ab.text(word)
        self.assertNotEqual(re.fullmatch(r"(?i)abc", text) is None, re.fullmatch("abc", text) is None)

    def test_boolean_algebra_holds(self):
        pats = [r"a", r"b$", r"^ab", r"\ba\b", r"a.b"]
        dfas = [dfa(p) for p in pats]
        ab = fa.joint([d.alphabet for d in dfas])
        dfas = [d.lift(ab) for d in dfas]
        for x, y in itertools.combinations(dfas, 2):
            left = fa.product([x, y], any).complement()
            right = fa.product([x.complement(), y.complement()], all)
            self.assertIsNone(fa.equivalent(left, right))
            self.assertEqual(left.minimize().states, left.states)       # products come back minimal

    def test_counting_and_sampling_agree_with_enumeration(self):
        d = dfa(r"(a|b)+\s", 0, False)
        ab = d.alphabet
        ones = [1] * ab.size
        for n in range(6):
            brute = sum(d.accepts(w) for w in itertools.product(range(ab.size), repeat=n))
            self.assertEqual(d.count(n, ones), brute)
        rng = random.Random(5)
        for n in range(1, 8):
            w = d.sample(n, rng)
            if w is not None:
                self.assertTrue(d.accepts(w))
        self.assertEqual(dfa(r"ab", 0, False).count(2), 1)
        self.assertEqual(dfa(r"[^a]", 0, False).count(1), 0x110000 - 1)

    def test_nearest_is_an_optimal_correction(self):
        d = dfa(r"ab{2}c", 0, False)
        alphabet = "abcx"

        def dist(s, t):
            row = list(range(len(t) + 1))
            for i, cs in enumerate(s, 1):
                prev, row[0] = row[0], i
                for j, ct in enumerate(t, 1):
                    prev, row[j] = row[j], min(row[j] + 1, row[j - 1] + 1, prev + (cs != ct))
            return row[-1]
        for size in range(4):
            for chars in itertools.product(alphabet, repeat=size):
                s = "".join(chars)
                cost, fixed = fa.nearest([(d, True)], s)
                self.assertTrue(d.run(fixed))
                self.assertEqual(cost, dist(s, "abbc"))

    def test_the_conformance_suite_catches_a_wrong_automaton(self):
        d = dfa(r"(?i)\s-e(nc)?\s+[a-z0-9+/]{4,}", 0, True)
        suite = fa.conformance_suite(d)
        for s in range(min(d.states, 12)):
            for k in range(d.alphabet.size):
                broken = fa.DFA(d.alphabet, [list(r) for r in d.delta], list(d.accept))
                broken.delta[s][k] = (broken.delta[s][k] + 1) % d.states
                if fa.equivalent(broken, d) is None:
                    continue
                self.assertTrue(any(broken.accepts(w) != verdict for w, verdict in suite), (s, k))


class Certify(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = certify.run()
        cls.models = {ident: certify.RuleModel(rule, ident) for ident, _kind, rule, _folder in certify.rules()}

    def test_every_rule_compiles_and_both_witnesses_replay(self):
        self.assertEqual(certify.problems(self.report), [])
        self.assertEqual(len(self.report), len(load_detections()) + len(load_correlations()))

    def test_every_value_test_agrees_with_the_engine_on_its_complete_suite(self):
        seen = {}
        for model in self.models.values():
            for atom in model.atoms:
                for t in atom.tests:
                    if t.regex is not None:
                        seen.setdefault((t.regex.pattern, t.regex.flags, t.regex.search, t.regex.lowered), t)
        rng = random.Random(11)
        wrong, words = [], 0
        for t in seen.values():
            d = t.regex.dfa()
            rep = [chr(c) for c in d.alphabet.rep]
            for word, verdict in fa.conformance_suite(d):
                s = "".join([rep[k] for k in word])
                words += 1
                if _match_single(s, t.expected, t.mods) != verdict:
                    wrong.append((t.text, s))
            for n in (0, 1, 3, 8, 20, 40):                  # random members of each class, accepted and rejected
                for side in (d, d.complement()):
                    w = side.sample(n, rng)
                    if w is not None:
                        s = "".join(chr(d.alphabet.member(k, rng)) for k in w)
                        words += 1
                        if _match_single(s, t.expected, t.mods) != (side is d):
                            wrong.append((t.text, s))
        self.assertEqual(wrong[:5], [])
        self.assertGreater(words, 1_000_000)

    def corpus(self):
        replay = load_jsonl(ROOT / "samples" / "replay" / "lab-day.jsonl")
        dets = load_detections()
        synthetic = generate(3000, dets)
        for d in dets:
            tps = d.tests("true_positive")
            events = tps + d.tests("true_negative")
            events += [ev for _n, ev, _x in generic_mutations(tps)] + [ev for _n, ev, _x in technique_mutations(d.folder, tps)]
            events += [new for tp in tps for _n, _c, new in variants(tp)]
            yield d.id, d.rule, events + replay + synthetic
        for c in load_correlations():
            events = c.tests("true_positive") + c.tests("true_negative")
            events += [ev for sc in c.scenarios() for ev in sc["events"]]
            yield c.id, c.base, events + replay + synthetic

    def test_rule_models_agree_with_the_engine_on_every_known_event(self):
        checked = 0
        for ident, rule, events in self.corpus():
            model = self.models[ident]
            for ev in events:
                self.assertEqual(model.verdict(ev), matches(rule, ev), f"{ident} on {ev}")
                checked += 1
        self.assertGreater(checked, 50_000)

    def test_refusals_say_why(self):
        def model(detection):
            return certify.RuleModel({"detection": detection}, "x")
        with self.assertRaisesRegex(certify.CertifyError, "keyword"):
            model({"k": ["mimikatz"], "condition": "k"})
        with self.assertRaisesRegex(certify.CertifyError, "backreference"):
            model({"s": {"CommandLine|re": r"(a)\1"}, "condition": "s"})
        with self.assertRaisesRegex(certify.CertifyError, "windash"):
            model({"s": {"CommandLine|windash": "-e"}, "condition": "s"})
        with self.assertRaisesRegex(certify.CertifyError, "unknown selection"):
            model({"s": {"Image": "x"}, "condition": "t"})

    def test_a_dead_rule_and_a_rule_that_matches_everything_are_proven(self):
        dead = certify.RuleModel({"detection": {"a": {"Image": "x"}, "b": {"Image": "y"}, "condition": "a and b"}}, "dead")
        self.assertIsNone(dead.witness(True))
        always = certify.RuleModel({"detection": {"a": {"Image": "x"}, "condition": "a or not a"}}, "always")
        self.assertIsNone(always.witness(False))

    def test_the_pages_are_current(self):
        self.assertEqual(certify.DOC.read_text(encoding="utf-8"), certify.render_doc(self.report),
                         "docs/CERTIFY.md is stale - run: rasd certify --write")
        self.assertEqual(certify.CERTIFICATES.read_text(encoding="utf-8"), certify.render_certificates(self.report),
                         "docs/CERTIFICATES.md is stale - run: rasd certify --write")

    def test_every_behaviour_spec_is_decided_as_it_expects(self):
        rows = [r for r in self.report if r.get("behaviour")]
        self.assertTrue(rows)
        for r in rows:
            for v in r["behaviour"]["variants"]:
                self.assertTrue(v["ok"], f"{r['id']}: {v['variant']}")
                if v.get("event"):                        # every event shown is a real counterexample
                    self.assertEqual(matches(self.models[r["id"]].rule, v["event"]), v["expect"] == "quiet")


class CommandLines(unittest.TestCase):
    """The C runtime's argument split: the transducer, the direct parser and Microsoft's examples agree."""

    def test_microsoft_examples(self):
        self.assertEqual(certify.crt_argv('p "a b c" d e')[1:], ["a b c", "d", "e"])
        self.assertEqual(certify.crt_argv('p a\\\\\\b d"e f"g h')[1:], ["a\\\\\\b", "de fg", "h"])
        for outside in ('p "ab\\"c" "\\\\" d', 'p a\\\\\\"b c d', 'p a"b"" c d', "p a\x00b"):
            self.assertIsNone(certify.crt_argv(outside), outside)    # escapes and "" inside quotes are not modelled
        self.assertEqual(certify.crt_argv('"C:\\Program Files\\x.exe"-e x'), ["C:\\Program Files\\x.exe-e", "x"])
        self.assertEqual(certify.crt_argv("  a"), ["", "a"])

    def test_the_transducer_is_the_parser(self):
        t = certify.crt_transducer()
        for size in range(7):
            for chars in itertools.product('a "\\\t\x00', repeat=size):
                line = "".join(chars)
                ref = certify.crt_argv(line)
                self.assertEqual(t.apply(line), None if ref is None else "\x00".join(ref), repr(line))

    def test_argv_automata_read_command_lines_like_the_parser(self):
        rng = random.Random(9)
        for pattern in (r"[^\x00]*\x00-e\x00[a]+", r"(?:[^\x00]*\x00)*[^\x00]*ab[^\x00]*(?:\x00[^\x00]*)*", r"x"):
            d = certify.argv_dfa(pattern)
            for _ in range(4000):
                line = "".join(rng.choice('ab -e"\\\t\n') for _ in range(rng.randrange(13)))
                ref = certify.crt_argv(line)
                want = ref is not None and re.fullmatch(pattern, "\x00".join(ref)) is not None
                self.assertEqual(d.run(line), want, (pattern, line))


SPEC_RULE = {"detection": {"sel": {"Image|endswith": "\\tool.exe", "CommandLine|contains": "-secret"},
                           "filter": {"ParentImage": "C:\\on.exe"}, "condition": "sel and not filter"}}


class BehaviourSpecs(unittest.TestCase):
    def check(self, listed: str, sources="sources: [{id: s, title: t, url: 'https://example.org'}]"):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "behavior.yml"
            path.write_text(f"behaviour: test\n{sources}\nvariants:\n{listed}", encoding="utf-8")
            spec = certify.load_spec(path)
            return certify.check_spec(certify.RuleModel(SPEC_RULE, "t"), spec)

    def test_proven_bypass_and_quiet(self):
        rows = self.check("""
  - {name: caught, why: w, sources: [s], event: {Image: '.*\\\\tool\\.exe', CommandLine: '.*-secret.*', ParentImage: {not: '{i:C:\\on.exe}', missing: true}}}
  - {name: gap, expect: bypass, reason: r, why: w, sources: [s], event: {Image: '.*\\\\tool\\.exe', CommandLine: '.*-sec"ret.*'}}
  - {name: excluded, expect: quiet, reason: r, why: w, sources: [s], event: {ParentImage: 'C:\\\\on\\.exe'}}
""")
        self.assertEqual([(r["variant"], r["result"], r["ok"]) for r in rows],
                         [("caught", "proven", True), ("gap", "bypass", True), ("excluded", "proven", True)])

    def test_an_unlisted_gap_and_a_closed_gap_fail(self):
        rows = self.check("""
  - {name: open, why: w, sources: [s], event: {Image: '.*\\\\tool\\.exe', CommandLine: '.*-secret.*'}}
  - {name: closed, expect: bypass, reason: r, why: w, sources: [s], event: {Image: '.*\\\\tool\\.exe', CommandLine: '.*-secret.*', ParentImage: null}}
""")
        self.assertEqual([(r["result"], r["ok"]) for r in rows], [("bypass", False), ("proven", False)])
        self.assertEqual(rows[0]["event"].get("ParentImage", "").lower(), "c:\\on.exe")   # the filter is the way past
        self.assertEqual(len(certify.spec_problems("t", rows)), 2)

    def test_the_kelvin_sign_is_found(self):
        # str.lower() turns the Kelvin sign into k, so a filter on "...k..." also silences "...\u212a...":
        # a spec that excludes only the ASCII spellings is answered with that event
        rule = {"detection": {"sel": {"Image|endswith": "\\tool.exe"}, "filter": {"ParentImage": "C:\\ok.exe"},
                              "condition": "sel and not filter"}}
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "behavior.yml"
            path.write_text("behaviour: t\nsources: [{id: s, title: t, url: 'https://example.org'}]\nvariants:\n"
                            "  - {name: v, why: w, sources: [s], event: {Image: '.*\\\\tool\\.exe', "
                            "ParentImage: {not: '{i:C:\\ok.exe}'}}}\n", encoding="utf-8")
            row = certify.check_spec(certify.RuleModel(rule, "t"), certify.load_spec(path))[0]
        self.assertEqual(row["result"], "bypass")
        self.assertIn("\u212a", row["event"]["ParentImage"])

    def test_mistakes_in_a_spec_are_refused(self):
        good = "{name: v, why: w, sources: [s], event: {Image: 'x'}}"
        for listed, message in (
                (f"  - {good}\n  - {good}", "share a name"),
                ("  - {name: v, why: w, sources: [nope], event: {Image: 'x'}}", "source"),
                ("  - {name: v, why: w, sources: [s], expect: bypass, event: {Image: 'x'}}", "reason"),
                ("  - {name: v, why: w, sources: [s], event: {Image: '(a)\\1'}}", "backreference"),
                ("  - {name: v, why: w, sources: [s], event: {Image: 'x'}, examples: [{Image: y}]}", "not in the variant"),
                ("  - {name: v, why: w, sources: [s], event: {Image: {match: 'a', not: 'a'}}}", "describes no event"),
                ("  - {name: v, why: w, sources: [s], event: {Image: '{undefined}'}}", "not defined")):
            with self.assertRaisesRegex(certify.CertifyError, message, msg=listed):
                self.check(listed)

    def test_placeholders(self):
        self.assertEqual(certify.expand("{i:aB.}", {}, "w"), "[aA][bB]\\.")
        self.assertEqual(certify.expand(r"\\{x}\{y}", {"x": "X"}, "w"), r"\\(?:X)\{y}")


def _vrule(detection):
    return {"title": "t", "logsource": {"product": "windows"}, "detection": detection}


class RuleVersions(unittest.TestCase):
    """certify.RulePair decides whether two versions of a rule classify every event alike, and the
    event it returns when they differ is real: the engine gives the two versions opposite verdicts on it."""

    def assertEquivalent(self, old, new):
        self.assertIsNone(certify.RulePair(old, new).difference())
        self.assertIsNone(certify.RulePair(new, old).difference())      # symmetric

    def assertDiffers(self, old, new):
        d = certify.RulePair(old, new).difference()
        self.assertIsNotNone(d)
        self.assertNotEqual(matches(old, d["event"]), matches(new, d["event"]))
        self.assertEqual((matches(old, d["event"]), matches(new, d["event"])), (d["old_fires"], d["new_fires"]))
        return d

    def test_a_rule_equals_itself(self):
        for det in load_detections():
            self.assertIsNone(certify.RulePair(det.rule, det.rule).difference(), det.id)

    def test_meaning_preserving_refactors_are_proven_equivalent(self):
        # one contains-list is the OR of its values
        self.assertEquivalent(
            _vrule({"sel": {"CommandLine|contains": ["foo", "bar"]}, "condition": "sel"}),
            _vrule({"a": {"CommandLine|contains": "foo"}, "b": {"CommandLine|contains": "bar"},
                    "condition": "a or b"}))
        # De Morgan
        self.assertEquivalent(
            _vrule({"a": {"Image|endswith": "\\p.exe"}, "b": {"CommandLine|contains": "zz"},
                    "condition": "not (a and b)"}),
            _vrule({"a": {"Image|endswith": "\\p.exe"}, "b": {"CommandLine|contains": "zz"},
                    "condition": "(not a) or (not b)"}))
        # a redundant branch that is subsumed by another changes nothing
        self.assertEquivalent(
            _vrule({"sel": {"CommandLine|contains": "powershell"}, "condition": "sel"}),
            _vrule({"a": {"CommandLine|contains": "powershell"}, "b": {"CommandLine|contains": "powershell.exe"},
                    "condition": "a or b"}))

    def test_a_meaning_change_produces_an_engine_verified_event(self):
        base = _vrule({"sel": {"CommandLine|contains": ["foo"]}, "condition": "sel"})
        self.assertEqual(self.assertDiffers(base,                                   # a value added to a list
            _vrule({"sel": {"CommandLine|contains": ["foo", "bar"]}, "condition": "sel"}))["new_fires"], True)
        self.assertDiffers(                                                         # a field condition dropped
            _vrule({"sel": {"Image|endswith": "\\s.exe", "CommandLine|contains": "k"}, "condition": "sel"}),
            _vrule({"sel": {"Image|endswith": "\\s.exe"}, "condition": "sel"}))
        self.assertDiffers(                                                         # an exclusion added
            _vrule({"sel": {"Image|endswith": "\\s.exe"}, "condition": "sel"}),
            _vrule({"sel": {"Image|endswith": "\\s.exe"}, "f": {"CommandLine|contains": "safe"},
                    "condition": "sel and not f"}))
        self.assertDiffers(                                                         # endswith widened to contains
            _vrule({"sel": {"Image|endswith": "cmd.exe"}, "condition": "sel"}),
            _vrule({"sel": {"Image|contains": "cmd.exe"}, "condition": "sel"}))

    def test_equiv_run_sees_the_working_tree_as_unchanged(self):
        # every current rule equals its own committed version; nothing is a meaning change or uncomparable
        if certify._git(["rev-parse", "--verify", "--quiet", "HEAD^{commit}"])[0] != 0:
            self.skipTest("not a git checkout")
        report = certify.equiv_run("HEAD")
        self.assertTrue(report)
        bad = [r for r in report if r["status"] in ("changed", "unmodelled")]
        self.assertEqual(bad, [], bad)
        self.assertTrue(all(r["status"] in ("identical", "added", "equivalent") for r in report))


if __name__ == "__main__":
    unittest.main()
