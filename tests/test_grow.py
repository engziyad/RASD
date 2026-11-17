"""Tests for RASD-Agent's lane (tools/grow.py): the ATT&CK reference, the queue, every gate, the computed proof,
the unattended run and the lane the repository ships."""
import copy
import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import agent_model  # noqa: E402
import common  # noqa: E402
import grow  # noqa: E402
from agent_model import Model, ModelError  # noqa: E402
from prove import killed_by, mutants  # noqa: E402
from replay import route  # noqa: E402
from sigma_engine import matches  # noqa: E402
from validate import FIELDS  # noqa: E402

TODAY = "2026-11-17"
RETIRED_ID = "T15" + "62.008"      # an identifier ATT&CK retired, built from parts: no tracked file may name one
S32 = "C:\\Windows\\System32\\"
_DOC, TECHS = grow.load_universe()
CORE = grow.core_owners()
NLTEST = TECHS["T1482"]


def proc(case, cmd, image=S32 + "nltest.exe", ofn="nltestrk.exe", **extra):
    ev = {"_case": case, "EventID": 1, "Image": image}
    if ofn:
        ev["OriginalFileName"] = ofn
    return {**ev, "CommandLine": cmd, "ParentImage": S32 + "cmd.exe", "User": "LAB\\lab.user01", **extra}


def draft(**changes):
    """A draft every gate accepts, for T1482: the example the model is shown; `changes` replace its keys."""
    return {**copy.deepcopy(grow.EXAMPLE), **changes}


def refusal(case: unittest.TestCase, the_draft: dict, others=None, tech=NLTEST) -> str:
    with case.assertRaises(grow.Refused) as caught:
        grow.build(tech, the_draft, CORE if others is None else others, TODAY)
    return str(caught.exception)


def survivors(rule: dict, tps: list, tns: list) -> list[str]:
    tests = grow.suite(tps, tns)
    return [desc for _mid, _kind, desc, mrule, _meta in mutants(rule) if killed_by(mrule, tests) is None]


class Script:
    """A drafter that answers from a script: per technique, the drafts to give in order (an exception is raised)."""

    def __init__(self, answers: dict):
        self.answers = {k: list(v) for k, v in answers.items()}
        self.calls: list[tuple[str, str | None]] = []

    def draft(self, tech, feedback):
        self.calls.append((tech.id, feedback))
        queue = self.answers.get(tech.id) or []
        if not queue:
            return None
        answer = queue.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    def describe(self) -> str:
        return "a script"


class LaneCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.lane = grow.Lane(self.tmp / "candidates", self.tmp / "growth.yml", grow.UNIVERSE)

    def run_lane(self, answers: dict, limit=5, tries=20, only=("T1482",)):
        script = Script(answers)
        report = grow.run(self.lane, script, limit, tries, list(only), TODAY, say=lambda _line: None)
        return report, script


def bundle(version: str, patterns: list[dict], uses: list[tuple[str, str]] = ()) -> dict:
    """A small STIX bundle shaped like ATT&CK's."""
    tactics = [("reconnaissance", "TA0043"), ("discovery", "TA0007"), ("impact", "TA0040")]
    objects: list[dict] = [{"type": "x-mitre-collection", "id": "x-mitre-collection--1", "x_mitre_version": version, "modified": "2026-11-05T15:11:27.678Z"},
                           {"type": "marking-definition", "id": "marking-definition--1", "definition": {"statement": "Copyright The MITRE Corporation."}},
                           {"type": "x-mitre-matrix", "id": "x-mitre-matrix--1", "tactic_refs": [f"x-mitre-tactic--{n}" for n, _ in tactics]}]
    objects += [{"type": "x-mitre-tactic", "id": f"x-mitre-tactic--{n}", "x_mitre_shortname": n,
                 "external_references": [{"source_name": "mitre-attack", "external_id": tid}]} for n, tid in tactics]
    for p in patterns:
        objects.append({"type": "attack-pattern", "id": f"attack-pattern--{p['id']}", "name": p["name"], "created": "2020-03-15T00:00:00.000Z",
                        "revoked": p.get("revoked", False), "x_mitre_deprecated": p.get("deprecated", False),
                        "x_mitre_platforms": p.get("platforms", ["Windows"]), "description": p.get("description", ""),
                        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": t} for t in p.get("tactics", ["discovery"])],
                        "external_references": [{"source_name": "mitre-attack", "external_id": p["id"]}]})
    for group, tid in uses:
        objects.append({"type": "intrusion-set", "id": f"intrusion-set--{group}", "name": group})
        objects.append({"type": "relationship", "id": f"relationship--{group}-{tid}", "relationship_type": "uses",
                        "source_ref": f"intrusion-set--{group}", "target_ref": f"attack-pattern--{tid}"})
    return {"type": "bundle", "id": "bundle--1", "objects": objects}


class Reference(unittest.TestCase):
    """The ATT&CK reference the queue is built from."""

    def test_the_core_reference_and_the_lane_reference_agree(self):
        for tid, (name, tactics) in common.TECHNIQUES.items():
            self.assertIn(tid, TECHS, tid)
            self.assertEqual(TECHS[tid].name, name, tid)
            self.assertEqual(TECHS[tid].tactics, tactics, tid)

    def test_the_reference_is_whole(self):
        self.assertEqual(_DOC["tactics"], list(common.ATTACK_TACTICS))
        self.assertRegex(_DOC["attack_version"], r"^\d+\.\d+$")
        self.assertRegex(_DOC["bundle"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertIn("MITRE", _DOC["notice"])
        self.assertTrue((grow.UNIVERSE.parent / "ATTACK_LICENSE.txt").read_text(encoding="utf-8").startswith("License"))
        for tid, t in TECHS.items():
            self.assertRegex(tid, r"^T\d{4}(\.\d{3})?$")
            self.assertTrue(t.tactics and set(t.tactics) <= set(_DOC["tactics"]), tid)
            self.assertTrue(t.platforms, tid)
            self.assertEqual(t.parent, any(other.startswith(tid + ".") for other in TECHS), tid)
        self.assertGreater(len(TECHS), 600)

    def test_the_file_is_what_the_reference_writes(self):
        text = grow.UNIVERSE.read_text(encoding="utf-8")
        self.assertEqual(text, grow.universe_text(json.loads(text)))
        self.assertNotIn("\r", text)
        self.assertEqual(sum(1 for line in text.splitlines() if line.startswith('    "T')), len(TECHS))

    def test_a_bundle_is_read_as_attack_writes_it(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        doc = bundle("21.0", [{"id": "T9001", "name": "Parent Thing", "tactics": ["impact", "discovery"]},
                              {"id": "T9001.001", "name": "Child Thing", "platforms": ["Linux", "Windows"], "description": "It does (Citation: X) a <code>thing</code>."},
                              {"id": "T9002", "name": "Gone", "revoked": True}, {"id": "T9003", "name": "Old", "deprecated": True}],
                     uses=[("g1", "T9001.001"), ("g2", "T9001.001"), ("g1", "T9001")])
        path = tmp / "enterprise-attack-21.0.json"
        path.write_text(json.dumps(doc), encoding="utf-8")
        ref = grow.read_bundle(path)
        self.assertEqual(ref["attack_version"], "21.0")
        self.assertEqual(sorted(ref["techniques"]), ["T9001", "T9001.001"])
        self.assertEqual(ref["techniques"]["T9001"]["tactics"], ["discovery", "impact"])
        self.assertEqual(ref["techniques"]["T9001.001"], {"name": "Parent Thing: Child Thing", "tactics": ["discovery"],
                                                         "platforms": ["Linux", "Windows"], "groups": 2, "created": "2020-03-15"})
        self.assertEqual(ref["bundle"]["name"], path.name)
        self.assertEqual(grow.descriptions(path)["T9001.001"], "It does a thing.")
        with self.assertRaises(SystemExit):
            grow.read_bundle(Path(__file__))
        for version, patterns in (("21", [{"id": "T9001", "name": "One"}]), ("21.0", []),
                                  ("21.0", [{"id": "T9001", "name": "One [see](../x.md)"}]), ("21.0", [{"id": "T9001", "name": "A | B"}]),
                                  ("21.0", [{"id": "T9001", "name": "One", "tactics": ["not-a-tactic"]}])):
            path.write_text(json.dumps(bundle(version, patterns)), encoding="utf-8")
            with self.assertRaises(SystemExit, msg=(version, patterns)):
                grow.read_bundle(path)
        self.assertTrue(all(grow.PLAIN_NAME.match(t.name) for t in TECHS.values()))

    def test_sync_says_what_a_release_changed(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        lane = grow.Lane(tmp / "candidates", tmp / "growth.yml", tmp / "attack.json")
        old, new = tmp / "old.json", tmp / "new.json"
        old.write_text(json.dumps(bundle("21.0", [{"id": "T9001", "name": "One"}, {"id": "T9002", "name": "Two"}, {"id": "T9003", "name": "Three"}])), encoding="utf-8")
        new.write_text(json.dumps(bundle("22.0", [{"id": "T9001", "name": "One"}, {"id": "T9002", "name": "Two Renamed"},
                                                    {"id": "T9003", "name": "Three", "tactics": ["impact"]}, {"id": "T9004", "name": "Four"}])), encoding="utf-8")
        first = grow.sync(old, lane, {})
        self.assertEqual((first["from"], first["to"], len(first["added"]), first["held"]), (None, "21.0", 3, []))
        second = grow.sync(new, lane, {"T9001": ("One", ("discovery",))})
        self.assertEqual((second["from"], second["to"]), ("21.0", "22.0"))
        self.assertEqual((second["added"], second["removed"], second["renamed"], second["moved"]), (["T9004"], [], ["T9002"], ["T9003"]))
        self.assertEqual(sorted(grow.load_universe(lane.universe)[1]), ["T9001", "T9002", "T9003", "T9004"])
        self.assertEqual(json.loads(lane.universe.read_text(encoding="utf-8"))["bundle"]["name"], "enterprise-attack-22.0.json")

    def test_a_release_that_disagrees_with_the_core_is_held(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        lane = grow.Lane(tmp / "candidates", tmp / "growth.yml", tmp / "attack.json")
        old, new = tmp / "old.json", tmp / "new.json"
        old.write_text(json.dumps(bundle("21.0", [{"id": "T9001", "name": "One"}, {"id": "T9002", "name": "Two"}, {"id": "T9003", "name": "Three"}])), encoding="utf-8")
        new.write_text(json.dumps(bundle("22.0", [{"id": "T9001", "name": "One Renamed"}, {"id": "T9002", "name": "Two", "tactics": ["impact"]},
                                                    {"id": "T9004", "name": "Four"}])), encoding="utf-8")
        core = {"T9001": ("One", ("discovery",)), "T9002": ("Two", ("discovery",)), "T9003": ("Three", ("discovery",))}
        grow.sync(old, lane, core)
        before = lane.universe.read_bytes()
        held = grow.sync(new, lane, core)
        self.assertEqual(held["held"], ["T9001", "T9002", "T9003"])
        self.assertEqual(lane.universe.read_bytes(), before)
        self.assertEqual(grow.disagreements(_DOC["techniques"], common.TECHNIQUES), [])
        self.assertEqual(grow.sync(new, lane, {"T9004": ("Four", ("discovery",))})["held"], [])
        self.assertNotEqual(lane.universe.read_bytes(), before)


class Queue(unittest.TestCase):
    """What is drafted next, and what is not drafted at all."""

    def tech(self, tid, groups=0, platforms=("Windows",), parent=False):
        return grow.Technique(tid, f"Name {tid}", ("discovery",), tuple(platforms), groups, "2020-01-01", parent)

    def test_where_a_technique_stands(self):
        t = self.tech("T9000")
        refused = lambda n, rasd=grow.VERSION: {"T9000": {"status": "refused", "reason": "a gate said no", "attempts": n, "rasd": rasd}}
        cases = [({"T9000": ["T9000_core"]}, {}, {}, "core"), ({}, {"T9000": "T9000_x"}, {}, "candidate"), ({}, {}, {}, "queued"),
                 ({}, {}, {"T9000": {"status": "declined", "reason": "no log source", "sources": grow.sources_hash()}}, "declined"),
                 ({}, {}, {"T9000": {"status": "declined", "reason": "no log source", "sources": "another"}}, "queued"),
                 ({}, {}, refused(1), "refused"), ({}, {}, refused(grow.MAX_ATTEMPTS), "parked"),
                 ({}, {}, refused(grow.MAX_ATTEMPTS, "0.9.0"), "queued"), ({}, {}, {"T9000": {"status": "accepted", "candidate": "gone"}}, "queued")]
        for core, taken, ledger, want in cases:
            self.assertEqual(grow.standing(t, core, taken, ledger), want, (core, taken, ledger))
        self.assertEqual(grow.standing(self.tech("T9000", parent=True), {}, {}, {}), "parent")
        self.assertEqual(grow.standing(self.tech("T9000", parent=True), {"T9000": ["x"]}, {}, {}), "core")
        self.assertEqual(grow.standing(self.tech("T9000", platforms=("SaaS", "macOS")), {}, {}, {}), "out_of_reach")
        self.assertEqual(grow.standing(self.tech("T9000", platforms=("Linux", "SaaS")), {}, {}, {}), "queued")

    def test_the_order_of_the_queue(self):
        techs = {t.id: t for t in (self.tech("T9001", 3), self.tech("T9002", 9), self.tech("T9003", 9), self.tech("T9004", 50),
                                   self.tech("T9005", 70), self.tech("T9006", 1, parent=True), self.tech("T9007", 99, ("PRE",)))}
        ledger = {"T9004": {"status": "refused", "reason": "a gate said no", "attempts": 2, "rasd": grow.VERSION},
                  "T9005": {"status": "refused", "reason": "a gate said no", "attempts": 1, "rasd": grow.VERSION}}
        order = [t.id for t in grow.queue(techs, {}, {}, ledger)]
        self.assertEqual(order, ["T9002", "T9003", "T9001", "T9005", "T9004"])

    def test_every_technique_stands_somewhere(self):
        st = grow.state(grow.Lane())
        self.assertEqual(sum(st["counts"].values()), st["techniques"])
        self.assertEqual(st["counts"]["core"], len(grow.core_techniques()))
        self.assertEqual(st["core_outside_reference"], [])
        self.assertEqual(len(st["queue"]), st["counts"]["queued"] + st["counts"]["refused"])
        for row in st["by_tactic"]:
            self.assertEqual(row["techniques"], row["core"] + row["candidate"] + row["queued"] + row["set_aside"] + row["out_of_reach"], row)
        queued = [q["id"] for q in st["queue"]]
        self.assertEqual(len(queued), len(set(queued)))
        self.assertFalse(set(queued) & set(grow.core_techniques()))
        self.assertTrue(all(TECHS[q].reachable and not TECHS[q].parent for q in queued))


class Form(unittest.TestCase):
    """The first gate: what a draft must be before anything is run."""

    def test_a_draft_becomes_a_complete_rule(self):
        folder, rule, tps, tns, notes = grow.assemble(NLTEST, draft(), TODAY)
        self.assertEqual(folder, "T1482_nltest_trust_listing")
        self.assertEqual(rule["id"], str(uuid.uuid5(grow.NAMESPACE, folder)))
        self.assertEqual((rule["status"], rule["author"], rule["date"]), ("experimental", grow.AUTHOR, TODAY))
        self.assertEqual(rule["tags"], ["attack.discovery", "attack.t1482"])
        self.assertEqual(rule["references"], ["https://attack.mitre.org/techniques/T1482/"])
        self.assertEqual(rule["logsource"], {"product": "windows", "category": "process_creation"})
        self.assertEqual(rule["falsepositives"], notes["false_positives"])
        self.assertEqual((len(tps), len(tns)), (4, 4))
        self.assertFalse(common.attack_tag_errors(["attack.credential-access", "attack.t1003.001"]))

    def test_what_the_form_refuses(self):
        bad_event = lambda **kv: [*draft()["true_positives"][:3], {**draft()["true_positives"][3], **kv}]
        cases = {
            "logsource must be": draft(logsource="windows/sysmon"),
            "name must be": draft(name="Nltest"),
            "name must be ": draft(name="one"),
            "level must be": draft(level="informational"),
            "title has": draft(title="Short"),
            "description has": draft(description="Too short."),
            "description holds": draft(description="See https://example.test/page for what this rule is meant to catch and why it matters here."),
            "false_positives #1 holds": draft(false_positives=["A table bar | inside the text of this item"]),
            "title holds": draft(title="Nltest Listing [the Trusts](../../README.md)"),
            "blind_spots #2 holds": draft(blind_spots=["Trust listing through LDAP starts no process", "A command written as <placeholder> in a script"]),
            "reads as a link or an image": draft(true_positives=bad_event(_case="see [the page](../../../README.md)")),
            "reads as a link or an image ": draft(true_negatives=[*draft()["true_negatives"][:3],
                                                               {**draft()["true_negatives"][3], "_case": 'an <IMG src="x.png"> in a label'}]),
            f"the draft names {RETIRED_ID}, an identifier ATT&CK retired for {common.attack_aliases()['revoked'][RETIRED_ID]}": draft(
                description=f"Nltest listing the trusts of the domain, often seen beside disabled cloud logs ({RETIRED_ID}) in the same session."),
            "blind_spots needs": draft(blind_spots=["Only one blind spot is given here"]),
            "first_checks repeats": draft(first_checks=["Check the account that ran it", "check the account that ran it"]),
            "true_positives needs": draft(true_positives=draft()["true_positives"][:3]),
            "repeats an earlier event": draft(true_positives=draft()["true_positives"][:3] + [dict(draft()["true_positives"][0], _case="again, the same")]),
            "'NewProcessName' is not a field": draft(true_positives=bad_event(NewProcessName="C:\\x.exe")),
            "must be text or a whole number": draft(true_positives=bad_event(User={"name": "x"})),
            "_case has": draft(true_positives=bad_event(_case="x")),
            "no timeframe": draft(detection={**draft()["detection"], "timeframe": "5m"}),
            "must be a map of fields": draft(detection={**draft()["detection"], "keywords": ["domain_trusts"]}),
            "detection must hold": draft(detection={"condition": "selection"}),
            "detection must hold ": draft(detection={**draft()["detection"], "condition": "selection_img and selection_arg | count() > 3"}),
            "must be letters, digits and underscores": draft(detection={**draft()["detection"], "selection arg": {"CommandLine|contains": "x"}}),
            "is not a field with its modifiers": draft(detection={**draft()["detection"], "selection_arg": {"CommandLine | contains": "domain_trusts"}}),
            "must be text, a whole number, or a list of them": draft(detection={**draft()["detection"], "selection_arg": {"CommandLine|contains": [["domain_trusts"]]}}),
            "must be text, a whole number, or a list of them ": draft(detection={**draft()["detection"], "selection_arg": {"CommandLine|contains": None}}),
            "is not one line of printable text": draft(detection={**draft()["detection"], "selection_arg": {"CommandLine|contains": "domain_trusts\n```\n# heading"}}),
            "is not one line of printable text ": draft(detection={**draft()["detection"], "selection_arg": {"CommandLine|contains": "x" * 401}}),
        }
        for expected, the_draft in cases.items():
            with self.assertRaises(grow.Refused, msg=expected) as caught:
                grow.assemble(NLTEST, the_draft, TODAY)
            self.assertIn(expected.strip(), str(caught.exception))
        with self.assertRaises(grow.Refused) as caught:
            grow.assemble(NLTEST, draft(), TODAY, ["T1482_nltest_trust_listing"])
        self.assertIn("already exists", str(caught.exception))

    def test_prose_is_kept_plain(self):
        _f, rule, _p, _n, _notes = grow.assemble(NLTEST, draft(description="Nltest started with `/domain_trusts`, which lists every domain "
                                                                         "the current one   trusts and where a foothold can reach."), TODAY)
        self.assertEqual(rule["description"], "Nltest started with '/domain_trusts', which lists every domain the current one trusts "
                                              "and where a foothold can reach.")
        self.assertFalse(grow.RETIRED.search(json.dumps(grow.EXAMPLE)))
        self.assertTrue(grow.RETIRED.search(f"see {RETIRED_ID} there"))

    def test_a_case_label_is_kept_as_text(self):
        events = draft()["true_positives"]
        events[0]["_case"] = "  download from `http://10.0.0.5/a`   with | a bar "
        _f, _r, tps, _t, _n = grow.assemble(NLTEST, draft(true_positives=events), TODAY)
        self.assertEqual(tps[0]["_case"], "download from 'http://10.0.0.5/a' with | a bar")


class Gates(unittest.TestCase):
    """Each gate refuses the draft that fails it alone, and says why in words the next draft can use."""

    def test_the_draft_passes_every_gate(self):
        self.assertEqual(NLTEST.id, grow.EXAMPLE_OF)
        built = grow.build(NLTEST, grow.EXAMPLE, CORE, TODAY)
        self.assertEqual((built["tps"], built["tns"]), (grow.EXAMPLE["true_positives"], grow.EXAMPLE["true_negatives"]))
        built = grow.build(NLTEST, draft(), CORE, TODAY)
        self.assertEqual(built["record"]["proof"]["true_positives"], 4)
        self.assertEqual(built["record"]["computed"], {"tests": 0, "parts_removed": 0})
        self.assertFalse(survivors(built["rule"], built["tps"], built["tns"]))

    def test_engine(self):
        tps = draft()["true_positives"]
        tps[0]["CommandLine"] = "nltest /dsgetdc:lab.test /force"
        self.assertIn("true positive 1 (domain trusts listed) is not matched", refusal(self, draft(true_positives=tps)))
        tns = draft()["true_negatives"]
        tns[1]["CommandLine"] = "nltest /trusted_domains /v"
        self.assertIn("true negative 2 (checking the secure channel) is matched", refusal(self, draft(true_negatives=tns)))
        self.assertIn("the engine refuses the rule", refusal(self, draft(detection={**draft()["detection"], "condition": "selection_img and missing"})))

    def test_vocabulary(self):
        detection = {**draft()["detection"], "selection_arg": {"Commandline|contains": ["domain_trusts", "trusted_domains"]}}
        self.assertIn("the rule reads Commandline", refusal(self, draft(detection=detection)))
        detection = {**draft()["detection"], "selection_arg": {"CommandLine|re": "domain_trusts|trusted_domains"}}
        self.assertIn("the linter", refusal(self, draft(detection=detection)))
        detection = {**draft()["detection"], "selection_arg": {"CommandLine|contains": ["domain_trusts", "trusted_domains", "/dt"]}}
        self.assertIn("very short substring", refusal(self, draft(detection=detection)))

    def test_routing(self):
        tps = draft()["true_positives"]
        tps[3] = {**tps[3], "Image": "/usr/bin/nltest"}
        self.assertIn("is not an event of Windows process creation", refusal(self, draft(true_positives=tps)))

    def test_evasion(self):
        one_phrase = {**draft()["detection"], "selection_arg": {"CommandLine|contains": ["nltest /domain_trusts", "nltest /trusted_domains"]}}
        tps = [proc("domain trusts listed", "nltest /domain_trusts"), proc("trusts listed verbosely", "nltest /domain_trusts /v"),
               proc("trusted domains listed", "nltest /trusted_domains"), proc("trusts listed, no version resource", "nltest /domain_trusts /all_trusts", ofn=None)]
        why = refusal(self, draft(detection=one_phrase, true_positives=tps))
        self.assertIn("the variation '", why)
        self.assertIn("is not matched", why)
        by_name_only = {**draft()["detection"], "selection_img": {"Image|endswith": "\\nltest.exe"}}
        self.assertIn("the variation 'binary_renamed' of true positive 1", refusal(self, draft(detection=by_name_only)))

    def test_noise_and_novelty(self):
        benign = grow.Owner("T9999_other_rule", {"logsource": {"product": "windows", "category": "process_creation"},
                                                 "detection": {"selection": {"Image|endswith": "\\never.exe"}, "condition": "selection"}},
                            [], [proc("a health check the repository calls benign", "nltest /domain_trusts /server:LAB-DC01")])
        self.assertIn("fires on an event the repository records as benign: true negative 1 of T9999_other_rule", refusal(self, draft(), [benign]))
        computed = copy.deepcopy(benign)
        computed.tns[0]["_case"] = "computed 1: holds selection: drop 'Image|endswith'"
        grow.build(NLTEST, draft(), [computed], TODAY)
        elsewhere = copy.deepcopy(benign)
        elsewhere.rule["logsource"] = {"product": "linux", "category": "process_creation"}
        grow.build(NLTEST, draft(), [elsewhere], TODAY)
        catches_all = grow.Owner("T9998_wide_rule", {"logsource": {"product": "windows", "category": "process_creation"},
                                                     "detection": {"selection": {"CommandLine|contains": "trust"}, "condition": "selection"}}, [], [])
        self.assertIn("every true positive is already caught by T9998_wide_rule", refusal(self, draft(), [catches_all]))

    def test_an_exclusion_needs_a_true_negative(self):
        detection = {**draft()["detection"], "filter_monitor": {"User": "LAB\\svc_monitor"}, "condition": "selection_img and selection_arg and not filter_monitor"}
        self.assertIn("no true negative needs the exclusion 'filter_monitor'", refusal(self, draft(detection=detection)))
        tns = [*draft()["true_negatives"], proc("the monitoring account's scheduled check", "nltest /domain_trusts", User="LAB\\svc_monitor")]
        built = grow.build(NLTEST, draft(detection=detection, true_negatives=tns), CORE, TODAY)
        self.assertIn("filter_monitor", built["rule"]["detection"])

    def test_parity(self):
        with mock.patch.object(grow, "compile_query", return_value=lambda _ev: True):
            self.assertIn("the generated KQL and the rule disagree on", refusal(self, draft()))

    def test_the_core_stays_quiet_on_the_lane(self):
        for cand in grow.load_candidates(grow.Lane()):
            for o in CORE:
                if o.key == cand.record["logsource"]:
                    for ev in o.tns:
                        self.assertFalse(matches(cand.rule, ev), f"{cand.id} fires on a true negative of {o.id}")


class Proof(unittest.TestCase):
    """The proof gate is computed: missing tests are added, redundant parts removed, nothing survives."""

    def test_a_missing_test_is_computed(self):
        tps = draft()["true_positives"]
        tps[2] = proc("domain trusts listed with a server", "nltest /domain_trusts /server:LAB-DC01")
        built = grow.build(NLTEST, draft(true_positives=tps), CORE, TODAY)
        self.assertGreaterEqual(built["record"]["computed"]["tests"], 1)
        added = [ev for ev in built["tps"] + built["tns"] if ev["_case"].startswith("computed ")]
        self.assertEqual(len(added), built["record"]["computed"]["tests"])
        self.assertTrue(any("trusted_domains" in str(ev["CommandLine"]).lower() for ev in built["tps"]))
        for ev in added:
            self.assertEqual(route(ev), "process_creation")
            self.assertTrue(set(ev) - {"_case"} <= set(FIELDS["process_creation"]))
        self.assertFalse(survivors(built["rule"], built["tps"], built["tns"]))
        self.assertEqual(built["record"]["proof"]["rule_mutants_killed"], sum(1 for _m in mutants(built["rule"])))

    def test_a_part_no_event_can_tell_apart_is_removed(self):
        detection = {**draft()["detection"], "selection_arg": {"CommandLine|contains|all": ["domain_trusts", "trusts"]}}
        tps = [proc("domain trusts listed", "nltest /domain_trusts"), proc("every trust listed", "nltest.exe /domain_trusts /all_trusts"),
               proc("trusts listed verbosely", "nltest /domain_trusts /v"), proc("domain trusts listed, no version resource", "nltest /DOMAIN_TRUSTS", ofn=None)]
        built = grow.build(NLTEST, draft(detection=detection, true_positives=tps), CORE, TODAY)
        self.assertEqual(built["record"]["computed"]["parts_removed"], 1)
        self.assertEqual(built["rule"]["detection"]["selection_arg"], {"CommandLine|contains|all": ["domain_trusts"]})
        self.assertFalse(survivors(built["rule"], built["tps"], built["tns"]))

    def test_an_unused_exclusion_does_not_survive(self):
        detection = {**draft()["detection"], "filter_never": {"CommandLine|contains": "dsgetdc"}, "condition": "selection_img and selection_arg and not filter_never"}
        tns = [*draft()["true_negatives"], proc("both switches in one run", "nltest /dsgetdc:lab.test /domain_trusts")]
        built = grow.build(NLTEST, draft(detection=detection, true_negatives=tns), CORE, TODAY)
        self.assertFalse(survivors(built["rule"], built["tps"], built["tns"]))
        self.assertIn("filter_never", built["rule"]["detection"])

    def test_every_candidate_of_the_lane_is_proven(self):
        cands = grow.load_candidates(grow.Lane())
        for cand in cands:
            tps, tns = cand.tests("true_positive"), cand.tests("true_negative")
            self.assertFalse(survivors(cand.rule, tps, tns), cand.id)
            for label, ev, expected in grow.suite(tps, tns):
                self.assertEqual(matches(cand.rule, ev), expected, f"{cand.id}: {label}")
                self.assertEqual(route(ev), cand.record["logsource"], f"{cand.id}: {label}")


class Run(LaneCase):
    """One unattended run, from the queue to the ledger."""

    def test_a_draft_is_accepted_and_the_lane_holds(self):
        report, script = self.run_lane({"T1482": [draft()]})
        self.assertEqual(report["accepted"], ["T1482_nltest_trust_listing"])
        self.assertEqual((report["asked"], script.calls), (1, [("T1482", None)]))
        folder = self.lane.root / "T1482_nltest_trust_listing"
        self.assertEqual(sorted(p.relative_to(folder).as_posix() for p in folder.rglob("*") if p.is_file()),
                         ["README.md", "candidate.yml", "query.kql", "query.spl", "rule.yml", "tests/true_negative.jsonl", "tests/true_positive.jsonl"])
        self.assertEqual(grow.load_ledger(self.lane.ledger)["T1482"], {"status": "accepted", "candidate": "T1482_nltest_trust_listing", "date": TODAY})
        self.assertEqual(grow.check(self.lane), [])
        readme = (folder / "README.md").read_text(encoding="utf-8")
        self.assertIn("**Candidate.** Drafted by a language model for RASD-Agent", readme)
        self.assertIn("No person has reviewed it", readme)
        for name in ("README.md", "rule.yml", "query.kql", "tests/true_positive.jsonl"):
            self.assertNotIn(b"\r", (folder / name).read_bytes())
        page = (self.lane.root / "README.md").read_text(encoding="utf-8")
        self.assertIn("[Nltest Listing the Trusts of the Domain](T1482_nltest_trust_listing/README.md)", page)
        again, _ = self.run_lane({"T1482": [draft()]})
        self.assertEqual((again["accepted"], again["asked"], again["retired"]), ([], 0, []))

    def test_the_refusal_is_the_next_drafts_feedback(self):
        by_name_only = draft(detection={**draft()["detection"], "selection_img": {"Image|endswith": "\\nltest.exe"}})
        report, script = self.run_lane({"T1482": [by_name_only, draft()]})
        self.assertEqual(report["accepted"], ["T1482_nltest_trust_listing"])
        self.assertEqual(script.calls[0], ("T1482", None))
        self.assertIn("binary_renamed", script.calls[1][1])
        self.assertEqual(report["asked"], 2)

    def test_a_later_run_is_told_why_the_earlier_one_was_refused(self):
        by_name_only = draft(detection={**draft()["detection"], "selection_img": {"Image|endswith": "\\nltest.exe"}})
        _, first = self.run_lane({"T1482": [by_name_only, by_name_only]})
        self.assertEqual(first.calls[0], ("T1482", None))
        reason = grow.load_ledger(self.lane.ledger)["T1482"]["reason"]
        self.assertIn("binary_renamed", reason)
        report, second = self.run_lane({"T1482": [draft()]})
        self.assertEqual(second.calls, [("T1482", reason)])
        self.assertEqual((report["accepted"], report["earlier"]), (["T1482_nltest_trust_listing"], {"T1482": 1}))

    def test_a_run_whose_candidates_break_the_pipeline_is_set_aside(self):
        report, _ = self.run_lane({"T1482": [draft()]})
        aside = grow.set_aside(self.lane, report, TODAY)
        self.assertFalse((self.lane.root / "T1482_nltest_trust_listing").exists())
        self.assertEqual((aside["accepted"], aside["refused"]), ([], [{"technique": "T1482", "reason": grow.SET_ASIDE}]))
        self.assertEqual(grow.load_ledger(self.lane.ledger)["T1482"],
                         {"status": "refused", "reason": grow.SET_ASIDE, "attempts": 1, "date": TODAY, "rasd": grow.VERSION})
        self.assertEqual(grow.check(self.lane), [])
        self.assertEqual(grow.message_of(aside).splitlines()[0], "grow: no candidate accepted, 1 refused")
        for n in range(2, grow.MAX_ATTEMPTS + 1):
            report, script = self.run_lane({"T1482": [draft()]})
            self.assertEqual(script.calls, [("T1482", grow.SET_ASIDE)])
            self.assertEqual(report["earlier"], {"T1482": n - 1})
            grow.set_aside(self.lane, report, TODAY)
            self.assertEqual(grow.load_ledger(self.lane.ledger)["T1482"]["attempts"], n)
        _, script = self.run_lane({"T1482": [draft()]})
        self.assertEqual(script.calls, [])
        self.assertEqual(grow.state(self.lane)["counts"]["parked"], 1)

    def test_declined_and_refused_are_remembered(self):
        report, _ = self.run_lane({"T1482": [{"observable": False, "reason": "Only network captures record this behaviour"}]})
        self.assertEqual(report["declined"], ["T1482"])
        entry = grow.load_ledger(self.lane.ledger)["T1482"]
        self.assertEqual((entry["status"], entry["sources"]), ("declined", grow.sources_hash()))
        again, script = self.run_lane({"T1482": [draft()]})
        self.assertEqual((again["accepted"], script.calls), ([], []))
        self.assertEqual(grow.check(self.lane), [])

    def test_a_technique_is_parked_after_enough_refusals(self):
        bad = draft(level="severe")
        for n in range(1, grow.MAX_ATTEMPTS + 1):
            report, script = self.run_lane({"T1482": [bad, bad]})
            self.assertEqual(len(script.calls), grow.ATTEMPTS)
            entry = grow.load_ledger(self.lane.ledger)["T1482"]
            self.assertEqual((entry["status"], entry["attempts"], entry["rasd"]), ("refused", n, grow.VERSION))
            self.assertIn("level must be", entry["reason"])
        _, script = self.run_lane({"T1482": [draft()]})
        self.assertEqual(script.calls, [])
        with mock.patch.object(grow, "VERSION", "9.9.9"):
            report, _ = self.run_lane({"T1482": [draft()]})
        self.assertEqual(report["accepted"], ["T1482_nltest_trust_listing"])

    def test_a_silent_model_stops_the_run_and_records_nothing(self):
        down = ModelError("the model server could not be reached")
        report, script = self.run_lane({"T1105": [down, down], "T1047": [down, down], "T1482": [draft()]}, only=("T1482", "T1105", "T1047"))
        self.assertTrue(report["stopped"])
        self.assertEqual([c[0] for c in script.calls], ["T1105", "T1105", "T1047"])
        self.assertEqual(len(script.calls), grow.MODEL_FAILURES)
        self.assertEqual(grow.load_ledger(self.lane.ledger), {})
        self.assertEqual(report["accepted"], [])

    def test_an_unusable_answer_is_not_a_refusal_of_the_technique(self):
        report, script = self.run_lane({"T1482": [ModelError("the model's answer is not valid JSON"), draft()]})
        self.assertEqual(report["accepted"], ["T1482_nltest_trust_listing"])
        self.assertIn("could not be used", script.calls[1][1])

    def test_the_limits_of_a_run(self):
        other = draft(name="wmic_starts_a_process", title="WMIC Asked to Start a Process",
                      detection={"selection_img": [{"Image|endswith": "\\wmic.exe"}, {"OriginalFileName": "wmic.exe"}],
                                 "selection_call": {"CommandLine|contains|all": ["process", "call", "create"]}, "condition": "selection_img and selection_call"},
                      true_positives=[proc(f"process created, form {i}", cmd, image=S32 + "wbem\\WMIC.exe", ofn=ofn) for i, (cmd, ofn) in enumerate(
                          [("wmic process call create calc.exe", "wmic.exe"), ("wmic /node:LAB-SRV01 process call create cmd.exe", "wmic.exe"),
                           ("wmic path win32_process call create notepad.exe", "wmic.exe"), ("wmic process call create mspaint.exe", None)])],
                      true_negatives=[proc(f"benign, form {i}", cmd, image=image, ofn=ofn) for i, (cmd, image, ofn) in enumerate(
                          [("wmic process list brief", S32 + "wbem\\WMIC.exe", "wmic.exe"), ("wmic process where name=\"x.exe\" call terminate", S32 + "wbem\\WMIC.exe", "wmic.exe"),
                           ("wmic shadowcopy call create Volume=C:\\", S32 + "wbem\\WMIC.exe", "wmic.exe"), ("wmic /output:created.txt process list", S32 + "wbem\\WMIC.exe", "wmic.exe"),
                           ("cmd.exe /c echo wmic process call create", S32 + "cmd.exe", "Cmd.Exe")])])
        answers = {"T1482": [draft()], "T1047": [other]}
        report, _ = self.run_lane(answers, limit=1, only=("T1482", "T1047"))
        self.assertEqual(len(report["accepted"]), 1)
        report, _ = self.run_lane(answers, tries=1, only=("T1482", "T1047"))
        self.assertEqual((len(report["accepted"]), report["asked"]), (1, 1))
        self.assertEqual(len(grow.load_candidates(self.lane)), 2)
        self.assertEqual(grow.check(self.lane), [])

    def test_a_candidate_that_no_longer_passes_is_retired(self):
        self.run_lane({"T1482": [draft()]})
        folder = self.lane.root / "T1482_nltest_trust_listing"
        with (folder / "tests" / "true_negative.jsonl").open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(proc("a check the repository now calls benign", "nltest /domain_trusts /server:LAB-DC01")) + "\n")
        self.assertTrue(any("is matched" in e for e in grow.check(self.lane)))
        report = grow.run(self.lane, None, 5, 20, [], TODAY, say=lambda _line: None)
        self.assertEqual([r["candidate"] for r in report["retired"]], ["T1482_nltest_trust_listing"])
        self.assertFalse(folder.exists())
        entry = grow.load_ledger(self.lane.ledger)["T1482"]
        self.assertEqual((entry["status"], entry["attempts"]), ("refused", 0))
        self.assertTrue(entry["reason"].startswith("retired: "))
        self.assertEqual(grow.check(self.lane), [])
        report, _ = self.run_lane({"T1482": [draft()]})
        self.assertEqual(report["accepted"], ["T1482_nltest_trust_listing"])

    def test_generated_files_are_repaired_not_retired(self):
        self.run_lane({"T1482": [draft()]})
        folder = self.lane.root / "T1482_nltest_trust_listing"
        (folder / "README.md").write_text("edited by hand\n", encoding="utf-8")
        record = yaml.safe_load((folder / "candidate.yml").read_text(encoding="utf-8"))
        record["proof"]["variations_matched"] = 1
        (folder / "candidate.yml").write_text(yaml.safe_dump(record, sort_keys=False), encoding="utf-8")
        (folder / "notes.txt").write_text("stray\n", encoding="utf-8")
        problems = grow.check(self.lane)
        self.assertTrue(any("README.md is not what" in e for e in problems) and any("candidate.yml is not what" in e for e in problems))
        self.assertTrue(any("unexpected file notes.txt" in e for e in problems))
        (folder / "notes.txt").unlink()
        report = grow.run(self.lane, None, 5, 20, [], TODAY, say=lambda _line: None)
        self.assertEqual(report["retired"], [])
        self.assertEqual(grow.check(self.lane), [])

    def test_the_ledger_and_the_lane_must_agree(self):
        self.run_lane({"T1482": [draft()]})
        ledger = grow.load_ledger(self.lane.ledger)
        grow.save_ledger(self.lane.ledger, {**ledger, "T0000": {"status": "refused", "reason": "a gate said no", "attempts": 1},
                                           "T1047": {"status": "accepted", "candidate": "T1047_missing", "date": TODAY},
                                           "T1105": {"status": "postponed"}, "T1140": {"status": "declined", "reason": "short"}})
        problems = "\n".join(grow.check(self.lane))
        for expected in ("T0000 is not a technique", "T1047 is accepted as T1047_missing", "T1105 has status 'postponed'", "T1140 is declined with no reason"):
            self.assertIn(expected, problems)
        grow.save_ledger(self.lane.ledger, {})
        self.assertIn("the ledger does not record it as accepted", "\n".join(grow.check(self.lane)))

    def test_what_left_the_reference_leaves_the_ledger_and_the_lane(self):
        self.run_lane({"T1482": [draft()]})
        ledger = grow.load_ledger(self.lane.ledger)
        grow.save_ledger(self.lane.ledger, {**ledger, "T0000": {"status": "refused", "reason": "a gate said no", "attempts": 1, "rasd": grow.VERSION}})
        doc = json.loads(grow.UNIVERSE.read_text(encoding="utf-8"))
        del doc["techniques"]["T1482"]
        smaller = self.tmp / "attack.json"
        smaller.write_text(grow.universe_text(doc), encoding="utf-8")
        lane = grow.Lane(self.lane.root, self.lane.ledger, smaller)
        report = grow.run(lane, None, 5, 20, [], TODAY, say=lambda _line: None)
        self.assertEqual([r["candidate"] for r in report["retired"]], ["T1482_nltest_trust_listing"])
        self.assertEqual(report["dropped"], ["T0000", "T1482"])
        self.assertEqual(grow.load_ledger(lane.ledger), {})
        self.assertEqual(grow.check(lane), [])

    def test_the_note_a_run_is_committed_with(self):
        report, _ = self.run_lane({"T1482": [draft()]})
        note = grow.message_of(report)
        self.assertEqual(note.splitlines()[0], "grow: 1 candidate accepted")
        self.assertIn("accepted: T1482_nltest_trust_listing", note)
        self.assertIn("reviewed by no person", note)
        self.assertIn(f"ATT&CK v{_DOC['attack_version']}", note)
        quiet = grow.message_of({"accepted": [], "declined": ["T1105"], "refused": [{"technique": "T1047", "reason": "x"}],
                                 "retired": [{"candidate": "T1482_nltest_trust_listing", "reason": "x"}], "attack_version": "20.1"})
        self.assertEqual(quiet.splitlines()[0], "grow: no candidate accepted, 1 declined, 1 refused, 1 retired")
        self.assertEqual(quiet.splitlines()[-1], "Nothing was kept in this run; the ledger records what was tried. ATT&CK v20.1.")
        self.assertNotIn("reviewed by no person", quiet)
        for line in ("declined: T1105", "refused: T1047", "retired: T1482_nltest_trust_listing"):
            self.assertIn(line, quiet)
        self.assertTrue(note.endswith("\n") and "\r" not in note)

    def test_a_folder_of_drafts(self):
        drafts = self.tmp / "drafts"
        drafts.mkdir()
        (drafts / "T1482.json").write_text(json.dumps(draft()), encoding="utf-8")
        (drafts / "T1047.json").write_text("{not json", encoding="utf-8")
        report = grow.run(self.lane, grow.FolderDrafter(drafts), 5, 20, [], TODAY, say=lambda _line: None)
        self.assertEqual(report["accepted"], ["T1482_nltest_trust_listing"])
        self.assertEqual(report["refused"], [])
        self.assertEqual(report["asked"], 2)
        self.assertEqual(len(report["errors"]), 1)
        self.assertIn("T1047.json is not JSON", report["errors"][0])
        self.assertNotIn("T1047", grow.load_ledger(self.lane.ledger))

    def test_the_model_is_asked_with_the_vocabulary_and_the_feedback(self):
        seen = {}

        class Fake:
            name = "lab-model"

            def json(self, system, user, required, max_tokens=0):
                seen.update(system=system, user=json.loads(user), required=required)
                return draft()

        drafter = grow.ModelDrafter(Fake(), {"T1482": "What ATT&CK says."}, grow.samples_of(CORE))
        self.assertEqual(drafter.draft(NLTEST, "the variation 'x' is not matched")["name"], "nltest_trust_listing")
        self.assertEqual(seen["required"], ("observable",))
        self.assertEqual(seen["user"]["technique"], {"id": "T1482", "name": "Domain Trust Discovery", "tactics": ["discovery"],
                                                     "platforms": ["Windows"], "description": "What ATT&CK says."})
        self.assertEqual(seen["user"]["previous_draft_refused_because"], "the variation 'x' is not matched")
        self.assertEqual(seen["user"]["accepted_example"], {"technique": "T1482", "draft": grow.EXAMPLE})
        self.assertIn("accepted_example", seen["system"])
        self.assertEqual(sorted(seen["user"]["log_sources"]), sorted(grow.SOURCES))
        for key, source in seen["user"]["log_sources"].items():
            self.assertEqual(source["fields"], FIELDS[key])
            self.assertTrue(set(source["example_event"]) <= set(FIELDS[key]), key)
        self.assertIn("lab-model", drafter.describe())
        self.assertNotIn("lab-model", json.dumps(grow.build(NLTEST, draft(), CORE, TODAY)["record"]))
        for word in ("contains|all", "OriginalFileName", "filter_", "observable"):
            self.assertIn(word, seen["system"])


class Server:
    """A chat-completions server on this machine that answers from a script: each entry is a status and a body."""

    def __init__(self, answers: list[tuple[int, dict]]):
        self.answers, self.requests = list(answers), []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append({"path": self.path, "auth": self.headers.get("Authorization"), "body": body})
                status, answer = outer.answers.pop(0) if outer.answers else (500, {"error": "nothing left to answer"})
                data = json.dumps(answer).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *_args):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/v1"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def said(doc: dict) -> tuple[int, dict]:
    return 200, {"choices": [{"message": {"role": "assistant", "content": "```json\n" + json.dumps(doc) + "\n```"}}]}


class Transport(LaneCase):
    """The model over HTTP, as an unattended run meets it."""

    def serve(self, answers):
        server = Server(answers)
        self.addCleanup(server.close)
        local = mock.patch.dict(os.environ, {"NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"})
        local.start()
        self.addCleanup(local.stop)
        still = mock.patch.object(agent_model.time, "sleep")
        self.slept = still.start()
        self.addCleanup(still.stop)
        return server

    def test_a_run_over_http_from_the_environment_to_the_lane(self):
        server = self.serve([said(draft())])
        model = Model.from_env({"RASD_MODEL": "lab-model", "RASD_MODEL_URL": server.url + "/", "RASD_MODEL_KEY": " lab-key "})
        drafter = grow.ModelDrafter(model, {"T1482": "What ATT&CK says."}, grow.samples_of(CORE))
        report = grow.run(self.lane, drafter, 1, 5, ["T1482"], TODAY, say=lambda _line: None)
        self.assertEqual((report["accepted"], report["errors"]), (["T1482_nltest_trust_listing"], []))
        request = server.requests[0]
        self.assertEqual((request["path"], request["auth"]), ("/v1/chat/completions", "Bearer lab-key"))
        self.assertEqual((request["body"]["model"], request["body"]["temperature"], request["body"]["max_tokens"]), ("lab-model", 0, 4000))
        self.assertEqual([m["role"] for m in request["body"]["messages"]], ["system", "user"])
        self.assertEqual(json.loads(request["body"]["messages"][1]["content"])["technique"]["id"], "T1482")
        self.assertEqual(grow.check(self.lane), [])
        for path in self.tmp.rglob("*"):
            if path.is_file():
                self.assertNotIn(b"lab-key", path.read_bytes(), path)
                self.assertNotIn(b"lab-model", path.read_bytes(), path)

    def test_the_client_follows_what_the_server_accepts(self):
        tokens = (400, {"error": {"message": "Unsupported parameter: 'max_tokens' is not supported with this model. Use 'max_completion_tokens' instead.",
                                  "param": "max_tokens", "code": "unsupported_parameter"}})
        warmth = (400, {"error": {"message": "Unsupported value: 'temperature' does not support 0 with this model. Only the default (1) value is supported.",
                                  "param": "temperature", "code": "unsupported_value"}})
        server = self.serve([tokens, warmth, said({"observable": True})])
        model = Model("lab-model", server.url, "chat", "lab-key", 10)
        self.assertEqual(model.json("system", "user", ("observable",), max_tokens=4000), {"observable": True})
        first, second, third = (r["body"] for r in server.requests)
        self.assertEqual((first["max_tokens"], first["temperature"]), (4000, 0))
        self.assertEqual((second["max_completion_tokens"], second["temperature"], "max_tokens" in second), (4000 * agent_model.REASONING_ROOM, 0, False))
        self.assertEqual((third["max_completion_tokens"], "temperature" in third), (4000 * agent_model.REASONING_ROOM, False))
        server.answers.append(said({"observable": False, "reason": "kept"}))
        model.json("system", "user", ("observable",), max_tokens=4000)
        self.assertEqual(len(server.requests), 4)
        self.assertEqual(server.requests[3]["body"], third)
        other = self.serve([(400, {"error": {"message": "The model does not exist."}})])
        with self.assertRaisesRegex(ModelError, "answered 400") as caught:
            Model("lab-model", other.url, "chat", "lab-key", 10).complete("system", "user")
        self.assertEqual((caught.exception.status, len(other.requests)), (400, 1))

    def test_an_answer_cut_at_the_limit_is_asked_for_again_with_more_room(self):
        cut = (200, {"choices": [{"finish_reason": "length", "message": {"role": "assistant", "content": '{"observable": tr'}}]})
        whole = (200, {"choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": '{"observable": true}'}}]})
        server = self.serve([cut, whole])
        self.assertEqual(Model("lab-model", server.url, "chat", "lab-key", 10).json("s", "u", ("observable",), max_tokens=4000), {"observable": True})
        self.assertEqual([r["body"]["max_tokens"] for r in server.requests], [4000, 4000 * agent_model.REASONING_ROOM])
        twice = self.serve([cut, cut])
        with self.assertRaisesRegex(ModelError, "not valid JSON|no JSON object"):
            Model("lab-model", twice.url, "chat", "lab-key", 10).json("s", "u", ("observable",))
        self.assertEqual(len(twice.requests), 2)

    def test_a_busy_server_is_asked_again_and_a_refusal_is_not(self):
        server = self.serve([(429, {"error": "slow down"}), (503, {"error": "busy"}), said({"observable": True})])
        self.assertEqual(Model("lab-model", server.url, "chat", "lab-key", 10).json("s", "u", ("observable",)), {"observable": True})
        self.assertEqual((len(server.requests), [c.args[0] for c in self.slept.call_args_list]), (3, list(agent_model.WAITS)))
        busy = self.serve([(503, {"error": "busy"})] * 3)
        with self.assertRaisesRegex(ModelError, "answered 503"):
            Model("lab-model", busy.url, "chat", "lab-key", 10).complete("s", "u")
        self.assertEqual(len(busy.requests), 3)
        refused = self.serve([(401, {"error": {"message": "Incorrect API key provided."}})])
        with self.assertRaisesRegex(ModelError, "answered 401") as caught:
            Model("lab-model", refused.url, "chat", "lab-key", 10).complete("s", "u")
        self.assertEqual((len(refused.requests), caught.exception.status), (1, 401))
        self.assertNotIn("lab-key", str(caught.exception))

    def test_a_server_that_is_not_there_stops_the_run(self):
        server = self.serve([])
        server.close()
        drafter = grow.ModelDrafter(Model("lab-model", server.url, "chat", None, 5), {}, {})
        report = grow.run(self.lane, drafter, 5, 20, ["T1482", "T1105", "T1047"], TODAY, say=lambda _line: None)
        self.assertTrue(report["stopped"])
        self.assertEqual((report["asked"], report["accepted"], grow.load_ledger(self.lane.ledger)), (grow.MODEL_FAILURES, [], {}))
        self.assertIn("could not be reached", report["errors"][-1])


class Guard(unittest.TestCase):
    """What an unattended run may change, and the workflow that publishes it."""

    def test_what_the_lane_owns(self):
        self.assertEqual(sorted(grow.PAGES), ["README.md", "agent/ADVICE.md", "docs/EXECUTIVE_SUMMARY.md", "docs/RASD_METRICS.md",
                                              "purple/executive_matrix.md"])
        for path in ("detect/candidates/README.md", "detect/candidates/T1482_x/tests/true_positive.jsonl", "agent/growth.yml",
                     "intel/mappings/attack_enterprise.json", *grow.PAGES):
            self.assertTrue(grow.owned(path), path)
        for path in ("detect/detections/T1059.001_powershell_encoded_command/rule.yml", "detect/candidatesx/rule.yml", "tools/grow.py",
                     "agent/decisions.yml", ".github/workflows/agent-grow.yml", "intel/mappings/backlog.yml", "docs/GROW.md",
                     "rasd.py", "detect/correlations/T1190_object_id_enumeration/base.yml", "tests/test_grow.py"):
            self.assertFalse(grow.owned(path), path)

    def test_the_pages_that_state_the_lane_are_the_ones_it_owns(self):
        st = grow.summary()
        row = f"{st['candidates']} candidate detection{'' if st['candidates'] == 1 else 's'} drafted by a language model"
        counsel = f"RASD-Agent's lane: {st['candidates']} candidate{'' if st['candidates'] == 1 else 's'} no person has reviewed"
        stated = sorted(p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*.md") if ".git" not in p.parts and "candidates" not in p.parts
                        and (row in p.read_text(encoding="utf-8") or counsel in p.read_text(encoding="utf-8")))
        self.assertEqual(stated, sorted(grow.PAGES))
        named = sorted(p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*.md") if ".git" not in p.parts and "candidates" not in p.parts
                       and any(f"detect/candidates/{c.id}" in p.read_text(encoding="utf-8") for c in grow.load_candidates(grow.Lane())))
        self.assertTrue(set(named) <= set(grow.PAGES), named)

    def test_the_guard_names_what_is_not_the_lanes(self):
        repo = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, repo, ignore_errors=True)
        git = lambda *a: subprocess.run(["git", "-C", str(repo), "-c", "user.name=lab", "-c", "user.email=lab@lab.test",  # noqa: S607
                                         "-c", "commit.gpgsign=false", *a], check=True, capture_output=True)
        write = lambda rel, text: grow._write(repo / rel, text)
        git("init", "--quiet")
        for rel in ("README.md", "tools/grow.py", "agent/growth.yml", "detect/candidates/T1482_x/rule.yml", "detect/detections/T1059.001_y/rule.yml",
                    "detect/detections/T1059.001_y/README.md"):
            write(rel, "first\n")
        git("add", "--all")
        git("commit", "--quiet", "-m", "first")
        self.assertEqual(grow.strays(repo), [])
        for rel in ("README.md", "agent/growth.yml", "detect/candidates/T1482_x/rule.yml", "detect/candidates/T1105 with a blank/rule.yml",
                    "intel/mappings/attack_enterprise.json"):
            write(rel, "second\n")
        (repo / "detect/candidates/T1482_x/rule.yml").unlink()
        self.assertEqual(grow.strays(repo), [])
        git("add", "--all")
        self.assertEqual(grow.strays(repo), [])
        write("tools/grow.py", "second\n")
        write(".github/workflows/other.yml", "second\n")
        (repo / "detect/detections/T1059.001_y/rule.yml").unlink()
        git("mv", "detect/detections/T1059.001_y/README.md", "detect/candidates/README.md")
        self.assertEqual(grow.strays(repo), [".github/workflows/other.yml", "detect/detections/T1059.001_y/README.md",
                                             "detect/detections/T1059.001_y/rule.yml", "tools/grow.py"])

    def test_the_workflow_publishes_only_behind_the_gates(self):
        flows = ROOT / ".github" / "workflows"
        doc = yaml.safe_load((flows / "agent-grow.yml").read_text(encoding="utf-8"))
        self.assertEqual(sorted(doc[True]), ["schedule", "workflow_dispatch"])
        self.assertEqual(doc["permissions"], {"contents": "read"})
        job = doc["jobs"]["grow"]
        self.assertEqual(job["if"], "vars.RASD_MODEL != ''")
        self.assertEqual(job["permissions"], {"contents": "write", "actions": "write"})
        self.assertFalse(doc["concurrency"]["cancel-in-progress"])
        steps = job["steps"]
        ci = (flows / "detection-ci.yml").read_text(encoding="utf-8")
        for step in steps:
            if "uses" in step:
                self.assertRegex(step["uses"], r"^actions/[a-z-]+@[0-9a-f]{40}$")
                self.assertIn(step["uses"], ci)
        holders = [i for i, step in enumerate(steps) if "secrets." in json.dumps(step)]
        self.assertEqual(len(holders), 1)
        self.assertEqual({k for k, v in steps[holders[0]]["env"].items() if "secrets." in str(v)}, {"RASD_MODEL_KEY"})
        self.assertNotIn("${{", steps[holders[0]]["run"])
        runs = [str(step.get("run", "")) for step in steps]
        at = lambda text: next(i for i, run in enumerate(runs) if text in run)
        order = [at("rasd grow --sync"), at('rasd grow "${args[@]}"'), at("rasd build"), at("rasd ci"), at("rasd grow --guard"), at("git push")]
        self.assertEqual(order, sorted(order))
        self.assertEqual(holders[0], order[1])
        gate = runs[at("rasd ci")]
        for command in ("ruff check . && mypy && rasd ci && git diff --exit-code", "if gate; then exit 0; fi", "rasd grow --set-aside", "rasd build"):
            self.assertIn(command, gate)
        self.assertTrue(gate.rstrip().endswith("\n          gate") or gate.rstrip().endswith("\ngate"), gate[-80:])
        for run in runs:
            self.assertNotIn("${{", run)
            self.assertNotIn("--force", run)
        self.assertEqual(sum("git push" in run for run in runs), 1)


class TheLane(unittest.TestCase):
    """The lane the repository ships."""

    def test_the_lane_holds(self):
        self.assertEqual(grow.check(grow.Lane()), [])

    def test_candidates_are_marked_and_apart_from_the_core(self):
        cands = grow.load_candidates(grow.Lane())
        core_ids = {str(o.rule.get("id")) for o in CORE}
        core = grow.core_techniques()
        for cand in cands:
            self.assertEqual(cand.rule["author"], grow.AUTHOR, cand.id)
            self.assertEqual(cand.rule["status"], "experimental", cand.id)
            self.assertNotIn(cand.rule["id"], core_ids, cand.id)
            self.assertNotIn(cand.technique, core, cand.id)
            self.assertIn(cand.record["logsource"], grow.SOURCES, cand.id)
            for path in cand.folder.rglob("*"):
                if path.is_file():
                    data = path.read_bytes()
                    self.assertNotIn(b"\r", data, path)
                    self.assertNotIn(b"TODO", data, path)
        self.assertEqual({d.id for d in common.load_detections()} & {c.id for c in cands}, set())
        self.assertFalse(str(grow.LANE).startswith(str(common.DETECTIONS)))

    def test_rule_edit_equivalence_is_the_cores_statement(self):
        import certify
        if certify._git(["rev-parse", "--verify", "--quiet", "HEAD^{commit}"])[0] != 0:
            self.skipTest("not a git checkout")
        report = certify.equiv_run("HEAD")
        self.assertEqual([r["path"] for r in report if "candidates" in str(r.get("path"))], [])
        self.assertEqual([r["id"] for r in report if r["status"] == "removed"], [])

    def test_the_page_states_what_the_lane_is(self):
        page = (grow.LANE / "README.md").read_text(encoding="utf-8")
        st = grow.state(grow.Lane())
        self.assertIn("No person reviewed them and no lab run validated them", page)
        self.assertIn(f"**ATT&CK v{st['attack_version']}**", page)
        self.assertIn(f"| Candidate of this lane | {st['counts']['candidate']} |", page)
        self.assertIn(f"| Core detection, written and reviewed by a person | {st['counts']['core']} |", page)
        for row in st["candidates"]:
            self.assertIn(f"]({row['id']}/README.md)", page)


class CommandLine(unittest.TestCase):
    def rasd(self, *argv, env=None):
        base = {k: v for k, v in os.environ.items() if not k.startswith("RASD_MODEL")}
        return subprocess.run([sys.executable, str(ROOT / "rasd.py"), "grow", *argv], cwd=ROOT, capture_output=True, text=True,
                              encoding="utf-8", env={**base, "NO_BANNER": "1", **(env or {})})

    def test_status_json_and_check(self):
        out = self.rasd()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("RASD-Agent's lane", out.stdout)
        st = json.loads(self.rasd("--json").stdout)
        self.assertEqual((st["format"], st["rasd"]), (grow.FORMAT, grow.VERSION))
        check = self.rasd("--check")
        self.assertEqual(check.returncode, 0, check.stdout)
        self.assertIn("[ OK ]", check.stdout)

    def test_a_misconfigured_model_is_said_and_nothing_runs(self):
        out = self.rasd("--run", env={"RASD_MODEL": "lab-model", "RASD_MODEL_PROVIDER": "telepathy"})
        self.assertEqual(out.returncode, 2)
        self.assertIn("model misconfigured", out.stdout)

    def test_prints_under_a_legacy_code_page(self):
        env = {k: v for k, v in os.environ.items() if k not in ("PYTHONUTF8", "PYTHONIOENCODING")}
        for codepage in ("cp1252", "cp1256"):
            out = subprocess.run([sys.executable, str(ROOT / "tools" / "grow.py")], cwd=ROOT, capture_output=True,
                                 env={**env, "NO_BANNER": "1", "PYTHONIOENCODING": codepage})
            self.assertEqual(out.returncode, 0, out.stderr.decode("utf-8", "replace")[-300:])
            out.stdout.decode("utf-8")


if __name__ == "__main__":
    unittest.main()
