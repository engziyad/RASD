#!/usr/bin/env python3
"""
review.py - the person's side of RASD-Agent's lane: read a candidate, decide, and leave a record.

The agent drafts candidates and the gates of `rasd grow` test them. Neither can know whether a rule
means what its technique means, whether it would be noise in a real environment, or whether an
exclusion is one a defender would write. Those are a person's judgements, and this is where they are
taken. Nothing the agent drafts reaches the core library, a generated query or the Splunk app without
passing through here.

  rasd review                          the board: every candidate and where it stands with people
  rasd review CANDIDATE                the dossier: the rule, what it will never alert on, its tests,
                                       what the gates measured, and what only a person can judge
  rasd review CANDIDATE --approve --by NAME [--rate logic=5 telemetry=4 noise=4 mapping=5] [--note TEXT]
  rasd review CANDIDATE --revise  --by NAME --note "what to change"
  rasd review CANDIDATE --reject  --by NAME --note "why it is wrong"
                                       a rejected candidate leaves the lane, and the next draft of its
                                       technique is told the reviewer's words
  rasd review CANDIDATE --promote --by NAME
                                       an approved candidate becomes a core detection: its rule and tests
                                       carried over unchanged, the contract, tuning guide and mutations
                                       left for a person to finish before CI accepts it
  rasd review CANDIDATE --withdraw --by NAME --note "why"       take one candidate out of the lane
  rasd review --rollback RUN --by NAME --note "why"             take out everything one run drafted
  rasd review --audit [N]              the last lines of the audit trail, and whether its chain holds
  rasd review --backfill               record the candidates that were in the lane before the trail was kept
  rasd review --check                  the records hold together (CI)

A review is bound to the SHA-256 of the rule text it judged: change the rule and the review no longer
stands. The unattended run of the lane may not change the review ledger, so the agent cannot approve
its own work (docs/GOVERNANCE.md).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import shutil
import sys
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BOLD, DETECTIONS, DIM, GREEN, RED, RESET, ROOT, VERSION, YELLOW
import governance
import grow
import new_detection

QUERIES = ROOT / "queries"
BEFORE_TRAIL = "in the lane before the trail was kept: what drafted it was not recorded"


class ReviewError(Exception):
    """What was asked cannot be done as asked: the text says why."""


def find(lane: grow.Lane, ref: str) -> grow.Candidate:
    cands = grow.load_candidates(lane)
    exact = [c for c in cands if c.id == ref]
    close = exact or [c for c in cands if ref.lower() in c.id.lower()]
    if len(close) != 1:
        raise ReviewError(f"'{ref}' names {'no' if not close else len(close)} candidate"
                          + (f": {', '.join(c.id for c in close[:6])}" if close else " of the lane (rasd review lists them)"))
    return close[0]


def stand_of(lane: grow.Lane, cand: grow.Candidate) -> dict:
    return governance.standing(cand.id, governance.rule_digest(cand.folder), governance.load_reviews(lane.reviews))


def ratings_of(pairs: Sequence[str]) -> dict[str, int]:
    out = {}
    for pair in pairs:
        key, _, value = pair.partition("=")
        if key not in governance.CRITERIA or value not in ("1", "2", "3", "4", "5"):
            raise ReviewError(f"--rate takes {', '.join(f'{k}=1..5' for k in governance.CRITERIA)}; '{pair}' is not one of them")
        out[key] = int(value)
    return out


def signer(by: str) -> str:
    try:
        return governance.person(by)
    except governance.GovernanceError as e:
        raise ReviewError(str(e)) from e


def withdraw(lane: grow.Lane, cand: grow.Candidate, by: str, reason: str, today: str | None = None) -> None:
    """Take a candidate out of the lane on a person's word. Its technique returns to the queue, and the
    next draft is given the reason."""
    by = signer(by)
    reason = " ".join(str(reason or "").split())
    if len(reason) < 10:
        raise ReviewError("say why in a sentence (--note): the next draft of the technique is told it")
    ledger = grow.load_ledger(lane.ledger)
    shutil.rmtree(cand.folder)
    ledger[cand.technique] = {"status": "refused", "reason": f"retired: a reviewer withdrew it: {reason}"[:300], "attempts": 0,
                              "date": today or dt.date.today().isoformat(), "rasd": VERSION}
    grow.save_ledger(lane.ledger, ledger)
    governance.append(lane.trail, "withdrawn", by, candidate=cand.id, technique=cand.technique, reason=reason)
    grow.write_pages(lane)


def decide(lane: grow.Lane, ref: str, verdict: str, by: str, note: str | None = None, ratings: Mapping[str, int] | None = None,
           today: str | None = None) -> dict:
    """Record a person's verdict on the rule text a candidate holds now."""
    cand = find(lane, ref)
    today = today or dt.date.today().isoformat()
    sha = governance.rule_digest(cand.folder)
    try:
        entry = governance.new_review(cand.id, sha, verdict, by, today, note, ratings)
    except governance.GovernanceError as e:
        raise ReviewError(str(e)) from e
    reviews = governance.load_reviews(lane.reviews)
    governance.save_reviews(lane.reviews, [*reviews, entry])
    governance.append(lane.trail, "reviewed", entry["by"], candidate=cand.id, rule_sha256=sha, verdict=verdict, note=entry.get("note"))
    if verdict == "reject":
        withdraw(lane, cand, entry["by"], str(entry.get("note")), today)
    else:
        grow.write_pages(lane)
    return entry


def contract_of(cand: grow.Candidate) -> str:
    """The contract a promoted detection starts with: what the candidate already states filled in, the
    rest left as the TODO a person has to write before the linter accepts it."""
    head, _, body = new_detection.CONTRACT.format(folder=cand.id, tech_tag=cand.technique.lower()).partition("\n")
    doc = yaml.safe_load(body)
    doc["name"] = cand.rule.get("title")
    doc["data_contract"]["required_logsource"] = dict(cand.rule.get("logsource") or {})
    doc["data_contract"]["required_fields"] = list(cand.record.get("fields") or [])
    doc["data_contract"]["telemetry_risk"] = {}
    doc["detection_logic"]["severity"] = cand.rule.get("level", "medium")
    doc["detection_logic"]["blind_spots"] = list(cand.record.get("blind_spots") or ["TODO"])
    doc["triage"]["first_checks"] = list(cand.record.get("first_checks") or ["TODO"])
    return head + "\n" + yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=1000)


def promote(lane: grow.Lane, ref: str, by: str, detections: Path = DETECTIONS) -> Path:
    """An approved candidate becomes the start of a core detection. The rule and the tests are carried over
    byte for byte, so the text in the core is the text that was approved."""
    by = signer(by)
    cand = find(lane, ref)
    stand = stand_of(lane, cand)
    if stand["state"] != "approved":
        raise ReviewError({"unreviewed": "no person has reviewed it",
                           "revise": "its review says to revise it first",
                           "stale": "its review judged an earlier text of the rule"}.get(stand["state"], "it is not approved")
                          + f": a candidate is promoted only with an approval of the rule text it holds now (rasd review {cand.id})")
    folder = detections / cand.id
    if folder.exists():
        raise ReviewError(f"{cand.id} already exists in the core")
    sha = governance.rule_digest(cand.folder)
    (folder / "tests").mkdir(parents=True)
    shutil.copyfile(cand.folder / "rule.yml", folder / "rule.yml")
    for kind in ("true_positive", "true_negative"):
        shutil.copyfile(cand.folder / "tests" / f"{kind}.jsonl", folder / "tests" / f"{kind}.jsonl")
    for rel, text in (("contract.yml", contract_of(cand)),
                      ("tuning.yml", new_detection.TUNING.format(folder=cand.id)),
                      ("tests/mutations.yml", new_detection.MUTATIONS),
                      ("README.md", new_detection.README.replace("# TODO - detection title", f"# {cand.rule.get('title')}"))):
        (folder / rel).write_text(text, encoding="utf-8", newline="\n")
    ledger = grow.load_ledger(lane.ledger)
    ledger.pop(cand.technique, None)
    shutil.rmtree(cand.folder)
    grow.save_ledger(lane.ledger, ledger)
    governance.append(lane.trail, "promoted", by, candidate=cand.id, detection=cand.id, rule_sha256=sha,
                      approved_by=(stand["review"] or {}).get("by"))
    grow.write_pages(lane)
    return folder


def rollback(lane: grow.Lane, run: str, by: str, reason: str, today: str | None = None) -> list[str]:
    """Take out every candidate one run drafted and that still holds the rule text that run wrote."""
    trail = governance.read_trail(lane.trail)
    drafted = {(e["candidate"], e["rule_sha256"]) for e in trail
               if e.get("event") in ("drafted", "backfilled") and str(e.get("run") or "before-the-trail") == run}
    if not drafted:
        runs = sorted({str(e.get("run") or "before-the-trail") for e in trail if e.get("event") in ("drafted", "backfilled")})
        raise ReviewError(f"the trail records no candidate drafted by run '{run}'" + (f"; it knows {', '.join(runs[-8:])}" if runs else ""))
    out = []
    for cand in grow.load_candidates(lane):
        if (cand.id, governance.rule_digest(cand.folder)) in drafted:
            withdraw(lane, cand, by, f"run {run} rolled back: {reason}", today)
            out.append(cand.id)
    return out


def backfill(lane: grow.Lane) -> list[str]:
    """One line for each candidate the trail does not account for: it was in the lane before the trail was."""
    trail = governance.read_trail(lane.trail)
    out = []
    for cand in grow.load_candidates(lane):
        sha = governance.rule_digest(cand.folder)
        if governance.origin(trail, cand.id, sha) is None:
            governance.append(lane.trail, "backfilled", governance.AGENT, candidate=cand.id, technique=cand.technique, rule_sha256=sha,
                              drafted=str(cand.record.get("drafted") or "unknown"), note=BEFORE_TRAIL)
            out.append(cand.id)
    return out


def deployed(ids: Mapping[str, str], queries: Path = QUERIES) -> list[str]:
    """Candidates named in what is generated for a SIEM. ids: candidate -> its rule id."""
    out = []
    for path in sorted(p for p in queries.rglob("*") if p.is_file()) if queries.is_dir() else []:
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        out += [f"{path.relative_to(queries.parent).as_posix()} names the candidate {cand}" for cand, rid in ids.items()
                if cand in text or rid in text]
    return out


def check(lane: grow.Lane, detections: Path = DETECTIONS, queries: Path = QUERIES) -> list[str]:
    """Everything that must hold for the lane to be answerable: the review ledger is what `rasd review`
    writes, the trail's chain holds and accounts for every candidate and every review, no candidate is
    deployed, and nothing drafted by the agent is in the core without a person's approval of its text."""
    try:
        reviews = governance.load_reviews(lane.reviews)
        trail = governance.read_trail(lane.trail)
    except governance.GovernanceError as e:
        return [str(e)]
    problems = governance.review_problems(reviews) + governance.trail_problems(lane.trail)
    cands = grow.load_candidates(lane)
    for cand in cands:
        if governance.origin(trail, cand.id, governance.rule_digest(cand.folder)) is None:
            problems.append(f"{cand.id}: in the lane with no line of the trail saying how this rule text got there "
                            "(rasd review --backfill, for a candidate that was there before the trail)")
        if cand.rule.get("status") != "experimental" or cand.rule.get("author") != grow.AUTHOR:
            problems.append(f"{cand.id}: a candidate is experimental and signed by {grow.AUTHOR}")
    recorded = {(e.get("candidate"), e.get("rule_sha256"), e.get("verdict"), e.get("by")) for e in trail if e.get("event") == "reviewed"}
    for r in reviews:
        if (r.get("candidate"), r.get("rule_sha256"), r.get("verdict"), r.get("by")) not in recorded:
            problems.append(f"the review of {r.get('candidate')} by {r.get('by')} has no line in the trail: "
                            "reviews are written with rasd review, not by hand")
    promoted = {e.get("detection"): e for e in trail if e.get("event") == "promoted"}
    approved = {(r.get("candidate"), r.get("rule_sha256")) for r in reviews if r.get("verdict") == "approve"}
    for folder in sorted(p for p in detections.iterdir() if p.is_dir()) if detections.is_dir() else []:
        try:
            rule = yaml.safe_load((folder / "rule.yml").read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            continue
        from_lane = str(rule.get("id")) == str(uuid.uuid5(grow.NAMESPACE, folder.name)) or rule.get("author") == grow.AUTHOR
        if not from_lane:
            continue
        entry = promoted.get(folder.name)
        if entry is None:
            problems.append(f"{folder.name}: a rule drafted by the agent is in the core with no promotion in the trail")
        elif (entry.get("candidate"), entry.get("rule_sha256")) not in approved:
            problems.append(f"{folder.name}: promoted with no approval of the rule text that was promoted")
    problems += deployed({c.id: str(c.rule.get("id")) for c in cands}, queries)
    return problems


def dossier(lane: grow.Lane, cand: grow.Candidate) -> str:
    """What a reviewer needs on one page."""
    stand = stand_of(lane, cand)
    rule, record, proof = cand.rule, cand.record, cand.record.get("proof") or {}
    review = stand["review"] or {}
    state = {"unreviewed": "not reviewed", "approved": f"approved by {review.get('by')} on {review.get('date')}",
             "revise": f"to revise ({review.get('by')}, {review.get('date')}): {review.get('note', '')}",
             "stale": f"not reviewed: {review.get('by')} judged an earlier text on {review.get('date')}"}[stand["state"]]
    out = [f"{BOLD}{cand.id}{RESET} · {rule.get('title')}",
           f"{DIM}Standing:{RESET} {state} · drafted {record.get('drafted')} · rule SHA-256 {governance.rule_digest(cand.folder)[:16]}",
           f"{DIM}ATT&CK:{RESET} {cand.technique} {record.get('name')} ({', '.join(record.get('tactics') or [])}) · "
           f"{grow.SOURCE_NAMES.get(str(record.get('logsource')), record.get('logsource'))} · severity {rule.get('level')}", "",
           f"{BOLD}What it says it catches{RESET}", f"  {rule.get('description')}", "",
           f"{BOLD}The rule{RESET}"]
    out += ["  " + line for line in yaml.safe_dump(rule.get("detection"), sort_keys=False, allow_unicode=True, width=1000).splitlines()]
    out += ["", f"{BOLD}What it will never alert on{RESET}"]
    never = sorted(grow.exclusions(rule.get("detection") or {}))
    out += [f"  {YELLOW}{name}{RESET}: {json.dumps(rule['detection'][name], ensure_ascii=False)}" for name in never] or \
           ["  nothing: the rule has no exclusion"]
    out += ["", f"{BOLD}Tested on{RESET}"]
    out += [f"  fires  {ev.get('_case')}" for ev in cand.tests("true_positive")]
    out += [f"  quiet  {ev.get('_case')}" for ev in cand.tests("true_negative")]
    out += ["", f"{BOLD}What the gates measured{RESET}",
            f"  {proof.get('rule_mutants_killed', 0)} rule mutants killed, none surviving · {proof.get('variations_matched', 0)} attacker "
            f"variations matched · KQL and SPL agree with the rule on {proof.get('parity_events', 0)} events (offline model, not a live SIEM)",
            "", f"{BOLD}What it says about itself{RESET}"]
    for title, key in (("False positives", "false_positives"), ("Does not see", "blind_spots"), ("First checks", "first_checks")):
        out += [f"  {title}"] + [f"    - {item}" for item in record.get(key) or []]
    out += ["", f"{BOLD}What only a person can judge{RESET}"]
    out += [f"  [ ] {key:<10} {text}" for key, text in governance.CRITERIA.items()]
    out += ["  [ ] every exclusion above is one you would write yourself" if never else "  [ ] it needs no exclusion in your environment",
            "", f"{BOLD}Record your decision{RESET}",
            f'  rasd review {cand.id} --approve --by "Your Name" --rate logic=5 telemetry=5 noise=4 mapping=5',
            f'  rasd review {cand.id} --revise  --by "Your Name" --note "what to change"',
            f'  rasd review {cand.id} --reject  --by "Your Name" --note "why it is wrong"']
    return "\n".join(out)


def board(lane: grow.Lane) -> dict[str, Any]:
    st = grow.state(lane)
    _doc, techs = grow.load_universe(lane.universe)
    rank = {"approved": 2, "revise": 1}
    rows = sorted(st["candidates"], key=lambda r: (rank.get(r["review"], 0), -getattr(techs.get(r["technique"]), "groups", 0), r["id"]))
    return {"quality": st["reviews"], "candidates": [{**r, "groups": getattr(techs.get(r["technique"]), "groups", 0)} for r in rows]}


def print_board(doc: Mapping[str, Any]) -> None:
    q = doc["quality"]
    print(f"{BOLD}RASD-Agent's lane · {q['candidates']} candidates · reviewed by a person: {q['approved'] + q['revise']} "
          f"({q['approved']} approved, {q['revise']} to revise) · {q['unreviewed'] + q['stale']} not reviewed{RESET}\n")
    colour = {"approved": GREEN, "revise": YELLOW}
    label = {"approved": "approved", "revise": "to revise", "stale": "not reviewed*", "unreviewed": "not reviewed"}
    for r in doc["candidates"]:
        who = f" · {r['reviewed_by']} {r['reviewed_on']}" if r.get("reviewed_by") and r["review"] != "unreviewed" else ""
        print(f"  {colour.get(r['review'], DIM)}{label[r['review']]:<13}{RESET} {r['id']:<50} {DIM}{r['level']} · "
              f"{r['groups']} groups{who}{RESET}")
    if q["stale"]:
        print(f"\n{DIM}* an earlier text of the rule was reviewed; the one in the lane now was not{RESET}")
    if q["reviewed_ever"]:
        print(f"\n{BOLD}What the reviews say about the gates{RESET}")
        print(f"  {q['reviewed_ever']} candidates reviewed so far: {q['approved_ever']} approved, {q['revise_ever']} sent back, "
              f"{q['rejected_ever']} rejected · {q['acceptance']}% right as drafted")
        if q["ratings"]:
            print("  mean rating: " + " · ".join(f"{k} {v}" for k, v in q["ratings"].items()))
        if q["second_opinions"]:
            print(f"  {q['second_opinions']} rule texts seen by more than one reviewer, {q['second_opinions_agree']} with the same verdict")
    first = next((r["id"] for r in doc["candidates"] if r["review"] in ("unreviewed", "stale")), None)
    if first:
        print(f"\n{DIM}next: rasd review {first}{RESET}")


def print_audit(lane: grow.Lane, last: int) -> int:
    trail = governance.read_trail(lane.trail)
    problems = governance.trail_problems(lane.trail)
    for e in trail[-last:]:
        what = e.get("candidate") or e.get("technique") or ""
        extra = e.get("verdict") or e.get("reason") or e.get("source") or ""
        print(f"  {e.get('n'):>5}  {e.get('at')}  {e.get('event'):<10} {what:<46} {DIM}{e.get('by')}{' · ' + str(extra)[:70] if extra else ''}{RESET}")
    for p in problems:
        print(f"{RED}✗{RESET} {p}")
    if not problems:
        print(f"{GREEN}✓{RESET} {len(trail)} lines, each chained to the one before it")
    return 1 if problems else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("candidate", nargs="?", help="a candidate of the lane (its id, or a part of it that names one)")
    verdict = ap.add_mutually_exclusive_group()
    verdict.add_argument("--approve", action="store_const", const="approve", dest="verdict")
    verdict.add_argument("--revise", action="store_const", const="revise", dest="verdict")
    verdict.add_argument("--reject", action="store_const", const="reject", dest="verdict")
    ap.add_argument("--promote", action="store_true", help="an approved candidate becomes the start of a core detection")
    ap.add_argument("--withdraw", action="store_true", help="take the candidate out of the lane")
    ap.add_argument("--rollback", metavar="RUN", help="take out every candidate one run drafted (the run's name in the trail)")
    ap.add_argument("--by", metavar="NAME", help="who decides: a person's name")
    ap.add_argument("--note", help="why, in a sentence")
    ap.add_argument("--rate", nargs="+", default=[], metavar="CRITERION=1..5", help=f"with --approve or --revise: {', '.join(governance.CRITERIA)}")
    ap.add_argument("--audit", nargs="?", const=20, type=int, metavar="N", help="the last N lines of the audit trail (20), and its chain")
    ap.add_argument("--backfill", action="store_true", help="record the candidates that were in the lane before the trail was kept")
    ap.add_argument("--check", action="store_true", help="fail when the records do not hold together (CI)")
    ap.add_argument("--json", action="store_true", help="the board as JSON")
    args = ap.parse_args()
    lane = grow.Lane()
    acting = args.verdict or args.promote or args.withdraw or args.rollback
    if acting and not args.by:
        ap.error("--by NAME: a decision carries the name of the person who took it")
    if (args.verdict or args.promote or args.withdraw) and not args.candidate:
        ap.error("name the candidate")
    try:
        if args.check:
            problems = check(lane)
            for p in problems:
                print(f"{RED}[FAIL]{RESET} {p}")
            if not problems:
                q = board(lane)["quality"]
                print(f"{GREEN}[ OK ]{RESET} governance: {len(governance.read_trail(lane.trail))} lines of trail, chained and complete · "
                      f"{q['approved'] + q['revise']} of {q['candidates']} candidates reviewed by a person · none deployed, none in the "
                      "core without an approval")
            return 1 if problems else 0
        if args.audit is not None:
            return print_audit(lane, max(1, args.audit))
        if args.backfill:
            filled = backfill(lane)
            print(f"{len(filled)} candidates recorded as in the lane before the trail was kept" if filled else
                  "every candidate is already accounted for")
            return 0
        if args.rollback:
            out = rollback(lane, args.rollback, args.by, args.note or "")
            print(f"{len(out)} candidates of run {args.rollback} taken out: {', '.join(out) or 'none still in the lane'}")
            return 0
        if args.verdict:
            entry = decide(lane, args.candidate, args.verdict, args.by, args.note, ratings_of(args.rate))
            done = {"approve": "approved", "revise": "to revise", "reject": "rejected and taken out of the lane"}[args.verdict]
            print(f"{GREEN}recorded{RESET} {entry['candidate']}: {done}, by {entry['by']}, for the rule text {entry['rule_sha256'][:16]}")
            if args.verdict == "approve":
                print(f"{DIM}it stays outside the core until: rasd review {entry['candidate']} --promote --by \"{entry['by']}\"{RESET}")
            return 0
        if args.promote:
            folder = promote(lane, args.candidate, args.by)
            print(f"{GREEN}promoted{RESET} {folder.name} → {folder.relative_to(ROOT).as_posix()}")
            print("  the rule and the tests are the approved ones; contract.yml, tuning.yml, tests/mutations.yml and README.md hold")
            print("  TODO marks: finish them, then: rasd build && rasd ci")
            return 0
        if args.withdraw:
            cand = find(lane, args.candidate)
            withdraw(lane, cand, args.by, args.note or "")
            print(f"{cand.id} taken out of the lane; its technique returns to the queue with your reason")
            return 0
        if args.candidate:
            print(dossier(lane, find(lane, args.candidate)))
            return 0
        doc = board(lane)
        if args.json:
            print(json.dumps(doc, indent=2, ensure_ascii=False))
        else:
            print_board(doc)
        return 0
    except (ReviewError, governance.GovernanceError) as e:
        print(f"{RED}rasd review{RESET}: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
