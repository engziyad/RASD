#!/usr/bin/env python3
"""
governance.py - the records that keep RASD-Agent's lane answerable to people.

Two files beside the lane's ledger, read by `rasd grow` and written through `rasd review`:

  agent/reviews.yml    what a person decided about a candidate: approve, revise or reject, by whom, when,
                       and the SHA-256 of the rule text that was judged. A review stands only for that
                       text: when the rule changes, the review no longer counts. The lane's unattended
                       run may not change this file (rasd grow --guard), so the agent cannot approve
                       its own work
  agent/audit.jsonl    every decision taken in the lane, by the agent or by a person, one line each, in
                       order: drafted, refused, declined, retired, set aside, reviewed, promoted,
                       withdrawn. Each line carries the SHA-256 of the line before it, so a line changed,
                       removed or moved breaks the chain at that point, and the unattended run may only
                       add lines at the end

This module is the data layer: it reads, writes and verifies the two files and knows nothing of the
gates. tools/review.py is the command people use; tools/grow.py records what the agent does.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

FORMAT = 1
AGENT = "RASD-Agent"
VERDICTS = ("approve", "revise", "reject")
CRITERIA = {"logic": "the rule describes the technique, not only the examples it was drafted with",
            "telemetry": "the log source and the fields are the right ones to see it",
            "noise": "it would stay quiet on ordinary administration",
            "mapping": "the ATT&CK technique and the severity are right"}
EVENTS = {"drafted": ("candidate", "technique", "rule_sha256", "source", "run"),
          "backfilled": ("candidate", "technique", "rule_sha256", "drafted"),
          "refused": ("technique", "reason", "source", "run"),
          "declined": ("technique", "reason", "source", "run"),
          "retired": ("candidate", "technique", "reason", "run"),
          "set_aside": ("candidate", "technique", "run"),
          "reviewed": ("candidate", "rule_sha256", "verdict"),
          "promoted": ("candidate", "detection", "rule_sha256"),
          "withdrawn": ("candidate", "technique", "reason")}
AGENT_EVENTS = ("drafted", "backfilled", "refused", "declined", "retired", "set_aside")
GENESIS = "0" * 64
SHA256 = re.compile(r"[0-9a-f]{64}")
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
PERSON = re.compile(r"[^\x00-\x1f|\[\]<>`]{2,80}")
REVIEWS_HEADER = ("# What people decided about the candidates of RASD-Agent's lane (detect/candidates), written by `rasd review`.\n"
                  "# A review stands only for the rule text whose SHA-256 it records. The lane's unattended run may not change this file.\n")


class GovernanceError(Exception):
    """A record that cannot be written as asked, or a file that is not what this module writes."""


def digest(text: str | bytes) -> str:
    return hashlib.sha256(text.encode("utf-8") if isinstance(text, str) else text).hexdigest()


def rule_digest(folder: Path) -> str:
    """SHA-256 of a candidate's rule.yml as it is on disk: the text a review judges."""
    return digest((folder / "rule.yml").read_bytes())


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- #
# reviews
# --------------------------------------------------------------------------- #
def person(name: object) -> str:
    """A reviewer's name as it is recorded: a person, never the agent."""
    text = " ".join(str(name or "").split())
    if not PERSON.fullmatch(text):
        raise GovernanceError("--by takes the reviewer's name: 2 to 80 characters, plain text")
    if text.lower().replace("-", " ").replace("_", " ") in ("rasd agent", "agent", "model", "ai", "github actions[bot]", "github actions"):
        raise GovernanceError(f"a decision is a person's: '{text}' cannot sign one")
    return text


def load_reviews(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        raise GovernanceError(f"{path.name} is not valid YAML: {e}") from e
    if not isinstance(doc, dict) or doc.get("rasd_reviews") != FORMAT or not isinstance(doc.get("reviews", []), list):
        raise GovernanceError(f"{path.name} is not a review ledger written by `rasd review` (rasd_reviews: {FORMAT})")
    return [r for r in doc.get("reviews") or [] if isinstance(r, dict)]


def save_reviews(path: Path, reviews: Sequence[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = yaml.safe_dump({"rasd_reviews": FORMAT, "reviews": [dict(r) for r in reviews]}, sort_keys=False, allow_unicode=True, width=1000)
    path.write_text(REVIEWS_HEADER + body, encoding="utf-8", newline="\n")


def review_problems(reviews: Sequence[Mapping[str, Any]]) -> list[str]:
    out = []
    for i, r in enumerate(reviews, 1):
        where = f"review #{i} ({r.get('candidate', '?')})"
        if not isinstance(r.get("candidate"), str) or not r["candidate"]:
            out.append(f"{where}: no candidate")
        if not SHA256.fullmatch(str(r.get("rule_sha256", ""))):
            out.append(f"{where}: rule_sha256 is not the SHA-256 of a rule text")
        if r.get("verdict") not in VERDICTS:
            out.append(f"{where}: verdict must be one of {', '.join(VERDICTS)}")
        if not DATE.fullmatch(str(r.get("date", ""))):
            out.append(f"{where}: date must be YYYY-MM-DD")
        try:
            person(r.get("by"))
        except GovernanceError as e:
            out.append(f"{where}: {e}")
        if r.get("verdict") in ("revise", "reject") and len(str(r.get("note") or "")) < 10:
            out.append(f"{where}: a {r.get('verdict')} needs a note saying what is wrong")
        ratings = r.get("ratings") or {}
        if not isinstance(ratings, dict) or any(k not in CRITERIA or v not in (1, 2, 3, 4, 5) for k, v in ratings.items()):
            out.append(f"{where}: ratings are 1 to 5 for {', '.join(CRITERIA)}")
    return out


def new_review(candidate: str, rule_sha256: str, verdict: str, by: str, date: str, note: str | None = None,
               ratings: Mapping[str, int] | None = None) -> dict:
    entry: dict[str, Any] = {"candidate": candidate, "rule_sha256": rule_sha256, "verdict": verdict, "by": person(by), "date": date}
    if note:
        entry["note"] = " ".join(str(note).split())[:600]
    if ratings:
        entry["ratings"] = dict(ratings)
    problems = review_problems([entry])
    if problems:
        raise GovernanceError(problems[0].split(": ", 1)[1])
    return entry


def standing(candidate: str, rule_sha256: str, reviews: Sequence[Mapping[str, Any]]) -> dict:
    """Where a candidate stands with people: unreviewed, approved, revise, or stale when the latest review
    judged another text of the rule. `review` is the review that decides it."""
    mine = [r for r in reviews if r.get("candidate") == candidate]
    if not mine:
        return {"state": "unreviewed", "review": None}
    last = mine[-1]
    if last.get("rule_sha256") != rule_sha256:
        return {"state": "stale", "review": dict(last)}
    return {"state": {"approve": "approved", "revise": "revise", "reject": "rejected"}[str(last.get("verdict"))], "review": dict(last)}


def quality(reviews: Sequence[Mapping[str, Any]], in_lane: Mapping[str, str]) -> dict:
    """What people's reviews say about what the gates let through. in_lane: candidate -> its rule's SHA-256.
    Every candidate ever reviewed counts once, by the last review of the last text reviewed."""
    last: dict[str, Mapping[str, Any]] = {}
    for r in reviews:
        last[str(r.get("candidate"))] = r
    verdicts = [str(r.get("verdict")) for r in last.values()]
    rated: dict[str, list[int]] = {}
    for r in last.values():
        for key, value in (r.get("ratings") or {}).items():
            rated.setdefault(key, []).append(int(value))
    by_text: dict[tuple[str, str], dict[str, str]] = {}
    for r in reviews:
        by_text.setdefault((str(r.get("candidate")), str(r.get("rule_sha256"))), {})[str(r.get("by"))] = str(r.get("verdict"))
    second = [set(v.values()) for v in by_text.values() if len(v) > 1]
    states = [standing(c, sha, reviews)["state"] for c, sha in in_lane.items()]
    return {"candidates": len(in_lane), "unreviewed": states.count("unreviewed"), "approved": states.count("approved"),
            "revise": states.count("revise"), "stale": states.count("stale"),
            "reviewed_ever": len(last), "approved_ever": verdicts.count("approve"), "rejected_ever": verdicts.count("reject"),
            "revise_ever": verdicts.count("revise"),
            "acceptance": round(100 * verdicts.count("approve") / len(verdicts)) if verdicts else None,
            "ratings": {k: round(sum(v) / len(v), 1) for k, v in sorted(rated.items())},
            "second_opinions": len(second), "second_opinions_agree": sum(1 for s in second if len(s) == 1)}


# --------------------------------------------------------------------------- #
# the audit trail
# --------------------------------------------------------------------------- #
def read_trail(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as e:
            raise GovernanceError(f"{path.name} line {n} is not JSON: {e}") from e
        if not isinstance(entry, dict):
            raise GovernanceError(f"{path.name} line {n} is not a record")
        out.append(entry)
    return out


def trail_problems(path: Path) -> list[str]:
    """Everything that makes the trail less than a record: a line that is not what was written, a number
    out of order, a link to the line before that does not hold."""
    if not path.exists():
        return []
    out: list[str] = []
    prev = GENESIS
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return [*out, f"{path.name} line {n} is not JSON: the trail cannot be read past it"]
        if not isinstance(entry, dict):
            return [*out, f"{path.name} line {n} is not a record"]
        if json.dumps(entry, ensure_ascii=False, separators=(",", ":")) != line:
            out.append(f"{path.name} line {n} is not written the way the trail writes a line")
        if entry.get("n") != n:
            out.append(f"{path.name} line {n} carries the number {entry.get('n')}: a line was removed, added or moved")
        if entry.get("prev") != prev:
            out.append(f"{path.name} line {n} does not follow the line before it: the chain breaks here")
        event = entry.get("event")
        if event not in EVENTS:
            out.append(f"{path.name} line {n}: unknown event {event!r}")
        else:
            missing = [k for k in ("at", "by", *EVENTS[event]) if entry.get(k) in (None, "")]
            if missing:
                out.append(f"{path.name} line {n} ({event}) lacks {', '.join(missing)}")
            if event in AGENT_EVENTS and entry.get("by") != AGENT:
                out.append(f"{path.name} line {n}: {event} is the agent's to record, not {entry.get('by')!r}")
            if event not in AGENT_EVENTS and entry.get("by") == AGENT:
                out.append(f"{path.name} line {n}: {event} is a person's decision, and the agent signed it")
        prev = digest(line)
    return out


def append(path: Path, event: str, by: str, at: str | None = None, **fields: Any) -> dict:
    """Add one line to the end of the trail, linked to the line before it."""
    if event not in EVENTS:
        raise GovernanceError(f"unknown event {event!r}")
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    entry: dict[str, Any] = {"n": len(lines) + 1, "at": at or now(), "event": event, "by": by}
    for key, value in fields.items():
        if value is not None and value != "":
            entry[key] = " ".join(value.split())[:300] if isinstance(value, str) else value
    missing = [k for k in EVENTS[event] if k not in entry]
    if missing:
        raise GovernanceError(f"{event} needs {', '.join(missing)}")
    entry["prev"] = digest(lines[-1]) if lines else GENESIS
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n")
    return entry


def only_appended(before: str, after: str) -> bool:
    """The trail as it is now starts with the trail as it was: lines were added at the end and nothing else."""
    return after.startswith(before) and (not before or before.endswith("\n"))


def origin(trail: Sequence[Mapping[str, Any]], candidate: str, rule_sha256: str) -> dict | None:
    """The record of how a candidate with this rule text came to be in the lane."""
    for entry in reversed(trail):
        if entry.get("event") in ("drafted", "backfilled") and entry.get("candidate") == candidate and entry.get("rule_sha256") == rule_sha256:
            return dict(entry)
    return None
