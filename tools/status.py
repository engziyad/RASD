#!/usr/bin/env python3
"""
rasd status: where every detection stands, what proves it, and what to do next.

  rasd status                    the five questions, answered from the record
  rasd status --gaps             every detection short of Verified, and why
  rasd status --critical         the gaps to close first
  rasd status --next             what to do next, and the detections each action moves on
  rasd status --detection ID     one detection, stage by stage, each stage with what proves it
  rasd status --health FILE      production health (the JSON of `rasd health --json`) read into the verdicts
  rasd status --as-of today      the evidence's freshness judged at today's date, not the newest evidence's
  rasd status --json             the record itself
  rasd status --fresh            recompute the record instead of reading status/status.json
  rasd status --write | --check  write the record, its page and the front page's status, or fail when they are out of
                                 date or two components contradict each other (CI)

The status is RASD's Decision layer. Nothing in it is typed: it is made from the Foundation (each detection's
rule, contract and response, and the offensive steps that reach it) and from the Assurance layer (what the build
proves on every run, the public attack recordings, the lab runs kept in purple/lab_runs, the evidence written from
them and what the lab's live SIEM said). status/status.json is the one record of every detection's state. The page,
this command and the front page all read it, so they cannot disagree.

Each detection gets one of eight verdicts (STATES). Code checks can only fail a detection: no number of passing
tests makes it Verified. That takes a real attack step that fired in a lab, the alert a live SIEM raised for it,
and evidence younger than FRESH_DAYS. The record also looks for components that contradict each other (an alert
credited to a search the SIEM says did not run, a page that states a lab result the evidence does not hold), and
--check fails on any.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from typing import Any
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import yaml

from common import ROOT

FORMAT = 1
OUT = ROOT / "status"
JSON_FILE = OUT / "status.json"
PAGE = OUT / "README.md"
FRONT = ROOT / "README.md"
STATUS_START, STATUS_END = "<!-- rasd:status:start -->", "<!-- rasd:status:end -->"
QUESTIONS_START, QUESTIONS_END = "<!-- rasd:questions:start -->", "<!-- rasd:questions:end -->"
FRESH_DAYS = 90                      # lab evidence older than this, at the record's as-of date, is Stale

STATES = {
    "Verified": "fired on a real attack step in a lab, and a live SIEM raised its alert; the evidence is fresh",
    "Partially Verified": "fired on its attack step in a lab, but the SIEM alert or the verified cleanup is missing",
    "Unverified": "passes its code checks; no lab run has fired it on its attack step yet",
    "Failed": "a check it must pass did not: a test, a proof, its lab step or the SIEM",
    "Blocked": "the lab could not run its attack step, for a reason the run recorded, or no step reaches it",
    "Degraded": "proven in a lab, and production health now says its events are not arriving as they should",
    "Stale": f"its lab evidence is more than {FRESH_DAYS} days older than the record's date",
    "Unknown": "its Foundation is incomplete (no tests, or no telemetry contract), so there is nothing to judge",
}
ORDER = ["Failed", "Degraded", "Stale", "Blocked", "Unknown", "Unverified", "Partially Verified", "Verified"]   # worst first
DISPLAY = ["Verified", "Partially Verified", "Unverified", "Failed", "Blocked", "Degraded", "Stale", "Unknown"]
MARK = {"Verified": "✅", "Partially Verified": "🟡", "Unverified": "⚪", "Failed": "❌", "Blocked": "⛔",
        "Degraded": "🟠", "Stale": "⏳", "Unknown": "❔"}
CODE_LAYERS = ("code", "replay")
LIVE_LAYERS = ("lab", "siem", "health", "noise")
MATURITY = ["draft", "tested", "hardened", "siem-ready", "validated", "reference"]
CRITICAL_LEVELS = ("high", "critical")

# What stops a step on a lab, read from the reason or error its run recorded: (pattern, blocker kind).
BLOCKERS = [
    (r"^opt-in", "opt-in"),
    (r"missing parameter: -(Spn|UserList)", "domain"),
    (r"domain either does not exist|could not be contacted|not joined to a domain|no domain", "domain"),
    (r"missing parameter: -Target", "target"),
]
BLOCKER_TEXT = {
    "opt-in": "its step is opt-in, so it runs only on a lab VM of your own, from a snapshot",
    "domain": "its step needs a lab domain: a lab host joined to it, and its domain controller",
    "target": "its step needs a second lab host to reach",
    "no step": "no offensive step reaches it yet",
}
OPT_IN = {"IncludeCredentialAccess": "it dumps LSASS memory", "IncludeSecurityLogClear": "it clears the Security log"}
NEXT = {
    "opt-in": ("On a lab VM of your own, from a snapshot: add `-IncludeCredentialAccess -IncludeSecurityLogClear` to "
               "`red/lab/Invoke-RasdLabRun.ps1 -LabConfirmed`, then give the run and its SIEM alert export to `rasd evidence --run`"),
    "domain": ("On a lab domain of your own: join the lab VM to it, set the DC's audit policy (`red/lab/Test-LabReadiness.ps1 "
               "-Fix`), add `-Spn <lab SPN> -UserList <file of lab accounts>` to `red/lab/Invoke-RasdLabRun.ps1 -LabConfirmed`, "
               "then give the run and the DC's Security export (`red/Export-LabTelemetry.ps1 -LogName Security`) to "
               "`rasd evidence --run`"),
    "target": "Add `-Target <second lab VM>` to `red/lab/Invoke-RasdLabRun.ps1 -LabConfirmed`, and give the target's export to "
              "`rasd evidence --run`",
    "no step": "Add a red test step that names it (`red/<platform>/<test>/test.yml`, then `rasd red`)",
    "lab": ("Run the lab: the `lab-run.yml` workflow (hosted runners, a live Splunk when its terms are accepted), or "
            "`red/lab/Invoke-RasdLabRun.ps1 -LabConfirmed` on a lab of your own, then `rasd evidence --run`"),
    "siem": "Run the lab with its SIEM beside it and give the alert export (`red/lab/splunk_lab.py export`) to `rasd evidence --run`",
    "cleanup": "Run its step again until the run records the cleanup as verified",
    "stale": "Run the lab again (the `lab-run.yml` workflow, or the wave of docs/EVIDENCE_PLAN.md it is in): its evidence is past its freshness",
    "noise": ("Decide on the lab alerts no step asked for and on the tuning proposed (`rasd tune --filter` with the "
              "detection's id shows what each proposal would silence)"),
    "dfir": "Collect the artifacts its closure note names at the next lab run: the evidence holds none for the investigation",
    "health": ("Restore the feed `rasd health` names (its finding says what to check first), then read production again: "
               "`rasd health --json`, then `rasd status --health`"),
}
VERDICT_MOVES = ("domain", "opt-in", "target", "no step", "lab", "siem", "cleanup", "foundation")
HOW = [
    "**Failed** when a check it must pass did not: a test, a proof, the public recordings it is expected to fire on, "
    "its lab step (the step ran and it did not fire) or the SIEM (the step fired and the SIEM beside the lab raised no alert).",
    "**Degraded** when production health, read with `rasd status --health`, says its events are not arriving as they should.",
    f"**Stale** when its lab evidence is more than {FRESH_DAYS} days older than the record's date.",
    "**Verified** when its step fired in a lab, a live SIEM raised the alert and the cleanup was verified.",
    "**Partially Verified** when its step fired in a lab but the SIEM alert or the verified cleanup is missing.",
    "**Blocked** when it has no lab evidence and the lab could not run its step, for a reason the kept run recorded "
    "(an opt-in step, no domain), or when no offensive step reaches it.",
    "**Unknown** when its Foundation is incomplete (no tests, or no telemetry contract), so there is nothing to judge.",
    "**Unverified** otherwise: it passes its code checks and no lab run has fired it yet. Code checks can only fail a "
    "detection: no number of them makes it Verified.",
]


@dataclass
class Check:
    stage: str
    layer: str                  # code | replay | lab | siem | health | noise
    state: str                  # passed | failed | limit | pending | blocked | missing | unknown | attention | degraded | n/a
    detail: str
    proof: str | None = None    # repository path that holds what this stage rests on


@dataclass
class Record:
    id: str
    kind: str
    technique: str
    title: str
    level: str
    folder: str
    verdict: str = "Unknown"
    why: str = ""
    critical: bool = False
    blocker: str | None = None
    next: str | None = None
    next_key: str | None = None
    also: list[dict] = field(default_factory=list)   # further actions: {key, text}, after the next one
    evidence: dict | None = None
    foundation: dict = field(default_factory=dict)
    checks: list[Check] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)

    def check(self, stage: str) -> Check | None:
        return next((c for c in self.checks if c.stage == stage), None)


@dataclass
class Context:
    """What the kept lab runs hold, read once for every detection."""
    parts: list = field(default_factory=list)
    steps: dict[str, list[tuple[str, dict]]] = field(default_factory=dict)   # detection -> (part label, step record)
    by_digest: dict[str, Any] = field(default_factory=dict)                 # results SHA-256 -> part
    about: dict[str, dict | None] = field(default_factory=dict)             # part label -> the SIEM's own description
    searches: dict[str, list[dict]] = field(default_factory=dict)           # part label -> what the SIEM said of each search
    unasked: dict[str, int] = field(default_factory=dict)                   # detection -> alerts with no step asking for them
    health: dict[str, dict] = field(default_factory=dict)                   # detection -> production health verdict


def _rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _day(value: object) -> date | None:
    text = str(value or "")[:10]
    try:
        return date.fromisoformat(text)
    except ValueError:
        return None


def _minutes(seconds: object) -> str:
    try:
        value = float(seconds)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "?"
    return f"{value:.0f} s" if value < 90 else f"{value / 60:.0f} min"


def context(store: Path | None = None, entries: list | None = None, health_file: Path | None = None) -> Context:
    import evidence
    store = store or evidence.STORE
    ctx = Context()
    ctx.parts = evidence.kept_parts(store)[0]
    for part in ctx.parts:
        digest = evidence.results_digest(part)
        if digest:
            ctx.by_digest[digest] = part
        about, _ran = evidence.part_siem(part)
        ctx.about[part.label] = about
        for record in evidence.part_results(part):
            for det_id in [*(record.get("detections") or []), *(record.get("correlations") or [])]:
                ctx.steps.setdefault(str(det_id), []).append((part.label, record))
    ctx.searches = evidence.siem_records(store)
    ctx.unasked = evidence.live_siem(store, entries)["unasked"]
    if health_file:
        ctx.health = production_health(health_file)
    return ctx


def production_health(path: Path) -> dict[str, dict]:
    """detection -> its verdict in a `rasd health --json` file: what production said, not what the lab did."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"rasd status: cannot read {path}: {exc}") from exc
    if not isinstance(doc, dict) or "rasd_health" not in doc:
        raise SystemExit(f"rasd status: {path} is not the JSON of `rasd health --json`")
    window = doc.get("current") or {}
    out = {}
    for row in doc.get("detections") or []:
        if isinstance(row, dict) and row.get("detection"):
            out[str(row["detection"])] = {"verdict": str(row.get("verdict")), "findings": row.get("findings") or [],
                                          "window": f"{str(window.get('start', ''))[:16]} to {str(window.get('end', ''))[:16]} UTC",
                                          "file": path.name}
    return out


# ---- the stages -----------------------------------------------------------------------------------------------------
def code_checks(repo, d, f: dict) -> list[Check]:
    import chain
    from correlation import Correlation
    det = chain.det_path(d)
    out = []
    tp, tn = f["tp"], f["tn"]
    state = "failed" if not f["tests_pass"] else ("passed" if tp >= 4 and tn >= 4 else "attention")
    out.append(Check("Tests", "code", state,
                     f"{tp} true positives and {tn} true negatives, " + ("all pass" if f["tests_pass"] else "not all pass")
                     + ("" if state != "attention" else "; the house rule is four of each"), f"{det}/tests/"))
    if isinstance(d, Correlation):
        state = "passed" if f["mutations_pass"] and f["param_survivors"] == 0 else "failed"
        out.append(Check("Mutations", "code", state, f"{f['mutations']} evasion mutations and {f['param_mutants']} parameter "
                         f"mutants; {f['param_survivors']} survive", f"{det}/tests/mutations.yml"))
        state = "passed" if f["tests_pass"] and f["scenarios"] else "failed"
        out.append(Check("Scenarios", "code", state, f"{f['scenarios']} scenarios ({f['scenarios_fire']} that must fire, "
                         f"{f['limits']} documented limit{'' if f['limits'] == 1 else 's'}); burst guarantee: {f['guarantee'] or 'none'}", f"{det}/tests/scenarios.yml"))
    else:
        state = "passed" if f["mutations_pass"] and f["proof"] == 100 else "failed"
        out.append(Check("Mutations", "code", state, f"{f['mutations']} evasion mutations caught; every value, field and branch "
                         f"of the rule proven by a test ({f['proof']:.0f}%)", f"{det}/tests/mutations.yml"))
    state = "passed" if f["fuzz"] == 100 else "failed"
    out.append(Check("Evasion fuzzer", "code", state, f"{f['fuzz_variants']} generated evasions, resistance {f['fuzz']:.0f}%",
                     "docs/PROOFS.md"))
    state = "passed" if f["parity_ok"] else "failed"
    out.append(Check("Query parity", "code", state, f"the generated KQL and SPL return the rule's verdict on {f['parity_events']} "
                     "events (RASD's model of each language, not a SIEM)" if state == "passed" else
                     "a generated query and the rule disagree", f"queries/spl/{'correlations/' if isinstance(d, Correlation) else ''}"
                     f"{d.id}.spl"))
    if not isinstance(d, Correlation):
        row = repo.certify_rows.get(d.id)
        if row:
            out.append(Check("Exact automaton", "code", "passed", f"compiled to {row['states']} states over {row['fields']} "
                             "fields; a firing event and its nearest quiet event built and replayed",
                             "docs/CERTIFICATES.md"))
        else:
            out.append(Check("Exact automaton", "code", "failed", "the rule did not compile to an automaton", "docs/CERTIFY.md"))
    return out


def replay_check(repo, d) -> Check:
    pub = repo.public.get(d.id) or {}
    held = pub.get("holdout") or {}
    expected, fired = pub.get("expected") or [], pub.get("independent") or pub.get("fired") or []
    proof = f"{_folder(d)}/public_evidence.md"
    if not expected and not held.get("expected"):
        return Check("Public attack data", "replay", "n/a", "no public recording of this behaviour", proof)
    detail = f"fires on {len(fired)} of {pub.get('recordings') or len(expected)} public recordings"
    if held.get("expected"):
        detail += f"; held-out files: {len(held.get('met') or [])} of {len(held['expected'])} expectations met"
    if expected and not pub.get("validated"):
        return Check("Public attack data", "replay", "failed", detail + "; it fires on none it is expected to", proof)
    if held.get("missed"):
        return Check("Public attack data", "replay", "limit", detail + "; missed: " + ", ".join(held["missed"])
                     + " (a documented limit, see the public data page)", proof)
    return Check("Public attack data", "replay", "passed", detail, proof)


def _folder(d) -> str:
    return _rel(d.folder)


def _quote(said: str, pattern: str) -> str:
    """The part of a recorded reason or error that says why: a .NET error wraps it in quotes and parentheses."""
    parts = [" ".join(f.split()).strip(" .:") for f in re.split(r'["()]', said)]
    return next((f for f in parts if re.search(pattern, f, re.I)), " ".join(said.split()))[:160]


def lab_checks(repo, d, ev: dict | None, ctx: Context) -> tuple[list[Check], str | None]:
    """The lab, the SIEM beside it and the cleanup; and the blocker when there is no lab evidence."""
    import chain
    det = _folder(d)
    if ev:
        part = ctx.by_digest.get(((ev.get("inputs") or {}).get("results") or {}).get("sha256", ""))
        label = getattr(part, "label", None)
        where = f"purple/lab_runs/{label}" if label else f"{det}/evidence.md"
        lab = Check("Lab run", "lab", "passed" if ev.get("result") == "fired" else "failed",
                    f"{'fired' if ev.get('result') == 'fired' else ev.get('result')} on {ev.get('host')} at "
                    f"{str(ev.get('run_utc', ''))[:16].replace('T', ' ')} UTC, step {ev.get('test')}/{ev.get('step')}, "
                    f"bound by {ev.get('bound_by')}", f"{det}/evidence.md")
        siem = ev.get("siem") or {}
        about = ctx.about.get(label) if label else None
        if int(siem.get("alerts") or 0) >= 1:
            platform = str(siem.get("platform") or "the SIEM").split(" (build")[0]
            siem_check = Check("Live SIEM", "siem", "passed", f"{platform} raised `{siem.get('alert_name')}` "
                               f"{_minutes(siem.get('latency_seconds'))} after the step", f"{where}/siem-alerts.csv")
        elif about:
            siem_check = Check("Live SIEM", "siem", "failed", f"{about.get('product')} {about.get('version')} stood beside the "
                               "lab host and raised no alert for it", f"{where}/siem-alerts.csv")
        else:
            siem_check = Check("Live SIEM", "siem", "missing", "the run that fired it had no SIEM beside it", where)
        cleanup = Check("Cleanup", "lab", "passed" if ev.get("cleanup") == "verified" else "missing",
                        "the step undid what it did, and the run checked it" if ev.get("cleanup") == "verified"
                        else f"cleanup: {ev.get('cleanup') or 'not recorded'}", f"{det}/evidence.md")
        return [lab, siem_check, cleanup], None
    reds = repo.red_for_detection(d.id)
    seen = ctx.steps.get(d.id, [])
    if not reds and not seen:
        kind = "no step"
        why = BLOCKER_TEXT[kind]
        if type(d).__name__ == "Correlation":
            why += f": a burst that reaches its threshold ({repo.det_facts(d)['describe']}) from one lab host"
        return [Check("Lab run", "lab", "blocked", why, "docs/EVIDENCE_PLAN.md"),
                Check("Live SIEM", "siem", "blocked", "needs the lab step first", None)], kind
    ran = [(label, s) for label, s in seen if s.get("status") == "executed"]
    if ran:
        label, s = ran[-1]
        return [Check("Lab run", "lab", "failed", f"its step {s.get('test')}/{s.get('step')} ran in {label} and it did not fire",
                      f"purple/lab_runs/{label}"),
                Check("Live SIEM", "siem", "pending", "nothing to alert on: the detection did not fire", None)], None
    if seen:
        label, s = seen[-1]
        said = str(s.get("reason") or s.get("error") or s.get("status") or "")
        hit = next(((pattern, k) for pattern, k in BLOCKERS if re.search(pattern, said, re.I)), None)
        found: str | None = hit[1] if hit else None
        said = _quote(said, hit[0]) if hit else " ".join(said.split())[:160]
        if found:
            why = BLOCKER_TEXT[found]
            if found == "opt-in":
                what = next((text for flag, text in OPT_IN.items() if flag in said), None)
                why = f"its step is opt-in ({what})" + why.split("opt-in", 1)[1] if what else why
            return [Check("Lab run", "lab", "blocked", f"{why}; the run {label} recorded for "
                          f"{s.get('test')}/{s.get('step')}: {s.get('status')}, \"{said}\"", f"purple/lab_runs/{label}"),
                    Check("Live SIEM", "siem", "blocked", "needs the lab step first", None)], found
        return [Check("Lab run", "lab", "pending", f"{s.get('test')}/{s.get('step')} did not run in {label}: {said}",
                      f"purple/lab_runs/{label}"),
                Check("Live SIEM", "siem", "pending", "needs the lab step first", None)], None
    waves = {chain.wave_of(t, step) for t in reds for step in t.get("steps") or []
             if d.id in [*(step.get("detections") or []), *(step.get("correlations") or [])]}
    if waves and waves <= {"opt_in", "dc"}:
        kind = "opt-in" if waves == {"opt_in"} else "domain"
        return [Check("Lab run", "lab", "blocked", BLOCKER_TEXT[kind] + " (no kept run has tried it)", "docs/EVIDENCE_PLAN.md"),
                Check("Live SIEM", "siem", "blocked", "needs the lab step first", None)], kind
    return [Check("Lab run", "lab", "pending", "no kept lab run has run its step yet", "docs/EVIDENCE_PLAN.md"),
            Check("Live SIEM", "siem", "pending", "needs the lab step first", None)], None


def health_check(d, ev: dict | None, ctx: Context) -> Check:
    prod = ctx.health.get(d.id)
    if prod:
        verdict = prod["verdict"]
        worst = next((f for f in prod["findings"] if f.get("level") in ("blind", "degraded")), None)
        if verdict in ("blind", "degraded"):
            return Check("Telemetry health", "health", "degraded", f"production ({prod['window']}): {verdict}; "
                         + (worst.get("text") if worst else "its events are not arriving as they should"), prod["file"])
        if verdict == "healthy":
            return Check("Telemetry health", "health", "passed", f"production ({prod['window']}): every kind of event it reads "
                         "arrived as the baseline expects", prod["file"])
        return Check("Telemetry health", "health", "unknown", f"production ({prod['window']}): {verdict}", prod["file"])
    lab, proof = "", "docs/HEALTH.md"
    if ev:
        part = ctx.by_digest.get(((ev.get("inputs") or {}).get("results") or {}).get("sha256", ""))
        label = getattr(part, "label", None)
        rows = [r for r in ctx.searches.get(label or "", []) if str(r.get("name", "")).startswith("RASD Health")]
        if rows:
            quiet = all(r.get("ok") and not int(r.get("results") or 0) for r in rows)
            lab = (f"the {len(rows)} health watchdogs ran beside its lab host with "
                   + ("no row, as a lab in order should" if quiet else "a finding: see the kept run") + "; ")
            proof = f"purple/lab_runs/{label}/siem-searches.json"
    return Check("Telemetry health", "health", "unknown", lab + "production: unknown until its SIEM's numbers are read "
                 "(`rasd health --json`, then `rasd status --health`)", proof)

def noise_check(repo, d, f: dict, ctx: Context) -> Check:
    pub = repo.public.get(d.id) or {}
    alerts = ctx.unasked.get(d.id, 0)
    fps = int(pub.get("false_positives") or 0)
    tuning = d.folder / "tuning.yml"
    proposed = []
    if tuning.exists():
        doc = yaml.safe_load(tuning.read_text(encoding="utf-8")) or {}
        proposed = [str(t.get("id")) for t in doc.get("tunings") or [] if isinstance(t, dict) and t.get("status") == "proposed"]
    said = [f"{f['tn']} true-negative tests quiet"]
    if pub.get("expected"):
        said.append(f"{fps} labelled false positive{'' if fps == 1 else 's'} in the public lab captures")
    if alerts:
        said.append(f"{alerts} alert{'' if alerts == 1 else 's'} in the lab with no step asking for it")
    if proposed:
        said.append(f"tuning proposed, not applied: {', '.join(proposed)}")
    if alerts or fps:
        return Check("False positives", "noise", "attention", "; ".join(said), f"{_folder(d)}/tuning.yml")
    return Check("False positives", "noise", "unknown", "; ".join(said) + "; no benign baseline of a real environment yet",
                 f"{_folder(d)}/tuning.yml")


# ---- one detection ------------------------------------------------------------------------------------------------------
def judge(rec: Record, as_of: date | None) -> None:
    """The verdict, its reason, the blocker's next step and the gaps, from the checks. Order matters: a failure wins."""
    failed = [c for c in rec.checks if c.state == "failed"]
    degraded = [c for c in rec.checks if c.state == "degraded"]
    lab, siem, cleanup = rec.check("Lab run"), rec.check("Live SIEM"), rec.check("Cleanup")
    fired = bool(lab and lab.state == "passed")
    run_day = _day((rec.evidence or {}).get("run_utc"))
    stale = bool(fired and run_day and as_of and (as_of - run_day).days > FRESH_DAYS)
    foundation_missing = [k for k, v in rec.foundation.items() if k in ("tests", "contract") and not v]
    if failed:
        c = failed[0]
        rec.verdict, rec.why = "Failed", f"{c.stage}: {c.detail}."
        rec.next_key = f"fix:{c.stage}"
        rec.next = {"Lab run": "Read why it did not fire on its step: `rasd evidence` on the kept run, then `rasd explain`",
                    "Live SIEM": "Ask the SIEM why it raised no alert: `red/lab/splunk_lab.py wait` explains a missing alert",
                    "Public attack data": "Read the recording it misses: `rasd datasets` names the events",
                    }.get(c.stage, f"Fix what `rasd ci` reports for {c.stage.lower()}")
    elif degraded and fired:
        c = degraded[0]
        rec.verdict, rec.why = "Degraded", f"Proven in the lab on {run_day}, and {c.detail}."
        rec.next_key, rec.next = "health", NEXT["health"]
    elif stale:
        rec.verdict = "Stale"
        rec.why = f"Its lab evidence of {run_day} is more than {FRESH_DAYS} days older than the record's date ({as_of})."
        rec.next_key, rec.next = "stale", NEXT["stale"]
    elif fired and siem and siem.state == "passed" and cleanup and cleanup.state == "passed":
        rec.verdict = "Verified"
        rec.why = f"Fired on its step in the lab on {run_day}; {siem.detail}."
    elif fired:
        missing = [c for c in (siem, cleanup) if c and c.state != "passed"]
        rec.verdict = "Partially Verified"
        rec.why = f"Fired on its step in the lab on {run_day}, but " + " and ".join(
            ("no live SIEM alert" if c.stage == "Live SIEM" else "the cleanup was not verified") for c in missing) + "."
        first = missing[0].stage if missing else "Live SIEM"
        rec.next_key = "siem" if first == "Live SIEM" else "cleanup"
        rec.next = NEXT[rec.next_key]
    elif lab and lab.state == "blocked":
        rec.verdict, rec.why = "Blocked", f"{lab.detail[0].upper()}{lab.detail[1:]}."
        rec.next_key = rec.blocker or "no step"
        rec.next = NEXT[rec.next_key]
    elif foundation_missing:
        rec.verdict = "Unknown"
        rec.why = "Its Foundation is incomplete: no " + " and no ".join(foundation_missing) + "."
        rec.next_key, rec.next = "foundation", "Complete the detection: `rasd lint` names what is missing"
    else:
        rec.verdict = "Unverified"
        rec.why = "Passes every code check; no lab run has fired it on its attack step yet."
        rec.next_key, rec.next = "lab", NEXT["lab"]
    rec.critical = rec.verdict in ("Failed", "Degraded", "Stale") or (rec.verdict != "Verified" and rec.level in CRITICAL_LEVELS)
    if degraded and rec.verdict != "Degraded":
        rec.gaps.append(f"{degraded[0].stage}: {degraded[0].detail}")
        rec.critical = True
        rec.also.append({"key": "health", "text": NEXT["health"]})
    for c in rec.checks:
        if c.state not in ("limit", "attention"):
            continue
        rec.gaps.append(f"{c.stage}: {c.detail}")
        if c.state == "attention" and c.stage == "False positives":
            rec.critical = rec.critical or rec.level in CRITICAL_LEVELS
            rec.also.append({"key": "noise", "text": NEXT["noise"]})
        elif c.state == "attention" and c.stage == "Tests":
            rec.also.append({"key": "tests", "text": "Add tests up to four true positives and four true negatives (`rasd test`)"})
    parts = (rec.evidence or {}).get("operational_parts") or {}
    if rec.evidence and parts.get("DFIR evidence", 15) == 0:
        rec.gaps.append("DFIR evidence: the lab run collected no artifact for the investigation (its closure note names what "
                        "to collect)")
        rec.also.append({"key": "dfir", "text": NEXT["dfir"]})
    if not rec.next and rec.also:
        step = rec.also.pop(0)
        rec.next_key, rec.next = step["key"], step["text"]

def conflicts(rec: Record, repo, d, ctx: Context) -> list[str]:
    """Components that contradict each other about this detection."""
    out = []
    ev = rec.evidence
    if ev:
        digest = ((ev.get("inputs") or {}).get("results") or {}).get("sha256", "")
        part = ctx.by_digest.get(digest)
        label = getattr(part, "label", None)
        if label:
            same = [s for lab_label, s in ctx.steps.get(d.id, []) if lab_label == label and s.get("test") == ev.get("test")
                    and s.get("step") == ev.get("step")]
            if same and all(s.get("status") != "executed" for s in same):
                out.append(f"its evidence says step {ev.get('test')}/{ev.get('step')} fired, and the kept run {label} says that "
                           "step did not run")
            if int((ev.get("siem") or {}).get("alerts") or 0):
                row = next((r for r in ctx.searches.get(label, []) if r.get("name") == f"RASD - {d.id}"), None)
                if row is not None and not row.get("ok"):
                    out.append(f"its evidence credits an alert to `RASD - {d.id}`, and the SIEM of {label} says that search did "
                               "not run to the end")
        siem = rec.check("Live SIEM")
        parity = rec.check("Query parity")
        if siem and siem.state == "passed" and parity and parity.state == "failed":
            out.append("a live SIEM alerted on it, and its generated query does not return the rule's verdict: the alert "
                       "came from a search that is not the rule")
    declared = str((d.contract or {}).get("maturity") or "").lower()
    computed = repo.maturity(d)
    if declared in MATURITY and MATURITY.index(declared) > MATURITY.index(computed):
        out.append(f"its contract claims {declared}, and the repository proves {computed}")
    return out


def record(repo, d, ctx: Context, as_of: date | None) -> Record:
    import chain
    import evidence
    from correlation import Correlation
    f = repo.det_facts(d)
    ev = repo.evidence[d.id]
    rec = Record(id=d.id, kind="correlation" if isinstance(d, Correlation) else "rule", technique=d.technique, title=d.title,
                 level=str(getattr(d, "level", None) or (d.rule.get("level") if isinstance(d.rule, dict) else None) or "medium"),
                 folder=_folder(d))
    reds = repo.red_for_detection(d.id)
    rec.foundation = {
        "rule": f"{rec.folder}/{'correlation.yml' if rec.kind == 'correlation' else 'rule.yml'}",
        "contract": [str(e) for e in f["events"]],
        "tests": f["tp"] + f["tn"],
        "response": [n for n in ("triage.md", "response.md", "closure.md") if (d.folder / n).exists()],
        "steps": sorted({f"{t['id']}/{s['id']}" for t in reds for s in t.get("steps") or []
                         if d.id in [*(s.get("detections") or []), *(s.get("correlations") or [])]}),
    }
    if ev:
        fresh = _day(ev.get("run_utc"))
        part = ctx.by_digest.get(((ev.get("inputs") or {}).get("results") or {}).get("sha256", ""))
        rec.evidence = {"file": f"{rec.folder}/evidence.md", "run_utc": str(ev.get("run_utc")),
                        "kept": f"purple/lab_runs/{part.label}" if part else None,
                        "fresh_until": str(fresh + timedelta(days=FRESH_DAYS)) if fresh else None,
                        "operational_score": ev.get("operational_score"),
                        "operational_parts": evidence.operational_score(ev)}
    rec.checks = code_checks(repo, d, f) + [replay_check(repo, d)]
    live, rec.blocker = lab_checks(repo, d, ev, ctx)
    rec.checks += live + [health_check(d, ev, ctx), noise_check(repo, d, f, ctx)]
    judge(rec, as_of)
    rec.conflicts = conflicts(rec, repo, d, ctx)
    del chain
    return rec


# ---- the whole record -----------------------------------------------------------------------------------------------------
def build(repo=None, store: Path | None = None, entries: list | None = None, health_file: Path | None = None,
          as_of: date | None = None) -> dict:
    """The record. Its date is the newest lab evidence's, so the record a build writes is the same on any day; pass
    as_of to judge freshness at another date (`rasd status --as-of today`)."""
    import chain
    repo = repo or chain.Repo()
    ctx = context(store, entries, health_file)
    days = [d for d in (_day((repo.evidence[x.id] or {}).get("run_utc")) for x in repo.items) if d]
    as_of = as_of or (max(days) if days else None)
    records = [record(repo, d, ctx, as_of) for d in repo.items]
    counts = {s: sum(1 for r in records if r.verdict == s) for s in DISPLAY}
    doc = {
        "rasd_status": FORMAT,
        "as_of": str(as_of) if as_of else None,
        "fresh_days": FRESH_DAYS,
        "production_health": next((v["file"] for v in ctx.health.values()), None),
        "counts": counts,
        "library": {"detections": len(repo.items), "rules": len(repo.dets), "correlations": len(repo.corrs),
                    "techniques": len(repo.techniques())},
        "detections": [_plain(r) for r in records],
    }
    doc["pages"] = page_claims(doc)
    return doc


def _plain(rec: Record) -> dict:
    out = asdict(rec)
    if out["evidence"]:
        out["evidence"].pop("operational_parts", None)
    return out


def records(doc: dict) -> list[Record]:
    out = []
    for row in doc["detections"]:
        rec = Record(**{k: v for k, v in row.items() if k != "checks"})
        rec.checks = [Check(**c) for c in row["checks"]]
        out.append(rec)
    return out


# ---- pages that state what the record states ---------------------------------------------------------------------------
LAB_ROW = re.compile(r"^\| Validated \(lab evidence\) \| (.+?) \|$", re.M)
LAB_COUNT = re.compile(r"\*\*Validated \(lab evidence\): (\d+) of (\d+)\*\*")


def page_claims(doc: dict) -> list[str]:
    """Generated pages from other tools that state a detection's lab result: each must agree with the record."""
    out = []
    fired = {r["id"] for r in doc["detections"] if r.get("evidence")
             and any(c["stage"] == "Lab run" and c["state"] == "passed" for c in r["checks"])}
    for r in doc["detections"]:
        path = ROOT / r["folder"] / "public_evidence.md"
        if not path.exists():
            continue
        m = LAB_ROW.search(path.read_text(encoding="utf-8"))
        if not m:
            continue
        says_pending = m.group(1).lower().startswith("pending")
        if says_pending and r["id"] in fired:
            out.append(f"{_rel(path)} says its lab evidence is pending, and {r['folder']}/evidence.md holds it")
        if not says_pending and r["id"] not in fired:
            out.append(f"{_rel(path)} states a lab result, and there is no lab evidence for {r['id']}")
    summary = ROOT / "docs" / "PUBLIC_DATA_VALIDATION.md"
    if summary.exists():
        m = LAB_COUNT.search(summary.read_text(encoding="utf-8"))
        if m and (int(m.group(1)), int(m.group(2))) != (len(fired), len(doc["detections"])):
            out.append(f"docs/PUBLIC_DATA_VALIDATION.md says {m.group(1)} of {m.group(2)} detections have lab evidence, and the "
                       f"record holds {len(fired)} of {len(doc['detections'])}")
    return out


# ---- what it says ------------------------------------------------------------------------------------------------------
def next_actions(doc: dict) -> list[tuple[str, list[str]]]:
    """Each action once, with the detections it moves on, in the order to take them: what fails first, then what
    moves a detection to a better verdict (the more critical detections it moves, the sooner), then the rest."""
    groups: dict[tuple[str, str], list[str]] = {}
    for r in doc["detections"]:
        for key, text in [(r.get("next_key"), r.get("next")), *((a["key"], a["text"]) for a in r.get("also") or [])]:
            if text:
                groups.setdefault((key or "", text), []).append(r["id"])
    critical = {r["id"] for r in doc["detections"] if r["critical"]}

    def tier(key: str) -> int:
        head = key.split(":")[0]
        return {"fix": 0, "health": 1, "stale": 2}.get(head, 3 if head in VERDICT_MOVES else 4)

    def order(item):
        (key, _text), ids = item
        return (tier(key), -sum(1 for i in ids if i in critical), -len(ids), key)
    return [(text, ids) for (_k, text), ids in sorted(groups.items(), key=order)]

def answers(doc: dict, up: str = "../", page_link: str = "") -> list[tuple[str, str, str]]:
    """The five questions a head of cyber defence asks, answered from the record: (question, answer, where the proof is).
    up leads from the page that shows them to the repository root; page_link to the status page ('' on the page itself)."""
    recs = doc["detections"]
    lib = doc["library"]
    counts = doc["counts"]
    verified = [r for r in recs if r["verdict"] == "Verified"]
    kept = sum(1 for r in verified if (r.get("evidence") or {}).get("kept"))
    code_ok = sum(1 for r in recs if not any(c["state"] == "failed" for c in r["checks"] if c["layer"] in CODE_LAYERS))
    platforms = sorted({c["detail"].split(" raised ")[0] for r in recs for c in r["checks"]
                        if c["stage"] == "Live SIEM" and c["state"] == "passed"})
    q1 = (f"{lib['detections']} detections ({lib['rules']} single-event rules, {lib['correlations']} correlations) across "
          f"{lib['techniques']} ATT&CK techniques, each with its telemetry contract, triage and response")
    q2 = (f"{len(verified)} Verified: each fired on a real attack step in a lab and {' and '.join(platforms) or 'a live SIEM'} "
          f"raised its alert" + (f"; {kept} of them are recomputed from the raw run kept in the repository on every build"
                                 if kept else "")
          + f". The code checks ({code_ok} of {lib['detections']} pass) can fail a detection, never verify one")
    prod = doc.get("production_health")
    health = [c for r in recs for c in r["checks"] if c["stage"] == "Telemetry health"]
    if prod:
        seen = {state: sum(1 for c in health if c["state"] == state) for state in ("degraded", "passed", "unknown")}
        q3 = (f"Production health read from {prod}: the events of {seen['degraded']} detections are not arriving as they "
              f"should ({counts.get('Degraded', 0)} of them proven in a lab, now Degraded), {seen['passed']} healthy, "
              f"{seen['unknown']} unknown")
    else:
        q3 = "In production: unknown until RASD reads its SIEM's numbers (`rasd health --json`, then `rasd status --health`)"
    quiet = sum(1 for c in health if "no row, as a lab in order should" in c["detail"])
    if quiet:
        q3 += f". In the lab: the health watchdogs ran quiet beside the hosts of {quiet} Verified detections"
    blocked = [r for r in recs if r["verdict"] == "Blocked"]
    kinds: dict[str, int] = {}
    for r in blocked:
        kinds[r["blocker"] or "no step"] = kinds.get(r["blocker"] or "no step", 0) + 1
    parts = [f"{n} {s}" for s in ("Failed", "Degraded", "Stale") if (n := counts.get(s, 0))]
    if blocked:
        parts.append(f"{len(blocked)} Blocked: " + ", ".join(_kind_short(k, n) for k, n in
                                                         sorted(kinds.items(), key=lambda x: (-x[1], x[0]))))
    parts += [f"{n} {s}" for s in ("Unknown", "Unverified", "Partially Verified") if (n := counts.get(s, 0))]
    noisy = [r["id"] for r in recs if any(c["state"] == "attention" and c["stage"] == "False positives" for c in r["checks"])]
    limits = [r["id"] for r in recs if any(c["state"] == "limit" for c in r["checks"])]
    if noisy:
        parts.append(f"{len(noisy)} alerted in the lab with no step asking for it ({', '.join(noisy)})")
    if limits:
        parts.append(f"{len(limits)} with a documented miss on held-out public data ({', '.join(limits)})")
    q4 = "; ".join(parts) if parts else "None: every detection is Verified and nothing is short of its proof"
    steps = next_actions(doc)
    if steps:
        text, ids = steps[0]
        crit = sum(1 for r in recs if r["id"] in ids and r["critical"])
        q5 = (f"{text}. It moves {len(ids)} detection{'' if len(ids) == 1 else 's'} on"
              + (f", {crit} of them critical" if crit else ""))
    else:
        q5 = "Nothing: every detection is Verified and nothing is in the way"
    return [("What can we detect?", q1, f"{up}detect/README.md"),
            ("What proves it?", q2, f"{up}purple/lab_runs/README.md"),
            ("Is it still working?", q3, f"{up}docs/HEALTH.md"),
            ("Where are the gaps, and why?", q4, f"{page_link}#gaps-and-why"),
            ("What should be fixed now?", q5, f"{page_link}#next")]


def _kind_short(kind: str, n: int) -> str:
    need = "need" if n != 1 else "needs"
    return f"{n} {need} " + {"domain": "a lab domain", "opt-in": "an opt-in step on a lab VM of your own",
                             "target": "a second lab host",
                             "no step": "an offensive step that reaches " + ("them" if n != 1 else "it")}.get(kind, kind)

def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _link(rec: dict, up: str) -> str:
    return f"[{rec['id']}]({up}{rec['folder']}/)"


def page(doc: dict) -> str:
    up = "../"
    recs = doc["detections"]
    out = ["<!-- Generated by `rasd status --write` from the record in status.json. Do not edit by hand. -->", "",
           "# RASD status", "",
           f"Where every detection stands, what proves it, and what to do next. Made on every build from the evidence, "
           f"as of **{doc['as_of'] or 'no lab evidence yet'}** (the newest lab evidence); lab evidence stays fresh for "
           f"{doc['fresh_days']} days. The same record answers `rasd status`, and the front page reads it: they cannot "
           "disagree. [How a verdict is reached](#how-a-verdict-is-reached) · [the record](status.json)", "",
           "## The five questions", "", "| | Question | Answer | Proof |", "|:-:|---|---|---|"]
    for i, (q, a, where) in enumerate(answers(doc), 1):
        out.append(f"| {i} | **{q}** | {_cell(a)} | [open]({where}) |")
    out += ["", "## Where the library stands", "", "| | Verdict | Detections | Meaning |", "|:-:|---|---:|---|"]
    for s in DISPLAY:
        out.append(f"| {MARK[s]} | **{s}** | {doc['counts'].get(s, 0)} | {STATES[s]} |")
    out += ["", "## Every detection", "",
            "Code checks are what the build proves without a lab: tests, mutations, the fuzzer, query parity, and the exact "
            "automaton of a rule or the scenarios of a correlation. Live checks are what a lab and its SIEM showed.", "",
            "| Detection | Verdict | Code checks | Public data | Lab step | Live SIEM | Health | False positives | Next |",
            "|---|---|---|---|---|---|---|---|---|"]
    for r in sorted(recs, key=lambda x: (ORDER.index(x["verdict"]), x["id"])):
        code = [c for c in r["checks"] if c["layer"] == "code"]
        ok = sum(1 for c in code if c["state"] == "passed")
        byname = {c["stage"]: c for c in r["checks"]}
        pub = byname.get("Public attack data", {})
        lab, siem, noise = byname.get("Lab run", {}), byname.get("Live SIEM", {}), byname.get("False positives", {})
        health = byname.get("Telemetry health", {})
        lab_cell = (f"blocked: {SHORT_BLOCKER.get(r['blocker'] or '', r['blocker'])}" if lab.get("state") == "blocked"
                    else _short_state(lab))
        out.append(f"| {_link(r, up)}{' · correlation' if r['kind'] == 'correlation' else ''} | {MARK[r['verdict']]} "
                   f"{r['verdict']}{' · **critical**' if r['critical'] else ''} | {ok} of {len(code)} passed | "
                   f"{_short_state(pub)} | {lab_cell} | {_short_state(siem)} | {_short_state(health)} | "
                   f"{_short_state(noise)} | {_cell(_next_short(r))} |")
    out += ["", "## Gaps, and why", ""]
    gaps = [r for r in recs if r["verdict"] != "Verified" or r["gaps"]]
    if not gaps:
        out.append("None: every detection is Verified and nothing is short of its proof.")
    for r in sorted(gaps, key=lambda x: (ORDER.index(x["verdict"]), x["id"])):
        line = f"- {MARK[r['verdict']]} **{r['id']}** ({r['verdict']}{', critical' if r['critical'] else ''}): {_cell(r['why'])}"
        out.append(line)
        for g in r["gaps"]:
            out.append(f"  - {_cell(g)}")
    out += ["", "## Next", ""]
    steps = next_actions(doc)
    if not steps:
        out.append("Nothing to do: every detection is Verified.")
    for i, (text, ids) in enumerate(steps, 1):
        out.append(f"{i}. {text}. Moves on: {', '.join(ids)}.")
    out += ["", "## Conflicts between components", ""]
    found = [(r["id"], c) for r in recs for c in r["conflicts"]] + [("pages", c) for c in doc.get("pages") or []]
    if found:
        out += [f"- **{who}**: {_cell(c)}" for who, c in found]
    else:
        out.append("None. Checked for every detection: a step its evidence says fired that the kept run says did not run; an "
                   "alert credited to a search the SIEM says did not run to the end; a live alert from a query that is not the "
                   "rule; a contract that claims more than the repository proves; and every generated page that states a lab "
                   "result the evidence does not hold.")
    out += ["", "## How a verdict is reached", "", "The first rule that holds decides:", ""]
    out += [f"{i}. {h}" for i, h in enumerate(HOW, 1)]
    out += ["", "A detection is **critical** when it is Failed, Degraded or Stale, when it is short of Verified and its rule's "
            "level is high or critical, when such a rule has false positives to decide on (an alert in the lab no step asked "
            "for, or one labelled in the public captures), or when production health says its events are not arriving.", "",
            "<sub>`rasd status` prints the same record · `rasd status --detection <id>` shows one detection stage by stage, "
            "each stage with the file it rests on</sub>", ""]
    return "\n".join(out)


SHORT_BLOCKER = {"opt-in": "opt-in step", "domain": "needs a lab domain", "target": "needs a second host",
                 "no step": "no step reaches it"}


def _short_state(c: dict) -> str:
    if not c:
        return "-"
    if c["stage"] == "Telemetry health":
        lab = "lab quiet · " if "no row, as a lab in order should" in c["detail"] else ""
        return lab + {"passed": "production healthy", "degraded": "**production degraded**"}.get(c["state"], "production unknown")
    state = c["state"]
    detail = c["detail"]
    if c["stage"] == "Live SIEM" and state == "passed":
        return "alert after " + detail.rsplit(" after the step", 1)[0].rsplit(" ", 2)[-2] + " " + \
            detail.rsplit(" after the step", 1)[0].rsplit(" ", 1)[-1]
    if c["stage"] == "Lab run" and state == "passed":
        return "fired " + detail.split(" at ")[1][:10]
    if c["stage"] == "Lab run" and state == "blocked":
        return "blocked: " + detail.split(";")[0].replace("its step ", "")
    if c["stage"] == "Public attack data":
        return {"passed": "fires", "limit": "fires · a documented held-out miss", "n/a": "no recording",
                "failed": "**misses**"}.get(state, state)
    if c["stage"] == "False positives":
        return "**attention**" if state == "attention" else "none seen · no baseline"
    return state


def _next_short(r: dict) -> str:
    if not r.get("next"):
        return "-"
    return {"domain": "run the domain wave", "opt-in": "run the opt-in steps", "no step": "give it a step",
            "lab": "run the lab", "siem": "run it with the SIEM", "stale": "run the lab again", "noise": "decide the tuning",
            "dfir": "collect DFIR artifacts", "health": "restore the feed", "cleanup": "verify the cleanup",
            "target": "run with a second host"}.get(r["next_key"] or "", "fix: " + (r["next_key"] or "").split(":")[-1].lower())


# ---- the command --------------------------------------------------------------------------------------------------------
def render_text(doc: dict, mode: str = "summary", det: str | None = None) -> str:
    recs = doc["detections"]
    head = f"RASD status · as of {doc['as_of'] or 'no lab evidence'} · lab evidence stays fresh {doc['fresh_days']} days"
    if doc.get("production_health"):
        head += f" · production health from {doc['production_health']}"
    lines = [head, ""]
    if mode == "detection":
        r = find(doc, det or "")
        lines += [f"{r['id']}  ({r['kind']}, {r['technique']}, level {r['level']})", f"  {r['title']}", "",
                  f"  Verdict  {r['verdict']}{'  (critical)' if r['critical'] else ''}", f"  Why      {r['why']}"]
        if r.get("next"):
            lines.append(f"  Next     {r['next']}")
        lines += ["", "  Foundation"]
        fd = r["foundation"]
        lines += [f"    rule       {fd['rule']}", f"    telemetry  {', '.join(fd['contract']) or '-'}",
                  f"    response   {', '.join(fd['response']) or '-'}", f"    red steps  {', '.join(fd['steps']) or 'none'}"]
        for title, layers in (("Code checks (no lab)", CODE_LAYERS), ("Live checks", LIVE_LAYERS)):
            lines += ["", f"  {title}"]
            for c in r["checks"]:
                if c["layer"] in layers:
                    lines.append(f"    {c['stage']:<18} {c['state']:<9} {c['detail']}")
                    if c.get("proof"):
                        lines.append(f"    {'':<18} {'':<9} rests on {c['proof']}")
        if r["gaps"]:
            lines += ["", "  Gaps"] + [f"    - {g}" for g in r["gaps"]]
        lines += ["", "  Conflicts"] + ([f"    - {c}" for c in r["conflicts"]] or ["    none"])
        return "\n".join(lines)
    if mode == "summary":
        for s in DISPLAY:
            n = doc["counts"].get(s, 0)
            if n:
                lines.append(f"  {s:<19}{n:>3}  {STATES[s]}")
        lines.append("")
        for i, (q, a, _w) in enumerate(answers(doc), 1):
            lines.append(f"{i}. {q}")
            lines.append(f"   {a}.")
        conflicts_found = sum(len(r["conflicts"]) for r in recs) + len(doc.get("pages") or [])
        lines += ["", f"Conflicts between components: {conflicts_found or 'none'}",
                  "", "rasd status --gaps · --critical · --next · --detection <id> · status/README.md"]
        return "\n".join(lines)
    if mode in ("gaps", "critical"):
        rows = [r for r in recs if (r["verdict"] != "Verified" or r["gaps"]) and (mode == "gaps" or r["critical"])]
        if not rows:
            return "\n".join(lines + ["Nothing " + ("critical." if mode == "critical" else "short of Verified.")])
        for r in sorted(rows, key=lambda x: (ORDER.index(x["verdict"]), x["id"])):
            lines.append(f"{r['verdict']:<19}{r['id']}{'  (critical)' if r['critical'] and mode == 'gaps' else ''}")
            lines.append(f"{'':<19}{r['why']}")
            for g in r["gaps"]:
                lines.append(f"{'':<19}- {g}")
            if r.get("next"):
                lines.append(f"{'':<19}next: {r['next']}")
            lines.append("")
        return "\n".join(lines).rstrip()
    if mode == "next":
        steps = next_actions(doc)
        if not steps:
            return "\n".join(lines + ["Nothing to do: every detection is Verified."])
        for i, (text, ids) in enumerate(steps, 1):
            lines.append(f"{i}. {text}")
            lines.append(f"   moves on: {', '.join(ids)}")
        return "\n".join(lines)
    raise ValueError(mode)


def find(doc: dict, needle: str) -> dict:
    exact = [r for r in doc["detections"] if r["id"] == needle]
    if exact:
        return exact[0]
    hits = [r for r in doc["detections"] if needle.lower() in r["id"].lower()]
    if len(hits) == 1:
        return hits[0]
    raise SystemExit(f"rasd status: {'no detection' if not hits else str(len(hits)) + ' detections'} match '{needle}'"
                     + ("" if not hits else ": " + ", ".join(r["id"] for r in hits)))


def sentence(doc: dict, link: str) -> str:
    """Where the detections stand, in one sentence: every page that states it says these words."""
    n = len(doc["detections"])
    counts = doc["counts"]
    verified = counts.get("Verified", 0)
    rest = [f"{k} {s}" for s in DISPLAY if s != "Verified" and (k := counts.get(s, 0))]
    head = f"**Status:** {verified} of {n} detections Verified"
    if verified:
        head += ": each fired on a real attack step in a lab and a live SIEM raised its alert"
    tail = "; " + ", ".join(rest) + ", each with the reason and the next step" if rest else "; nothing is in the way"
    return f"{head}{tail} ([status]({link}))."


def front_status(doc: dict) -> str:
    import chain
    n = len(doc["detections"])
    counts = doc["counts"]
    calm = chain.CALM
    badges = [chain.badge("detections", str(n), calm["info"]),
              chain.badge("verified", f"{counts.get('Verified', 0)}/{n}", calm["good"] if counts.get("Verified") == n else calm["none"])]
    badges += [chain.badge(s.lower(), str(counts[s]), calm["wait"]) for s in DISPLAY[1:] if counts.get(s) and s != "Failed"]
    conflicts = sum(len(r["conflicts"]) for r in doc["detections"]) + len(doc.get("pages") or [])
    badges += [chain.badge("failed", str(counts.get("Failed", 0)), calm["good"] if not counts.get("Failed") else calm["wait"]),
               chain.badge("conflicts", str(conflicts), calm["good"] if not conflicts else calm["wait"])]
    return STATUS_START + "\n" + "\n".join(badges) + "\n\n" + sentence(doc, "status/README.md") + "\n" + STATUS_END


def front_questions(doc: dict) -> str:
    rows = ["| | Question | Answer | Proof |", "|:-:|---|---|---|"]
    rows += [f"| {i} | **{q}** | {_cell(a)} | [open]({where}) |"
             for i, (q, a, where) in enumerate(answers(doc, up="", page_link="status/README.md"), 1)]
    return (QUESTIONS_START + "\n" + "\n".join(rows) + "\n\n<sub>Answered by `rasd status` from the record every build "
            "writes: [status/status.json](status/status.json)</sub>\n" + QUESTIONS_END)


def files(doc: dict) -> dict[Path, str]:
    """What `--write` writes and `--check` compares: the record, its page, and the front page's two blocks."""
    out = {JSON_FILE: json.dumps(doc, indent=1, ensure_ascii=False) + "\n", PAGE: page(doc)}
    if FRONT.exists():
        import chain
        text = chain.replace_block(FRONT.read_text(encoding="utf-8"), STATUS_START, STATUS_END, front_status(doc))
        out[FRONT] = chain.replace_block(text, QUESTIONS_START, QUESTIONS_END, front_questions(doc))
    return out


def load() -> dict:
    try:
        return json.loads(JSON_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"rasd status: no record to read ({exc}); run: rasd build, or rasd status --fresh") from exc


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="rasd status", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    view = ap.add_mutually_exclusive_group()
    view.add_argument("--gaps", action="store_true", help="every detection short of Verified, and why")
    view.add_argument("--critical", action="store_true", help="the gaps to close first")
    view.add_argument("--next", action="store_true", help="what to do next, and the detections each action moves on")
    view.add_argument("--detection", metavar="ID", help="one detection, stage by stage (an id or a unique part of one)")
    view.add_argument("--write", action="store_true", help="write status/status.json, its page and the front page's status")
    view.add_argument("--check", action="store_true", help="fail when the record or its page is out of date, or components conflict")
    ap.add_argument("--json", action="store_true", help="print the record as JSON (one detection with --detection)")
    ap.add_argument("--health", metavar="FILE", help="production health: the JSON `rasd health --json` wrote")
    ap.add_argument("--as-of", metavar="DATE", help="judge freshness at this date (YYYY-MM-DD or 'today') instead of the "
                    "newest evidence's; recomputes the record")
    ap.add_argument("--fresh", action="store_true", help="recompute the record instead of reading status/status.json")
    args = ap.parse_args(argv)
    when = None
    if args.as_of:
        when = date.today() if args.as_of == "today" else _day(args.as_of)
        if not when:
            ap.error(f"--as-of: not a date: {args.as_of}")
    if args.write or args.check:
        doc = build()
        want = files(doc)
        if args.write:
            OUT.mkdir(parents=True, exist_ok=True)
            for path, text in want.items():
                path.write_text(text, encoding="utf-8", newline="\n")
            print(f"status: {', '.join(f'{n} {s}' for s, n in doc['counts'].items() if n)} · wrote {_rel(JSON_FILE)}, {_rel(PAGE)}")
            return 0
        stale = [_rel(p) for p, text in want.items() if not p.exists() or p.read_text(encoding="utf-8") != text]
        found = [f"{r['id']}: {c}" for r in doc["detections"] for c in r["conflicts"]] + list(doc.get("pages") or [])
        for p in stale:
            print(f"✗ {p} is out of date - run: rasd build")
        for c in found:
            print(f"✗ conflict: {c}")
        if stale or found:
            return 1
        print(f"✓ status: the record and its page are current, and no component contradicts another "
              f"({', '.join(f'{n} {s}' for s, n in doc['counts'].items() if n)})")
        return 0
    if args.fresh or args.health or when:
        doc = build(health_file=Path(args.health) if args.health else None, as_of=when)
    else:
        doc = load()
    if args.json:
        print(json.dumps(find(doc, args.detection) if args.detection else doc, indent=1, ensure_ascii=False))
        return 0
    mode = "detection" if args.detection else "gaps" if args.gaps else "critical" if args.critical else \
        "next" if args.next else "summary"
    print(render_text(doc, mode, args.detection))
    age = (date.today() - date.fromisoformat(doc["as_of"])).days if doc.get("as_of") else None
    if age is not None and age > FRESH_DAYS and not when:
        print(f"\n! the newest lab evidence is {age} days old today: `rasd status --as-of today` judges every detection "
              "at today's date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
