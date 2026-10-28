#!/usr/bin/env python3
"""
profiles.py - read a log export in its own field names and give the rules theirs.

The rules, their tests and the evidence step use Sysmon / Windows native field names
(Image, CommandLine, TicketEncryptionType ...). Real exports rarely do: Elastic writes
process.command_line, Defender writes ProcessCommandLine, Splunk's CIM writes process.
A telemetry profile in profiles/ says, per log source, where each rule field lives in
that export and how to recognise the event type. doctor, replay, evidence and benchmark
apply it with --profile <name>, or --profile auto to pick the best fit for the export.

Profile format (profiles/<name>.yml)
  name, description, source, docs      what it reads and where the field names come from
  covers                               the RASD log sources it can carry
  event:                               how the event type is read
    Channel / EventID: [candidates]    native channel and event id, when the export has them
    infer:                             for EDR schemas without a channel, first match wins:
      - when: {field: value | [values] | "*"}   ("*" = present)
        set:  {Channel: ..., EventID: ...}
  fields:
    common: {RuleField: [candidates]}            for every event
    <log source>: {RuleField: [candidates]}      only for that log source
  fallback_prefix: winlog.event_data.            any field under it is also read by its own name

  A candidate is a field path (a dotted path also reads nested JSON), or
    {join: [a, b], sep: "\\"}     the non-empty parts joined
    {path: [folder, file]}        folder + "\\" + file, unless the folder already ends with it

Native fields already in the event always win: a profile only fills what is missing,
and the original fields are kept. --profile auto picks the profile that gives the rules the
most of the fields they read, on events that reach a rule.

Usage
  rasd profiles                      # list profiles and what they cover
  rasd profiles --detect export.jsonl
  rasd profiles --readme             # refresh the table in profiles/README.md
"""
from __future__ import annotations

import argparse
import functools
import sys
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BOLD, DIM, GREEN, RED, RESET, ROOT, load_jsonl
from replay import route
from sigma_engine import _get_field

PROFILES_DIR = ROOT / "profiles"
NATIVE = "sysmon-native"
LOGSOURCES = ("process_creation", "process_access", "registry_set", "windows/security", "windows/system",
              "linux/process_creation", "webserver", "opencanary/honeypot")
README_START, README_END = "<!-- rasd:profiles:start -->", "<!-- rasd:profiles:end -->"


class ProfileError(SystemExit):
    pass


def names() -> list[str]:
    return sorted(p.stem for p in PROFILES_DIR.glob("*.yml"))


def load(name: str | None) -> dict | None:
    """A profile by name; None (or sysmon-native) means the events already use native names."""
    if not name or name == NATIVE:
        return None
    path = PROFILES_DIR / f"{name}.yml"
    if not path.exists():
        raise ProfileError(f"unknown profile '{name}' - available: {', '.join(names())}, auto")
    prof = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    prof.setdefault("name", name)
    return prof


def present(v: Any) -> bool:
    return v not in (None, "", "-", [], {})


def _value(ev: dict, cand: Any) -> Any:
    if isinstance(cand, str):
        return _get_field(ev, cand)
    if isinstance(cand, dict) and "join" in cand:
        parts = [str(v) for v in (_get_field(ev, c) for c in cand["join"]) if present(v)]
        return cand.get("sep", "").join(parts) if parts else None
    if isinstance(cand, dict) and "path" in cand:
        folder, file = (_get_field(ev, c) for c in cand["path"])
        if not present(folder):
            return file if present(file) else None
        folder = str(folder)
        if not present(file) or folder.lower().rstrip("\\/").endswith(str(file).lower()):
            return folder
        return folder.rstrip("\\/") + "\\" + str(file)
    raise ProfileError(f"invalid candidate {cand!r}")


def pick(ev: dict, candidates) -> Any:
    for cand in candidates or []:
        v = _value(ev, cand)
        if present(v):
            return v
    return None


def _when(ev: dict, cond: dict) -> bool:
    for field, wanted in cond.items():
        actual = _get_field(ev, field)
        if wanted == "*":
            if not present(actual):
                return False
            continue
        values = {str(w).lower() for w in (wanted if isinstance(wanted, list) else [wanted])}
        actuals = {str(a).lower() for a in (actual if isinstance(actual, list) else [actual]) if a is not None}
        if not values & actuals:
            return False
    return True


def _flat(ev: dict, prefix: str = "") -> dict:
    out = {}
    for k, v in ev.items():
        if isinstance(v, dict):
            out.update(_flat(v, f"{prefix}{k}."))
        else:
            out[f"{prefix}{k}"] = v
    return out


def normalize(ev: dict, prof: dict | None) -> dict:
    """The event with the rules' native field names filled in from the profile."""
    if prof is None:
        return ev
    out = dict(ev)
    spec = prof.get("event") or {}
    channel, eid = pick(ev, spec.get("Channel")), pick(ev, spec.get("EventID"))
    if not present(channel):
        for rule in spec.get("infer") or []:
            if _when(ev, rule.get("when") or {}):
                channel = rule["set"].get("Channel", channel)
                eid = rule["set"].get("EventID", eid)
                break
    if present(channel) and not present(out.get("Channel")):
        out["Channel"] = channel
    if present(eid) and not present(out.get("EventID")):
        out["EventID"] = int(eid) if str(eid).isdigit() else eid
    fields = prof.get("fields") or {}
    mapping = {**(fields.get("common") or {}), **(fields.get(route(out) or "") or {})}
    for target, candidates in mapping.items():
        if not present(out.get(target)):
            v = pick(ev, candidates)
            if present(v):
                out[target] = v
    prefix = prof.get("fallback_prefix")
    if prefix:
        for key, v in _flat(ev).items():
            name = key[len(prefix):]
            if key.startswith(prefix) and name and not present(out.get(name)) and present(v):
                out[name] = v
    return out


def apply(events: list[dict], name: str | None) -> tuple[list[dict], str]:
    """Events normalised with a profile (or 'auto'), and the profile name actually used."""
    if name == "auto":
        name = detect(events)[0]
    prof = load(name)
    return ([normalize(e, prof) for e in events] if prof else events), (name or NATIVE)


@functools.lru_cache(maxsize=1)
def rule_reads() -> dict[str, tuple[frozenset[str] | None, frozenset[str]]]:
    """Per log source with rules: the event ids they read (None when a rule there reads every
    event of the source) and the fields they read."""
    from common import load_detections
    from convert import logsource_key, referenced_fields
    from correlation import load_correlations           # imported here: correlation imports replay too
    ids_of: dict[str, frozenset[str] | None] = {}
    fields_of: dict[str, frozenset[str]] = {}
    for rule in [d.rule for d in load_detections()] + [c.base for c in load_correlations()]:
        src = logsource_key(rule)
        ids = {str(v) for sel in rule["detection"].values() if isinstance(sel, dict) for k, val in sel.items()
               if k.split("|")[0] == "EventID" for v in (val if isinstance(val, list) else [val])}
        known = ids_of.get(src, frozenset())
        ids_of[src] = None if not ids or known is None else known | ids
        fields_of[src] = fields_of.get(src, frozenset()) | (set(referenced_fields(rule["detection"])) - {"EventID"})
    return {src: (ids_of[src], fields_of[src]) for src in ids_of}


def score(ev: dict) -> int:
    """How many of the fields the rules read this event carries, when it reaches one of them."""
    src = route(ev)
    reads = rule_reads().get(src or "")
    if reads is None:
        return 0
    ids, fields = reads
    if ids is not None and str(ev.get("EventID", "")) not in ids:
        return 0
    return 1 + sum(1 for f in fields if present(_get_field(ev, f)))


def evidence(prof: dict, events: list[dict]) -> int:
    """How many of the profile's own source field names (not the native names it fills) the export
    carries: a tie on score goes to the profile whose schema the export visibly uses."""
    names: set[str] = set()

    def walk(cands, target: str) -> None:
        for c in cands or []:
            if isinstance(c, str) and c != target:
                names.add(c)
            elif isinstance(c, dict):
                names.update(x for x in (c.get("join") or c.get("path") or []) if x != target)
    spec = prof.get("event") or {}
    for target in ("Channel", "EventID"):
        walk(spec.get(target), target)
    for section in (prof.get("fields") or {}).values():
        for target, cands in (section or {}).items():
            walk(cands, target)
    return sum(1 for n in names if any(present(_get_field(e, n)) for e in events))


def detect(events: list[dict], sample: int = 500) -> tuple[str, dict[str, int]]:
    """The profile that gives the rules the most of the fields they read, on events that reach a rule.
    Ties go to the native names, then to the profile whose source field names the export carries,
    then to the narrower profile (fewer log sources covered)."""
    head = events[:sample]
    scores = {NATIVE: sum(score(e) for e in head)}
    tiebreak: dict[str, tuple[int, int]] = {NATIVE: (0, 0)}
    for n in names():
        if n != NATIVE:
            prof = load(n) or {}
            scores[n] = sum(score(normalize(e, prof)) for e in head)
            tiebreak[n] = (evidence(prof, head), -len(prof.get("covers") or []))
    best = max(scores, key=lambda k: (scores[k], k == NATIVE, *tiebreak[k]))
    return best, scores


def table() -> str:
    rows = ["| Profile | Reads exports from | " + " | ".join(f"`{s}`" for s in LOGSOURCES) + " |",
            "|---|---|" + "---|" * len(LOGSOURCES)]
    for n in names():
        prof = yaml.safe_load((PROFILES_DIR / f"{n}.yml").read_text(encoding="utf-8")) or {}
        covers = set(prof.get("covers") or [])
        rows.append(f"| [`{n}`]({n}.yml) | {prof.get('source', '')} | "
                    + " | ".join("✓" if s in covers else "-" for s in LOGSOURCES) + " |")
    return "\n".join(rows)


def write_readme(check: bool = False) -> bool:
    path = PROFILES_DIR / "README.md"
    text = path.read_text(encoding="utf-8")
    head, _, rest = text.partition(README_START)
    _, _, tail = rest.partition(README_END)
    new = f"{head}{README_START}\n{table()}\n{README_END}{tail}"
    if new == text:
        return True
    if not check:
        path.write_text(new, encoding="utf-8")
    return not check


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--detect", nargs="+", metavar="EXPORT", help="which profile fits this export")
    ap.add_argument("--readme", action="store_true", help="refresh the coverage table in profiles/README.md")
    ap.add_argument("--check", action="store_true", help="fail if profiles/README.md is stale")
    args = ap.parse_args()
    if args.readme or args.check:
        before = (PROFILES_DIR / "README.md").read_text(encoding="utf-8")
        ok = write_readme(check=args.check)
        if args.check and not ok:
            print(f"{RED}profiles/README.md is stale (run: rasd build){RESET}")
            return 1
        changed = (PROFILES_DIR / "README.md").read_text(encoding="utf-8") != before
        print(f"{GREEN}profiles/README.md profile table {'written' if changed else 'up to date'}{RESET}")
        return 0
    if args.detect:
        events = [e for p in args.detect for e in load_jsonl(Path(p))]
        best, scores = detect(events)
        print(f"{BOLD}Profile fit for {min(len(events), 500)} events{RESET}\n")
        for n, s in sorted(scores.items(), key=lambda x: -x[1]):
            print(f"  {GREEN if n == best else DIM}{n:<22} {s} event(s) reach a RASD log source{RESET}")
        print(f"\nUse: --profile {best}")
        return 0
    print(table())
    return 0


if __name__ == "__main__":
    sys.exit(main())
