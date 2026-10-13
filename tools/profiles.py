#!/usr/bin/env python3
"""
profiles.py - read a log export in its own field names and give the rules theirs.

The rules, their tests and the evidence step use Sysmon / Windows native field names
(Image, CommandLine, TicketEncryptionType ...). Real exports rarely do: Elastic writes
process.command_line, Defender writes ProcessCommandLine, Splunk's CIM writes process.
A telemetry profile in mappings/ says, per log source, where each rule field lives in
that export and how to recognise the event type. doctor, replay, evidence and benchmark
apply it with --profile <name>, or --profile auto to pick the best fit for the export.

Profile format (mappings/<name>.yml)
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
and the original fields are kept.

Usage
  python tools/profiles.py                      # list profiles and what they cover
  python tools/profiles.py --detect export.jsonl
  python tools/profiles.py --readme             # refresh the table in mappings/README.md
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BOLD, DIM, GREEN, RED, RESET, ROOT, load_jsonl  # noqa: E402
from replay import route  # noqa: E402
from sigma_engine import _get_field  # noqa: E402

PROFILES_DIR = ROOT / "mappings"
NATIVE = "sysmon-native"
LOGSOURCES = ("process_creation", "process_access", "registry_set", "windows/security", "windows/system")
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


def detect(events: list[dict], sample: int = 500) -> tuple[str, dict[str, int]]:
    """The profile under which most of the export reaches a RASD log source."""
    head = events[:sample]
    scores = {NATIVE: sum(1 for e in head if route(e))}
    for n in names():
        if n != NATIVE:
            prof = load(n)
            scores[n] = sum(1 for e in head if route(normalize(e, prof)))
    best = max(scores, key=lambda k: (scores[k], k == NATIVE))
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
    ap.add_argument("--readme", action="store_true", help="refresh the coverage table in mappings/README.md")
    ap.add_argument("--check", action="store_true", help="fail if mappings/README.md is stale")
    args = ap.parse_args()
    if args.readme or args.check:
        before = (PROFILES_DIR / "README.md").read_text(encoding="utf-8")
        ok = write_readme(check=args.check)
        if args.check and not ok:
            print(f"{RED}mappings/README.md is stale (run: python rasd.py build){RESET}")
            return 1
        changed = (PROFILES_DIR / "README.md").read_text(encoding="utf-8") != before
        print(f"{GREEN}mappings/README.md profile table {'written' if changed else 'up to date'}{RESET}")
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
