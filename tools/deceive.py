#!/usr/bin/env python3
"""
deceive.py - RASD-Deceive: one inventory of decoys, held in step with everything that depends on it.

deceive/decoys.yml names every decoy RASD plants: honey accounts, the honey SPN account, the honey
credential files, the decoy network host. Each one is read by a detection rule, proven by that
rule's tests and behaviour spec, touched by a red test and created by a deployment script. This
tool keeps them from drifting apart:

  --check    every decoy's detection and red test exist and the red test triggers that detection;
             every identity (account name, SPN account, file path, node_id) is a value of its rule
             and appears in one of its true positives; the decoy host's rule lists exactly the event
             codes of the modules the inventory enables, and the OpenCanary configuration enables
             exactly those modules under that node_id; the lures point at decoys that exist; the
             catalogue in deceive/README.md is current
  --rename   OLD NEW: adopt your own identity for a decoy. Rewrites the inventory, the rule, its
             tests, mutations and behaviour spec, the red test, the deployment scripts, the
             playbooks, scenarios and docs that name it - then `rasd build` regenerates the rest
             and `rasd ci` re-proves everything with your names
  --gaps     the decoy classes RASD knows and has not built, ranked the way the detection backlog
             ranks techniques: telemetry already mapped and a red test that can produce it first
  (default)  render the catalogue block of deceive/README.md

Operational deception metrics - time to first touch, decoys touched per intrusion, dwell time
before the first decoy alert - need lab evidence (rasd evidence) and stay pending until a run is
committed; this tool never estimates them.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BOLD, DETECTIONS, DFIR, DIM, DOCS, GREEN, PURPLE, RED, RESET, ROOT, TECHNIQUE_NAMES, YELLOW, load_jsonl
from red import covers, load_tests

DECEIVE = ROOT / "deceive"
INVENTORY = DECEIVE / "decoys.yml"
README = DECEIVE / "README.md"
CATALOG_START, CATALOG_END = "<!-- rasd:deceive-catalog:start -->", "<!-- rasd:deceive-catalog:end -->"
KINDS = ("account", "spn", "file", "service")
# The event codes each OpenCanary module writes (opencanary/logger.py, LOG_* constants; the https module
# reuses the http codes). The decoy host's rule must list exactly the codes of the modules the inventory enables.
MODULE_CODES = {
    "ftp": (2000, 2001), "http": (3000, 3001, 3002, 3003), "https": (3000, 3001, 3002, 3003),
    "ssh": (4000, 4001, 4002), "smb": (5000,), "portscan": (5001, 5002, 5003, 5004, 5005),
    "telnet": (6001, 6002), "httpproxy": (7001,), "mysql": (8001, 9003), "mssql": (9001, 9002),
    "tftp": (10001,), "ntp": (11001,), "vnc": (12001,), "snmp": (13001,), "rdp": (14001,), "sip": (15001,),
    "git": (16001,), "redis": (17001,), "tcpbanner": (18001, 18002, 18003, 18004, 18005), "llmnr": (19001,),
    "mongodb": (20001,),
}
TIERS = ("telemetry mapped and the red test can produce it today", "needs a red test step", "needs a new log source")
D3FEND_NAMES = {"D3-DO": "DecoyObject", "D3-DUC": "DecoyUserCredential", "D3-DF": "DecoyFile", "D3-DNR": "DecoyNetworkResource",
                "D3-DP": "DecoyPersona", "D3-DST": "DecoySessionToken", "D3-DPR": "DecoyPublicRelease"}   # D3FEND 1.6


class DeceiveError(SystemExit):
    pass


# --------------------------------------------------------------------------- #
# Inventory
# --------------------------------------------------------------------------- #
def load_inventory() -> dict:
    if not INVENTORY.exists():
        raise DeceiveError(f"{INVENTORY.relative_to(ROOT)} is missing")
    doc = yaml.safe_load(INVENTORY.read_text(encoding="utf-8")) or {}
    if not isinstance(doc.get("decoys"), list):
        raise DeceiveError(f"{INVENTORY.relative_to(ROOT)}: `decoys` must be a list")
    return doc


def identity(decoy: dict) -> str:
    """The value the detection rule reads for this decoy."""
    kind = decoy.get("kind")
    if kind in ("account", "spn"):
        return str(decoy.get("name", ""))
    if kind == "file":
        return str(decoy.get("path", ""))
    if kind == "service":
        return str(decoy.get("node_id", ""))
    return ""


def identities(doc: dict) -> dict[str, dict]:
    return {identity(d): d for d in doc.get("decoys") or [] if identity(d)}


def rule_of(detection_id: str) -> dict | None:
    path = DETECTIONS / detection_id / "rule.yml"
    return yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else None


def rule_values(rule: dict, field: str | None = None) -> set[str]:
    """Every value of the rule's selections (of one field, when given), lower-cased."""
    out: set[str] = set()
    for name, sel in (rule.get("detection") or {}).items():
        if name == "condition":
            continue
        for block in (sel if isinstance(sel, list) else [sel]):
            if not isinstance(block, dict):
                continue
            for key, value in block.items():
                if field and key.split("|")[0] != field:
                    continue
                for v in (value if isinstance(value, list) else [value]):
                    out.add(str(v).lower())
    return out


def tp_events(detection_id: str) -> list[dict]:
    return load_jsonl(DETECTIONS / detection_id / "tests" / "true_positive.jsonl")


def red_test(doc_id: str) -> dict | None:
    return next((t for t in load_tests() if t.get("id") == doc_id), None)


def event_mentions(ev: dict, text: str) -> bool:
    needle = text.lower()
    return any(needle in str(v).lower() for k, v in ev.items() if not k.startswith("_"))


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #
def check(doc: dict) -> list[str]:
    where = INVENTORY.relative_to(ROOT)
    errs: list[str] = []
    decoys = doc.get("decoys") or []
    ids = [d.get("id") for d in decoys]
    if len(set(ids)) != len(ids):
        errs.append(f"{where}: decoy ids must be unique")
    for d in decoys:
        did = d.get("id") or "<no id>"
        for key in ("id", "kind", "detection", "red_test", "looks_like", "lure", "telemetry", "fires_when"):
            if not d.get(key):
                errs.append(f"{where}: {did}: missing '{key}'")
        if d.get("kind") not in KINDS:
            errs.append(f"{where}: {did}: kind must be one of {KINDS}")
            continue
        ident = identity(d)
        if not ident:
            errs.append(f"{where}: {did}: no identity (name, path or node_id)")
            continue
        rule = rule_of(str(d.get("detection")))
        if rule is None:
            errs.append(f"{where}: {did}: detection '{d.get('detection')}' does not exist")
            continue
        det_id = str(d["detection"])
        values = rule_values(rule)
        if d["kind"] in ("account", "spn"):
            field = "TargetUserName" if d["kind"] == "account" else "ServiceName"
            named = rule_values(rule, field)
            for form in (ident, f"{ident}@*"):
                if form.lower() not in named:
                    errs.append(f"{det_id}: rule.yml does not list the decoy {d['kind']} '{form}' under {field}")
        elif d["kind"] == "file":
            if ident.lower() not in rule_values(rule, "ObjectName"):
                errs.append(f"{det_id}: rule.yml does not list the decoy file '{ident}' under ObjectName")
        elif d["kind"] == "service":
            if ident.lower() not in rule_values(rule, "node_id"):
                errs.append(f"{det_id}: rule.yml does not list the decoy host '{ident}' under node_id")
            modules = [str(m) for m in d.get("modules") or []]
            unknown = [m for m in modules if m not in MODULE_CODES]
            if unknown:
                errs.append(f"{where}: {did}: unknown OpenCanary module(s) {unknown} (known: {', '.join(MODULE_CODES)})")
            want = {str(c) for m in modules if m in MODULE_CODES for c in MODULE_CODES[m]}
            have = rule_values(rule, "logtype")
            if want - have:
                errs.append(f"{det_id}: rule.yml lacks the event codes {sorted(want - have, key=int)} of the modules the inventory enables")
            if have - want:
                errs.append(f"{det_id}: rule.yml lists the event codes {sorted(have - want, key=int)} of modules the inventory does not enable")
            errs += settings_errors(d, modules)
        if not any(event_mentions(ev, ident) for ev in tp_events(det_id)):
            errs.append(f"{det_id}: no true positive carries the decoy '{ident}' ({did})")
        t = red_test(str(d.get("red_test")))
        if t is None:
            errs.append(f"{where}: {did}: red test '{d.get('red_test')}' does not exist")
        elif det_id not in covers(t):
            errs.append(f"red/{t['platform']}/{t['id']}: no step triggers {det_id}, which {did} needs")
        for ref in d.get("credentials_for") or []:
            if ref not in ids:
                errs.append(f"{where}: {did}: credentials_for names '{ref}', which is not a decoy")
        _ = values
    errs += class_errors(doc)
    return errs


def settings_errors(decoy: dict, modules: list[str]) -> list[str]:
    """The OpenCanary configuration of the decoy host enables exactly the inventory's modules under its node_id."""
    rel = str(decoy.get("config") or "")
    path = ROOT / rel
    if not rel or not path.exists():
        return [f"{INVENTORY.relative_to(ROOT)}: {decoy.get('id')}: config '{rel}' does not exist"]
    try:
        settings = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return [f"{rel}: not valid JSON ({e})"]
    errs = []
    if settings.get("device.node_id") != decoy.get("node_id"):
        errs.append(f"{rel}: device.node_id is '{settings.get('device.node_id')}', the inventory says '{decoy.get('node_id')}'")
    enabled = {m for m in MODULE_CODES if settings.get(f"{m}.enabled") is True}
    if enabled != set(modules):
        errs.append(f"{rel}: enables {sorted(enabled)}, the inventory lists {sorted(modules)}")
    return errs


def class_errors(doc: dict) -> list[str]:
    where = INVENTORY.relative_to(ROOT)
    errs = []
    kinds_built = {d.get("kind") for d in doc.get("decoys") or []}
    classes = doc.get("classes") or []
    for c in classes:
        kind = c.get("kind")
        if c.get("status") == "built" and kind not in kinds_built:
            errs.append(f"{where}: class {kind} is 'built' but no decoy has that kind")
        if c.get("status") == "planned":
            if kind in kinds_built:
                errs.append(f"{where}: class {kind} is 'planned' but a decoy of that kind exists")
            if not all(isinstance(c.get(k), bool) for k in ("log_source_mapped", "red_test_produces")) or \
                    not all(c.get(k) for k in ("name", "telemetry", "missing", "next")):
                errs.append(f"{where}: planned class {kind} needs name, telemetry, missing, next, and "
                            "log_source_mapped / red_test_produces as true/false")
            elif c.get("red_test_produces") and not c.get("log_source_mapped"):
                errs.append(f"{where}: planned class {kind}: a red test cannot produce telemetry RASD does not map")
        if c.get("status") not in ("built", "planned"):
            errs.append(f"{where}: class {kind}: status must be built or planned")
        if c.get("d3fend") not in D3FEND_NAMES:
            errs.append(f"{where}: class {kind}: d3fend must be one of {', '.join(D3FEND_NAMES)} (a D3FEND decoy technique)")
    for kind in kinds_built:
        if kind not in {c.get("kind") for c in classes}:
            errs.append(f"{where}: no class describes the decoy kind {kind}")
    return errs


# --------------------------------------------------------------------------- #
# Catalogue
# --------------------------------------------------------------------------- #
def technique_link(t: str) -> str:
    return f"[{t}](https://attack.mitre.org/techniques/{t.replace('.', '/')}/)"


def cell(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ").strip()


def render_catalog(doc: dict) -> str:
    tests = {t["id"]: t for t in load_tests() if "_yaml_error" not in t}
    out = [CATALOG_START, "| Decoy | Looks like | Lure | Fires when | Detection | Red test |", "|---|---|---|---|---|---|"]
    for d in doc.get("decoys") or []:
        ident = identity(d)
        shown = f"`{cell(ident)}`" + (f"<br>`{cell(d['spn'])}`" if d.get("spn") else "")
        if d.get("kind") == "file":
            shown = f"`{cell(d.get('unc') or ident)}`<br>rule reads `{cell(ident)}`"
        if d.get("kind") == "service":
            shown = f"`{cell(ident)}` · {cell(d.get('address', ''))}<br>" + ", ".join(str(m) for m in d.get("modules") or [])
        t = tests.get(str(d.get("red_test")))
        red_link = f"[{d.get('red_test')}](../red/{t['platform']}/{t['id']}/)" if t else cell(d.get("red_test"))
        out.append(f"| **{cell(d.get('id'))}** ({cell(d.get('kind'))})<br>{shown} | {cell(d.get('looks_like'))} | {cell(d.get('lure'))} | "
                   f"{cell(d.get('fires_when'))} | [`{cell(d.get('detection'))}`](../detect/detections/{cell(d.get('detection'))}/) | {red_link} |")
    chains = [(d, list(d.get("credentials_for") or [])) for d in doc.get("decoys") or [] if d.get("credentials_for")]
    if chains:
        out += ["", "**Decoy chains** - what a lure leads to, so one touch becomes a second alert:", ""]
        for d, refs in chains:
            out.append(f"- `{cell(d.get('id'))}` leads to " + ", ".join(f"`{r}`" for r in refs))
    out += ["", "| Decoy class | Status | ATT&CK techniques caught | D3FEND | Telemetry |", "|---|---|---|---|---|"]
    for c in doc.get("classes") or []:
        techs = " · ".join(technique_link(str(t)) for t in c.get("techniques") or [])
        status = "built" if c.get("status") == "built" else f"planned · {TIERS[tier(c)]}"
        d3 = f"[{c['d3fend']}](https://d3fend.mitre.org/technique/d3f:{D3FEND_NAMES.get(str(c['d3fend']), '')})" if c.get("d3fend") else "-"
        out.append(f"| {cell(c.get('name'))} | {status} | {techs} | {d3} | {cell(c.get('telemetry'))} |")
    counts = {k: sum(1 for d in doc.get("decoys") or [] if d.get("kind") == k) for k in KINDS}
    dets = sorted({str(d.get("detection")) for d in doc.get("decoys") or []})
    out += ["", f"{sum(counts.values())} decoys ({', '.join(f'{n} {k}' for k, n in counts.items() if n)}) · {len(dets)} deception detections · "
            f"{len({str(d.get('red_test')) for d in doc.get('decoys') or []})} red tests touch them · operational metrics (time to first touch, "
            "decoys touched per intrusion) pending a lab run",
            "", "<sub>Generated by tools/deceive.py from decoys.yml · RASD-Deceive</sub>", CATALOG_END]
    return "\n".join(out)


def tier(c: dict) -> int:
    return 0 if c.get("red_test_produces") else (1 if c.get("log_source_mapped") else 2)


def write_readme(doc: dict, check: bool) -> bool:
    """Replace the catalogue block; True when the file is (already) current."""
    if not README.exists():
        raise DeceiveError(f"{README.relative_to(ROOT)} is missing")
    text = README.read_text(encoding="utf-8")
    if CATALOG_START not in text or CATALOG_END not in text:
        raise DeceiveError(f"{README.relative_to(ROOT)}: the markers {CATALOG_START} ... {CATALOG_END} are missing")
    new = text.split(CATALOG_START)[0] + render_catalog(doc) + text.split(CATALOG_END, 1)[1]
    if new == text:
        return True
    if not check:
        README.write_text(new, encoding="utf-8")
    return False


# --------------------------------------------------------------------------- #
# Gaps
# --------------------------------------------------------------------------- #
def render_gaps(doc: dict) -> str:
    planned = sorted((c for c in doc.get("classes") or [] if c.get("status") == "planned"), key=tier)
    lines = [f"{BOLD}Deception coverage · decoy classes RASD has not built{RESET}", ""]
    if not planned:
        lines.append("  every known decoy class is built")
    current = None
    for c in planned:
        if tier(c) != current:
            current = tier(c)
            lines.append(f"  {YELLOW}{TIERS[current]}{RESET}")
        techs = ", ".join(f"{t} {TECHNIQUE_NAMES.get(str(t), '')}".strip() for t in c.get("techniques") or [])
        lines += [f"    {BOLD}{c.get('name')}{RESET} {DIM}({techs}){RESET}",
                  f"      telemetry  {c.get('telemetry')}",
                  f"      missing    {c.get('missing')}",
                  f"      next       {c.get('next')}"]
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Rename
# --------------------------------------------------------------------------- #
TEXT_SUFFIXES = {".yml", ".yaml", ".md", ".jsonl", ".json", ".ps1", ".sh", ".py", ".txt", ".csv", ".kql", ".spl", ".conf"}


def rename_targets(doc: dict) -> list[Path]:
    """Every file a decoy identity may be written in: the inventory and deployment files, the deception
    detections, their red tests, and the playbooks, scenarios and docs that mention a decoy."""
    paths: list[Path] = [p for p in DECEIVE.rglob("*") if p.is_file() and p.suffix in TEXT_SUFFIXES]
    tests = {t["id"]: t for t in load_tests() if "_yaml_error" not in t}
    for d in doc.get("decoys") or []:
        folder = DETECTIONS / str(d.get("detection"))
        paths += [p for p in folder.rglob("*") if p.is_file() and p.suffix in TEXT_SUFFIXES]
        t = tests.get(str(d.get("red_test")))
        if t:
            paths += [p for p in t["_folder"].rglob("*") if p.is_file() and p.suffix in TEXT_SUFFIXES]
    paths += [p for folder in (DFIR / "playbooks", PURPLE / "scenarios", DOCS) for p in folder.glob("*.md")]
    seen, unique = set(), []
    for p in paths:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    return unique


def _forms(text: str) -> list[str]:
    """The literal, and its JSON-escaped form when that differs (test events are JSON lines)."""
    escaped = json.dumps(text)[1:-1]
    return [text] if escaped == text else [text, escaped]


def _pairs(old: str, new: str) -> list[tuple[str, str]]:
    """(old form, new form) for the literal and, when the old identity has one, its JSON-escaped form."""
    o, n = _forms(old), _forms(new)
    if len(o) == 2 and len(n) == 1:
        n = [new, new]
    if len(o) == 1 and len(n) == 2:
        raise DeceiveError("the new identity contains a character JSON escapes (a backslash or a quote); only a decoy file path may")
    return list(zip(o, n, strict=True))


def _replace_case(match: re.Match, new: str) -> str:
    found = match.group(0)
    if found.isupper() and any(c.isalpha() for c in found):
        return new.upper()
    if found.islower() and any(c.isalpha() for c in found):
        return new if new.lower() == new else new.lower()
    return new


def rename(doc: dict, old: str, new: str) -> list[str]:
    """Rewrite OLD to NEW in every file that may hold a decoy identity; returns the files changed."""
    known = identities(doc)
    if old not in known:
        raise DeceiveError(f"'{old}' is not a decoy identity in {INVENTORY.relative_to(ROOT)} (known: "
                           + ", ".join(sorted(known)) + ")")
    if not new.strip() or any(ch in new for ch in "\r\n\t") or new != new.strip():
        raise DeceiveError("the new identity must be one line without leading or trailing spaces")
    if old.lower() == new.lower():
        raise DeceiveError("the new identity is the old one")
    if any(ch in new for ch in "*?\""):
        raise DeceiveError("the new identity must not contain Sigma wildcards (* ?) or a double quote")
    if known[old].get("kind") == "file" and not new.startswith("\\"):
        raise DeceiveError("a decoy file path starts with a backslash and is relative to the share root, as in \\IT\\Passwords\\file.xlsx")
    targets = rename_targets(doc)
    for form in _forms(new):
        pattern = re.compile(re.escape(form), re.IGNORECASE)
        clash = [p for p in targets if pattern.search(p.read_text(encoding="utf-8"))]
        if clash:
            raise DeceiveError(f"'{new}' already occurs in " + ", ".join(str(p.relative_to(ROOT)) for p in clash[:5])
                               + (" ..." if len(clash) > 5 else "") + "; a decoy identity must be unique")
    pairs = _pairs(old, new)
    changed = []
    for p in targets:
        text = before = p.read_text(encoding="utf-8")
        for old_form, new_form in pairs:
            def swap(m: re.Match, n: str = new_form) -> str:
                return _replace_case(m, n)
            text = re.sub(re.escape(old_form), swap, text, flags=re.IGNORECASE)
        if text != before:
            p.write_text(text, encoding="utf-8")
            changed.append(str(p.relative_to(ROOT)))
    return changed


# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="fail when inventory, rules, tests, red tests, configuration or catalogue disagree")
    ap.add_argument("--gaps", action="store_true", help="the decoy classes not built, ranked")
    ap.add_argument("--rename", nargs=2, metavar=("OLD", "NEW"), help="adopt your own identity for a decoy, everywhere")
    ap.add_argument("--json", action="store_true", help="print the inventory with its check result as JSON")
    args = ap.parse_args()
    doc = load_inventory()

    if args.rename:
        old, new = args.rename
        changed = rename(doc, old, new)
        print(f"{GREEN}renamed{RESET} '{old}' -> '{new}' in {len(changed)} file(s):")
        for c in changed:
            print(f"  {c}")
        print(f"\n{DIM}now: rasd build (generated files), then rasd ci (the proofs, with your identity){RESET}")
        return 0
    if args.gaps:
        print(render_gaps(doc))
        return 0

    errs = check(doc)
    current = write_readme(doc, check=args.check)
    if args.check and not current:
        errs.append(f"{README.relative_to(ROOT)}: the catalogue is out of date (run: rasd deceive)")
    if args.json:
        print(json.dumps({"decoys": doc.get("decoys"), "classes": doc.get("classes"), "problems": errs}, indent=2, default=str))
        return 1 if errs else 0
    decoys = doc.get("decoys") or []
    print(f"{BOLD}RASD-Deceive · {len(decoys)} decoys · {len({d.get('detection') for d in decoys})} deception detections · "
          f"{len({d.get('red_test') for d in decoys})} red tests{RESET}\n")
    for d in decoys:
        print(f"  {d.get('kind', '?'):<8} {identity(d):<42} {DIM}-> {d.get('detection')} · red {d.get('red_test')}{RESET}")
    if errs:
        print(f"\n{RED}{len(errs)} problem(s){RESET}")
        for e in errs:
            print(f"  - {e}")
        return 1
    print(f"\n{GREEN}inventory, rules, tests, red tests and configuration agree{RESET}"
          + ("" if current else f" {DIM}(catalogue written){RESET}"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
