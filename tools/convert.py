#!/usr/bin/env python3
"""
convert.py - translate the lab's Sigma rules into SIEM queries.

Backends
  kql : Microsoft Sentinel (Kusto Query Language)
  spl : Splunk (Search Processing Language)
  mde : Microsoft Defender XDR advanced hunting - optional, for the log sources a Defender
        table carries (process creation, registry); the KQL filter over an extend that
        rebuilds the rule's field names from the Defender columns

Field names and base tables come from tools/mappings.yml, so the same
rule can be retargeted to any environment by editing one file.

Usage
  rasd convert --backend kql                 # print all
  rasd convert --backend spl --rule "detect/detections/T1059.001_*/rule.yml"
  rasd convert --all --out queries/          # write files
"""
from __future__ import annotations

import argparse
import glob
import os
import re
import sys
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sigma_engine import SigmaError, _parse_key, check_values, conditions, resolve_pattern, tokenize

ROOT = Path(__file__).resolve().parent.parent
MAPPINGS = yaml.safe_load((ROOT / "tools" / "mappings.yml").read_text(encoding="utf-8"))


def logsource_key(rule: dict) -> str:
    """Windows categories keep their bare name (process_creation); a category on another product
    is qualified with it (linux/process_creation); services are product/service."""
    ls = rule.get("logsource", {})
    product, category = ls.get("product", ""), ls.get("category")
    if category:
        return category if product in ("", "windows") else f"{product}/{category}"
    return f"{product}/{ls.get('service', '')}"


def sigma_regex(value: Any, mods: list[str]) -> str:
    """The rule's |re pattern for a SIEM: Sigma semantics (case-sensitive unless the
    pattern says (?i) or the rule uses re|i), sub-modifiers merged into ONE leading
    inline-flag group - RE2 (KQL) and PCRE (SPL) both accept (?ims), and a second
    group would be rejected."""
    pattern = str(value)
    letters = {m for m in "ims" if m in mods}
    lead = re.match(r"\(\?([ims]+)\)", pattern)
    if lead:
        letters |= set(lead.group(1))
        pattern = pattern[lead.end():]
    return (f"(?{''.join(sorted(letters))})" if letters else "") + pattern


def wildcard_to_regex(value: str) -> str:
    return "^" + re.escape(value).replace(r"\*", ".*").replace(r"\?", ".") + "$"


# --------------------------------------------------------------------------- #
# Backends: each turns (field, modifiers, value) into one predicate string
# --------------------------------------------------------------------------- #
class KQL:
    name = "kql"
    AND, OR = "and", "or"

    @staticmethod
    def negate(x: str) -> str:
        return f"not({x})"

    @staticmethod
    def s(v: Any) -> str:                       # verbatim string literal
        return '@"' + str(v).replace('"', '""') + '"'

    def predicate(self, f: str, mods: list[str], v: Any, null_safe: bool = False) -> str:
        # string columns are never null in Kusto (missing = ""), so negation is already safe
        if "exists" in mods:
            return f"isnotempty({f})" if v else f"isempty({f})"
        if v is None:
            return f"isempty({f})"
        if "re" in mods:
            return f"{f} matches regex {self.s(sigma_regex(v, mods))}"
        cs = "cased" in mods
        if "contains" in mods:
            return f"{f} {'contains_cs' if cs else 'contains'} {self.s(v)}"
        if "startswith" in mods:
            return f"{f} {'startswith_cs' if cs else 'startswith'} {self.s(v)}"
        if "endswith" in mods:
            return f"{f} {'endswith_cs' if cs else 'endswith'} {self.s(v)}"
        if isinstance(v, str) and ("*" in v or "?" in v):
            return f"{f} matches regex {self.s(('' if cs else '(?i)') + wildcard_to_regex(v))}"
        if isinstance(v, (int, float)):
            return f"{f} == {v}"
        return f"{f} {'==' if cs else '=~'} {self.s(v)}"

    @staticmethod
    def wrap(base: str, where: str) -> str:
        return f"{base}\n| where {where}"


class SPL:
    name = "spl"
    AND, OR = "AND", "OR"

    @staticmethod
    def negate(x: str) -> str:
        return f"NOT {x if x.startswith('(') else '(' + x + ')'}"

    @staticmethod
    def s(v: Any) -> str:
        return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'

    def predicate(self, f: str, mods: list[str], v: Any, null_safe: bool = False) -> str:
        if "exists" in mods:
            return f"isnotnull('{f}')" if v else f"isnull('{f}')"
        if v is None:
            return f"isnull('{f}')"
        # In SPL a missing field is NULL and NOT NULL is still NULL, so under a negation
        # `NOT match('F', ...)` would silently drop every event that lacks F. Inside a
        # negated branch the field is read as coalesce('F', "") - missing reads as empty,
        # exactly like the Sigma semantics the tests run against (proven by parity.py).
        ref = f"coalesce('{f}', \"\")" if null_safe else f"'{f}'"
        flag = "" if "cased" in mods else "(?i)"
        if "re" in mods:
            return f"match({ref}, {self.s(sigma_regex(v, mods))})"
        if isinstance(v, (int, float)):
            return f"{ref}={v}"
        # contains/startswith/endswith/wildcards -> anchored regex (safe with backslashes)
        if "contains" in mods:
            rx = re.escape(str(v))
        elif "startswith" in mods:
            rx = "^" + re.escape(str(v))
        elif "endswith" in mods:
            rx = re.escape(str(v)) + "$"
        elif "*" in str(v) or "?" in str(v):
            rx = wildcard_to_regex(str(v))
        else:
            if "cased" in mods:
                return f"{ref}={self.s(v)}"
            return f"lower({ref})={self.s(str(v).lower())}"
        return f"match({ref}, {self.s(flag + rx)})"

    @staticmethod
    def wrap(base: str, where: str) -> str:
        return f"{base}\n| where {where}"


BACKENDS: dict[str, KQL | SPL] = {"kql": KQL(), "spl": SPL()}
DEFENDER = "mde"                                   # optional backend: not every log source has a table


def legacy_note(rule: dict) -> str:
    """' | ATT&CK v19.2 T1685.005, v18 T1070.001' for a rule whose technique moved in ATT&CK v19, else ''."""
    from common import attack_aliases, legacy_technique
    for tag in rule.get("tags") or []:
        if re.match(r"^attack\.t\d{4}", str(tag)):
            tech = str(tag).split(".", 1)[1].upper()
            old = legacy_technique(tech)
            if old:
                a = attack_aliases()
                return f" | ATT&CK v{a['attack_version']} {tech}, v{a['legacy_version']} {old}"
    return ""


def defender_expression(spec: Any) -> str:
    """The KQL expression that rebuilds one rule field from Defender columns (see tools/mappings.yml)."""
    if isinstance(spec, str):
        return f"tostring({spec})"
    if "path" in spec:
        folder, file = spec["path"]
        trimmed = rf'trim_end(@"[\\/]+", {folder})'
        return (f"iff(isempty({folder}), {file}, iff(isempty({file}) or {trimmed} endswith {file}, {folder}, "
                rf'strcat({trimmed}, @"\", {file})))')
    if "account" in spec:
        domain, name = spec["account"]
        return rf'iff(isempty({domain}), {name}, strcat({domain}, @"\", {name}))'
    if "registry" in spec:
        key, value = spec["registry"]
        hive = (f'replace_regex(replace_regex(replace_regex({key}, @"(?i)^HKEY_LOCAL_MACHINE", "HKLM"), '
                f'@"(?i)^HKEY_(CURRENT_USER|USERS)", "HKU"), @"(?i)^HKEY_CLASSES_ROOT", "HKCR")')
        # an empty value name is the key's default value, which Sysmon writes as "(Default)"
        return rf'strcat({hive}, @"\", iff(isempty({value}), "(Default)", {value}))'
    raise SigmaError(f"invalid Defender field spec {spec!r}")


def convert_defender(rule: dict) -> str:
    """Microsoft Defender XDR advanced hunting: the Defender table, an extend that gives the rule
    its own field names, then the KQL backend's filter."""
    m, key = MAPPINGS[DEFENDER], logsource_key(rule)
    if key not in m["logsources"]:
        raise SigmaError(f"Defender advanced hunting has no table for log source '{key}'")
    spec = (m.get("extend") or {}).get(key) or {}
    fields = referenced_fields(rule["detection"])
    missing = [f for f in fields if f not in spec]
    if missing:
        raise SigmaError(f"Defender advanced hunting has no column for {', '.join(missing)} ({key})")
    base = m["logsources"][key].strip()
    if fields:
        base += "\n| extend " + ",\n    ".join(f"{f} = {defender_expression(spec[f])}" for f in fields)
    where = translate_condition(rule["detection"], BACKENDS["kql"], {})
    return f"// {rule['title']} | {rule['id']} | Microsoft Defender XDR advanced hunting{legacy_note(rule)}\n{KQL.wrap(base, where)}"


# --------------------------------------------------------------------------- #
# Generic translation of selections + condition
# --------------------------------------------------------------------------- #
def _join(parts: list[str], op: str) -> str:
    parts = [p for p in parts if p]
    if len(parts) == 1:
        return parts[0]
    return "(" + f" {op} ".join(parts) + ")"


def translate_selection(sel: Any, backend, fieldmap: dict, null_safe: bool = False) -> str:
    if isinstance(sel, list):
        if not all(isinstance(s, dict) for s in sel):
            raise SigmaError("Keyword selections are not supported by the converter")
        return _join([translate_selection(s, backend, fieldmap, null_safe) for s in sel], backend.OR)
    if not isinstance(sel, dict):
        raise SigmaError(f"Invalid selection type: {type(sel).__name__}")
    clauses = []
    for key, value in sel.items():
        field, parsed = _parse_key(key)          # the engine's own validation: one definition of what is supported
        check_values(field, parsed, value)
        mods = list(parsed)
        field = fieldmap.get(field, field)
        values = value if isinstance(value, list) else [value]
        preds = [backend.predicate(field, mods, v, null_safe) for v in values]
        clauses.append(_join(preds, backend.AND if "all" in mods else backend.OR))
    return _join(clauses, backend.AND)


class _CondTranslator:
    """Recursive-descent translator mirroring sigma_engine's grammar."""

    def __init__(self, tokens, detection, backend, fieldmap):
        self.t, self.i = tokens, 0
        self.det, self.b, self.fm = detection, backend, fieldmap
        self.negations = 0                      # >0 while inside a `not` branch

    def peek(self):
        return self.t[self.i].lower() if self.i < len(self.t) else None

    def take(self):
        tok = self.t[self.i]
        self.i += 1
        return tok

    def expr(self):
        parts = [self.term()]
        while self.peek() == "or":
            self.take()
            parts.append(self.term())
        return _join(parts, self.b.OR)

    def term(self):
        parts = [self.factor()]
        while self.peek() == "and":
            self.take()
            parts.append(self.factor())
        return _join(parts, self.b.AND)

    def factor(self):
        tok = self.peek()
        if tok == "not":
            self.take()
            self.negations += 1
            inner = self.factor()
            self.negations -= 1
            return self.b.negate(inner)
        if tok == "(":
            self.take()
            val = self.expr()
            self.take()  # ')'
            return val
        if tok in ("1", "all") and self.i + 1 < len(self.t) and self.t[self.i + 1].lower() == "of":
            quant = self.take().lower()
            self.take()
            names = resolve_pattern(self.det, self.take())
            subs = [translate_selection(self.det[n], self.b, self.fm, self.negations > 0) for n in names]
            return _join(subs, self.b.AND if quant == "all" else self.b.OR)
        return translate_selection(self.det[self.take()], self.b, self.fm, self.negations > 0)


def translate_condition(detection: dict, backend, fieldmap: dict) -> str:
    return _join([_CondTranslator(tokenize(c), detection, backend, fieldmap).expr() for c in conditions(detection)],
                 backend.OR)


def referenced_fields(detection: dict) -> list[str]:
    """Every field name a rule's selections read, in first-seen order."""
    seen: list[str] = []

    def walk(sel: Any) -> None:
        if isinstance(sel, dict):
            for key in sel:
                name = key.split("|")[0]
                if name and name not in seen:
                    seen.append(name)
        elif isinstance(sel, list):
            for item in sel:
                walk(item)

    for name, sel in detection.items():
        if name != "condition":
            walk(sel)
    return seen


def kql_eventdata(rule: dict, key: str, fieldmap: dict) -> str:
    """`| extend` lines that read the rule's non-column fields from the EventData XML."""
    cfg = MAPPINGS["kql"].get("eventdata") or {}
    if key not in cfg.get("logsources", []):
        return ""
    native = set(cfg.get("native", []))
    lines = []
    for f in referenced_fields(rule["detection"]):
        col = fieldmap.get(f, f)
        if col in native:
            continue
        lines.append(f'| extend {col} = coalesce(tostring(column_ifexists("{col}", "")), '
                     f"extract(@'Name=\"{col}\">([^<]*)<', 1, EventData))")
    return ("\n" + "\n".join(lines)) if lines else ""


def convert(rule: dict, backend_name: str) -> str:
    if backend_name == DEFENDER:
        return convert_defender(rule)
    backend = BACKENDS[backend_name]
    m = MAPPINGS[backend_name]
    key = logsource_key(rule)
    if key not in m["logsources"]:
        raise SigmaError(f"No {backend_name} mapping for logsource '{key}'")
    base = m["logsources"][key].strip()
    if backend_name == "kql":
        base += kql_eventdata(rule, key, m.get("fields", {}))
    where = translate_condition(rule["detection"], backend, m.get("fields", {}))
    query = backend.wrap(base, where)
    if backend_name == "kql":
        return f"// {rule['title']} | {rule['id']}{legacy_note(rule)}\n{query}"
    # SPL: no leading comment - the file must start with the search itself so it
    # pastes cleanly into any Splunk version and saved-search/API context.
    return query


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backend", choices=[*BACKENDS, DEFENDER], default="kql")
    ap.add_argument("--rule", help="glob of rule files (default: all)")
    ap.add_argument("--all", action="store_true", help="generate every backend")
    ap.add_argument("--out", help="write queries to this directory instead of stdout")
    args = ap.parse_args()

    files = sorted(glob.glob(args.rule or str(ROOT / "detect" / "detections" / "*" / "rule.yml")))
    backends = [*BACKENDS, DEFENDER] if args.all else [args.backend]
    failed = written = 0
    defender_files: set[str] = set()
    for path in files:
        rule = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        folder = Path(path).parent.name
        for b in backends:
            if b == DEFENDER and logsource_key(rule) not in MAPPINGS[DEFENDER]["logsources"]:
                continue                               # no Defender table for this log source
            try:
                q = convert(rule, b)
            except SigmaError as e:
                print(f"[!] {folder} ({b}): {e}", file=sys.stderr)
                failed += 1
                continue
            if args.out:
                os.makedirs(Path(args.out) / b, exist_ok=True)
                ext = "spl" if b == "spl" else "kql"
                (Path(args.out) / b / f"{folder}.{ext}").write_text(q + "\n", encoding="utf-8")
                written += 1
                if b == DEFENDER:
                    defender_files.add(f"{folder}.kql")
            else:
                print(q, end="\n\n")
    if args.out and DEFENDER in backends and not args.rule:   # only a full run knows which files are stale
        for stale in (Path(args.out) / DEFENDER).glob("*.kql"):
            if stale.name not in defender_files:
                stale.unlink()                         # a rule removed, or its log source no longer covered
    if args.out:
        print(f"[+] wrote {written} queries to {args.out}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
