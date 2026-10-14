#!/usr/bin/env python3
"""
sigma_support.py - which Sigma features RASD evaluates and converts, with the proof.

RASD runs its own Sigma engine (sigma_engine.py) and converter (convert.py). They cover a
defined subset of the Sigma specification, and everything outside it raises an error: no
rule is ever evaluated or converted approximately. This tool writes docs/SIGMA_SUPPORT.md
from the engine's own tables, and on every build it proves the page:

  supported   every listed construct gives the same verdict in the engine, the compiled
              engine, the generated SPL and the generated KQL (each parsed back and run with
              that SIEM's semantics, as parity.py does) on a probe matrix of values: exact and
              other case, wildcards, empty, missing, multi-line
  refused     every listed unsupported construct raises an error in the engine, the compiled
              engine and both converters

Usage
  rasd sigma            # run the proofs, write docs/SIGMA_SUPPORT.md
  rasd sigma --check    # CI: fail if a proof fails or the page is stale
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BOLD, GREEN, RED, RESET, ROOT
from convert import convert
from correlation import OPS, SUPPORTED as CORRELATION_TYPES
from parity import ParseError, compile_query
from sigma_engine import RE_FLAGS, SUPPORTED_MODIFIERS, SigmaError, compile_rule, matches

OUT = ROOT / "docs" / "SIGMA_SUPPORT.md"
CMD = "C:\\Windows\\System32\\cmd.exe"

# Events every supported construct is proven on: case variants, look-alikes, empty and missing values.
PROBES: list[dict] = [
    {"Image": CMD, "CommandLine": "cmd.exe /c whoami", "User": "LAB\\alice"},
    {"Image": CMD.lower().replace("cmd.exe", "CMD.EXE"), "CommandLine": "CMD.EXE /C WHOAMI", "User": "lab\\ALICE"},
    {"Image": "C:\\Tools\\cmd.exe.bak", "CommandLine": "notepad readme.txt", "User": ""},
    {"Image": "C:\\Windows\\System32\\rundll32.exe", "CommandLine": "rundll32.exe javascript:x"},
    {"Image": "", "CommandLine": ""},
    {},
    {"Image": "C:\\Windows\\System32\\cmX.exe", "CommandLine": "line1\nline2 whoami", "User": "bob"},
]

# (construct, what it means, detection). Each one is proven by prove_supported().
SUPPORTED: list[tuple[str, str, dict]] = [
    ("Plain value", "equality, case-insensitive",
     {"sel": {"Image": CMD}, "condition": "sel"}),
    ("Wildcards `*` and `?`", "any run of characters / exactly one character, nothing else is special",
     {"sel": {"Image": ["*\\cmd.exe", "C:\\Windows\\System32\\cm?.exe"]}, "condition": "sel"}),
    ("Value list", "any value matches (OR)",
     {"sel": {"Image|endswith": ["\\cmd.exe", "\\rundll32.exe"]}, "condition": "sel"}),
    ("`contains` `startswith` `endswith`", "substring, prefix, suffix; case-insensitive",
     {"a": {"CommandLine|contains": "whoami"}, "b": {"CommandLine|startswith": "cmd.exe"},
      "c": {"Image|endswith": "\\cmd.exe"}, "condition": "a or b or c"}),
    ("`all`", "every value of the list must match (AND)",
     {"sel": {"CommandLine|contains|all": ["cmd", "whoami"]}, "condition": "sel"}),
    ("`cased`", "case-sensitive match, with any of the above",
     {"a": {"CommandLine|contains|cased": "whoami"}, "b": {"Image|cased": CMD}, "condition": "a or b"}),
    ("`re`", "regular expression search, case-sensitive unless the pattern starts with `(?i)`",
     {"a": {"CommandLine|re": "who(ami)?$"}, "b": {"CommandLine|re": "(?i)^CMD\\.EXE"}, "condition": "a or b"}),
    ("`re` with `i` `m` `s`", "ignore case, multi-line anchors, dot matches a newline",
     {"a": {"CommandLine|re|i": "WHOAMI$"}, "b": {"CommandLine|re|m": "^line2"},
      "c": {"CommandLine|re|s": "line1.line2"}, "condition": "a or b or c"}),
    ("`exists`", "`true`: present and not empty; `false`: missing or empty",
     {"a": {"User|exists": True}, "b": {"CommandLine|exists": False}, "condition": "a or b"}),
    ("`null`", "the field is missing or empty",
     {"sel": {"User": None}, "condition": "sel"}),
    ("Map selection", "every field must match (AND)",
     {"sel": {"Image|endswith": "\\cmd.exe", "CommandLine|contains": "whoami"}, "condition": "sel"}),
    ("List of maps", "any map matches (OR)",
     {"sel": [{"Image|endswith": "\\cmd.exe"}, {"CommandLine|contains": "javascript"}], "condition": "sel"}),
    ("`and` `or` `not`, parentheses", "boolean condition over selections",
     {"a": {"Image|endswith": "\\cmd.exe"}, "b": {"Image|endswith": "\\rundll32.exe"},
      "c": {"User|contains": "alice"}, "condition": "(a or b) and not c"}),
    ("`1 of` / `all of` a pattern, `them`", "quantifiers over selections named by a wildcard",
     {"sel_a": {"CommandLine|contains": "whoami"}, "sel_b": {"Image|endswith": "\\cmd.exe"},
      "filter_x": {"User": "bob"}, "condition": "(1 of sel_* and not 1 of filter_*) or all of them"}),
    ("A list of conditions", "any condition matches (OR)",
     {"a": {"CommandLine|contains": "javascript"}, "b": {"User": "bob"}, "condition": ["a", "b"]}),
]

SEL = {"CommandLine|contains": "x"}
# (construct, why, detection). Each one must raise an error everywhere.
REFUSED: list[tuple[str, str, dict]] = [
    *[(f"`{m}`", why, {"sel": {f"F|{m}": "x"} if m not in ("gt", "gte", "lt", "lte") else {f"F|{m}": 5},
                       "condition": "sel"})
      for m, why in (
          ("base64", "encoded search values"), ("base64offset", "encoded search values"),
          ("utf16le", "encoded search values"), ("utf16be", "encoded search values"),
          ("utf16", "encoded search values"), ("wide", "encoded search values"),
          ("windash", "dash variants: the rules spell out `-`, `/` and the Unicode dashes instead"),
          ("cidr", "network ranges"), ("expand", "placeholders"), ("fieldref", "field-to-field comparison"),
          ("gt", "numeric comparison"), ("gte", "numeric comparison"), ("lt", "numeric comparison"),
          ("lte", "numeric comparison"))],
    ("`i` `m` `s` without `re`", "regex flags on a non-regex value",
     {"sel": {"CommandLine|contains|i": "x"}, "condition": "sel"}),
    ("Aggregation in a condition", "`\\| count() by ...` was removed in Sigma v2: write a correlation rule",
     {"sel": SEL, "condition": "sel | count() by User > 5"}),
    ("`timeframe` in a detection", "belongs to the removed aggregations: write a correlation rule",
     {"sel": SEL, "timeframe": "5m", "condition": "sel"}),
    ("A condition that is not a string", "only strings and lists of strings are conditions",
     {"sel": SEL, "condition": {"sel": True}}),
    ("The escapes `\\*` `\\?` `\\\\` in a value", "Sigma reads them as escapes and RASD would read every backslash "
     "literally, so one value would mean two things: write single backslashes (`\\127.0.0.1\\` finds a UNC path), "
     "or use `re`", {"sel": {"Image": "C:\\Users\\*"}, "condition": "sel"}),
    ("Wildcards inside `contains` `startswith` `endswith`", "Sigma expands them there and RASD would compare them "
     "literally: split the value, or use `re`", {"sel": {"CommandLine|contains": "who*mi"}, "condition": "sel"}),
]

# Evaluated offline, refused by the converters: no SIEM query proves the same verdict.
ENGINE_ONLY: list[tuple[str, str, dict]] = [
    ("Keyword selection", "a bare list of plain strings (no wildcards or escapes) searched in every field: write a "
     "field condition to deploy it",
     {"keywords": ["whoami"], "condition": "keywords"}),
]


def rule(detection: dict) -> dict:
    return {"title": "probe", "id": "00000000-0000-0000-0000-000000000000",
            "logsource": {"product": "windows", "category": "process_creation"}, "detection": detection}


def raises(fn) -> bool:
    try:
        fn()
    except (SigmaError, ParseError):
        return True
    return False


def prove_supported() -> list[str]:
    errors = []
    for name, _meaning, det in SUPPORTED:
        r = rule(det)
        try:
            fast = compile_rule(r)
            queries = {b: compile_query(r, b) for b in ("spl", "kql")}
        except (SigmaError, ParseError) as e:
            errors.append(f"supported construct '{name}' is refused: {e}")
            continue
        fired = 0
        for i, ev in enumerate(PROBES):
            expected = matches(r, ev)
            fired += expected
            got = {"compiled engine": fast(ev) is True, **{b: q(ev) is True for b, q in queries.items()}}
            for where, verdict in got.items():
                if verdict != expected:
                    errors.append(f"'{name}': {where} says {verdict} on probe #{i + 1}, the engine says {expected}")
        if not 0 < fired < len(PROBES):
            errors.append(f"'{name}': the probes do not separate it ({fired}/{len(PROBES)} match)")
    return errors


def prove_refused() -> list[str]:
    errors = []
    for name, _why, det in REFUSED:
        r = rule(det)
        checks = {"engine": lambda r=r: matches(r, PROBES[0]), "compiled engine": lambda r=r: compile_rule(r),
                  "SPL converter": lambda r=r: convert(r, "spl"), "KQL converter": lambda r=r: convert(r, "kql")}
        errors += [f"refused construct '{name}' is accepted by the {where}" for where, fn in checks.items()
                   if not raises(fn)]
    for name, _why, det in ENGINE_ONLY:
        r = rule(det)
        if raises(lambda r=r: matches(r, PROBES[0])):
            errors.append(f"'{name}' should be evaluated by the engine")
        errors += [f"'{name}' should be refused by the {b.upper()} converter" for b in ("spl", "kql")
                   if not raises(lambda b=b, r=r: convert(r, b))]
    return errors


def render() -> str:
    mods = sorted(SUPPORTED_MODIFIERS - RE_FLAGS.keys())
    out = ["<!-- Generated by tools/sigma_support.py - do not edit by hand. -->", "", "# Sigma Support", "",
           "RASD evaluates and converts a defined subset of the Sigma specification with its own engine "
           "(`tools/sigma_engine.py`) and converter (`tools/convert.py`). Anything outside the subset raises an "
           "error: no rule is evaluated or converted approximately. Rule files use standard Sigma syntax only; "
           "contracts, tuning guides and tests live beside them.", "",
           f"Every row is checked on each build by `tools/sigma_support.py`: a supported construct gives the same "
           f"verdict in the engine, the compiled engine and the generated SPL and KQL (run by RASD's interpreters of "
           f"each language) on {len(PROBES)} probe events (exact and other case, look-alikes, wildcards, empty and "
           "missing fields, a multi-line value), and a refused construct raises an error in all four.", "",
           "## Supported", "", "| Construct | Meaning |", "|---|---|"]
    out += [f"| {name} | {meaning} |" for name, meaning, _ in SUPPORTED]
    out += ["", f"Modifiers: {', '.join(f'`{m}`' for m in mods)}, and `i`, `m`, `s` with `re`. Regular "
            "expressions must also be RE2-safe for Sentinel (no lookarounds, backreferences, possessive "
            "quantifiers or atomic groups); `rasd lint` checks it.", "",
            "## Refused", "", "| Construct | Why |", "|---|---|"]
    grouped: dict[str, list[str]] = {}
    for name, why, _ in REFUSED:
        grouped.setdefault(why, []).append(name)
    out += [f"| {' '.join(names)} | {why} |" for why, names in grouped.items()]
    out += ["", "## Evaluated offline, not converted", "", "| Construct | Why |", "|---|---|"]
    out += [f"| {name} | {why} |" for name, why, _ in ENGINE_ONLY]
    out += ["", "## Correlation rules", "",
            f"Types {' and '.join(f'`{t}`' for t in CORRELATION_TYPES)} over one base rule, with `group-by`, a "
            "`timespan` of whole minutes that divide an hour (or whole hours that divide a day), and one condition: "
            + ", ".join(f"`{o}`" for o in OPS) + ". `temporal`, `temporal_ordered` and any other type are refused "
            "(`tests/test_correlation.py`). Proofs: [CORRELATIONS](CORRELATIONS.md).", "",
            "## Numbers", "",
            "A number in a rule is compared as a number in SPL and KQL. Quote it when the column is text, as the "
            "web rules do for status codes (`sc-status: '401'`).", ""]
    return "\n".join(out)


def check() -> list[str]:
    return prove_supported() + prove_refused()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="fail if a proof fails or the page is stale")
    args = ap.parse_args()
    errors = check()
    body = render()
    stale = not OUT.exists() or OUT.read_text(encoding="utf-8") != body
    if args.check and stale:
        errors.append(f"{OUT.relative_to(ROOT)} is stale (run: rasd build)")
    elif not args.check:
        OUT.write_text(body, encoding="utf-8")
    for e in errors:
        print(f"  {RED}✗{RESET} {e}")
    print(f"{BOLD}Sigma support · {len(SUPPORTED)} supported constructs on {len(PROBES)} probes · "
          f"{len(REFUSED) + len(ENGINE_ONLY)} refused · {len(errors)} problem(s){RESET}"
          if errors else f"{GREEN}✓{RESET} {BOLD}Sigma support · {len(SUPPORTED)} supported constructs agree on "
          f"{len(PROBES)} probes in the engine, SPL and KQL · {len(REFUSED) + len(ENGINE_ONLY)} refused{RESET}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
