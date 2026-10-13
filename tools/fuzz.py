#!/usr/bin/env python3
"""
fuzz.py - evasion fuzzer: attack every detection with automatically generated variants.

Hand-written mutation tests check the evasions you thought of. The fuzzer checks
the ones you did not. It takes every true-positive event and rewrites it the way
real tradecraft and real log pipelines do, while keeping the behaviour identical,
then reports every variant that slips past the rule.

Transform categories
  semantic       Same action on Windows, different telemetry text
                 (case, quoting, parameter abbreviation, switch order, ordinals ...)
  normalization  Same event, represented differently by another log pipeline
                 (decimal vs hex codes, expanded registry hive names ...)
  plausible      Usually equivalent, but depends on the program or the shell
                 (forward slashes in paths, '-' instead of '/' switches ...)

Regression gate
  detect/evasion/baseline.json records the bypasses that are known and accepted
  (each one is a documented blind spot). `--check` fails when a NEW bypass
  appears, so a tuning change can never silently open a hole. Run with
  `--update-baseline` after deliberately accepting or fixing bypasses.

Usage
  python tools/fuzz.py                 # report
  python tools/fuzz.py --check         # CI gate
  python tools/fuzz.py --filter T1059 --verbose
  python tools/fuzz.py --json out.json
"""
from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BOLD, DIM, EVASION_BASELINE, GREEN, RED, RESET, YELLOW, load_detections  # noqa: E402
from sigma_engine import SigmaError, matches  # noqa: E402

BASELINE = EVASION_BASELINE
CASE_FIELDS = ("Image", "CommandLine", "ParentImage", "TargetObject", "Details",
               "ImagePath", "ServiceName", "TargetImage", "SourceImage", "OriginalFileName")
PS_NAMES = ("powershell.exe", "pwsh.exe", "pwsh.dll")
HEX_FIELDS = ("TicketEncryptionType", "Status", "GrantedAccess")


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _get(ev: dict, f: str) -> str:
    v = ev.get(f)
    return v if isinstance(v, str) else ""


def _is_ps(ev: dict) -> bool:
    return (_get(ev, "Image").lower().endswith(("\\powershell.exe", "\\pwsh.exe"))
            or _get(ev, "OriginalFileName").lower() in PS_NAMES)


def _image_is(ev: dict, name: str) -> bool:
    return _get(ev, "Image").lower().endswith("\\" + name)


def _split_lead(cmd: str) -> tuple[str, str]:
    """Split a command line into (program token, rest), honouring quotes."""
    cmd = cmd.lstrip()
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        return (cmd[: end + 1], cmd[end + 1:]) if end > 0 else (cmd, "")
    m = re.match(r"(\S+)(.*)", cmd, re.S)
    return (m.group(1), m.group(2)) if m else (cmd, "")


def _outside_quotes(s: str, fn) -> str:
    parts = re.split(r'("[^"]*")', s)
    return "".join(p if p.startswith('"') else fn(p) for p in parts)


def _with(ev: dict, **changes) -> dict:
    out = copy.deepcopy(ev)
    out.update(changes)
    return out


# --------------------------------------------------------------------------- #
# transforms: each yields (name, category, mutated_event)
# --------------------------------------------------------------------------- #
def t_case(ev):
    for name, fn in (("case_upper", str.upper),
                     ("case_alternating", lambda s: "".join(ch.upper() if i % 2 else ch.lower()
                                                            for i, ch in enumerate(s)))):
        changes = {f: fn(ev[f]) for f in CASE_FIELDS if isinstance(ev.get(f), str)}
        if changes:
            yield name, "semantic", _with(ev, **changes)


def t_spacing(ev):
    cmd = _get(ev, "CommandLine")
    if " " in cmd:
        yield "cmd_double_space", "semantic", _with(ev, CommandLine=_outside_quotes(cmd, lambda p: p.replace(" ", "  ")))


def t_program_token(ev):
    cmd, image = _get(ev, "CommandLine"), _get(ev, "Image")
    if not cmd:
        return
    lead, rest = _split_lead(cmd)
    bare = lead.strip('"')
    if not lead.startswith('"'):
        yield "exe_quoted", "semantic", _with(ev, CommandLine=f'"{bare}"{rest}')
    if image and "\\" not in bare:
        yield "exe_full_path", "semantic", _with(ev, CommandLine=f'"{image}"{rest}')
    if bare.lower().endswith(".exe") and "\\" not in bare:
        yield "exe_no_extension", "semantic", _with(ev, CommandLine=bare[:-4] + rest)


def t_powershell(ev):
    if not _is_ps(ev):
        return
    cmd = _get(ev, "CommandLine")
    lead, rest = _split_lead(cmd)
    for name, prefix in (("ps_slash_prefix", "/"), ("ps_en_dash_prefix", "\u2013"), ("ps_em_dash_prefix", "\u2014"),
                         ("ps_horizontal_bar_prefix", "\u2015")):
        new = re.sub(r"(\s)[-/\u2013\u2014\u2015](?=[A-Za-z])", lambda m: m.group(1) + prefix, rest)
        if new != rest:
            yield name, "semantic", _with(ev, CommandLine=lead + new)
    m = re.search(r"(\s)([-/\u2013\u2014\u2015])(e|ec|en[a-z]*)(\s+)(\S+)", rest, re.I)
    if m:
        for alt in ("e", "ec", "enco", "EncodedCommand", "eNcOdEdCoMmAnD"):
            if alt.lower() != m.group(3).lower():
                new = rest[: m.start(3)] + alt + rest[m.end(3):]
                yield f"ps_param_{alt.lower()}", "semantic", _with(ev, CommandLine=lead + new)
        sw, blob = m.group(2) + m.group(3), m.group(5).strip('"')
        forms = (("ps_double_dash", f"--{m.group(3)}{m.group(4)}{blob}"),         # pwsh accepts --switch
                 ("ps_double_em_dash", f"\u2014\u2014{m.group(3)}{m.group(4)}{blob}"),
                 ("ps_quoted_switch", f'"{sw}"{m.group(4)}{blob}'),               # quotes are stripped by argv parsing
                 ("ps_quoted_blob", f'{sw}{m.group(4)}"{blob}"'),
                 ("ps_quoted_after_dash", f'{m.group(2)}"{m.group(3)}"{m.group(4)}{blob}'))
        for name, form in forms:
            yield name, "semantic", _with(ev, CommandLine=lead + rest[: m.start(2)] + form + rest[m.end(5):])


def t_rename(ev):
    if not _get(ev, "OriginalFileName") or not _get(ev, "Image"):
        return
    new_image = "C:\\Users\\Public\\wuauhelper.exe"
    lead, rest = _split_lead(_get(ev, "CommandLine"))
    yield "binary_renamed", "semantic", _with(ev, Image=new_image, CommandLine=f'"{new_image}"{rest}')


def t_schtasks(ev):
    if not _image_is(ev, "schtasks.exe"):
        return
    cmd = _get(ev, "CommandLine")
    lead, rest = _split_lead(cmd)
    yield "switch_dash_prefix", "plausible", _with(
        ev, CommandLine=lead + _outside_quotes(rest, lambda p: re.sub(r"(^|\s)/(?=[A-Za-z])", r"\1-", p)))
    quoted = re.sub(r'(^|\s)([/-](?:create|change))(?=\s|$)', r'\1"\2"', rest, count=1, flags=re.I)
    if quoted != rest:
        yield "switch_quoted", "semantic", _with(ev, CommandLine=lead + quoted)
    tokens = re.findall(r'"[^"]*"|\S+', rest)
    pairs, i = [], 0
    while i < len(tokens):
        if tokens[i].startswith("/") and i + 1 < len(tokens) and not tokens[i + 1].startswith("/"):
            pairs.append(tokens[i:i + 2]); i += 2
        else:
            pairs.append(tokens[i:i + 1]); i += 1
    head = [p for p in pairs if p[0].lower() == "/create"]
    tail = [p for p in pairs if p[0].lower() != "/create"]
    if head and len(tail) > 1:
        reordered = head + tail[::-1]
        yield "switch_reordered", "semantic", _with(ev, CommandLine=lead + " " + " ".join(" ".join(p) for p in reordered))


def t_wevtutil(ev):
    if not _image_is(ev, "wevtutil.exe"):
        return
    cmd = _get(ev, "CommandLine")
    if re.search(r"\scl\s", cmd, re.I):
        yield "wevtutil_long_verb", "semantic", _with(ev, CommandLine=re.sub(r"\scl\s", " clear-log ", cmd, flags=re.I))
        m = re.search(r"\scl\s+(\S+)", cmd, re.I)
        if m and not m.group(1).startswith('"'):
            yield "wevtutil_quoted_log", "semantic", _with(
                ev, CommandLine=cmd[: m.start(1)] + f'"{m.group(1)}"' + cmd[m.end(1):])


def t_comsvcs(ev):
    cmd = _get(ev, "CommandLine")
    if re.search(r"comsvcs", cmd, re.I) and re.search(r"minidump", cmd, re.I):
        yield "comsvcs_ordinal_24", "semantic", _with(ev, CommandLine=re.sub(r"minidump", "#24", cmd, flags=re.I))
        yield "comsvcs_ordinal_padded", "semantic", _with(ev, CommandLine=re.sub(r"minidump", "#+0000024", cmd, flags=re.I))
        # rundll32 keeps only the low 16 bits of an ordinal: 65560 and -4294967272 both resolve to 24
        yield "comsvcs_ordinal_wrapped", "semantic", _with(ev, CommandLine=re.sub(r"minidump", "#65560", cmd, flags=re.I))
        yield "comsvcs_ordinal_negative", "semantic", _with(ev, CommandLine=re.sub(r"minidump", "#-4294967272", cmd, flags=re.I))


PATH_TOKEN = re.compile(r"[A-Za-z]:\\[^\s\"',]*")


def t_forward_slash(ev):
    """Windows APIs accept '/' as a path separator; rewrite file paths only (never account names)."""
    cmd = _get(ev, "CommandLine")
    if cmd:
        lead, rest = _split_lead(cmd)
        new = PATH_TOKEN.sub(lambda m: m.group(0).replace("\\", "/"), rest)
        if new != rest:
            yield "path_forward_slashes", "plausible", _with(ev, CommandLine=lead + new)
    details = _get(ev, "Details")
    new = PATH_TOKEN.sub(lambda m: m.group(0).replace("\\", "/"), details)
    if new != details:
        yield "registry_data_forward_slashes", "plausible", _with(ev, Details=new)
    image_path = _get(ev, "ImagePath")
    new = PATH_TOKEN.sub(lambda m: m.group(0).replace("\\", "/"), image_path)
    if new != image_path:
        yield "service_path_forward_slashes", "plausible", _with(ev, ImagePath=new)


def t_service_path(ev):
    path = _get(ev, "ImagePath")
    if re.match(r"(?i)%systemroot%\\", path):
        yield "service_path_expanded", "plausible", _with(ev, ImagePath=re.sub(r"(?i)%systemroot%", "C:\\\\Windows", path))


def t_normalization(ev):
    changes = {}
    for f in HEX_FIELDS:
        v = ev.get(f)
        if isinstance(v, str) and re.fullmatch(r"0x[0-9a-fA-F]+", v):
            changes[f] = str(int(v, 16))
    if changes:
        yield "hex_as_decimal", "normalization", _with(ev, **changes)
    tobj = _get(ev, "TargetObject")
    long_names = {"HKLM\\": "HKEY_LOCAL_MACHINE\\", "HKU\\": "HKEY_USERS\\", "HKCU\\": "HKEY_CURRENT_USER\\"}
    for short, full in long_names.items():
        if tobj.upper().startswith(short):
            yield "registry_long_hive", "normalization", _with(ev, TargetObject=full + tobj[len(short):])
    if isinstance(ev.get("EventID"), int):
        yield "eventid_as_string", "normalization", _with(ev, EventID=str(ev["EventID"]))
    ip = _get(ev, "IpAddress")
    if ip.startswith("::ffff:"):
        yield "ipv4_unmapped", "normalization", _with(ev, IpAddress=ip[7:])


TRANSFORMS = (t_case, t_spacing, t_program_token, t_powershell, t_rename, t_schtasks, t_wevtutil,
              t_comsvcs, t_forward_slash, t_service_path, t_normalization)


def variants(ev: dict):
    seen = set()
    for t in TRANSFORMS:
        for name, cat, new in t(ev):
            key = json.dumps(new, sort_keys=True, ensure_ascii=False)
            if new != ev and key not in seen:
                seen.add(key)
                yield name, cat, new


# --------------------------------------------------------------------------- #
def fuzz(filter_: str | None = None) -> dict:
    report = {}
    for d in load_detections(filter_):
        tried, bypasses = 0, []
        for i, ev in enumerate(d.tests("true_positive"), 1):
            for name, cat, new in variants(ev):
                tried += 1
                try:
                    hit = matches(d.rule, new)
                except SigmaError as e:
                    hit = False
                    name = f"{name} (error: {e})"
                if not hit:
                    bypasses.append({"id": f"tp{i}:{name}", "category": cat, "case": ev.get("_case", f"tp{i}"),
                                     "variant": {k: v for k, v in new.items() if new.get(k) != ev.get(k)}})
        resistance = 100.0 if tried == 0 else round(100 * (tried - len(bypasses)) / tried, 1)
        report[d.id] = {"tried": tried, "bypasses": bypasses, "resistance": resistance}
    return report


def load_baseline() -> dict:
    return json.loads(BASELINE.read_text(encoding="utf-8")) if BASELINE.exists() else {}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--filter")
    ap.add_argument("--check", action="store_true", help="fail on bypasses not in detect/evasion/baseline.json")
    ap.add_argument("--update-baseline", action="store_true")
    ap.add_argument("--verbose", "-v", action="store_true")
    ap.add_argument("--json", help="write the full report to this file")
    args = ap.parse_args()

    report = fuzz(args.filter)
    baseline = load_baseline()
    new_total, fixed_total, tried_total, byp_total = 0, 0, 0, 0
    for det, r in report.items():
        known = set(baseline.get(det, []))
        ids = {b["id"] for b in r["bypasses"]}
        new, fixed = ids - known, known - ids
        new_total += len(new); fixed_total += len(fixed)
        tried_total += r["tried"]; byp_total += len(ids)
        colour = GREEN if r["resistance"] == 100 else (YELLOW if not new else RED)
        print(f"{colour}{r['resistance']:5.1f}%{RESET}  {det:<48} {r['tried']:3d} variants  "
              f"{len(ids):2d} bypass{'es' if len(ids) != 1 else ''}"
              + (f"  {RED}{len(new)} NEW{RESET}" if new else "") + (f"  {GREEN}{len(fixed)} fixed{RESET}" if fixed else ""))
        if args.verbose or new:
            for b in r["bypasses"]:
                if args.verbose or b["id"] in new:
                    tag = f"{RED}NEW{RESET} " if b["id"] in new else f"{DIM}known{RESET} "
                    print(f"         {tag}{b['id']} [{b['category']}] {DIM}{json.dumps(b['variant'], ensure_ascii=False)[:110]}{RESET}")

    overall = 100.0 if tried_total == 0 else 100 * (tried_total - byp_total) / tried_total
    print(f"\n{BOLD}{tried_total} evasion variants · {byp_total} bypasses · "
          f"overall resistance {overall:.1f}%{RESET}" + (f"  ·  {RED}{new_total} new{RESET}" if new_total else ""))

    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if args.update_baseline:
        BASELINE.parent.mkdir(exist_ok=True)
        data = {d: sorted(b["id"] for b in r["bypasses"]) for d, r in report.items() if r["bypasses"]}
        if args.filter:                       # keep untouched detections when filtering
            data = {**{k: v for k, v in baseline.items() if k not in report}, **data}
        BASELINE.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[+] baseline updated ({sum(len(v) for v in data.values())} accepted bypasses)")
        return 0
    if args.check and new_total:
        print(f"{RED}New evasion bypasses detected. Fix the rule, or accept them with --update-baseline "
              f"and document the blind spot in contract.yml.{RESET}")
        return 1
    if fixed_total and args.check:
        print(f"{YELLOW}{fixed_total} accepted bypass(es) no longer reproduce - run --update-baseline to tighten.{RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
