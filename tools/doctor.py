#!/usr/bin/env python3
"""
doctor.py - will these detections actually work on YOUR telemetry?

A rule can be perfect and still detect nothing: the log source is not collected,
a field is named differently by your pipeline, the command line is truncated, or
the event ID the rule needs is filtered out at the collector. `doctor` checks a
sample export of your own logs against every detection's contract and tells you,
before deployment, which detections are READY, DEGRADED or BLIND, and why. Correlation
detections are checked through their base rule, with the fields they group and count.

Checks per detection
  * log source present        events routed to the rule's logsource exist
  * event IDs present         the EventIDs the rule selects on appear in the sample
  * field coverage            every required field is present and non-empty (%), counted over
                              the events the field matters for: when a selection pairs the field
                              with EventIDs, only those events (SubStatus is a 4625 field, not a
                              4771 one)
  * field naming              missing fields that exist under another common name
                              (ECS, CIM, 4688 names ...) -> exact mapping to add
  * truncation                CommandLine values piling up at a fixed maximum length

Telemetry profiles (mappings/) translate an export's own field names - Elastic ECS,
Splunk CIM, Sentinel ASIM, Defender advanced hunting - into the rules' names first:
--profile <name>, or --profile auto to use the best fit. Without --profile the export is
read as-is, and doctor says when a profile would fit it better.

Usage
  python tools/doctor.py my-export.jsonl
  python tools/doctor.py samples/doctor/ecs-export.jsonl --profile auto
  python tools/doctor.py samples/doctor/ecs-export.jsonl --profile elastic-ecs --json doctor.json
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BOLD, DIM, GREEN, RED, RESET, YELLOW, load_detections, load_jsonl  # noqa: E402
from convert import logsource_key  # noqa: E402
import profiles  # noqa: E402
from replay import route  # noqa: E402

ALIASES = {
    "CommandLine": ["process.command_line", "command_line", "cmdline", "CommandLine_", "ProcessCommandLine", "process_command_line"],
    "Image": ["process.executable", "NewProcessName", "process_path", "FolderPath", "ImagePath_", "exe"],
    "ParentImage": ["process.parent.executable", "ParentProcessName", "parent_process_path", "InitiatingProcessFolderPath"],
    "OriginalFileName": ["process.pe.original_file_name", "original_file_name", "ProcessVersionInfoOriginalFileName"],
    "User": ["user.name", "SubjectUserName", "AccountName", "user"],
    "TargetImage": ["winlog.event_data.TargetImage", "target_process_path"],
    "SourceImage": ["winlog.event_data.SourceImage", "source_process_path"],
    "GrantedAccess": ["winlog.event_data.GrantedAccess", "granted_access"],
    "TargetObject": ["registry.path", "RegistryKey", "registry_path"],
    "Details": ["registry.data.strings", "RegistryValueData", "registry_value_data"],
    "EventID": ["event.code", "EventCode", "event_id", "winlog.event_id"],
    "ServiceName": ["service.name", "winlog.event_data.ServiceName", "Service_Name"],
    "ImagePath": ["service.executable", "winlog.event_data.ImagePath", "Service_File_Name"],
    "Provider_Name": ["winlog.provider_name", "SourceName", "Source"],
    "TicketEncryptionType": ["winlog.event_data.TicketEncryptionType", "Ticket_Encryption_Type"],
    "IpAddress": ["source.ip", "Client_Address", "winlog.event_data.IpAddress"],
    "Status": ["winlog.event_data.Status", "Failure_Code"],
}
TRUNCATION_LENGTHS = (255, 256, 512, 1000, 1024, 2048, 4000, 4096, 8191, 8192, 32767)


def flatten(ev: dict, prefix: str = "") -> dict:
    out = {}
    for k, v in ev.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(flatten(v, key + "."))
        else:
            out[key] = v
    return out


def rule_event_ids(rule: dict) -> set[str]:
    ids = set()
    def walk(sel):
        if isinstance(sel, dict):
            for k, v in sel.items():
                if k.split("|")[0] == "EventID":
                    ids.update(str(x) for x in (v if isinstance(v, list) else [v]))
        elif isinstance(sel, list):
            for s in sel:
                walk(s)
    for name, sel in (rule.get("detection") or {}).items():
        if name != "condition" and not name.startswith("filter"):      # every positive selection
            walk(sel)
    return ids


def field_event_ids(rule: dict) -> dict[str, set[str]]:
    """field -> the EventIDs of the positive selections that read it together with EventID."""
    out: dict[str, set[str]] = defaultdict(set)

    def walk(sel):
        if isinstance(sel, dict):
            ids = {str(x) for k, v in sel.items() if k.split("|")[0] == "EventID"
                   for x in (v if isinstance(v, list) else [v])}
            for k in sel:
                if ids and k.split("|")[0] != "EventID":
                    out[k.split("|")[0]] |= ids
        elif isinstance(sel, list):
            for item in sel:
                walk(item)
    for name, sel in (rule.get("detection") or {}).items():
        if name != "condition" and not name.startswith("filter"):
            walk(sel)
    return out


def present(v) -> bool:
    return v not in (None, "", "-", [])


def diagnose(events: list[dict], dets, profile: str | None = None) -> list[dict]:
    """profile: the name of the telemetry profile the events were normalised with (for messages)."""
    covers = None
    if profile and profile != profiles.NATIVE:
        covers = set((profiles.load(profile) or {}).get("covers") or [])
    flat = [flatten(e) for e in events]
    by_source = defaultdict(list)
    for raw, f in zip(events, flat):
        src = route(raw) or route({k.split(".")[-1]: v for k, v in f.items()})
        if src:
            by_source[src].append(f)
    all_keys = Counter(k for f in flat for k in f)
    results = []
    for d in dets:
        src = logsource_key(d.rule)
        evs = by_source.get(src, [])
        dc = d.contract.get("data_contract", {})
        required = dc.get("required_fields", [])
        issues, fixes, coverage = [], [], {}
        verdict = "READY"
        if not evs:
            why = (f"the {profile} profile has no record for log source '{src}' - collect the native "
                   "Windows / Sysmon events for this rule" if covers is not None and src not in covers
                   else f"no events for log source '{src}' in the sample")
            results.append({"detection": d.id, "logsource": src, "events": 0, "verdict": "BLIND",
                            "issues": [why], "fixes": [], "coverage": {}})
            continue
        wanted_ids = rule_event_ids(d.rule)
        if wanted_ids:
            seen_ids = {str(f.get("EventID", f.get("event.code", ""))) for f in evs}
            missing_ids = wanted_ids - seen_ids
            if missing_ids == wanted_ids:
                verdict = "BLIND"; issues.append(f"EventID {', '.join(sorted(missing_ids))} never appears in the sample")
        scopes = field_event_ids(d.rule)
        for field in required:
            ids = scopes.get(field) or wanted_ids
            pool = [f for f in evs if str(f.get("EventID", f.get("event.code", ""))) in ids] if ids else evs
            if not pool:
                continue                                  # none of its events in the sample: reported above
            missing = [f for f in pool if not present(f.get(field))]
            pct = round(100 * (len(pool) - len(missing)) / len(pool), 1)
            coverage[field] = pct
            alias = None
            if missing:
                alias = max(ALIASES.get(field, []), key=lambda a: sum(1 for f in missing if present(f.get(a))), default=None)
                if alias and sum(1 for f in missing if present(f.get(alias))) < 0.5 * len(missing):
                    alias = None
            if pct == 0:
                issues.append(f"field '{field}' missing, but '{alias}' exists" if alias else f"required field '{field}' missing")
                verdict = "BLIND"
            elif pct < 95:
                if verdict != "BLIND":
                    verdict = "DEGRADED"
                issues.append(f"'{field}' empty in {100 - pct:.0f}% of events"
                              + (f" (those events carry it as '{alias}')" if alias else ""))
            if alias:
                fixes.append(f"add '{field}: [{alias}]' for {src} to a profile in mappings/ and pass --profile")
        cmds = [f.get("CommandLine") for f in evs if isinstance(f.get("CommandLine"), str)]
        if cmds:
            lengths = Counter(len(c) for c in cmds)
            for L in TRUNCATION_LENGTHS:
                if lengths.get(L, 0) >= max(3, 0.02 * len(cmds)):
                    if verdict == "READY":
                        verdict = "DEGRADED"
                    issues.append(f"{lengths[L]} command lines are exactly {L} chars - likely truncated at the collector")
        results.append({"detection": d.id, "logsource": src, "events": len(evs), "verdict": verdict,
                        "issues": issues, "fixes": fixes, "coverage": coverage})
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logs", nargs="+")
    ap.add_argument("--filter")
    ap.add_argument("--json")
    ap.add_argument("--profile", help="telemetry profile from mappings/ (or 'auto') the export is written in")
    args = ap.parse_args()
    raw = [e for p in args.logs for e in load_jsonl(Path(p))]
    events, used = profiles.apply(raw, args.profile)
    from types import SimpleNamespace
    from correlation import load_correlations         # imported here: correlation imports replay
    corrs = [SimpleNamespace(id=c.id, rule=c.base, contract=c.contract) for c in load_correlations(args.filter)]
    res = diagnose(events, [*load_detections(args.filter), *corrs], used)
    colour = {"READY": GREEN, "DEGRADED": YELLOW, "BLIND": RED}
    print(f"{BOLD}Telemetry readiness for {len(events)} sample events · profile {used}{RESET}\n")
    for r in res:
        print(f"  {colour[r['verdict']]}{r['verdict']:<9}{RESET} {r['detection']:<48} {DIM}{r['events']} events · {r['logsource']}{RESET}")
        for i in r["issues"]:
            print(f"            {DIM}- {i}{RESET}")
        for f in r["fixes"]:
            print(f"            {GREEN}+ fix: {f}{RESET}")
    tally = Counter(r["verdict"] for r in res)
    print(f"\n{BOLD}{tally.get('READY', 0)} ready · {tally.get('DEGRADED', 0)} degraded · {tally.get('BLIND', 0)} blind{RESET}")
    if not args.profile:
        best, scores = profiles.detect(raw)
        if best != profiles.NATIVE and scores[best] > scores[profiles.NATIVE]:
            print(f"\n{YELLOW}This export looks like {best}: {scores[best]} of {min(len(raw), 500)} sampled events reach a "
                  f"RASD log source with it, {scores[profiles.NATIVE]} without.{RESET}")
            print(f"  python rasd.py doctor {' '.join(args.logs)} --profile {best}")
    if args.json:
        Path(args.json).write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
