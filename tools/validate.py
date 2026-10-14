#!/usr/bin/env python3
"""
validate.py - quality gate for every detection (runs before unit tests).

Checks
  * required metadata (title, UUID id, status, level, author, date, ...)
  * ATT&CK tags present and folder name matches a tagged technique
  * unique rule IDs across the repository
  * condition parses and only references existing selections
  * logsource has a mapping for every SIEM backend
  * every detection ships a README plus true-positive AND true-negative tests
  * contract.yml exists, is complete, and agrees with the rule:
      - primary_technique is one of the rule's ATT&CK tags
      - every field the rule matches on is declared in the data contract
      - coverage depth, blind spots, triage and response are filled in
  * filter coverage: every filter_* selection is exercised by at least one
    true-negative event (removing the filter must make that event match),
    so no exclusion exists without a test proving why it is there
  * mutations.yml present and well-formed when the contract requires it
  * generated triage.md / response.md / closure.md are present (content is drift-checked in CI)
"""
from __future__ import annotations

import copy
import fnmatch
import re
import sys
import uuid
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DETECTIONS, load_jsonl, attack_tag_errors
from convert import BACKENDS, MAPPINGS, logsource_key
from sigma_engine import SigmaError, matches, tokenize

WARNINGS: dict[str, list[str]] = {}

ROOT = Path(__file__).resolve().parent.parent
REQUIRED = ["title", "id", "status", "description", "author", "date",
            "tags", "logsource", "detection", "falsepositives", "level"]
STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
LEVELS = {"informational", "low", "medium", "high", "critical"}
TECH_TAG = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
FOLDER = re.compile(r"^(T\d{4}(?:\.\d{3})?)_[a-z0-9_]+$")


MATURITY = ["draft", "tested", "hardened", "siem-ready", "validated", "reference"]   # RASD maturity model, in order
MATURITY_LABELS = {"draft": "Draft", "tested": "Tested", "hardened": "Hardened", "siem-ready": "SIEM-Ready",
                   "validated": "Validated", "reference": "Reference"}
RENAMED_MATURITY = {"operational": "siem-ready"}   # "Operational" is kept for lab evidence only


def maturity_label(level: str) -> str:
    return MATURITY_LABELS.get(level, str(level).capitalize())
RISK_CONDITIONS = set((yaml.safe_load((ROOT / "detect" / "risk_conditions.yml").read_text(encoding="utf-8"))
                       or {}).get("conditions", {}))
DEPTH = {"minimal", "partial", "medium", "high"}
NEVER = {"__dacp_never__|exists": True}   # a selection that can never match


def rule_fields(detection: dict) -> set[str]:
    """Every event field a rule's selections reference."""
    fields: set[str] = set()

    def walk(sel):
        if isinstance(sel, dict):
            fields.update(k.split("|")[0] for k in sel)
        elif isinstance(sel, list):
            for s in sel:
                walk(s)
    for name, sel in detection.items():
        if name not in ("condition", "timeframe"):
            walk(sel)
    return fields


def unexercised_filters(rule: dict, negatives: list[dict]) -> list[str]:
    """Filters that no true-negative event depends on."""
    missing = []
    for name in (k for k in rule["detection"] if k.startswith("filter")):
        probe = copy.deepcopy(rule)
        probe["detection"][name] = NEVER
        if not any(matches(probe, ev) and not matches(rule, ev) for ev in negatives):
            missing.append(name)
    return missing


def check_contract(folder: Path, rule: dict) -> list[str]:
    path = folder / "contract.yml"
    if not path.exists():
        return ["missing contract.yml (detection contract)"]
    try:
        c = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        return [f"contract.yml YAML error: {e}"]
    errs = []

    def need(dotted: str):
        cur = c
        for part in dotted.split("."):
            if not isinstance(cur, dict) or part not in cur or cur[part] in (None, "", [], {}):
                errs.append(f"contract.yml: missing '{dotted}'")
                return None
            cur = cur[part]
        return cur

    if c.get("detection_id") != folder.name:
        errs.append("contract.yml: detection_id must equal the folder name")
    if need("maturity") and c["maturity"] in RENAMED_MATURITY:
        errs.append(f"contract.yml: maturity '{c['maturity']}' was renamed to '{RENAMED_MATURITY[c['maturity']]}' "
                    "(Operational now means lab evidence only)")
    elif need("maturity") and c["maturity"] not in MATURITY:
        errs.append(f"contract.yml: maturity must be one of {MATURITY}")
    need("name")
    need("owner")
    primary = need("primary_technique")
    if primary and primary not in rule.get("tags", []):
        errs.append(f"contract.yml: primary_technique {primary} is not a tag of rule.yml")
    need("data_contract.required_events")
    need("data_contract.telemetry_risk")
    required = need("data_contract.required_fields") or []
    declared = set(required) | set((c.get("data_contract") or {}).get("optional_fields") or [])
    undeclared = sorted(rule_fields(rule.get("detection", {})) - declared)
    if undeclared:
        errs.append(f"contract.yml: rule uses fields not in the data contract: {undeclared}")
    blind = need("detection_logic.blind_spots") or []
    if blind and len(blind) < 2:
        errs.append("contract.yml: document at least 2 blind spots")
    level = need("coverage_depth.level")
    if level and level not in DEPTH:
        errs.append(f"contract.yml: coverage_depth.level must be one of {sorted(DEPTH)}")
    need("coverage_depth.reason")
    for key in ("triage.first_checks", "triage.escalate_if", "response.evidence", "response.containment",
                "response.l1_action", "response.l2_action", "response.ir_action"):
        need(key)
    risk = need("risk_model") or {}
    if risk:
        base = risk.get("base_score")
        if not isinstance(base, int) or not 0 <= base <= 100:
            errs.append("contract.yml: risk_model.base_score must be an integer 0-100")
        for kind, amount in (("increase_if", "add"), ("decrease_if", "subtract")):
            for item in risk.get(kind) or []:
                if item.get("condition") not in RISK_CONDITIONS:
                    errs.append(f"contract.yml: risk_model condition '{item.get('condition')}' is not defined in "
                                "detect/risk_conditions.yml")
                if not isinstance(item.get(amount), int) or item.get(amount) <= 0:
                    errs.append(f"contract.yml: risk_model {kind} needs a positive integer '{amount}'")
    for t in c.get("related_techniques") or []:
        if not TECH_TAG.match(str(t)):
            errs.append(f"contract.yml: related technique '{t}' is not an attack.tNNNN tag")

    validation = c.get("validation") or {}
    mpath = folder / "tests" / "mutations.yml"
    if validation.get("mutation_tests_required") and not mpath.exists():
        errs.append("contract requires mutation tests but tests/mutations.yml is missing")
    if mpath.exists():
        doc = yaml.safe_load(mpath.read_text(encoding="utf-8")) or {}
        for i, m in enumerate(doc.get("mutations") or [], 1):
            for key in ("name", "base", "set", "should_match"):
                if key not in m:
                    errs.append(f"mutations.yml #{i}: missing '{key}'")
        if not doc.get("mutations"):
            errs.append("mutations.yml has no mutations")
        for i, a in enumerate(doc.get("accepted_rule_mutants") or [], 1):
            if not a.get("id"):
                errs.append(f"mutations.yml accepted_rule_mutants #{i}: missing 'id'")
            if len(str(a.get("reason", "")).strip()) < 30:
                errs.append(f"mutations.yml accepted_rule_mutants #{i}: a reason of at least 30 characters is required")
    return errs


FIELDS = yaml.safe_load((ROOT / "tools" / "fields.yml").read_text(encoding="utf-8"))
MIN_SUBSTRING = 4
# Constructs Python and PCRE (Splunk) accept but RE2 (KQL `matches regex`) rejects:
# a rule using them passes every offline test and then fails to deploy in Sentinel.
_ESCAPE = re.compile(r"\\(.)", re.DOTALL)
_CHAR_CLASS = re.compile(r"\[\^?\]?[^\]]*\]")


def re2_issues(pattern: str) -> list[str]:
    found = []
    escapes = _ESCAPE.findall(pattern)
    if any(ch in "123456789" for ch in escapes) or "(?P=" in pattern:
        found.append("a backreference")
    if "Z" in escapes:
        found.append("the \\Z anchor (use $)")
    bare = _CHAR_CLASS.sub("C", _ESCAPE.sub("E", pattern))     # drop escapes and [..] classes
    if re.search(r"\(\?<?[=!]", bare):
        found.append("a lookaround")
    if "(?>" in bare:
        found.append("an atomic group")
    if re.search(r"[*+?}]\+", bare):
        found.append("a possessive quantifier")
    return found


def referenced_selections(detection: dict) -> set[str]:
    names = {k for k in detection if k not in ("condition", "timeframe")}
    used: set[str] = set()
    conds = detection.get("condition") or []
    for cond in (conds if isinstance(conds, list) else [conds]):
        tokens = tokenize(cond)
        for i, tok in enumerate(tokens):
            if tok.lower() in ("and", "or", "not", "(", ")", "1", "all", "of", "them"):
                if tok.lower() == "them":
                    used |= names
                continue
            if i >= 1 and tokens[i - 1].lower() == "of":
                used |= {n for n in names if fnmatch.fnmatchcase(n, tok)}
            elif tok in names:
                used.add(tok)
    return used


def lint_rule(rule: dict) -> tuple[list[str], list[str]]:
    """Deeper static checks. Returns (errors, warnings)."""
    errors, warnings = [], []
    det = rule.get("detection") or {}
    names = {k for k in det if k not in ("condition", "timeframe")}
    try:
        unused = names - referenced_selections(det)
    except SigmaError:
        unused = set()
    errors += [f"selection '{n}' is defined but never used in the condition" for n in sorted(unused)]
    vocab = FIELDS.get(logsource_key(rule), [])
    lower = {f.lower(): f for f in vocab}

    def walk(sel, where):
        if isinstance(sel, list):
            for s in sel:
                walk(s, where)
            return
        if not isinstance(sel, dict):
            return
        for key, value in sel.items():
            field, *mods = key.split("|")
            if vocab and field not in vocab:
                if field.lower() in lower:
                    errors.append(f"{where}: field '{field}' should be '{lower[field.lower()]}' (SIEM columns are case-sensitive)")
                else:
                    warnings.append(f"{where}: field '{field}' is not in the {logsource_key(rule)} vocabulary (tools/fields.yml)")
            values = value if isinstance(value, list) else [value]
            if len({str(v).lower() for v in values}) < len(values):
                warnings.append(f"{where}: duplicate values for '{key}'")
            for v in values:
                if "re" in mods:
                    try:
                        re.compile(str(v))
                    except re.error as e:
                        errors.append(f"{where}: invalid regex for '{field}': {e}")
                    for what in re2_issues(str(v)):
                        errors.append(f"{where}: regex for '{field}' uses {what}, which KQL (RE2) cannot run")
                    if re.search(r"[A-Za-z]", re.sub(r"\\.", "", str(v))) and not str(v).startswith("(?i)") \
                            and "i" not in mods:
                        warnings.append(f"{where}: regex for '{field}' is case-sensitive (Sigma |re semantics); "
                                        "start it with (?i) unless case really matters")
                elif "contains" in mods and isinstance(v, str) and len(v.strip()) < MIN_SUBSTRING and len(v) < MIN_SUBSTRING:
                    warnings.append(f"{where}: very short substring {v!r} on '{field}' - likely to match noise")
    for n in names:
        walk(det[n], n)
    return errors, warnings


SHA256 = re.compile(r"^[0-9a-f]{64}$")


def evidence_errors(folder: Path) -> list[str]:
    """Problems with detect/detections/<id>/evidence.md (empty list = valid or absent).

    Evidence is written by tools/evidence.py from a real lab run. The front matter is
    checked so a hand-typed or truncated file cannot earn the Evidence points.
    """
    path = folder / "evidence.md"
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n") or "\n---\n" not in text[4:]:
        return ["evidence.md: missing front matter (generate it with: rasd evidence)"]
    try:
        front = yaml.safe_load(text[4:text.index("\n---\n", 4)]) or {}
    except yaml.YAMLError as e:
        return [f"evidence.md: front matter is not valid YAML ({e})"]
    errs = []
    if front.get("rasd_evidence") != 1:
        errs.append("evidence.md: unknown format (rasd_evidence must be 1)")
    if front.get("detection") != folder.name:
        errs.append(f"evidence.md: written for '{front.get('detection')}', not this detection")
    if front.get("result") != "fired" or not isinstance(front.get("matched_events"), int) or front["matched_events"] < 1:
        errs.append("evidence.md: does not record a rule that fired")
    inputs = front.get("inputs") or {}
    hashes = [inputs.get("results", {}).get("sha256")] + [t.get("sha256") for t in inputs.get("telemetry") or []]
    if len(hashes) < 2 or not all(isinstance(h, str) and SHA256.match(h) for h in hashes):
        errs.append("evidence.md: inputs must carry the SHA-256 of the results file and every telemetry file")
    return errs


def tuning_errors(folder: Path, rule: dict) -> list[str]:
    """Structure of tuning.yml, and every filter in rule.yml documented as an applied tuning."""
    path = folder / "tuning.yml"
    if not path.exists():
        return ["missing tuning.yml (tuning guide)"]
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        return [f"tuning.yml YAML error: {e}"]
    errs = []
    if doc.get("detection_id") != folder.name:
        errs.append("tuning.yml: detection_id must equal the folder name")
    for key in ("expected_noise", "noise_sources", "never_tune", "review"):
        if not doc.get(key):
            errs.append(f"tuning.yml: missing '{key}'")
    det = rule.get("detection") or {}
    applied = set()
    for i, t in enumerate(doc.get("tunings") or [], 1):
        where = f"tuning.yml #{i} ({t.get('id', '?')})"
        status = t.get("status")
        if status not in ("applied", "proposed", "rejected"):
            errs.append(f"{where}: status must be applied, proposed or rejected")
        if len(str(t.get("reason", ""))) < 10:
            errs.append(f"{where}: needs a reason")
        if status == "applied":
            if t.get("selection") not in det:
                errs.append(f"{where}: selection '{t.get('selection')}' is not in rule.yml")
            applied.add(t.get("selection"))
        elif status in ("proposed", "rejected"):
            flt = t.get("filter")
            if not isinstance(flt, dict) or not flt:
                errs.append(f"{where}: needs a `filter` selection")
            else:
                probe = {"logsource": rule.get("logsource", {}), "detection": {"tune": flt, "condition": "tune"}}
                errs += [f"{where}: {e}" for e in lint_rule(probe)[0]]
            if t.get("residual_risk") not in ("low", "medium", "high"):
                errs.append(f"{where}: residual_risk must be low, medium or high")
    undocumented = sorted(k for k in det if k.startswith("filter") and k not in applied)
    if undocumented:
        errs.append(f"tuning.yml: filters in rule.yml without an applied tuning entry: {undocumented}")
    return errs


def check(folder: Path, seen_ids: dict) -> list[str]:
    errs: list[str] = []
    rule_path = folder / "rule.yml"
    if not rule_path.exists():
        return ["missing rule.yml"]
    try:
        rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        return [f"YAML error: {e}"]

    errs += [f"missing field '{k}'" for k in REQUIRED if k not in rule]
    if "TODO" in rule_path.read_text(encoding="utf-8"):
        errs.append("rule.yml still contains TODO placeholders")

    try:
        uuid.UUID(str(rule.get("id")))
    except ValueError:
        errs.append("id is not a valid UUID")
    rid = str(rule.get("id"))
    if rid in seen_ids:
        errs.append(f"duplicate id (also used by {seen_ids[rid]})")
    seen_ids[rid] = folder.name

    if rule.get("status") not in STATUSES:
        errs.append(f"invalid status '{rule.get('status')}'")
    if rule.get("level") not in LEVELS:
        errs.append(f"invalid level '{rule.get('level')}'")
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", str(rule.get("date", ""))):
        errs.append("date must be YYYY-MM-DD")

    techniques = [t for t in rule.get("tags", []) if TECH_TAG.match(t)]
    if not techniques:
        errs.append("no ATT&CK technique tag (attack.tXXXX)")
    errs += attack_tag_errors(rule.get("tags", []))
    m = FOLDER.match(folder.name)
    if not m:
        errs.append("folder must be named <TechniqueID>_<snake_case_name>")
    elif f"attack.{m.group(1).lower()}" not in techniques:
        errs.append(f"folder technique {m.group(1)} not present in tags")

    lint_errors, lint_warnings = lint_rule(rule)
    errs += lint_errors
    errs += evidence_errors(folder)
    errs += tuning_errors(folder, rule)
    WARNINGS.setdefault(folder.name, []).extend(lint_warnings)

    # Condition must parse and reference real selections (evaluate on empty event)
    try:
        matches(rule, {})
    except SigmaError as e:
        errs.append(f"detection logic: {e}")

    key = logsource_key(rule)
    for b in BACKENDS:
        if key not in MAPPINGS[b]["logsources"]:
            errs.append(f"logsource '{key}' has no {b} mapping in tools/mappings.yml")

    readme = folder / "README.md"
    if not readme.exists():
        errs.append("missing README.md (detection documentation)")
    elif "TODO" in readme.read_text(encoding="utf-8"):
        errs.append("README.md still contains TODO placeholders")
    for kind in ("true_positive", "true_negative"):
        p = folder / "tests" / f"{kind}.jsonl"
        if not p.exists() or not p.read_text(encoding="utf-8").strip():
            errs.append(f"missing or empty tests/{kind}.jsonl")

    errs += check_contract(folder, rule)
    for name in ("contract.yml", "tuning.yml", "tests/mutations.yml"):
        if (folder / name).exists() and "TODO" in (folder / name).read_text(encoding="utf-8"):
            errs.append(f"{name} still contains TODO placeholders")

    try:
        for name in unexercised_filters(rule, load_jsonl(folder / "tests" / "true_negative.jsonl")):
            errs.append(f"filter coverage: '{name}' has no true-negative event proving it is needed")
    except SigmaError:
        pass  # already reported above as a logic error

    for generated in ("triage.md", "response.md", "closure.md"):
        if not (folder / generated).exists():
            errs.append(f"missing {generated} (run: rasd build)")
    return errs


def main() -> int:
    folders = sorted(p for p in DETECTIONS.iterdir() if p.is_dir())
    seen: dict = {}
    failed = 0
    for f in folders:
        errs = check(f, seen)
        if errs:
            failed += 1
            print(f"[FAIL] {f.name}")
            for e in errs:
                print(f"         - {e}")
        else:
            print(f"[ OK ] {f.name}")
        for w in WARNINGS.get(f.name, []):
            print(f"         ! {w}")
    print(f"\n{len(folders) - failed}/{len(folders)} detections valid")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
