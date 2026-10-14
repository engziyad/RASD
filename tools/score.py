#!/usr/bin/env python3
"""
score.py - two scores per detection, both computed from checkable facts only.

Every point comes from something a script can verify in the repository (a test that
passes, a field that is declared, a query proven equivalent, an evidence file with
hashes), never from a reviewer's opinion. The weights are a published model, not a truth:
see docs/QUALITY_MODEL.md.

Engineering Score - is the detection built right?
  Tests                    25  TP and TN volume, all passing, every rule part proven (prove.py)
  Telemetry contract       20  events, fields (consistent with the rule), telemetry risks
  False-positive handling  15  documented FP sources, TN volume, every filter proven by a TN
  Evasion awareness        15  blind spots, README gap section, mutation tests, fuzzer resistance
  SIEM portability         10  converts to KQL and SPL with zero parity divergences (parity.py)
  Response playbook        10  triage checks, escalation, evidence, containment, L1/L2/IR actions
  Documentation             5  README sections and a valid tuning guide

Correlation detections (detect/correlations) are scored on the same seven areas, from the
facts `rasd correlate` proves: Tests adds scenario volume and counts the correlation's
parameter mutants in the proof; Evasion awareness counts the verified burst guarantee
next to the base rule's mutation tests; SIEM portability needs the base filter AND the
aggregation to be identical in each backend.

Operational Score - was it proven in a real lab telemetry flow?
  Computed from detect/detections/<id>/evidence.md, written by evidence.py from a lab run
  (Lab evidence 35, SIEM result 25, Detection latency 15, DFIR evidence 15, Cleanup 10).
  Without a lab run it is "pending" - never estimated.

Output: console table and detect/quality/QUALITY.md (drift-checked in CI).
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DETECTIONS, QUALITY_DIR
from convert import BACKENDS, convert
from evidence import OPERATIONAL_WEIGHTS, operational_score
from fuzz import fuzz as run_fuzz
from mutation_test import run as run_mutations
from parity import check as run_parity
from prove import prove as run_prove
from run_tests import run as run_tests
from sigma_engine import SigmaError
from validate import evidence_errors, load_jsonl, rule_fields, tuning_errors, unexercised_filters

WEIGHTS = {"Tests": 25, "Telemetry contract": 20, "False-positive handling": 15, "Evasion awareness": 15,
           "SIEM portability": 10, "Response playbook": 10, "Documentation": 5}
README_SECTIONS = ("## Telemetry required", "## How the detection works", "## False positives")


def ratio(n: int, target: int) -> float:
    return min(n, target) / target


def evidence_front(folder: Path) -> dict | None:
    """The front matter of a valid evidence.md, or None."""
    path = folder / "evidence.md"
    if not path.exists() or evidence_errors(folder):
        return None
    text = path.read_text(encoding="utf-8")
    return yaml.safe_load(text[4:text.index("\n---\n", 4)]) or {}


def score_one(folder: Path, test_results: list[dict], mut_results: list[dict], fuzz_report: dict,
              proof: dict | None = None, parity: dict | None = None) -> dict:
    rule = yaml.safe_load((folder / "rule.yml").read_text(encoding="utf-8"))
    c = yaml.safe_load((folder / "contract.yml").read_text(encoding="utf-8"))
    mine = [r for r in test_results if r["detection"] == folder.name]
    muts = [r for r in mut_results if r["detection"] == folder.name and r["kind"] == "technique"]
    tps = [r for r in mine if r["kind"] == "true_positive"]
    tns = [r for r in mine if r["kind"] == "true_negative"]
    s: dict[str, float] = {}
    notes: list[str] = []

    # Tests: 4 TP and 4 TN plus a 100% proof score earn full marks; any failing test zeroes it
    proof_score = (proof or {}).get(folder.name, {}).get("score", 0.0)
    if all(r["passed"] for r in mine):
        s["Tests"] = 25 * (0.3 * ratio(len(tps), 4) + 0.3 * ratio(len(tns), 4) + 0.4 * proof_score / 100)
    else:
        s["Tests"] = 0
        notes.append("failing tests")
    if proof_score < 100:
        notes.append(f"proof score {proof_score:.0f}%")
    if len(tps) < 4:
        notes.append(f"only {len(tps)} TP cases")
    if len(tns) < 4:
        notes.append(f"only {len(tns)} TN cases")

    # Telemetry contract
    dc = c.get("data_contract", {})
    declared = set(dc.get("required_fields", [])) | set(dc.get("optional_fields", []))
    consistent = rule_fields(rule["detection"]) <= declared
    s["Telemetry contract"] = 6 * bool(dc.get("required_events")) + 8 * consistent + 6 * bool(dc.get("telemetry_risk"))

    # False-positive handling
    negatives = load_jsonl(folder / "tests" / "true_negative.jsonl")
    filters = [k for k in rule["detection"] if k.startswith("filter")]
    unproven = unexercised_filters(rule, negatives) if filters else []
    filter_part = 1.0 if not filters else 1 - len(unproven) / len(filters)
    s["False-positive handling"] = 5 * bool(rule.get("falsepositives")) + 5 * ratio(len(tns), 4) + 5 * filter_part

    # Evasion awareness
    blind = c.get("detection_logic", {}).get("blind_spots", [])
    readme = (folder / "README.md").read_text(encoding="utf-8") if (folder / "README.md").exists() else ""
    mut_ok = bool(muts) and all(r["passed"] for r in muts)
    resistance = fuzz_report.get(folder.name, {}).get("resistance", 0.0)
    s["Evasion awareness"] = 4 * ratio(len(blind), 3) + 3 * ("Evasion" in readme) + 4 * mut_ok + 4 * resistance / 100
    if not muts:
        notes.append("no technique mutation tests")
    if resistance < 100:
        notes.append(f"fuzzer resistance {resistance:.0f}%")

    # SIEM portability: converts, and the deployed query returns what the tested rule returns
    portable = 0
    par = (parity or {}).get(folder.name, {})
    for b in BACKENDS:
        try:
            convert(rule, b)
        except SigmaError:
            notes.append(f"does not convert to {b}")
            continue
        if not par or par.get(b) or par.get("errors"):
            notes.append(f"{b} parity not proven")
            continue
        portable += 1
    s["SIEM portability"] = 10 * portable / len(BACKENDS)

    # Response playbook
    t, r = c.get("triage", {}), c.get("response", {})
    s["Response playbook"] = (2 * bool(t.get("first_checks")) + 2 * bool(t.get("escalate_if"))
                              + 2 * bool(r.get("evidence")) + 2 * bool(r.get("containment"))
                              + 2 * all(r.get(k) for k in ("l1_action", "l2_action", "ir_action")))

    # Documentation
    sections = sum(h in readme for h in README_SECTIONS)
    tuning_ok = (folder / "tuning.yml").exists() and not tuning_errors(folder, rule)
    s["Documentation"] = 3 * sections / len(README_SECTIONS) + 2 * tuning_ok
    if sections < len(README_SECTIONS):
        notes.append("README sections missing")
    if not tuning_ok:
        notes.append("tuning guide missing or invalid")

    # Operational Score from a real lab run
    front = evidence_front(folder)
    ops = operational_score(front) if front else None
    if not front:
        notes.append("evidence: pending lab run" if not (folder / "evidence.md").exists() else "invalid evidence.md")

    return {"folder": folder.name, "title": rule["title"], "scores": s, "total": round(sum(s.values())),
            "operational": ops, "operational_total": sum(ops.values()) if ops else None, "notes": notes}


def score_correlation(corr, r: dict) -> dict:
    """Engineering and operational scores of one correlation detection, from its correlate report."""
    folder, c = corr.folder, corr.contract
    b, scen = r.get("base") or {}, r.get("scenarios") or []
    cm, ap, bp, g = (r.get("correlation_mutants") or {}, r.get("aggregation_parity") or {}, r.get("base_parity") or {},
                     r.get("guarantee"))
    s: dict[str, float] = {}
    notes: list[str] = []
    tp, tn = b.get("tp", 0), b.get("tn", 0)

    proof = min(b.get("proof", 0.0), cm.get("score", 0.0))
    passing = bool(b) and not b.get("failing") and not any(x.get("problem") for x in scen) and not r.get("errors")
    fires = sum(1 for x in scen if x.get("expect") == "fire")
    if passing:
        s["Tests"] = 25 * (0.2 * ratio(tp, 4) + 0.2 * ratio(tn, 4) + 0.1 * ratio(fires, 3)
                           + 0.1 * ratio(len(scen) - fires, 3) + 0.4 * proof / 100)
    else:
        s["Tests"] = 0
        notes.append("failing tests, scenarios or structure")
    if proof < 100:
        notes.append(f"proof score {proof:.0f}%")
    if tp < 4:
        notes.append(f"only {tp} TP cases")
    if tn < 4:
        notes.append(f"only {tn} TN cases")

    dc = c.get("data_contract", {})
    declared = set(dc.get("required_fields", [])) | set(dc.get("optional_fields", []))
    try:
        reads = set(corr.params.reads())
    except Exception:                       # an invalid correlation.yml is reported by correlate
        reads = {"<invalid correlation>"}
    consistent = (rule_fields(corr.base.get("detection") or {}) | reads) <= declared
    s["Telemetry contract"] = 6 * bool(dc.get("required_events")) + 8 * consistent + 6 * bool(dc.get("telemetry_risk"))

    negatives = corr.tests("true_negative")
    filters = [k for k in (corr.base.get("detection") or {}) if k.startswith("filter")]
    try:
        unproven = unexercised_filters(corr.base, negatives) if filters else []
    except SigmaError:
        unproven = filters
    filter_part = 1.0 if not filters else 1 - len(unproven) / len(filters)
    s["False-positive handling"] = 5 * bool(corr.rule.get("falsepositives")) + 5 * ratio(tn, 4) + 5 * filter_part

    blind = c.get("detection_logic", {}).get("blind_spots", [])
    readme = (folder / "README.md").read_text(encoding="utf-8") if (folder / "README.md").exists() else ""
    mut_ok = bool(b) and not any(f.startswith("mutation:") for f in b.get("failing", [])) and \
        (folder / "tests" / "mutations.yml").exists()
    guarantee_ok = g is None or (bool(g.get("burst")) and not g.get("failures") and g.get("tight"))
    resistance = b.get("fuzz", 0.0)
    s["Evasion awareness"] = (4 * ratio(len(blind), 3) + 3 * ("Evasion" in readme) + 2 * mut_ok + 2 * guarantee_ok
                              + 4 * resistance / 100)
    if not guarantee_ok:
        notes.append("burst guarantee not verified")
    if resistance < 100:
        notes.append(f"fuzzer resistance {resistance:.0f}%")

    portable = 0
    for backend in BACKENDS:
        ok = bool(bp) and bool(ap) and not bp.get(backend) and not bp.get("errors") and not ap.get(backend) \
            and not ap.get("errors")
        portable += ok
        if not ok:
            notes.append(f"{backend} parity not proven")
    s["SIEM portability"] = 10 * portable / len(BACKENDS)

    t, rsp = c.get("triage", {}), c.get("response", {})
    s["Response playbook"] = (2 * bool(t.get("first_checks")) + 2 * bool(t.get("escalate_if"))
                              + 2 * bool(rsp.get("evidence")) + 2 * bool(rsp.get("containment"))
                              + 2 * all(rsp.get(k) for k in ("l1_action", "l2_action", "ir_action")))

    sections = sum(h in readme for h in README_SECTIONS)
    tuning_ok = (folder / "tuning.yml").exists() and not tuning_errors(folder, corr.base)
    s["Documentation"] = 3 * sections / len(README_SECTIONS) + 2 * tuning_ok
    if sections < len(README_SECTIONS):
        notes.append("README sections missing")
    if not tuning_ok:
        notes.append("tuning guide missing or invalid")

    front = evidence_front(folder)
    ops = operational_score(front) if front else None
    if not front:
        notes.append("evidence: pending lab run" if not (folder / "evidence.md").exists() else "invalid evidence.md")
    return {"folder": folder.name, "title": corr.title, "scores": s, "total": round(sum(s.values())),
            "operational": ops, "operational_total": sum(ops.values()) if ops else None, "notes": notes,
            "kind": "correlation"}


def score_correlations() -> list[dict]:
    from correlate import check as run_correlate          # imported here: correlate imports score's neighbours
    from correlation import load_correlations
    corrs = load_correlations()
    report = run_correlate(None) if corrs else {}
    return sorted((score_correlation(cr, report.get(cr.id, {})) for cr in corrs), key=lambda r: (-r["total"], r["folder"]))


def score_all() -> list[dict]:
    tests, muts, fz = run_tests(None), run_mutations(None), run_fuzz(None)
    proof, par = run_prove(None), run_parity(None)
    rows = [score_one(f, tests, muts, fz, proof, par) for f in sorted(p for p in DETECTIONS.iterdir() if p.is_dir())]
    rows.sort(key=lambda r: (-r["total"], r["folder"]))
    return rows


def fmt(v: float) -> str:
    return f"{v:.1f}".rstrip("0").rstrip(".")


def main() -> int:
    det_rows, corr_rows = score_all(), score_correlations()
    rows = det_rows + corr_rows
    width = max(len(r["folder"]) for r in rows)
    print(f"{'Eng':>4} {'Ops':>7}  Detection")
    for r in rows:
        ops = f"{r['operational_total']:>3}/100" if r["operational"] else "pending"
        kind = " (correlation)" if r.get("kind") == "correlation" else ""
        print(f"{r['total']:>4} {ops:>7}  {r['folder'] + kind:<{width + 14}}  {'; '.join(r['notes']) or '-'}")
    eng_avg = sum(r["total"] for r in rows) / len(rows)
    validated = [r for r in rows if r["operational"]]
    ops_avg = sum(r["operational_total"] for r in validated) / len(validated) if validated else None
    print(f"\nEngineering Score: {eng_avg:.0f}/100 average")
    print("Operational Score: " + (f"{ops_avg:.0f}/100 average over {len(validated)} Validated detection(s) (lab evidence)"
                                             if validated else "pending - no lab run evidence yet"))

    cols = list(WEIGHTS)
    short = {"Tests": "Tests", "Telemetry contract": "Contract", "False-positive handling": "FP",
             "Evasion awareness": "Evasion", "SIEM portability": "Portability",
             "Response playbook": "Response", "Documentation": "Docs"}
    lines = [
        "# Detection Quality",
        "",
        "> Auto-generated by `tools/score.py` from checkable facts - do not edit by hand. "
        "Model and weights: [QUALITY_MODEL.md](../../docs/QUALITY_MODEL.md).",
        "",
        "| | |", "|---|---|",
        f"| **Engineering Score** | **{eng_avg:.0f}/100** average across {len(det_rows) + len(corr_rows)} detections"
        + (f" ({len(det_rows)} single-event rules, {len(corr_rows)} correlations)" if corr_rows else "") + " |",
        "| **Operational Score** | "
        + (f"**{ops_avg:.0f}/100** average across {len(validated)} Validated detections (lab evidence) |" if validated
           else "**pending** - no lab run evidence yet |"),
        "",
        "## Engineering Score",
        "",
        "| Detection | Score | " + " | ".join(f"{short[c]} /{WEIGHTS[c]}" for c in cols) + " | Notes |",
        "|---|---|" + "---|" * len(cols) + "---|",
    ]
    def where(r: dict) -> str:
        return "correlations" if r.get("kind") == "correlation" else "detections"

    for r in det_rows:
        cells = " | ".join(fmt(r["scores"][c]) for c in cols)
        eng_notes = [n for n in r["notes"] if not n.startswith("evidence:") and n != "invalid evidence.md"]
        lines.append(f"| [{r['title']}](../detections/{r['folder']}/) | **{r['total']}** | {cells} | "
                     f"{'; '.join(eng_notes) or '-'} |")
    if corr_rows:
        lines += ["", "### Correlation detections", "",
                  "Scored on the same areas from what `rasd correlate` proves: scenarios and parameter mutants count "
                  "in Tests, the verified burst guarantee in Evasion, base filter and aggregation parity in Portability.", "",
                  "| Correlation | Score | " + " | ".join(f"{short[c]} /{WEIGHTS[c]}" for c in cols) + " | Notes |",
                  "|---|---|" + "---|" * len(cols) + "---|"]
        for r in corr_rows:
            cells = " | ".join(fmt(r["scores"][c]) for c in cols)
            eng_notes = [n for n in r["notes"] if not n.startswith("evidence:") and n != "invalid evidence.md"]
            lines.append(f"| [{r['title']}](../correlations/{r['folder']}/) | **{r['total']}** | {cells} | "
                         f"{'; '.join(eng_notes) or '-'} |")
    ocols = list(OPERATIONAL_WEIGHTS)
    lines += ["", "## Operational Score", "",
              "| Detection | Score | " + " | ".join(f"{c} /{OPERATIONAL_WEIGHTS[c]}" for c in ocols) + " |",
              "|---|---|" + "---|" * len(ocols)]
    for r in sorted(rows, key=lambda x: x["folder"]):
        if r["operational"]:
            cells = " | ".join(str(r["operational"][c]) for c in ocols)
            lines.append(f"| [{r['title']}](../{where(r)}/{r['folder']}/evidence.md) | **{r['operational_total']}** | {cells} |")
        else:
            lines.append(f"| [{r['title']}](../{where(r)}/{r['folder']}/) | pending | "
                         + " | ".join("-" for _ in ocols) + " |")
    lines += ["", "The Operational Score stays **pending** until a real lab run is turned into evidence with "
              "`rasd evidence` (see [OPERATIONAL_VALIDATION.md](../../docs/OPERATIONAL_VALIDATION.md)). "
              "That is intentional: RASD never claims validation that has not happened, and a detection "
              "cannot reach the Validated or Reference maturity level without it.", "",
              "<sub>Generated by RASD · Attack-to-Defense Validation Framework</sub>", ""]
    QUALITY_DIR.mkdir(parents=True, exist_ok=True)
    (QUALITY_DIR / "QUALITY.md").write_text("\n".join(lines), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
