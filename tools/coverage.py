#!/usr/bin/env python3
"""
coverage.py - generate ATT&CK coverage artifacts straight from the rules.

Outputs
  detect/coverage/attack_navigator_layer.json  -> import into MITRE ATT&CK Navigator
  detect/coverage/COVERAGE.md                  -> human-readable coverage matrix

A technique's score reflects *validated* coverage and its *depth*: severity is
scaled by the contract's coverage_depth, and rules without passing tests are
halved, so the heatmap never overstates what the SOC can actually detect.
Correlation detections (detect/correlations) count like rules; they are validated
when their base rule's tests pass and every scenario behaves as declared.
"""
from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import COVERAGE_DIR, DETECTIONS  # noqa: E402
from run_tests import run  # noqa: E402
from sigma_engine import compile_rule  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DEPTH_FACTOR = {"minimal": 0.4, "partial": 0.6, "medium": 0.8, "high": 1.0}
DEPTH_RANK = {"minimal": 0, "partial": 1, "medium": 2, "high": 3}
LEVEL_SCORE = {"informational": 20, "low": 40, "medium": 60, "high": 80, "critical": 100}
TACTIC_ORDER = ["initial-access", "execution", "persistence", "privilege-escalation",
                "defense-evasion", "credential-access", "discovery", "lateral-movement",
                "collection", "command-and-control", "exfiltration", "impact"]


def collect() -> list[dict]:
    results = run(None)
    status = defaultdict(lambda: {"tp": 0, "tp_pass": 0, "all_pass": True})
    for r in results:
        s = status[r["detection"]]
        s["all_pass"] &= r["passed"]
        if r["kind"] == "true_positive":
            s["tp"] += 1
            s["tp_pass"] += r["passed"]

    rules = []
    for folder in sorted(p for p in DETECTIONS.iterdir() if p.is_dir()):
        rule = yaml.safe_load((folder / "rule.yml").read_text(encoding="utf-8"))
        contract = yaml.safe_load((folder / "contract.yml").read_text(encoding="utf-8"))
        tags = rule.get("tags", [])
        rules.append({
            "folder": folder.name,
            "title": rule["title"],
            "level": rule["level"],
            "primary": contract["primary_technique"].split(".", 1)[1].upper(),
            "depth": contract["coverage_depth"]["level"],
            "depth_reason": contract["coverage_depth"]["reason"],
            "techniques": [t.split(".", 1)[1].upper() for t in tags if re.match(r"^attack\.t\d{4}", t)],
            "tactics": [t.split(".", 1)[1] for t in tags
                        if t.startswith("attack.") and not re.match(r"^attack\.t\d{4}", t)],
            **status[folder.name],
            "path": "detections",
        })
    return rules + collect_correlations()


def collect_correlations() -> list[dict]:
    from correlate import problem                          # imported here: correlate imports run_tests' neighbours
    from correlation import evaluate, load_correlations
    rows = []
    for corr in load_correlations():
        fn = compile_rule(corr.base)
        tps, tns = corr.tests("true_positive"), corr.tests("true_negative")
        tp_pass = sum(1 for ev in tps if fn(ev))
        scenarios_ok = all(problem(sc, evaluate(corr, sc["events"], base_fn=fn)) is None for sc in corr.scenarios())
        tags = corr.rule.get("tags", [])
        rows.append({
            "folder": corr.id, "title": corr.title, "level": corr.level,
            "primary": corr.contract["primary_technique"].split(".", 1)[1].upper(),
            "depth": corr.contract["coverage_depth"]["level"], "depth_reason": corr.contract["coverage_depth"]["reason"],
            "techniques": [t.split(".", 1)[1].upper() for t in tags if re.match(r"^attack\.t\d{4}", t)],
            "tactics": [t.split(".", 1)[1] for t in tags if t.startswith("attack.") and not re.match(r"^attack\.t\d{4}", t)],
            "tp": len(tps), "tp_pass": tp_pass,
            "all_pass": tp_pass == len(tps) and not any(fn(ev) for ev in tns) and scenarios_ok,
            "path": "correlations",
        })
    return rows


def navigator_layer(rules: list[dict]) -> dict:
    per_tech: dict[str, list[dict]] = defaultdict(list)
    for r in rules:
        for t in r["techniques"]:
            per_tech[t].append(r)
    techniques = []
    for tid, rs in sorted(per_tech.items()):
        primaries = [r for r in rs if r["primary"] == tid] or rs
        best = max(LEVEL_SCORE[r["level"]] * DEPTH_FACTOR[r["depth"]] for r in primaries)
        if not any(r["primary"] == tid for r in rs):
            best *= 0.5          # only covered as a related technique
        validated = all(r["all_pass"] and r["tp_pass"] > 0 for r in rs)
        techniques.append({
            "techniqueID": tid,
            "score": round(best if validated else best / 2),
            "comment": "\n".join(f"{r['title']} ({r['folder']}{', correlation' if r['path'] == 'correlations' else ''})"
                                 f" - depth {r['depth']}{'' if r['primary'] == tid else ' (related)'} - "
                                 f"{'validated' if r['all_pass'] else 'FAILING TESTS'}" for r in rs),
            "enabled": True,
            "showSubtechniques": True,
            "metadata": [{"name": "rules", "value": str(len(rs))}],
        })
    return {
        "name": "Purple Lab - Validated Detection Coverage",
        "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Auto-generated by tools/coverage.py from tested Sigma rules and Sigma correlation rules.",
        "techniques": techniques,
        "gradient": {"colors": ["#ffe5e5", "#ff9f43", "#10ac84"], "minValue": 0, "maxValue": 100},
        "legendItems": [
            {"label": "Validated high-fidelity detection", "color": "#10ac84"},
            {"label": "Detection present, lower confidence/untested", "color": "#ff9f43"},
        ],
        "layout": {"layout": "side", "showName": True, "showID": True},
        "hideDisabled": False,
    }


def markdown(rules: list[dict]) -> str:
    def tactic_rank(r: dict) -> int:
        ranks = [TACTIC_ORDER.index(t) for t in r["tactics"] if t in TACTIC_ORDER]
        return min(ranks) if ranks else 99

    lines = [
        "# Detection Coverage",
        "",
        "> Auto-generated by `tools/coverage.py` - do not edit by hand.",
        "",
        f"**{len(rules)} detections** ({sum(1 for r in rules if r['path'] == 'correlations')} of them Sigma correlations) "
        f"covering **{len({r['primary'] for r in rules})} ATT&CK techniques as primary** "
        f"(+{len({t for r in rules for t in r['techniques']} - {r['primary'] for r in rules})} related), "
        f"**{sum(r['tp'] for r in rules)} true-positive** test cases.",
        "",
        "Depth comes from each detection's `contract.yml`: **partial** means part of the technique's "
        "procedures are covered, **high** means the outcome is detected regardless of method.",
        "",
        "## By technique",
        "",
        "| Technique | Detections | Best depth |",
        "|---|---|---|",
    ]
    by_tech: dict[str, list[dict]] = defaultdict(list)
    for r in rules:
        by_tech[r["primary"]].append(r)
    for tid, rs in sorted(by_tech.items()):
        best = max(rs, key=lambda r: DEPTH_RANK[r["depth"]])["depth"]
        names = "<br>".join(f"[{r['title']}](../{r['path']}/{r['folder']}/)" for r in rs)
        lines.append(f"| [{tid}](https://attack.mitre.org/techniques/{tid.replace('.', '/')}/) | {names} | **{best}** |")
    lines += [
        "",
        "## By detection",
        "",
        "| Tactic | Primary | Related | Detection | Level | Depth | TP tests | Status |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in sorted(rules, key=lambda r: (tactic_rank(r), r["folder"])):
        tactic = ", ".join(t for t in r["tactics"] if t in TACTIC_ORDER) or "-"
        link = lambda t: f"[{t}](https://attack.mitre.org/techniques/{t.replace('.', '/')}/)"
        related = ", ".join(link(t) for t in r["techniques"] if t != r["primary"]) or "-"
        status = "✅ validated" if r["all_pass"] else "❌ failing"
        lines.append(f"| {tactic} | {link(r['primary'])} | {related} | [{r['title']}](../{r['path']}/{r['folder']}/) | "
                     f"{r['level']} | {r['depth']} | {r['tp_pass']}/{r['tp']} | {status} |")
    lines += ["", "## Depth notes", ""]
    lines += [f"- **{r['title']}** ({r['depth']}): {r['depth_reason']}" for r in sorted(rules, key=lambda r: r["folder"])]
    lines += ["", "Import [`attack_navigator_layer.json`](attack_navigator_layer.json) into "
              "[ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) for the heatmap.", ""]
    return "\n".join(lines)


def main() -> int:
    rules = collect()
    COVERAGE_DIR.mkdir(parents=True, exist_ok=True)
    (COVERAGE_DIR / "attack_navigator_layer.json").write_text(
        json.dumps(navigator_layer(rules), indent=2) + "\n", encoding="utf-8")
    (COVERAGE_DIR / "COVERAGE.md").write_text(markdown(rules), encoding="utf-8")
    corrs = sum(1 for r in rules if r["path"] == "correlations")
    print(f"[+] coverage generated for {len(rules) - corrs} detections and {corrs} correlations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
