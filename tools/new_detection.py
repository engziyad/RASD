#!/usr/bin/env python3
"""
new_detection.py - scaffold a new detection folder that already passes the linter's
structure checks, so contributors only write the logic, tests and notes.

Usage
  rasd new T1021.006 winrm_remote_shell
"""
from __future__ import annotations

import datetime as dt
import re
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DETECTIONS  # noqa: E402

RULE = """title: TODO - short, specific title
id: {id}
status: experimental
description: |
  TODO - what behaviour this detects and why it matters.
references:
  - https://attack.mitre.org/techniques/{tech_path}/
author: Ziyad (github.com/engziyad)
date: {date}
tags:
  - attack.TODO-tactic
  - attack.{tech_tag}
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\TODO.exe'
  condition: selection
falsepositives:
  - TODO
level: medium
"""

CONTRACT = """# yaml-language-server: $schema=../../../schemas/contract.schema.json
detection_id: {folder}
name: TODO
maturity: draft
owner: detection-engineering
primary_technique: attack.{tech_tag}
related_techniques: []
data_contract:
  required_logsource:
    product: windows
    category: process_creation
  required_events:
  - TODO
  required_fields:
  - Image
  optional_fields: []
  telemetry_risk:
    missing_commandline: critical
detection_logic:
  type: single-event
  confidence: medium
  severity: medium
  expected_noise: medium
  blind_spots:
  - TODO
  - TODO
coverage_depth:
  level: partial
  reason: TODO
risk_model:
  base_score: 40
  increase_if:
  - condition: host_is_critical
    add: 15
  decrease_if:
  - condition: approved_admin_activity
    subtract: 20
validation:
  mutation_tests_required: true
  lab_emulation_available: false
  siem_backends:
  - splunk
  - kql
triage:
  first_checks:
  - TODO
  escalate_if:
  - TODO
response:
  l1_action: TODO - what the L1 analyst validates first
  l2_action: TODO - which pivots the L2 analyst runs
  ir_action: TODO - when and how incident response contains
  evidence:
  - TODO
  containment:
  - TODO
governance:
  evidence_type:
  - detection rule
  - test results
"""

TUNING = """# yaml-language-server: $schema=../../../schemas/tuning.schema.json
detection_id: {folder}
expected_noise: medium
noise_sources:
- TODO
tunings: []
never_tune:
- TODO
review:
  owner: detection-engineering
  cadence_days: 90
"""

MUTATIONS = """# yaml-language-server: $schema=../../../../schemas/mutation.schema.json
mutations:
- name: todo_variant
  description: TODO - an attacker variation that must still match
  base: 1
  set:
    Image: C:\\TODO\\variant.exe
  should_match: true
"""

README = """# TODO - detection title

<!-- rasd:facts:start -->
<!-- rasd:facts:end -->

## Telemetry required
## How the detection works
## Evasion & coverage gaps
## False positives & tuning
"""


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 1
    tech, name = sys.argv[1].upper(), sys.argv[2].lower()
    if not re.match(r"^T\d{4}(\.\d{3})?$", tech) or not re.match(r"^[a-z0-9_]+$", name):
        print("Usage: new_detection.py T1234.001 snake_case_name")
        return 1
    folder = DETECTIONS / f"{tech}_{name}"
    if folder.exists():
        print(f"{folder} already exists")
        return 1
    (folder / "tests").mkdir(parents=True)
    (folder / "rule.yml").write_text(RULE.format(
        id=uuid.uuid4(), date=dt.date.today().isoformat(),
        tech_path=tech.replace(".", "/"), tech_tag=tech.lower()), encoding="utf-8")
    (folder / "README.md").write_text(README, encoding="utf-8")
    (folder / "contract.yml").write_text(CONTRACT.format(folder=folder.name, tech_tag=tech.lower()), encoding="utf-8")
    (folder / "tuning.yml").write_text(TUNING.format(folder=folder.name), encoding="utf-8")
    (folder / "tests" / "mutations.yml").write_text(MUTATIONS, encoding="utf-8")
    (folder / "tests" / "true_positive.jsonl").write_text(
        '{"_case": "TODO malicious example", "EventID": 1, "Image": "C:\\\\TODO.exe"}\n', encoding="utf-8")
    (folder / "tests" / "true_negative.jsonl").write_text(
        '{"_case": "TODO benign example", "EventID": 1, "Image": "C:\\\\Windows\\\\explorer.exe"}\n', encoding="utf-8")
    print(f"[+] scaffolded {folder.relative_to(ROOT)}")
    print("    edit rule.yml, contract.yml, tuning.yml, tests/ and README.md, then run: rasd ci")
    return 0


if __name__ == "__main__":
    sys.exit(main())
