"""common.py - shared loaders and terminal helpers for the RASD toolchain."""
from __future__ import annotations

import base64
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

VERSION = "2.1.0"
ROOT = Path(__file__).resolve().parent.parent
DETECT = ROOT / "detect"
DETECTIONS = DETECT / "detections"          # one folder per detection (rule, contract, tests, guides)
CORRELATIONS = DETECT / "correlations"      # one folder per Sigma correlation (correlation, base rule, scenarios)
COVERAGE_DIR = DETECT / "coverage"          # ATT&CK Navigator layer + coverage matrix
QUALITY_DIR = DETECT / "quality"            # engineering / operational scores
EVASION_BASELINE = DETECT / "evasion" / "baseline.json"
RED = ROOT / "red"                          # offensive validation tests
DFIR = ROOT / "dfir"
INTEL = ROOT / "intel"
PURPLE = ROOT / "purple"
DOCS = ROOT / "docs"

_TTY = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
def c(code: str) -> str: return f"\033[{code}m" if _TTY else ""
GREEN, RED, YELLOW, DIM, BOLD, RESET = c("32"), c("31"), c("33"), c("2"), c("1"), c("0")
GOLD, SAGE, IVORY = c("38;5;180"), c("38;5;108"), c("38;5;188")


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for n, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):   # tolerate a BOM
        if line.strip():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise SystemExit(f"{path}:{n}: invalid JSON ({e})")
    return out


@dataclass
class Detection:
    folder: Path
    rule: dict
    contract: dict = field(default_factory=dict)

    @property
    def id(self) -> str: return self.folder.name

    @property
    def technique(self) -> str: return self.folder.name.split("_")[0]

    @property
    def title(self) -> str: return self.rule.get("title", self.id)

    @property
    def level(self) -> str: return self.rule.get("level", "medium")

    @property
    def tactics(self) -> list[str]:
        return [t.split(".", 1)[1] for t in self.rule.get("tags", [])
                if t.startswith("attack.") and not re.match(r"^attack\.t\d{4}", t)]

    def tests(self, kind: str) -> list[dict]:
        return load_jsonl(self.folder / "tests" / f"{kind}.jsonl")


def load_detections(filter_: str | None = None) -> list[Detection]:
    out = []
    for folder in sorted(p for p in DETECTIONS.iterdir() if p.is_dir()):
        if filter_ and filter_.lower() not in folder.name.lower():
            continue
        rule = yaml.safe_load((folder / "rule.yml").read_text(encoding="utf-8"))
        cpath = folder / "contract.yml"
        contract = yaml.safe_load(cpath.read_text(encoding="utf-8")) if cpath.exists() else {}
        out.append(Detection(folder, rule, contract or {}))
    return out


def find_detection(ref: str) -> Detection:
    """Resolve a detection by folder name, technique ID or rule UUID (prefix match allowed)."""
    dets = load_detections()
    exact = [d for d in dets if ref in (d.id, d.rule.get("id"))]
    if exact:
        return exact[0]
    partial = [d for d in dets if d.id.lower().startswith(ref.lower()) or str(d.rule.get("id", "")).startswith(ref)]
    if len(partial) == 1:
        return partial[0]
    if not partial:
        raise SystemExit(f"No detection matches '{ref}'")
    raise SystemExit(f"'{ref}' is ambiguous: " + ", ".join(d.id for d in partial))


# --------------------------------------------------------------------------- #
# Run tokens: what binds a telemetry event to ONE emulation run
# --------------------------------------------------------------------------- #
TOKEN_ENCODINGS = ("base64-utf16le:",)
TOKEN_FIELDS = ("{marker}", "{hex}")


def expand_token(template: str, marker: str) -> str:
    """A step's `bind` template for one run.

    {marker} is the run marker (purplelab_1a2b3c4d), {hex} its random part (1a2b3c4d).
    The prefix base64-utf16le: encodes the expanded text the way powershell -enc does,
    so an encoded command line can be bound to its run too.
    """
    hexpart = marker.rsplit("_", 1)[-1]
    encoded = template.startswith(TOKEN_ENCODINGS[0])
    text = template[len(TOKEN_ENCODINGS[0]):] if encoded else template
    text = text.replace("{marker}", marker).replace("{hex}", hexpart)
    return base64.b64encode(text.encode("utf-16-le")).decode() if encoded else text


MARKER_RE = re.compile(r"^purplelab_[0-9a-f]{8}$")


def carries_token(event: dict, template: str, marker: str) -> bool:
    """True when any field of the event contains the run's token (Base64 compared exactly).
    Without a well-formed marker nothing carries the token: an empty marker would turn
    'R{hex}' into 'R' and match almost any event."""
    if not MARKER_RE.match(str(marker or "")):
        return False
    token = expand_token(template, marker)
    exact = template.startswith(TOKEN_ENCODINGS[0])
    for value in event.values():
        text = str(value)
        if (token in text) if exact else (token.lower() in text.lower()):
            return True
    return False
