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

VERSION = "1.0.0"
ROOT = Path(__file__).resolve().parent.parent
DETECT = ROOT / "detect"
DETECTIONS = DETECT / "detections"          # one folder per detection (rule, contract, tests, guides)
CORRELATIONS = DETECT / "correlations"      # one folder per Sigma correlation (correlation, base rule, scenarios)
COVERAGE_DIR = DETECT / "coverage"          # ATT&CK Navigator layer + coverage matrix
QUALITY_DIR = DETECT / "quality"            # engineering / operational scores
EVASION_BASELINE = DETECT / "evasion" / "baseline.json"
DFIR = ROOT / "dfir"
INTEL = ROOT / "intel"
PURPLE = ROOT / "purple"
DOCS = ROOT / "docs"

# ATT&CK Enterprise, one reference for every tool and page: the version the mappings follow, its
# tactics in matrix order (the short names Sigma tags use) and the name of every technique RASD maps
# or emulates, written exactly as ATT&CK writes it ("Parent: Sub-technique")
ATTACK_VERSION = "18"
ATTACK_TACTICS = ("reconnaissance", "resource-development", "initial-access", "execution", "persistence",
                  "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement",
                  "collection", "command-and-control", "exfiltration", "impact")
TECHNIQUES = {       # ID: (name, the tactics ATT&CK lists for it, in matrix order)
    "T1003.001": ("OS Credential Dumping: LSASS Memory", ("credential-access",)),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares", ("lateral-movement",)),
    "T1021.006": ("Remote Services: Windows Remote Management", ("lateral-movement",)),
    "T1027": ("Obfuscated Files or Information", ("defense-evasion",)),
    "T1053.003": ("Scheduled Task/Job: Cron", ("execution", "persistence", "privilege-escalation")),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", ("execution", "persistence", "privilege-escalation")),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", ("execution",)),
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell", ("execution",)),
    "T1070.001": ("Indicator Removal: Clear Windows Event Logs", ("defense-evasion",)),
    "T1083": ("File and Directory Discovery", ("discovery",)),
    "T1087.002": ("Account Discovery: Domain Account", ("discovery",)),
    "T1110.003": ("Brute Force: Password Spraying", ("credential-access",)),
    "T1190": ("Exploit Public-Facing Application", ("initial-access",)),
    "T1218.011": ("System Binary Proxy Execution: Rundll32", ("defense-evasion",)),
    "T1505.003": ("Server Software Component: Web Shell", ("persistence",)),
    "T1547.001": ("Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
                  ("persistence", "privilege-escalation")),
    "T1558.003": ("Steal or Forge Kerberos Tickets: Kerberoasting", ("credential-access",)),
    "T1569.002": ("System Services: Service Execution", ("execution",)),
    "T1606": ("Forge Web Credentials", ("credential-access",)),
}
TECHNIQUE_NAMES = {tid: name for tid, (name, _t) in TECHNIQUES.items()}
TECHNIQUE_TACTICS = {tid: tactics for tid, (_n, tactics) in TECHNIQUES.items()}
_ID_TAG = re.compile(r"^attack\.[tgs]\d{4}(\.\d{3})?$")


def attack_tag_errors(tags: list) -> list[str]:
    """ATT&CK tags checked against the reference above: every technique tag is in it, every attack.<name> tag
    is a tactic of this version, and every tactic belongs to one of the tagged techniques (group and software
    tags pass)."""
    tags = [str(t) for t in tags if str(t).startswith("attack.")]
    techs = [t.split(".", 1)[1].upper() for t in tags if re.match(r"^attack\.t\d{4}", t)]
    errs = [f"technique {t} is not in the ATT&CK reference (TECHNIQUES in tools/common.py)" for t in techs
            if t not in TECHNIQUES]
    for t in tags:
        if _ID_TAG.match(t):
            continue
        name = t.split(".", 1)[1]
        if name not in ATTACK_TACTICS:
            errs.append(f"tag {t} is not an ATT&CK v{ATTACK_VERSION} tactic ({', '.join(ATTACK_TACTICS)})")
        elif techs and all(name not in TECHNIQUE_TACTICS.get(x, (name,)) for x in techs):
            errs.append(f"tag {t} is a tactic of none of the tagged techniques ("
                        + "; ".join(f"{x}: {', '.join(TECHNIQUE_TACTICS[x])}" for x in techs if x in TECHNIQUE_TACTICS) + ")")
    return errs


_TTY = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
def c(code: str) -> str: return f"\033[{code}m" if _TTY else ""
GREEN, RED, YELLOW, DIM, BOLD, RESET = c("32"), c("31"), c("33"), c("2"), c("1"), c("0")
GOLD, SAGE, IVORY = c("38;5;180"), c("38;5;108"), c("38;5;188")


def read_text(path: Path) -> str:
    """A text file as Windows tools save it: UTF-8 with or without a BOM, or UTF-16 with a BOM."""
    data = path.read_bytes()
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as e:
        raise SystemExit(f"{path}: neither UTF-8 nor UTF-16 text") from e


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for n, line in enumerate(read_text(path).splitlines(), 1):
        if line.strip():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise SystemExit(f"{path}:{n}: invalid JSON ({e})") from e
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

    {marker} is the run marker (rasd_1a2b3c4d), {hex} its random part (1a2b3c4d).
    The prefix base64-utf16le: encodes the expanded text the way powershell -enc does,
    so an encoded command line can be bound to its run too.
    """
    hexpart = marker.rsplit("_", 1)[-1]
    encoded = template.startswith(TOKEN_ENCODINGS[0])
    text = template[len(TOKEN_ENCODINGS[0]):] if encoded else template
    text = text.replace("{marker}", marker).replace("{hex}", hexpart)
    return base64.b64encode(text.encode("utf-16-le")).decode() if encoded else text


MARKER_RE = re.compile(r"^rasd_[0-9a-f]{8}$")


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
