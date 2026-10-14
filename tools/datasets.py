#!/usr/bin/env python3
"""
datasets.py - public attack datasets as evidence: pinned, hashed, replayed through every rule.

A dataset is not evidence. Evidence is a dataset every rule ran on, with the result recorded
where anyone can check it. This tool turns the first into the second:

  catalog   datasets/catalog.yml pins each file to a commit of its source repository and to
            its SHA-256, names its license, the reader and the telemetry profile it needs, and
            says what RASD must do on it: the detections that must fire (`expect`), the ones
            that also fire and why (`also`: harness, benign, false-positive - for all of a
            detection's alerts on the file, or with `where` for the alerts whose fields contain
            given text, the rest being the recorded attack), the detections
            for its technique that stay quiet, of which kind and why (`quiet`), and the
            earlier files that hold some of the same records (`overlap`)
  fetch     download the files into datasets/cache (never committed) and verify every hash;
            the member read from a zip is verified too. Files outside Git LFS (a source's own,
            or a file a source keeps in the repository itself: `lfs: false`) can also be
            fetched with git where the raw download host is blocked (--git)
  run       read each file, normalise it with its profile, run every detection and
            correlation over it and compare with the catalog: an expected detection that
            stays quiet, a `quiet` one that fires, an alert the catalog does not explain, or
            records shared with an earlier file that the catalog does not declare fail the
            run. Each record counts once: a repeat inside a file is read once, and an alert on
            a record an earlier file holds is not new evidence. The applied tunings are
            measured on the same events: what each filter kept quiet, and what each
            exception took back
  --write   keep the result: datasets/results.json (every count, with the SHA-256 of each
            rule, tuning, profile and catalog entry that produced it), datasets/extracts/
            (the events that fired or were counted, reduced to the fields the rules read,
            each with the ordinal and SHA-256 of its original record) and the pages below -
            after a leak scan: no value distinctive of a file that cannot be redistributed
            may be anywhere in the repository
  leaks     the leak scan on its own
  render    detect/*/<id>/public_evidence.md and docs/PUBLIC_DATA_VALIDATION.md from
            results.json (part of `rasd build`)
  check     CI, offline: the catalog is well-formed, results.json was produced by the rules,
            tunings, profiles and catalog in the repository (a changed rule needs a new
            run), every extract still fires exactly as recorded, and the pages are current

What a public dataset proves: the rule fires on telemetry recorded from real attack tooling
in somebody else's lab, and its applied tunings are measured on that lab's background
activity. A rule changed after a file showed it a gap is in-sample on that file, and the
catalog says so. What it does not prove: the SIEM side (ingestion, field extraction, latency,
alerting) - that is the lab run and a SIEM replay - and a lab's background activity is not an
estate's noise.

Usage
  rasd datasets                       # the catalog: sources, licenses, what is cached
  rasd datasets fetch                 # download and verify everything (--only, --git)
  rasd datasets run                   # replay and report; --write keeps the result
  rasd datasets run --only T1003.001 -v
  rasd datasets run --case-dir reports/public-cases
  rasd datasets check                 # CI
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import http.client
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET  # only files whose SHA-256 matches the catalog are parsed, and DTDs are refused
import zipfile
from collections import Counter, defaultdict
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import profiles
from common import (BOLD, CORRELATIONS, DETECTIONS, DIM, DOCS, GREEN, RED, RESET, ROOT, VERSION, YELLOW, attack_aliases,
                    load_detections, read_text)
from convert import logsource_key, referenced_fields
from correlation import Correlation, epoch, evaluate, iso, load_correlations, value_reader
from replay import HOST_FIELDS, TIME_FIELDS, USER_FIELDS, first, parse_time, route
from sigma_engine import SigmaError, compile_rule

DATASETS = ROOT / "datasets"
CATALOG = DATASETS / "catalog.yml"
RESULTS = DATASETS / "results.json"
EXTRACTS = DATASETS / "extracts"
HOLDOUT_LABELS = DATASETS / "holdout_labels.json"    # labels of the held-out files, written before their first replay
CACHE = DATASETS / "cache"
VALIDATION_DOC = DOCS / "PUBLIC_DATA_VALIDATION.md"
PAGE = "public_evidence.md"
READER = 5                       # bump when a reader, the counting or the extract format changes: results.json must be re-run
FORMATS = ("windows-xml", "windows-classic", "nxlog-json", "evtx")
ALSO_KINDS = ("benign", "harness", "false-positive")
QUIET_KINDS = {                  # why a detection stays quiet on a recording of its technique
    "gap": "public data shows the behaviour in telemetry RASD reads, and no rule reads it yet",
    "scope": "the recorded behaviour is outside what the rule is written to detect",
    "blind-spot": "a blind spot the rule documents",
    "telemetry": "the recording lacks the event the rule reads",
    "negative": "the file does not hold the behaviour the rule detects",
}
CUT = 300                        # longer values are cut in extracts; the verdicts are checked unchanged
NEVER = {"RasdNeutralisedSelection": "never"}       # stands in for a selection whose effect is measured
CONTEXT = ("EventID", "Channel", "Provider_Name", "SourceName", "Computer", "Hostname", "EventRecordID",
           "ProcessGuid", "ProcessId", "ParentProcessGuid", "SourceProcessGUID", "SourceProcessId", "TargetProcessId",
           "EventTime")
GENERATED = "<!-- Generated by tools/datasets.py from datasets/results.json - do not edit by hand. -->\n\n"
FOOTER = "\n<sub>Generated by tools/datasets.py · RASD · Attack-to-Defense Validation Framework</sub>\n"
EVENT_RE = re.compile(r"<Event[\s>].*?</Event>", re.S)
HEX40, HEX64 = re.compile(r"^[0-9a-f]{40}$"), re.compile(r"^[0-9a-f]{64}$")
DATASET_ID = re.compile(r"^[a-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9._-]+)*$")
MAX_DOWNLOAD = 512 * 1024 * 1024


class RunError(Exception):
    """A dataset cannot be read or does not match the catalog."""


# --------------------------------------------------------------------------- #
# catalog
# --------------------------------------------------------------------------- #
@dataclass
class Source:
    id: str
    title: str
    home: str
    repo: str
    commit: str
    license: str
    license_file: str | None
    url: str | None
    lfs: bool
    redistribute: bool


@dataclass
class Dataset:
    id: str
    source: Source
    path: str
    sha256: str
    size: int
    format: str
    profile: str
    technique: str
    title: str
    expect: list[str]
    also: dict[str, dict]
    quiet: dict[str, dict]
    member: str | None = None
    member_sha256: str | None = None
    splunk: dict | None = None             # sourcetype and source to replay the file into Splunk with
    overlap: dict[str, str] = field(default_factory=dict)   # earlier files that hold some of the same records, and why
    holdout: str | None = None             # label id in holdout_labels.json: added after the rule changes, labelled first
    missed: dict[str, str] = field(default_factory=dict)    # held-out: expected detections that stayed quiet, and why
    found: dict[str, str] = field(default_factory=dict)     # held-out: detections that fired beyond the labels, and why
    demoted_from: str | None = None        # a held-out label this file had until a fix made after its replay
    lfs: bool | None = None                # False: kept in the repository itself although its source uses Git LFS

    def cached(self, cache: Path) -> Path:
        return cache / self.source.id / self.path

    @property
    def extract(self) -> Path | None:
        """The committed extract, for sources whose license allows redistribution."""
        return EXTRACTS / f"{self.id}.jsonl" if self.source.redistribute else None

    @property
    def link(self) -> str:
        return f"{self.source.repo}/blob/{self.source.commit}/{urllib.parse.quote(self.path)}"

    @property
    def in_lfs(self) -> bool:
        return self.source.lfs if self.lfs is None else self.lfs

    @property
    def url(self) -> str | None:
        """Where `fetch` downloads the file: the source's template, or for a file a Git LFS source keeps in
        the repository itself, GitHub's raw host at the pinned commit (the LFS media host does not serve it)."""
        path = urllib.request.pathname2url(self.path).lstrip("/")
        if self.source.lfs and not self.in_lfs:
            return f"https://raw.githubusercontent.com/{self.source.repo.removeprefix('https://github.com/')}/{self.source.commit}/{path}"
        return self.source.url.format(commit=self.source.commit, path=path) if self.source.url else None

    def explained(self, rid: str) -> dict | None:
        """The `also` entry that explains some of a detection's alerts by `where`, or None."""
        entry = self.also.get(rid) or {}
        return entry if entry.get("where") else None

    @property
    def short(self) -> str:
        return self.id.split("/", 1)[1] if "/" in self.id else self.id

    def matches(self, only: str | None) -> bool:
        if not only:
            return True
        needle = only.lower()
        return any(needle in s.lower() for s in (self.id, self.technique, self.title, *self.expect, *self.also, *self.quiet))


@dataclass
class Catalog:
    sources: dict[str, Source]
    datasets: list[Dataset]
    gaps: dict[str, str]
    raw: dict
    errors: list[str] = field(default_factory=list)
    next: list[dict] = field(default_factory=list)
    changed: dict[str, str] = field(default_factory=dict)   # rules changed after replaying the catalog: in-sample there


def holdout_doc() -> dict:
    return json.loads(read_text(HOLDOUT_LABELS)) if HOLDOUT_LABELS.exists() else {}


def _check_holdout_labels(held: list[Dataset], demoted: list[Dataset] | None = None) -> list[str]:
    """The catalog's expect and quiet entries of a held-out file are its labels, unchanged: `attack`
    labels are the expected detections, `scope`, `telemetry` and `blind-spot` labels the quiet ones.
    A demoted file names a label the labels file lists as demoted, with the reason."""
    if not held and not demoted:
        return []
    if not HOLDOUT_LABELS.exists():
        return [f"{HOLDOUT_LABELS.name} is missing: held-out files need the labels written before their first replay"]
    try:
        doc = holdout_doc()
        files = {f["label"]: f for f in doc.get("files") or []}
        gone = {str(k): str(v) for k, v in (doc.get("demoted") or {}).items()}
    except (ValueError, AttributeError, KeyError, TypeError) as e:
        return [f"{HOLDOUT_LABELS.name}: unreadable ({e})"]
    errors = []
    # labels written before a detection was renamed keep the ID the reviewer saw; the alias file maps it
    current = {legacy: rid for rid, legacy in attack_aliases()["detections"].items()}
    for ds in demoted or []:
        if ds.demoted_from not in gone or (files.get(str(ds.demoted_from)) or {}).get("dataset") != ds.id:
            errors.append(f"dataset {ds.id}: demoted_from {ds.demoted_from} must be a label of this file listed as demoted in "
                          f"{HOLDOUT_LABELS.name}, with the reason")
    for ds in held:
        if str(ds.holdout) in gone:
            errors.append(f"dataset {ds.id}: label {ds.holdout} was demoted and cannot be held out again")
    for ds in held:
        f = files.get(str(ds.holdout))
        if (f is None or f.get("dataset") != ds.id or f.get("sha256") != ds.sha256
                or (ds.member and f.get("member_sha256") != ds.member_sha256)):
            errors.append(f"dataset {ds.id}: holdout label {ds.holdout} is not in {HOLDOUT_LABELS.name} for this file")
            continue
        labels = f.get("labels") or []
        attack = sorted(current.get(x["detection"], x["detection"]) for x in labels if x.get("label") == "attack")
        quiet = {current.get(x["detection"], x["detection"]): x.get("label") for x in labels
                 if x.get("label") in ("scope", "telemetry", "blind-spot")}
        if sorted(ds.expect) != attack or {k: q.get("kind") for k, q in ds.quiet.items()} != quiet:
            errors.append(f"dataset {ds.id}: expect and quiet must be the labels of {ds.holdout}, unchanged")
    return errors


def _where(value: Any) -> dict[str, list[str]] | None:
    """A `where` selector as {field: [text, ...]}, or None when it is not one."""
    if not isinstance(value, dict) or not value:
        return None
    out: dict[str, list[str]] = {}
    for f, texts in value.items():
        texts = [texts] if isinstance(texts, str) else texts
        if not (isinstance(f, str) and f.strip() and isinstance(texts, list) and texts
                and all(isinstance(t, str) and t.strip() for t in texts)):
            return None
        out[f] = list(texts)
    return out


def where_match(ev: dict, sel: dict[str, list[str]]) -> bool:
    """True when every field the selector names contains one of its texts (case-insensitive): an alert
    the catalog's `also` entry explains rather than the recorded attack."""
    for f, texts in sel.items():
        v = ev.get(f)
        if v in (None, ""):
            return False
        low = str(v).lower()
        if not any(t.lower() in low for t in texts):
            return False
    return True


def also_of(ev: dict, fires: list[str] | tuple, ds: Dataset) -> list[str]:
    """The detections among `fires` whose alert on this event an `also` entry with `where` explains."""
    return sorted(r for r in fires if (e := ds.explained(r)) and where_match(ev, e["where"]))


def known_ids() -> dict[str, Any]:
    return {**{d.id: d for d in load_detections()}, **{c.id: c for c in load_correlations()}}


def load_catalog(path: Path = CATALOG) -> Catalog:
    """The catalog, with every problem found in it (the run and the check refuse a catalog with errors)."""
    doc = yaml.safe_load(read_text(path)) if path.exists() else None
    errors: list[str] = []
    if not isinstance(doc, dict):
        return Catalog({}, [], {}, {}, [f"{path.name}: missing or not a mapping"])
    if doc.get("format") != 1:
        errors.append("catalog: format must be 1")
    ids = known_ids()
    sources: dict[str, Source] = {}
    for sid, s in (doc.get("sources") or {}).items():
        s = s or {}
        where = f"source {sid}"
        for key in ("title", "home", "repo", "commit", "license"):
            if not s.get(key):
                errors.append(f"{where}: {key} is required")
        if s.get("repo") and not str(s["repo"]).startswith("https://github.com/"):
            errors.append(f"{where}: repo must be an https://github.com/ repository")
        if s.get("commit") and not HEX40.match(str(s["commit"])):
            errors.append(f"{where}: commit must be a full 40-character SHA-1")
        url = s.get("url")
        if url and not (str(url).startswith("https://") and "{commit}" in url and "{path}" in url):
            errors.append(f"{where}: url must be an https:// template with {{commit}} and {{path}}")
        for key in ("lfs", "redistribute"):
            if not isinstance(s.get(key), bool):
                errors.append(f"{where}: {key} must be true or false")
        lic = s.get("license_file")
        if s.get("redistribute") and not lic:
            errors.append(f"{where}: a redistributed source needs license_file")
        if lic and not (ROOT / lic).exists():
            errors.append(f"{where}: license_file {lic} does not exist")
        sources[sid] = Source(sid, str(s.get("title", sid)), str(s.get("home", "")), str(s.get("repo", "")),
                              str(s.get("commit", "")), str(s.get("license", "")), lic, url,
                              bool(s.get("lfs")), bool(s.get("redistribute")))
    datasets: list[Dataset] = []
    seen: set[str] = set()
    profile_names = set(profiles.names())
    for n, d in enumerate(doc.get("datasets") or [], 1):
        d = d or {}
        did = str(d.get("id", f"#{n}"))
        where = f"dataset {did}"
        if not DATASET_ID.match(did) or ".." in did:
            errors.append(f"{where}: id must be a relative path of letters, digits, '.', '_' and '-'")
        if did in seen:
            errors.append(f"{where}: duplicate id")
        seen.add(did)
        src = sources.get(str(d.get("source")))
        if src is None:
            errors.append(f"{where}: unknown source {d.get('source')!r}")
            continue
        p = str(d.get("path", ""))
        if not p or p.startswith(("/", "\\")) or ".." in Path(p).parts:
            errors.append(f"{where}: path must be relative to the source repository")
        if not HEX64.match(str(d.get("sha256", ""))):
            errors.append(f"{where}: sha256 must be 64 lowercase hex characters")
        if not isinstance(d.get("size"), int) or d["size"] <= 0:
            errors.append(f"{where}: size must be the file size in bytes")
        fmt = d.get("format")
        if fmt not in FORMATS:
            errors.append(f"{where}: format must be one of {', '.join(FORMATS)}")
        if d.get("profile") not in profile_names:
            errors.append(f"{where}: unknown profile {d.get('profile')!r}")
        member, member_sha = d.get("member"), d.get("member_sha256")
        if bool(member) != bool(member_sha):
            errors.append(f"{where}: member and member_sha256 go together")
        if member and not p.endswith(".zip"):
            errors.append(f"{where}: member is only for a .zip")
        if member_sha and not HEX64.match(str(member_sha)):
            errors.append(f"{where}: member_sha256 must be 64 lowercase hex characters")
        for key in ("technique", "title"):
            if not d.get(key):
                errors.append(f"{where}: {key} is required")
        spl = d.get("splunk")
        if spl is not None and not (isinstance(spl, dict) and spl.get("sourcetype") and spl.get("source")):
            errors.append(f"{where}: splunk needs sourcetype and source")
        expect = [str(x) for x in d.get("expect") or []]
        also = {str(k): (dict(v) if isinstance(v, dict) else v or {}) for k, v in (d.get("also") or {}).items()}
        quiet = {str(k): (v if isinstance(v, dict) else {"reason": str(v or "")}) for k, v in (d.get("quiet") or {}).items()}
        overlap = {str(k): str(v or "") for k, v in (d.get("overlap") or {}).items()}
        holdout = str(d["holdout"]) if d.get("holdout") else None
        demoted = str(d["demoted_from"]) if d.get("demoted_from") else None
        if holdout and demoted:
            errors.append(f"{where}: a file is held out or was demoted, not both")
        missed = {str(k): str(v or "") for k, v in (d.get("missed") or {}).items()}
        found = {str(k): str(v or "") for k, v in (d.get("found") or {}).items()}
        if (missed or found) and not holdout:
            errors.append(f"{where}: missed and found are for held-out files only")
        for rid, why in missed.items():
            if rid not in expect or not why.strip():
                errors.append(f"{where}: missed.{rid} must be an expected detection, with the reason it stayed quiet")
        for rid, why in found.items():
            if rid in expect or rid in also or not why.strip() or rid not in ids:
                errors.append(f"{where}: found.{rid} must be a detection the labels did not expect, with the reason it fired")
        for rid in [*expect, *also, *quiet]:
            if rid not in ids:
                errors.append(f"{where}: {rid} is not a detection or correlation in this repository")
        for rid, v in also.items():
            if not isinstance(v, dict) or v.get("kind") not in ALSO_KINDS or not str(v.get("reason", "")).strip():
                errors.append(f"{where}: also.{rid} needs kind ({', '.join(ALSO_KINDS)}) and a reason")
                continue
            if "where" in v:
                sel = _where(v["where"])
                if sel is None:
                    errors.append(f"{where}: also.{rid}.where maps field names to the text the field of such an alert contains "
                                  "(a string or a list of strings)")
                elif isinstance(ids.get(rid), Correlation):
                    errors.append(f"{where}: also.{rid}.where is for detections: a correlation window is not one event")
                else:
                    v["where"] = sel
        for rid, q in quiet.items():
            if q.get("kind") not in QUIET_KINDS or not str(q.get("reason", "")).strip():
                errors.append(f"{where}: quiet.{rid} needs kind ({', '.join(QUIET_KINDS)}) and a reason")
            if (q.get("kind") == "gap") != bool(q.get("next")):
                errors.append(f"{where}: quiet.{rid}: a gap names the next rule (next), and only a gap does")
        for other, why in overlap.items():
            if other not in {x.id for x in datasets}:
                errors.append(f"{where}: overlap names {other}, which is not an earlier dataset in the catalog")
            if not why.strip():
                errors.append(f"{where}: overlap.{other} needs a reason")
        split = {r for r in also if isinstance(also[r], dict) and also[r].get("where")}
        if holdout and set(quiet) & split:
            errors.append(f"{where}: on a held-out file a detection labelled quiet that fires goes under found, not under also")
        both = ((set(expect) & set(also) - split) | (set(expect) & set(quiet)) | (set(also) & set(quiet) - split))
        if both:
            errors.append(f"{where}: {', '.join(sorted(both))} listed in more than one of expect, also, quiet "
                          "(a detection can be under also beside expect or quiet only with where)")
        lfs = d.get("lfs")
        if lfs is not None and not (lfs is False and src.lfs):
            errors.append(f"{where}: lfs: false is only for a file its Git LFS source keeps in the repository itself")
        # a malformed entry is reported above and not kept, so the pages still render from a catalog with errors
        also = {k: v for k, v in also.items() if isinstance(v, dict) and k in ids and v.get("kind") in ALSO_KINDS
                and str(v.get("reason", "")).strip()}
        expect = [r for r in expect if r in ids]
        quiet = {k: q for k, q in quiet.items() if k in ids and q.get("kind") in QUIET_KINDS}
        missed = {k: w for k, w in missed.items() if k in expect}
        found = {k: w for k, w in found.items() if k in ids}
        datasets.append(Dataset(did, src, p, str(d.get("sha256", "")), int(d.get("size") or 0), str(fmt), str(d.get("profile")),
                                str(d.get("technique", "")), str(d.get("title", "")), expect, also, quiet,
                                member, member_sha, spl, overlap, holdout, missed, found, demoted,
                                False if lfs is False else None))
    labels = [ds.holdout for ds in datasets if ds.holdout]
    for dup in sorted({x for x in labels if labels.count(x) > 1}):
        errors.append(f"holdout label {dup} is used by more than one dataset")
    errors += _check_holdout_labels([ds for ds in datasets if ds.holdout], [ds for ds in datasets if ds.demoted_from])
    gaps = {str(k): str(v or "") for k, v in (doc.get("gaps") or {}).items()}
    for rid, why in gaps.items():
        if rid not in ids:
            errors.append(f"gaps: {rid} is not a detection or correlation in this repository")
        elif not why.strip():
            errors.append(f"gaps: {rid} needs a reason")
        if any(rid in ds.expect for ds in datasets):
            errors.append(f"gaps: {rid} is expected to fire on a dataset, so it is not a gap")
    for rid in ids:
        if rid not in gaps and not any(rid in ds.expect or rid in ds.quiet for ds in datasets):
            errors.append(f"{rid}: no dataset expects it and it is not listed under gaps")
    nexts = [nx or {} for nx in doc.get("next") or []]
    known_ds = {ds.id for ds in datasets}
    next_ids = [str(nx.get("id")) for nx in nexts]
    for nx in nexts:
        where = f"next {nx.get('id')}"
        if next_ids.count(str(nx.get("id"))) > 1:
            errors.append(f"{where}: duplicate id")
        if nx.get("detection") not in ids:
            errors.append(f"{where}: {nx.get('detection')} is not a detection or correlation in this repository")
        if not nx.get("technique") or not str(nx.get("rule", "")).strip():
            errors.append(f"{where}: technique and rule are required")
        for did in nx.get("evidence") or []:
            if did not in known_ds:
                errors.append(f"{where}: evidence {did} is not a dataset in the catalog")
        if not nx.get("evidence"):
            errors.append(f"{where}: needs at least one dataset as evidence")
    for ds in datasets:
        for rid, q in ds.quiet.items():
            if q.get("next") and q["next"] not in next_ids:
                errors.append(f"dataset {ds.id}: quiet.{rid} names next rule {q['next']}, which is not under next")
    changed = {str(k): str(v or "") for k, v in (doc.get("changed_after_replay") or {}).items()}
    for rid, why in changed.items():
        if rid not in ids or not why.strip():
            errors.append(f"changed_after_replay: {rid} needs to be a detection or correlation here, with what changed")
    return Catalog(sources, datasets, gaps, doc, errors, nexts, changed)


# --------------------------------------------------------------------------- #
# fingerprints: what produced results.json
# --------------------------------------------------------------------------- #
def _digest(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()


def _yaml(path: Path) -> dict:
    return (yaml.safe_load(path.read_text(encoding="utf-8")) or {}) if path.exists() else {}


def fingerprints(cat: Catalog) -> dict[str, str]:
    """The SHA-256 of everything a recorded result depends on: each rule's log source and detection,
    each correlation's parameters, each applied tuning, each profile used, each file's identity, reader
    and listed detections, and the reader version. Titles, descriptions and reasons are left out, so
    editing prose needs no re-run (the pages are rendered from the catalog on every build)."""
    out = {"reader": str(READER)}
    for folder in sorted(p for p in DETECTIONS.iterdir() if p.is_dir()):
        rule = _yaml(folder / "rule.yml")
        out[f"rule:{folder.name}"] = _digest({"logsource": rule.get("logsource"), "detection": rule.get("detection")})
        out[f"tuning:{folder.name}"] = _digest(_applied(_yaml(folder / "tuning.yml")))
    if CORRELATIONS.exists():
        for folder in sorted(p for p in CORRELATIONS.iterdir() if p.is_dir()):
            corr, base = _yaml(folder / "correlation.yml"), _yaml(folder / "base.yml")
            out[f"rule:{folder.name}"] = _digest({"correlation": corr.get("correlation"), "logsource": base.get("logsource"),
                                                  "detection": base.get("detection"), "name": base.get("name")})
            out[f"tuning:{folder.name}"] = _digest(_applied(_yaml(folder / "tuning.yml")))
    for name in sorted({ds.profile for ds in cat.datasets}):
        path = profiles.PROFILES_DIR / f"{name}.yml"
        out[f"profile:{name}"] = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else "missing"
    if HOLDOUT_LABELS.exists():
        out["holdout_labels"] = hashlib.sha256(HOLDOUT_LABELS.read_bytes()).hexdigest()
    for sid, src in sorted((cat.raw.get("sources") or {}).items()):
        out[f"source:{sid}"] = _digest({k: (src or {}).get(k) for k in ("repo", "commit", "url", "lfs", "redistribute")})
    for d in cat.raw.get("datasets") or []:
        d = d or {}
        out[f"dataset:{d.get('id')}"] = _digest({
            **{k: d.get(k) for k in ("source", "path", "sha256", "size", "member", "member_sha256", "format", "profile")},
            "expect": sorted(d.get("expect") or []), "quiet": sorted(d.get("quiet") or {}),
            "also": {k: v.get("where") if isinstance(v, dict) else v for k, v in sorted((d.get("also") or {}).items())},
            "overlap": sorted(d.get("overlap") or {}), "holdout": d.get("holdout"),
            "missed": sorted(d.get("missed") or {}), "found": sorted(d.get("found") or {}), "demoted": d.get("demoted_from")})
    return out


def _applied(doc: dict) -> list:
    return [(t.get("id"), t.get("kind", "filter"), t.get("selection")) for t in doc.get("tunings") or []
            if t.get("status") == "applied"]


def stale_inputs(recorded: dict[str, str], current: dict[str, str]) -> list[str]:
    """The inputs that changed since results.json was written (added, removed or edited)."""
    return sorted(k for k in set(recorded) | set(current) if recorded.get(k) != current.get(k))


# --------------------------------------------------------------------------- #
# readers
# --------------------------------------------------------------------------- #
def _strip(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


CORE = ("Channel", "Provider_Name", "EventID", "Computer", "TimeCreated")


def xml_event(text: str) -> dict | None:
    """One Windows event as XML (Splunk XmlWinEventLog, an EVTX record, Sysmon for Linux) as a flat
    event, named the way red/Export-LabTelemetry.ps1 names fields: System fields under their RASD
    names, EventData and UserData by name; an EventData field cannot replace a core key (it becomes
    <name>_EventData), System 104's cleared-log name is Channel_Cleared, and another clashing
    UserData field becomes <name>_UserData. None when the record is not well-formed XML."""
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        raise RunError("an XML record declares a DTD or an entity; refused")
    try:
        root = ET.fromstring(text)  # noqa: S314 - SHA-256 verified against the catalog first, DTDs refused above
    except ET.ParseError:
        try:                        # some exports leave &, < and > unescaped inside Data values (a script with 2>&1 or <#)
            root = ET.fromstring(_escape_data_values(text))  # noqa: S314 - same record, values escaped
        except ET.ParseError:
            return None
    ev: dict[str, Any] = {}
    for section in root:
        name = _strip(section.tag)
        if name == "System":
            for node in section:
                tag = _strip(node.tag)
                if tag == "Provider" and node.get("Name"):
                    ev["Provider_Name"] = node.get("Name")
                elif tag == "TimeCreated" and node.get("SystemTime"):
                    ev["TimeCreated"] = node.get("SystemTime")
                elif tag in ("EventID", "Channel", "Computer", "EventRecordID") and (node.text or "").strip():
                    value = (node.text or "").strip()
                    ev[tag] = int(value) if tag in ("EventID", "EventRecordID") and value.isdigit() else value
        elif name == "EventData":
            for i, data in enumerate(section):
                if _strip(data.tag) == "Data":
                    key = data.get("Name") or f"Data{i}"
                    ev[f"{key}_EventData" if key in CORE else key] = data.text or ""
        elif name == "UserData":
            for child in section:
                for node in child:
                    key = _strip(node.tag)
                    key = "Channel_Cleared" if key == "Channel" else (f"{key}_UserData" if key in ev else key)
                    ev[key] = node.text or ""
    return ev


_DATA_VALUE = re.compile(r"(<Data\b[^>]*>)(.*?)(</Data>)", re.S)
_BARE_AMP = re.compile(r"&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[0-9A-Fa-f]+);)")


def _escape_data_values(text: str) -> str:
    """The record with &, < and > escaped inside each Data value, as Windows' own rendering escapes them."""
    def fix(m: re.Match) -> str:
        return m.group(1) + _BARE_AMP.sub("&amp;", m.group(2)).replace("<", "&lt;").replace(">", "&gt;") + m.group(3)
    return _DATA_VALUE.sub(fix, text)


def json_event(line: str) -> dict | None:
    try:
        ev = json.loads(line)
    except ValueError:
        return None
    return ev if isinstance(ev, dict) else None


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


Record = tuple[int, str, "dict | None"]          # ordinal in the file, SHA-256 of the record text, event


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Splunk's classic WinEventLog text: a time line, Key=Value header lines, then the rendered Message
# --------------------------------------------------------------------------- #
CLASSIC_START = re.compile(r"(?m)^(\d\d/\d\d/\d{4} \d\d:\d\d:\d\d [AP]M)\r?\n(?=LogName=)")
CLASSIC_PROVIDERS = {                      # SourceName as the classic format writes it -> the event's provider name
    "Microsoft Windows security auditing.": "Microsoft-Windows-Security-Auditing",
    "Microsoft-Windows-Service Control Manager": "Service Control Manager",
}
_SUBJECT = {"Security ID": "SubjectUserSid", "Account Name": "SubjectUserName", "Account Domain": "SubjectDomainName",
            "Domain Name": "SubjectDomainName", "Logon ID": "SubjectLogonId", "Logon GUID": "LogonGuid"}
_TARGET = {"Security ID": "TargetUserSid", "Account Name": "TargetUserName", "Account Domain": "TargetDomainName",
           "Logon ID": "TargetLogonId"}
CLASSIC_FIELDS: dict[str, dict[str, str]] = {   # message section -> label -> the field name of the XML event
    "Subject": _SUBJECT, "Creator Subject": _SUBJECT,
    "Target Subject": _TARGET, "New Logon": _TARGET, "Account For Which Logon Failed": _TARGET,
    "Account Information": {"Account Name": "TargetUserName", "Account Domain": "TargetDomainName",
                            "Supplied Realm Name": "TargetDomainName", "Security ID": "TargetSid", "User ID": "TargetSid",
                            "Logon GUID": "LogonGuid"},
    "Service Information": {"Service Name": "ServiceName", "Service ID": "ServiceSid", "Service File Name": "ServiceFileName",
                            "Service Type": "ServiceType", "Service Start Type": "ServiceStartType",
                            "Service Account": "ServiceAccount"},
    "Network Information": {"Client Address": "IpAddress", "Client Port": "IpPort", "Source Network Address": "IpAddress",
                            "Source Port": "IpPort", "Workstation Name": "WorkstationName",
                            "Network Address": "IpAddress", "Port": "IpPort"},                       # 4648
    "Additional Information": {"Ticket Options": "TicketOptions", "Ticket Encryption Type": "TicketEncryptionType",
                               "Failure Code": "Status", "Result Code": "Status", "Pre-Authentication Type": "PreAuthType",
                               "Transited Services": "TransmittedServices"},
    "Failure Information": {"Failure Reason": "FailureReason", "Status": "Status", "Sub Status": "SubStatus"},
    "Process Information": {"New Process ID": "NewProcessId", "New Process Name": "NewProcessName",
                            "Token Elevation Type": "TokenElevationType", "Mandatory Label": "MandatoryLabel",
                            "Creator Process ID": "ProcessId", "Creator Process Name": "ParentProcessName",
                            "Process Command Line": "CommandLine", "Caller Process ID": "ProcessId",
                            "Caller Process Name": "ProcessName", "Process ID": "ProcessId", "Process Name": "ProcessName",
                            "Exit Status": "Status"},                                                    # 4689
    "Logon Information": {"Logon Type": "LogonType"},
    "Detailed Authentication Information": {"Logon Process": "LogonProcessName",
                                            "Authentication Package": "AuthenticationPackageName"},
    "Task Information": {"Task Name": "TaskName", "Task Content": "TaskContent"},                     # 4698
    "Account Whose Credentials Were Used": {"Account Name": "TargetUserName", "Account Domain": "TargetDomainName",
                                            "Logon GUID": "TargetLogonGuid"},                         # 4648
    "Target Server": {"Target Server Name": "TargetServerName", "Additional Information": "TargetInfo"},
    "": {"Logon Type": "LogonType", "Service Name": "ServiceName", "Service File Name": "ImagePath",   # 4625, 7045
         "Service Type": "ServiceType", "Service Start Type": "StartType", "Service Account": "AccountName",
         "Authentication Package": "PackageName", "Logon Account": "TargetUserName",                 # 4776
         "Source Workstation": "Workstation", "Error Code": "Status"},
}
_SECTION = re.compile(r"^([A-Z][A-Za-z ]{1,48}):\s*$")
_LABEL = re.compile(r"^(\t*)([A-Z][A-Za-z0-9 ()/'-]{0,48}):(?:\t+| {2,}|\t* |\s*$)(.*)$")
_CLEARED = re.compile(r"The (.+?) log file was cleared")
_PROSE = re.compile(r"^Token Elevation Type indicates ")   # the paragraph after a 4688 command line, which ends it


def classic_event(text: str) -> dict | None:
    """One event of Splunk's classic WinEventLog text as the flat event the XML reader makes: header
    keys as System fields (LogName as Channel, EventCode as EventID, RecordNumber as EventRecordID,
    ComputerName as Computer, the provider by its event name), and the rendered message's labels by
    their XML field names, section by section (Account Name under Target Subject is TargetUserName).
    The time line has no zone; it is read as UTC. None when the text is not such an event."""
    lines = text.splitlines()
    if len(lines) < 3 or not lines[1].startswith("LogName="):
        return None
    try:
        when = datetime.strptime(lines[0].strip(), "%m/%d/%Y %I:%M:%S %p")
    except ValueError:
        return None
    ev: dict[str, Any] = {"TimeCreated": when.strftime("%Y-%m-%dT%H:%M:%SZ")}
    body: list[str] = []
    for n, line in enumerate(lines[1:], 1):
        if line.startswith("Message="):
            body = [line[len("Message="):], *lines[n + 1:]]
            break
        key, _, value = line.partition("=")
        value = value.strip()
        if key == "LogName":
            ev["Channel"] = value
        elif key == "EventCode" and value.isdigit():
            ev["EventID"] = int(value)
        elif key == "ComputerName":
            ev["Computer"] = value
        elif key == "RecordNumber" and value.isdigit():
            ev["EventRecordID"] = int(value)
        elif key == "SourceName":
            ev["Provider_Name"] = CLASSIC_PROVIDERS.get(value, value)
    if "Channel" not in ev or "EventID" not in ev:
        return None
    section = ""
    last: str | None = None                  # the field a multi-line value (a script on a command line) continues
    blank = 0                                # blank lines inside a command line, kept when more of it follows
    for line in body[1:]:
        if not line.strip():
            if last == "CommandLine":
                blank += 1
            else:
                last = None
            continue
        if last == "CommandLine":
            if not _PROSE.match(line):       # the command line is the last field of 4688: every line up to the
                ev[last] += "\n" * (blank + 1) + line.rstrip()   # paragraph after it is part of it, blank ones too
                blank = 0
                continue
            last = None
        blank = 0
        head = _SECTION.match(line)
        if head and head.group(1) in CLASSIC_FIELDS[""] and head.group(1) not in CLASSIC_FIELDS:
            head = None                      # a label left empty ("Service Account:"), not a section header
        m = None if head else _LABEL.match(line)
        if head:
            section, last = head.group(1), None
            continue
        if not m:
            if last:                         # the next line of the value: the message keeps its line breaks
                ev[last] += "\n" + line.rstrip()
            continue
        if not m.group(1):                   # a label at the left margin belongs to no section
            section = ""
        name = (CLASSIC_FIELDS.get(section) or {}).get(m.group(2)) or (CLASSIC_FIELDS[""].get(m.group(2)) if not section else None)
        last = None
        if name and name not in ev:
            ev[name] = m.group(3).strip()
            last = name
    cleared = _CLEARED.search(body[0]) if body else None
    if cleared and ev.get("EventID") == 104:
        ev["Channel_Cleared"] = cleared.group(1)
    return ev


def classic_records(text: str) -> Iterator[Record]:
    """Every event of a classic export, in file order. An export can also carry XML events on lines
    of their own (Splunk's XmlWinEventLog beside WinEventLog): those are read with the XML reader."""
    marks = sorted([(m.start(), m.end(), "xml") for m in EVENT_RE.finditer(text)]
                   + [(m.start(), -1, "classic") for m in CLASSIC_START.finditer(text)])
    for n, (start, end, kind) in enumerate(marks, 1):
        if kind == "xml":
            chunk = text[start:end]
            yield n, _sha(chunk), xml_event(chunk)
            continue
        stop = marks[n][0] if n < len(marks) else len(text)
        chunk = text[start:stop].rstrip("\r\n")
        yield n, _sha(chunk), classic_event(chunk)


def text_records(fmt: str, text: str) -> Iterator[Record]:
    if fmt == "windows-classic":
        yield from classic_records(text)
        return
    if fmt == "windows-xml":
        for n, m in enumerate(EVENT_RE.finditer(text), 1):
            yield n, _sha(m.group(0)), xml_event(m.group(0))
        return
    n = 0
    for line in text.splitlines():
        if line.strip():
            n += 1
            yield n, _sha(line.strip()), json_event(line)


def zip_records(ds: Dataset, path: Path) -> Iterator[Record]:
    """The member's records, read line by line without extracting it; its SHA-256 is checked at the end.
    An EVTX member is checked first, then read from a temporary copy (the EVTX reader needs a file)."""
    with zipfile.ZipFile(path) as zf:
        try:
            info = zf.getinfo(str(ds.member))
        except KeyError as e:
            raise RunError(f"{ds.id}: {ds.member} is not in {Path(ds.path).name}") from e
        if info.file_size > MAX_DOWNLOAD * 2:
            raise RunError(f"{ds.id}: {ds.member} unpacks to {info.file_size} bytes, more than RASD reads")
        h = hashlib.sha256()
        n = 0
        if ds.format == "evtx":
            data = zf.read(info)
            if hashlib.sha256(data).hexdigest() != ds.member_sha256:
                raise RunError(f"{ds.id}: {ds.member} has SHA-256 {hashlib.sha256(data).hexdigest()[:12]}…, "
                               f"the catalog says {str(ds.member_sha256)[:12]}…")
            with tempfile.TemporaryDirectory(prefix="rasd-evtx-") as tmp:
                member = Path(tmp) / "member.evtx"
                member.write_bytes(data)
                yield from evtx_records(member)
            return
        with zf.open(info) as fh:
            if ds.format == "windows-xml":
                data = fh.read()
                h.update(data)
                yield from text_records(ds.format, data.decode("utf-8-sig", errors="replace"))
            else:
                for raw in fh:
                    h.update(raw)
                    line = raw.decode("utf-8", errors="replace").strip().lstrip("\ufeff")
                    if line:
                        n += 1
                        yield n, _sha(line), json_event(line)
        if h.hexdigest() != ds.member_sha256:
            raise RunError(f"{ds.id}: {ds.member} has SHA-256 {h.hexdigest()[:12]}…, the catalog says {str(ds.member_sha256)[:12]}…")


def windows_hex(nodes: Any) -> None:
    """python-evtx renders HexInt32 and HexInt64 values with every byte ('0x001fffff', '0x00000017',
    '0x00000018'); Windows renders them without leading zeros ('0x1fffff', '0x17', '0x18'), and so
    does every pipeline fed from Windows (event forwarding, Splunk, NXLog, Winlogbeat). The rules
    are written for what a SIEM receives, so the EVTX reader renders hex values the Windows way."""
    def render(self: Any) -> str:
        return hex(int.from_bytes(bytes(self.hex()), "little"))
    for name in ("Hex32TypeNode", "Hex64TypeNode"):
        cls = getattr(nodes, name, None)
        if cls is None:
            raise RunError(f"this python-evtx has no {name}: the hex rendering cannot be matched to Windows")
        cls.string = render


def evtx_available() -> bool:
    try:
        import Evtx.Evtx  # noqa: F401
    except ImportError:
        return False
    return True


def evtx_records(path: Path) -> Iterator[Record]:
    try:
        from Evtx import Nodes        # optional: python-evtx, only for the EVTX sources
        from Evtx.Evtx import Evtx
    except ImportError as e:
        raise RunError("EVTX files need python-evtx: pip install python-evtx") from e
    windows_hex(Nodes)
    with Evtx(str(path)) as log:
        for rec in log.records():
            try:
                text = rec.xml()
            except Exception:           # a damaged record counts as unparsed; the rest of the file is still read
                yield rec.record_num(), "", None
                continue
            yield rec.record_num(), _sha(text), xml_event(text)


def records(ds: Dataset, cache: Path) -> Iterator[Record]:
    """Every record of a cached dataset file, after its SHA-256 matched the catalog."""
    path = ds.cached(cache)
    if not path.exists():
        raise RunError(f"{ds.id}: not downloaded - run: rasd datasets fetch --only {ds.id}")
    digest = sha256_file(path)
    if digest != ds.sha256:
        raise RunError(f"{ds.id}: SHA-256 {digest[:12]}… does not match the catalog ({ds.sha256[:12]}…) - fetch it again")
    if ds.member:
        yield from zip_records(ds, path)
    elif ds.format == "evtx":
        yield from evtx_records(path)
    else:
        yield from text_records(ds.format, read_text(path))


# --------------------------------------------------------------------------- #
# fetch
# --------------------------------------------------------------------------- #
def http_fetch(url: str, dest: Path, limit: int, attempts: int = 4) -> None:
    """Download over https into dest, at most `limit` bytes. A transfer cut off midway (it happens to
    large files behind proxies) resumes from where it stopped with a Range request; the caller checks
    the SHA-256 of the result against the catalog either way."""
    if not url.startswith("https://"):
        raise RunError(f"refusing a non-https URL: {url}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    part.unlink(missing_ok=True)
    for attempt in range(attempts):
        have = part.stat().st_size if part.exists() else 0
        headers = {"User-Agent": f"rasd/{VERSION}", **({"Range": f"bytes={have}-"} if have else {})}
        req = urllib.request.Request(url, headers=headers)  # noqa: S310 - https checked above, URL from the catalog
        try:
            with urllib.request.urlopen(req, timeout=600) as resp:  # noqa: S310 - https checked above
                resumed = have and resp.status == 206
                total = have if resumed else 0
                with part.open("ab" if resumed else "wb") as out:
                    for chunk in iter(lambda: resp.read(1 << 20), b""):
                        total += len(chunk)
                        if total > limit:
                            raise RunError(f"{url}: larger than the catalog says ({limit} bytes); stopped")
                        out.write(chunk)
            part.replace(dest)
            return
        except (OSError, http.client.HTTPException) as e:          # a reset or a short read: resume
            if attempt == attempts - 1:
                raise RunError(f"{url}: the transfer stopped {attempts} times ({e})") from e


def git_fetch(src: Source, wanted: list[Dataset], cache: Path) -> None:
    """Check the files out of the pinned commit with a blob-less fetch: for hosts where the raw
    download URL is blocked but git works. Not for files in Git LFS (git would give the pointers)."""
    lfs = [ds.id for ds in wanted if ds.in_lfs]
    if lfs:
        raise RunError(f"{', '.join(lfs[:3])}: kept in Git LFS, git would return pointers - use the https download")
    git = shutil.which("git")
    if not git:
        raise RunError("git is not installed")
    work = cache / "_git" / src.id
    run = lambda *a: subprocess.run([git, "-C", str(work), *a], check=True, capture_output=True, text=True,
                                    env={**os.environ, "GIT_LFS_SKIP_SMUDGE": "1", "GIT_TERMINAL_PROMPT": "0"})
    if not (work / ".git").exists():
        work.mkdir(parents=True, exist_ok=True)
        run("init", "-q")
        run("remote", "add", "origin", src.repo)
    run("fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", src.commit)
    run("checkout", "-q", src.commit, "--", *[ds.path for ds in wanted])
    for ds in wanted:
        dest = ds.cached(cache)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(work / ds.path, dest)


def fetch(cat: Catalog, cache: Path, only: str | None, use_git: bool) -> int:
    todo: dict[str, list[Dataset]] = defaultdict(list)
    have = bad = 0
    for ds in cat.datasets:
        if not ds.matches(only):
            continue
        path = ds.cached(cache)
        if path.exists() and sha256_file(path) == ds.sha256:
            have += 1
            continue
        todo[ds.source.id].append(ds)
    for sid, items in todo.items():
        src = cat.sources[sid]
        by_git = [ds for ds in items if use_git and not ds.in_lfs]
        if by_git:
            try:
                git_fetch(src, by_git, cache)
            except (subprocess.CalledProcessError, RunError) as e:
                print(f"  {RED}✗{RESET} {sid}: git fetch failed: {getattr(e, 'stderr', '') or e}")
        for ds in items:
            if ds in by_git:
                continue
            if not ds.url:
                print(f"  {RED}✗{RESET} {ds.id}: the source has no download URL; use --git")
                continue
            try:
                http_fetch(ds.url, ds.cached(cache), ds.size)
            except (urllib.error.URLError, OSError, RunError) as e:
                print(f"  {RED}✗{RESET} {ds.id}: {e}" + ("" if ds.in_lfs else " (try --git)"))
        for ds in items:
            path = ds.cached(cache)
            ok = path.exists() and sha256_file(path) == ds.sha256
            if not ok and path.exists():
                path.unlink()
            bad += not ok
            print(f"  {GREEN + '✓' if ok else RED + '✗'}{RESET} {ds.id} {DIM}{ds.size:,} bytes{RESET}"
                  + ("" if ok else f" {RED}SHA-256 does not match the catalog: removed{RESET}" if path.exists() else ""))
    print(f"\n{have} already cached and verified, {sum(len(v) for v in todo.values()) - bad} downloaded and verified, "
          f"{bad} failed · {cache}")
    return 1 if bad else 0


# --------------------------------------------------------------------------- #
# the run
# --------------------------------------------------------------------------- #
@dataclass
class Tuning:
    owner: str
    id: str
    kind: str                       # filter | exception
    selection: str
    fields: list[str]
    variant: Callable[[dict], bool]


@dataclass
class Plan:
    """Every rule compiled once, with its tuning variants, by log source."""
    rules: dict[str, list[tuple[str, Callable[[dict], bool]]]]
    bases: dict[str, list[tuple[Correlation, Callable[[dict], bool]]]]
    tunings: dict[str, list[Tuning]]
    corrs: list[Correlation]
    keep: set[str]
    titles: dict[str, Any]


def _safe(fn: Callable[[dict], bool], ev: dict) -> bool:
    try:
        return bool(fn(ev))
    except (SigmaError, TypeError, ValueError):
        return False


def tuning_variants(owner: str, rule: dict, folder: Path) -> list[Tuning]:
    """Each applied tuning of a rule as a compiled variant without it: a filter's variant shows
    what the filter keeps quiet, an exception's variant what the exception takes back."""
    out = []
    for t in _yaml(folder / "tuning.yml").get("tunings") or []:
        sel = t.get("selection")
        if t.get("status") != "applied" or sel not in rule.get("detection", {}):
            continue
        variant = copy.deepcopy(rule)
        variant["detection"][sel] = dict(NEVER)
        out.append(Tuning(owner, str(t.get("id")), "exception" if t.get("kind") == "exception" else "filter", sel,
                          referenced_fields({sel: rule["detection"][sel]}), compile_rule(variant)))
    return out


def build_plan() -> Plan:
    dets, corrs = load_detections(), load_correlations()
    rules: dict[str, list] = defaultdict(list)
    bases: dict[str, list] = defaultdict(list)
    tunings: dict[str, list[Tuning]] = defaultdict(list)
    for d in dets:
        src = logsource_key(d.rule)
        rules[src].append((d.id, compile_rule(d.rule)))
        tunings[src] += tuning_variants(d.id, d.rule, d.folder)
    for c in corrs:
        src = logsource_key(c.base)
        bases[src].append((c, compile_rule(c.base)))
        tunings[src] += tuning_variants(c.id, c.base, c.folder)
    keep = set(CONTEXT) | set(HOST_FIELDS) | set(USER_FIELDS) | set(TIME_FIELDS)
    for _src, (_ids, fields) in profiles.rule_reads().items():
        keep |= set(fields)
    for c in corrs:
        keep |= set(c.params.reads())
    return Plan(dict(rules), dict(bases), dict(tunings), corrs, keep, {**{d.id: d for d in dets}, **{c.id: c for c in corrs}})


def profile_sources(name: str) -> set[str]:
    """The source field names a profile reads, which an extract keeps so the profile still applies."""
    prof = profiles.load(name)
    if not prof:
        return set()
    out: set[str] = set()

    def walk(cands) -> None:
        for c in cands or []:
            if isinstance(c, str):
                out.add(c.split(".")[0])
            elif isinstance(c, dict):
                out.update(str(x).split(".")[0] for x in (c.get("join") or c.get("path") or []))
    spec = prof.get("event") or {}
    walk(spec.get("Channel"))
    walk(spec.get("EventID"))
    for rule in spec.get("infer") or []:
        out.update(str(k).split(".")[0] for k in (rule.get("when") or {}))
    for section in (prof.get("fields") or {}).values():
        for cands in (section or {}).values():
            walk(cands)
    return out


@dataclass
class Hit:
    record: int
    sha: str
    raw: dict
    ev: dict
    fires: list[str]
    counts: list[str] = field(default_factory=list)
    seen_in: str | None = None             # an earlier file of the catalog that holds the same record
    also: list[str] = field(default_factory=list)   # fired detections whose alert here an `also` entry's where explains


SAME_RECORD = 1.0       # seconds: one record number on one host and channel within a second is one record


@dataclass
class Ledger:
    """Every record already read in this run, by identity: the file it was first read in, its time
    and a prefix of its content hash, so a record found again - copied, or copied with a field
    edited, even with its time nudged - is recognised and counted once."""
    ids: list[str] = field(default_factory=list)
    seen: dict[int, list[tuple[int, float | None, int]]] = field(default_factory=dict)


def record_identity(raw: dict, sha: str) -> tuple[int, float | None]:
    """The record as Windows numbered it - host, channel and record number - with its time, or its
    SHA-256 when it carries no number. Two records with one number less than SAME_RECORD apart are
    one record, even when a field differs or the time was nudged by a few nanoseconds; further apart,
    the number was reused (logs that were cleared or rolled over)."""
    num = raw.get("EventRecordID", raw.get("RecordNumber"))
    host = raw.get("Computer") or raw.get("Hostname")
    when: float | None = None
    if num in (None, "") or not host:
        text = "sha:" + sha
    else:
        text = f"{str(host).lower()}|{str(raw.get('Channel', '')).lower()}|{num}"
        t = parse_time({"TimeCreated": raw.get("TimeCreated") or raw.get("@timestamp") or raw.get("EventTime")
                        or raw.get("UtcTime") or ""})
        when = epoch(t) if t is not None else None
    return int.from_bytes(hashlib.blake2b(text.encode("utf-8", "surrogatepass"), digest_size=8).digest(), "big"), when


def _near(a: float | None, b: float | None) -> bool:
    return a is None or b is None or abs(a - b) < SAME_RECORD


def verdicts(ev: dict, plan: Plan) -> tuple:
    """Everything an event decides: its route, the rules it fires, the correlations that count it and
    with which group and value, and its time."""
    src = route(ev)
    fires = tuple(rid for rid, fn in plan.rules.get(src or "", ()) if _safe(fn, ev))
    counted = []
    for c, fn in plan.bases.get(src or "", ()):
        if _safe(fn, ev):
            read, p = value_reader(c.params), c.params
            counted.append((c.id, tuple(read(ev, g) for g in p.group_by), read(ev, p.counted) if p.counted else None))
    t = parse_time(ev)
    return src, fires, tuple(counted), t.isoformat() if t else None


def _top(counter: Counter, n: int = 8) -> list[list]:
    return [[v, c] for v, c in counter.most_common(n)]


def _iso(t: datetime | None) -> str | None:
    return iso(t) if t else None


def run_dataset(ds: Dataset, plan: Plan, cache: Path, ledger: Ledger | None = None) -> tuple[dict, list[Hit]]:
    """Stream one dataset through every rule: counts, alerts, correlation windows, tuning effects,
    and the events to keep (every one that fired, and every one a firing correlation window counted).
    A record read twice in the file is read once; with a ledger, a record an earlier file already
    held still runs, but its alert is not counted as new evidence."""
    prof = profiles.load(ds.profile)
    routed: Counter = Counter()
    events = unparsed = duplicates = edited = 0
    lo: datetime | None = None
    hi: datetime | None = None
    alerts: dict[str, list[tuple[datetime | None, str, int, bool, bool]]] = defaultdict(list)
    hits: dict[int, Hit] = {}
    base_hits: dict[str, list[Hit]] = defaultdict(list)
    tuned: dict[tuple[str, str], dict] = {}
    mine: dict[int, list[tuple[float | None, int]]] = {}
    shared: dict[int, list[int]] = defaultdict(lambda: [0, 0])
    for rec, sha, raw in records(ds, cache):
        if raw is None:
            unparsed += 1
            continue
        events += 1
        (key, when), content = record_identity(raw, sha), int(sha[:16], 16)
        twin = next((c for t0, c in mine.get(key, ()) if _near(t0, when)), None)
        if twin is not None:                             # the same record twice in one file: read once
            duplicates += 1
            edited += twin != content
            continue
        mine.setdefault(key, []).append((when, content))
        seen_in = None
        if ledger is not None:
            before = next(((i, c) for i, t0, c in ledger.seen.get(key, ()) if _near(t0, when)), None)
            if before is not None:
                seen_in = ledger.ids[before[0]]
                shared[before[0]][0 if before[1] == content else 1] += 1
        ev = profiles.normalize(raw, prof)
        t = parse_time(ev)
        if t is not None:
            lo, hi = (t if lo is None or t < lo else lo), (t if hi is None or t > hi else hi)
        src = route(ev)
        if not src:
            continue
        routed[src] += 1
        fires = [rid for rid, fn in plan.rules.get(src, ()) if _safe(fn, ev)]
        counted = [c.id for c, fn in plan.bases.get(src, ()) if _safe(fn, ev)]
        for tu in plan.tunings.get(src, ()):
            on = tu.owner in fires or tu.owner in counted
            hit = (_safe(tu.variant, ev) and not on) if tu.kind == "filter" else (on and not _safe(tu.variant, ev))
            if hit:
                slot = tuned.setdefault((tu.owner, tu.id), {"kind": tu.kind, "events": 0,
                                                            "values": {f: Counter() for f in tu.fields}})
                slot["events"] += 1
                for f in tu.fields:
                    v = ev.get(f)
                    if v not in (None, ""):
                        slot["values"][f][str(v)[:160]] += 1
        if fires or counted:
            h = Hit(rec, sha, raw, ev, fires, seen_in=seen_in, also=also_of(ev, fires, ds))
            if fires:
                hits[rec] = h
                for rid in fires:
                    alerts[rid].append((t, first(ev, HOST_FIELDS), rec, seen_in is None, rid in h.also))
            for cid in counted:
                base_hits[cid].append(h)
    if ledger is not None:
        index = len(ledger.ids)
        ledger.ids.append(ds.id)
        for key, entries in mine.items():
            ledger.seen.setdefault(key, []).extend((index, when, content) for when, content in entries)
    # field values (hosts, correlation groups, tuned values) are quoted only from files whose license allows
    # redistribution; from the others results.json keeps counts, times and record numbers
    quote = ds.source.redistribute
    windows: dict[str, list[dict]] = {}
    for c in plan.corrs:
        cand = base_hits.get(c.id) or []
        if not cand:
            continue
        fn = {x.id: f for x, f in plan.bases[logsource_key(c.base)]}[c.id]
        found = evaluate(c, [h.ev for h in cand], base_fn=fn)
        if not found:
            continue
        p, read = c.params, value_reader(c.params)
        keys = {(epoch(a["window_start"]), tuple(a["group"].values())) for a in found}
        fresh: dict[tuple, bool] = {}
        for h in cand:
            t = parse_time(h.ev)
            if t is None:
                continue
            group = tuple(read(h.ev, g) for g in p.group_by)
            start = math.floor(epoch(t) / p.timespan) * p.timespan
            if (start, group) in keys and (not p.counted or read(h.ev, p.counted) is not None):
                h.counts.append(c.id)
                hits[h.record] = h
                fresh[(start, group)] = fresh.get((start, group), False) or h.seen_in is None
        windows[c.id] = [{"window_start": iso(a["window_start"]), **({"group": a["group"]} if quote else {}),
                          "metric": a["metric"], "events": a["event_count"], "crossed_at": iso(a["crossed_at"]),
                          "unique": fresh.get((epoch(a["window_start"]), tuple(a["group"].values())), False)}
                         for a in found]
    result: dict[str, Any] = {
        "sha256": ds.sha256, "events": events, "unparsed": unparsed, "duplicates": duplicates, "duplicates_edited": edited,
        "overlap": {ledger.ids[i]: {"same": n[0], "edited": n[1]} for i, n in sorted(shared.items())} if ledger else {},
        "routed": dict(sorted(routed.items())),
        "start": _iso(lo), "end": _iso(hi),
        "alerts": {rid: {"count": len(rows), "unique": sum(1 for r in rows if r[3]),
                         "first": _iso(min((r[0] for r in rows if r[0]), default=None)),
                         "last": _iso(max((r[0] for r in rows if r[0]), default=None)),
                         "hosts": [h for h, _ in Counter(r[1] for r in rows).most_common(3)] if quote else [],
                         "records": sorted(r[2] for r in rows)[:5],
                         **({"also": {"count": sum(1 for r in rows if r[4]), "unique": sum(1 for r in rows if r[3] and r[4])},
                             "attack": _alert_span([r for r in rows if not r[4]], quote)}
                            if ds.explained(rid) else {})}
                   for rid, rows in sorted(alerts.items())},
        "correlations": dict(sorted(windows.items())),
        "tuning": {},
    }
    for (owner, tid), slot in sorted(tuned.items()):
        result["tuning"].setdefault(owner, {})[tid] = {"kind": slot["kind"], "events": slot["events"],
                                                       "values": {f: _top(cnt) for f, cnt in slot["values"].items() if cnt and quote}}
    return result, sorted(hits.values(), key=lambda h: h.record)


def _alert_span(rows: list[tuple], quote: bool) -> dict:
    """First and last time, hosts and first records of some alerts: those of the recorded attack when an
    `also` entry's where takes the harness alerts out."""
    return {"first": _iso(min((r[0] for r in rows if r[0]), default=None)),
            "last": _iso(max((r[0] for r in rows if r[0]), default=None)),
            "hosts": [h for h, _ in Counter(r[1] for r in rows).most_common(3)] if quote else [],
            "records": sorted(r[2] for r in rows)[:5]}


def quoted_values(result: dict) -> list[str]:
    """What a recorded result quotes from the file itself: host names, correlation groups, tuned values."""
    out = [f"the hosts of {rid}" for rid, a in (result.get("alerts") or {}).items()
           if a.get("hosts") or (a.get("attack") or {}).get("hosts")]
    out += [f"the groups of {cid}" for cid, ws in (result.get("correlations") or {}).items() if any("group" in w for w in ws)]
    out += [f"the values of {tid}" for ts in (result.get("tuning") or {}).values() for tid, t in ts.items() if t.get("values")]
    return out


ASSESSMENT = ("missed", "unexplained", "quiet_fired", "also_silent", "overlap_undeclared", "overlap_gone",
              "holdout_changed", "found_silent")


def assess(ds: Dataset, result: dict, ran: set[str] | None = None) -> dict[str, Any]:
    """The run against the catalog: missed, unexplained, a quiet rule that fired, a stale `also`, and
    records shared with an earlier file that the catalog does not declare (or a declared overlap
    that is gone). `ran` is the set of files read in this run: an overlap needs both files. An
    expected detection counts as fired only on alerts no `also` entry's where explains, and a
    detection with such an entry that is not expected must have no other alert."""
    fired = set(result["alerts"]) | set(result["correlations"])
    attack = {r for r in fired if _attack_count(result, r)}
    shared = set(result.get("overlap") or {})

    def unexplained(r: str) -> int:
        if r in ds.expect or r in ds.found or r in ds.quiet:
            return 0
        if r in ds.also:
            return _attack_count(result, r) if ds.explained(r) else 0
        return _fired_count(result, r)
    return {
        "missed": [r for r in ds.expect if r not in attack and r not in ds.missed],
        "unexplained": {r: n for r in sorted(fired) if (n := unexplained(r))},
        "quiet_fired": [r for r in ds.quiet if r in attack and r not in ds.found],
        "also_silent": [r for r in ds.also if not (_also_part(result, r)[0] if ds.explained(r) else r in fired)],
        "overlap_undeclared": sorted(shared - set(ds.overlap)),
        "overlap_gone": sorted(x for x in ds.overlap if x not in shared and (ran is None or x in ran)),
        "holdout_changed": [r for r in ds.missed if r in attack],         # a held-out miss now fires: a rule changed
        "found_silent": [r for r in ds.found if r not in fired],
    }


def _fired_count(result: dict, rid: str) -> int:
    if rid in result["alerts"]:
        return int(result["alerts"][rid]["count"])
    return len(result["correlations"].get(rid) or [])


def _unique_count(result: dict, rid: str) -> int:
    """Alerts (or correlation windows) on records no earlier file of the catalog holds: new evidence."""
    if rid in result.get("alerts", {}):
        return int(result["alerts"][rid].get("unique", result["alerts"][rid]["count"]))
    return sum(1 for w in result.get("correlations", {}).get(rid) or [] if w.get("unique", True))


def _also_part(result: dict, rid: str) -> tuple[int, int]:
    """The alerts of a detection that an `also` entry's where explains: all of them, and those on new records."""
    part = ((result.get("alerts") or {}).get(rid) or {}).get("also") or {}
    return int(part.get("count", 0)), int(part.get("unique", 0))


def _attack_count(result: dict, rid: str) -> int:
    """Alerts (or windows) that no `also` entry's where explains."""
    return _fired_count(result, rid) - _also_part(result, rid)[0] if result else 0


def _attack_unique(result: dict, rid: str) -> int:
    """Of those, the ones on records no earlier file of the catalog holds: new evidence of the recorded attack."""
    return _unique_count(result, rid) - _also_part(result, rid)[1] if result else 0


def _also_unique(result: dict, rid: str, entry: dict) -> int:
    """New-record alerts an `also` entry explains: those its where selects, or all the detection's alerts."""
    if not result:
        return 0
    return _also_part(result, rid)[1] if entry.get("where") else _unique_count(result, rid)


# --------------------------------------------------------------------------- #
# extracts
# --------------------------------------------------------------------------- #
def cut(value: Any) -> Any:
    if isinstance(value, str) and len(value) > CUT:
        return f"{value[:200]} …[{len(value) - 260} characters cut]… {value[-60:]}"
    return value


def extract_line(h: Hit, keep: set[str], plan: Plan, prof: dict | None, ds: Dataset | None = None) -> dict:
    """The event reduced to the fields the rules, the profile and the catalog's `where` selectors read,
    long values cut, checked to decide exactly what the full event decided - and to fall under the
    same `also` entries; a value that cannot be cut without changing a verdict is kept whole."""
    sel_fields = {f for e in (ds.also.values() if ds else ()) for f in (e.get("where") or {})}
    reduced = {k: v for k, v in h.raw.items() if k in keep or k in sel_fields}

    def decides(raw: dict) -> tuple:
        ev = profiles.normalize(raw, prof)
        got = verdicts(ev, plan)
        return got, tuple(also_of(ev, list(got[1]), ds)) if ds else ()
    want = (verdicts(h.ev, plan), tuple(h.also))
    if decides(reduced) != want:
        missing = sorted(set(h.raw) - keep)
        raise RunError(f"record {h.record}: the reduced event decides differently - a field the rules read is not kept "
                       f"(dropped: {', '.join(missing[:8])})")
    out = dict(reduced)
    for k in list(out):
        trial = {**out, k: cut(out[k])}
        if trial[k] != out[k] and decides(trial) == want:
            out = trial
    meta: dict[str, Any] = {"record": h.record, "sha256": h.sha, "fires": h.fires, "counts": sorted(set(h.counts))}
    if h.also:
        meta["also"] = h.also              # alerts here that the catalog's also entry explains, not the recorded attack
    if h.seen_in:
        meta["seen_in"] = h.seen_in        # an earlier file holds this record: its alert is not new evidence
    return {"_rasd": meta, **out}


def read_extract(path: Path) -> list[dict]:
    out = []
    for n, line in enumerate(read_text(path).splitlines(), 1):
        if line.strip():
            try:
                row = json.loads(line)
            except ValueError as e:
                raise RunError(f"{path.relative_to(ROOT)}:{n}: invalid JSON ({e})") from e
            if not isinstance(row, dict) or not isinstance(row.get("_rasd"), dict):
                raise RunError(f"{path.relative_to(ROOT)}:{n}: not an extract record")
            out.append(row)
    return out


def replay_extract(ds: Dataset, rows: list[dict], plan: Plan) -> dict[str, Any]:
    """What the rules decide on a committed extract: alerts per rule, correlation windows, and the
    records whose verdict differs from the one recorded beside them."""
    prof = profiles.load(ds.profile)
    alerts: Counter = Counter()
    explained: dict[str, Counter] = defaultdict(Counter)
    drift: list[str] = []
    counted: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        meta = row["_rasd"]
        ev = profiles.normalize({k: v for k, v in row.items() if k != "_rasd"}, prof)
        _src, fires, bases, _t = verdicts(ev, plan)
        if sorted(fires) != sorted(meta.get("fires") or []):
            drift.append(f"record {meta.get('record')}: fires {sorted(fires) or 'nothing'}, recorded {meta.get('fires') or 'nothing'}")
        part = also_of(ev, list(fires), ds)
        if part != sorted(meta.get("also") or []):
            drift.append(f"record {meta.get('record')}: explained by also {part or 'nothing'}, recorded {meta.get('also') or 'nothing'}")
        for rid in part:
            explained[rid]["count"] += 1
            explained[rid]["unique"] += not meta.get("seen_in")
        for rid in fires:
            alerts[rid] += 1
        for cid, _g, _v in bases:
            counted[cid].append(ev)
    windows = {}
    for c in plan.corrs:
        if counted.get(c.id):
            found = evaluate(c, counted[c.id])
            if found:
                windows[c.id] = [{"window_start": iso(a["window_start"]), "group": a["group"], "metric": a["metric"]}
                                 for a in found]
    return {"alerts": dict(alerts), "windows": windows, "drift": drift,
            "also": {rid: {"count": c["count"], "unique": c["unique"]} for rid, c in explained.items()}}


# --------------------------------------------------------------------------- #
# run, write, check
# --------------------------------------------------------------------------- #
def run_all(cat: Catalog, cache: Path, only: str | None, verbose: bool, write: bool, case_dir: str | None) -> int:
    if cat.errors:
        for e in cat.errors:
            print(f"  {RED}✗{RESET} {e}")
        return 1
    plan = build_plan()
    results: dict[str, dict] = {}
    extracts: dict[str, list[dict]] = {}
    problems = 0
    chosen = [ds for ds in cat.datasets if ds.matches(only)]
    print(f"{BOLD}Public datasets · every detection and correlation over {len(chosen)} pinned files{RESET}\n")
    skipped: list[str] = []
    ledger = Ledger()
    ran = {ds.id for ds in chosen if ds.format != "evtx" or evtx_available()}
    for ds in chosen:
        if ds.format == "evtx" and not evtx_available():
            skipped.append(ds.id)
            continue
        try:
            result, hits = run_dataset(ds, plan, cache, ledger)
            if ds.extract is not None:
                keep = plan.keep | profile_sources(ds.profile)
                prof = profiles.load(ds.profile)
                extracts[ds.id] = [extract_line(h, keep, plan, prof, ds) for h in hits]
                result["extract"] = {"file": str(ds.extract.relative_to(ROOT)), "events": len(hits)}
            else:
                result["extract"] = None
        except RunError as e:
            print(f"  {RED}✗{RESET} {ds.id}: {e}")
            problems += 1
            continue
        a = assess(ds, result, ran)
        result["assessment"] = a
        results[ds.id] = result
        bad = any(a[k] for k in ASSESSMENT)
        problems += bad
        fired = ", ".join(f"{r} {_fired_count(result, r)}" for r in sorted(set(result["alerts"]) | set(result["correlations"])))
        print(f"  {RED + '✗' if bad else GREEN + '✓'}{RESET} {ds.id} {DIM}{result['events']:,} events · "
              f"{sum(result['routed'].values()):,} routed{RESET}" + (f" · {fired}" if fired else f" · {DIM}no alert{RESET}"))
        for label, key in (("expected, did not fire", "missed"), ("fired, not explained in the catalog", "unexplained"),
                           ("listed quiet, but fired", "quiet_fired"), ("listed under also, did not fire", "also_silent"),
                           ("holds records of an earlier file, not declared under overlap", "overlap_undeclared"),
                           ("declared overlap, but no record is shared", "overlap_gone"),
                           ("held-out miss now fires - a rule changed after the held-out run: take the file out of the "
                            "held-out set and list the rule under changed_after_replay", "holdout_changed"),
                           ("listed under found, did not fire", "found_silent")):
            if a[key]:
                print(f"      {RED}{label}: {', '.join(a[key])}{RESET}")
        if result["duplicates"]:
            edits = f" ({result['duplicates_edited']} with a field edited)" if result["duplicates_edited"] else ""
            print(f"      {DIM}{result['duplicates']} record(s) read twice in the file{edits}, counted once{RESET}")
        for other, n in result["overlap"].items():
            print(f"      {DIM}shares {n['same']} record(s) with {other}" + (f" and {n['edited']} with a field edited" if n["edited"] else "")
                  + f": alerts on them are not new evidence{RESET}")
        if result["unparsed"]:
            print(f"      {YELLOW}{result['unparsed']} records could not be parsed{RESET}")
        if verbose:
            for rid, info in result["alerts"].items():
                where = f" on {', '.join(info['hosts'])}" if info["hosts"] else ""
                print(f"      {DIM}{rid}: first {info['first']}{where} · records {info['records']}{RESET}")
            for owner, ts in result["tuning"].items():
                for tid, t in ts.items():
                    vals = "; ".join(f"{f}: " + ", ".join(f"{v} ×{c}" for v, c in rows[:3]) for f, rows in t["values"].items())
                    print(f"      {DIM}{owner} {t['kind']} {tid}: {t['events']} events · {vals[:240]}{RESET}")
        if case_dir and hits:
            _cases(ds, hits, plan, Path(case_dir))
    if skipped:
        print(f"  {YELLOW}{len(skipped)} EVTX file(s) not read: pip install python-evtx (or pip install -e .[datasets]){RESET}")
    validated = sorted({r for ds in chosen for r in ds.expect if ds.id in results and r not in results[ds.id]["assessment"]["missed"]})
    total = len({r for ds in chosen for r in ds.expect}) if only else len(plan.titles)
    print(f"\n{BOLD}{len(validated)}/{total} detections fire on the public data that records their behaviour · "
          f"{len(results)}/{len(chosen)} datasets read · "
          f"{GREEN + '0 problems' if not problems else RED + f'{problems} problem(s)'}{RESET}")
    if write:
        if only:
            print(f"{RED}--write needs the whole catalog: run without --only{RESET}")
            return 1
        if problems or skipped:
            print(f"{RED}nothing written: every file must be read and match the catalog first{RESET}")
            return 1
        leaks = leak_scan(cat, cache)
        if leaks:
            for line in leaks[:20]:
                print(f"  {RED}✗{RESET} {line}")
            print(f"{RED}nothing written: {len(leaks)} value(s) from files that cannot be redistributed are in the repository"
                  f"{RESET}")
            return 1
        print(f"{GREEN}✓{RESET} leak scan: no value distinctive of a file that cannot be redistributed is in the repository")
        write_results(cat, results, extracts)
    return 1 if problems else 0


def _cases(ds: Dataset, hits: list[Hit], plan: Plan, case_dir: Path) -> None:
    """Replay case folders for one dataset, from the events that fired or were counted."""
    import replay
    alerts, _stats = replay.replay([h.ev for h in hits], load_detections(), {}, corrs=plan.corrs)
    stories = replay.storylines(alerts, 60)
    rules: dict[str, Any] = {d.id: d for d in load_detections()}
    rules.update({c.id: c for c in plan.corrs})
    replay.write_cases(case_dir / ds.id, stories, rules, [ds.link])


def write_results(cat: Catalog, results: dict[str, dict], extracts: dict[str, list[dict]]) -> None:
    doc = {"format": 1, "rasd": VERSION, "fingerprints": fingerprints(cat),
           "datasets": {ds.id: results[ds.id] for ds in cat.datasets}}
    RESULTS.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    wanted = set()
    for ds_id, rows in extracts.items():
        path = EXTRACTS / f"{ds_id}.jsonl"
        wanted.add(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
    for old in EXTRACTS.rglob("*.jsonl") if EXTRACTS.exists() else []:
        if old not in wanted:
            old.unlink()
    written = render(cat, doc)
    print(f"{GREEN}[+]{RESET} wrote {RESULTS.relative_to(ROOT)}, {len(wanted)} extracts and {written} pages")


def load_results() -> dict | None:
    return json.loads(RESULTS.read_text(encoding="utf-8")) if RESULTS.exists() else None


def check() -> list[str]:
    cat = load_catalog()
    problems = list(cat.errors)
    res = load_results()
    if res is None:
        return [*problems, "datasets/results.json is missing - run: rasd datasets fetch && rasd datasets run --write"]
    if res.get("format") != 1:
        problems.append("datasets/results.json: unknown format")
        return problems
    stale = stale_inputs(res.get("fingerprints") or {}, fingerprints(cat))
    if stale:
        problems.append(f"datasets/results.json was produced by other inputs ({', '.join(stale[:6])}"
                        f"{'…' if len(stale) > 6 else ''}) - run: rasd datasets fetch && rasd datasets run --write")
    recorded = res.get("datasets") or {}
    for ds in cat.datasets:
        if ds.id not in recorded:
            problems.append(f"{ds.id}: no result recorded")
    for did in recorded:
        if did not in {ds.id for ds in cat.datasets}:
            problems.append(f"{did}: recorded but not in the catalog")
    if problems:
        return problems
    plan = build_plan()
    order = {ds.id: n for n, ds in enumerate(cat.datasets)}
    for ds in cat.datasets:
        r = recorded[ds.id]
        a = r.get("assessment") or {}
        if any(a.get(k) for k in ASSESSMENT) or set(a) != set(ASSESSMENT):
            problems.append(f"{ds.id}: the recorded run does not match the catalog")
        quoted = [] if ds.source.redistribute else quoted_values(r)
        if quoted:
            problems.append(f"{ds.id}: results.json quotes {', '.join(quoted[:3])} from a source whose license does not "
                            "allow redistribution")
        if ds.extract is None:
            continue
        if not ds.extract.exists():
            problems.append(f"{ds.extract.relative_to(ROOT)} is missing")
            continue
        try:
            rows = read_extract(ds.extract)
        except RunError as e:
            problems.append(str(e))
            continue
        got = replay_extract(ds, rows, plan)
        problems += [f"{ds.id} {d}" for d in got["drift"][:5]]
        want_alerts = {rid: info["count"] for rid, info in r["alerts"].items()}
        if got["alerts"] != want_alerts:
            problems.append(f"{ds.id}: the extract fires {got['alerts']}, the full run recorded {want_alerts}")
        earlier = [row["_rasd"]["seen_in"] for row in rows if row["_rasd"].get("seen_in")]
        if any(order.get(x, len(order)) >= order[ds.id] for x in earlier):
            problems.append(f"{ds.id}: an extract record names a file that does not come earlier in the catalog")
        fresh = Counter(rid for row in rows if not row["_rasd"].get("seen_in") for rid in row["_rasd"].get("fires") or [])
        if dict(fresh) != {rid: info["unique"] for rid, info in r["alerts"].items() if info.get("unique")}:
            problems.append(f"{ds.id}: the extract's alerts on records no earlier file holds differ from results.json")
        want_also = {rid: info["also"] for rid, info in r["alerts"].items() if info.get("also", {}).get("count")}
        if got["also"] != want_also:
            problems.append(f"{ds.id}: the extract's alerts explained by also's where are {got['also']}, results.json says {want_also}")
        want_windows = {cid: [{k: w[k] for k in ("window_start", "group", "metric")} for w in ws]
                        for cid, ws in r["correlations"].items()}
        if got["windows"] != want_windows:
            problems.append(f"{ds.id}: the extract's correlation windows differ from the full run")
        if (r.get("extract") or {}).get("events") != len(rows):
            problems.append(f"{ds.id}: the extract holds {len(rows)} events, results.json says {(r.get('extract') or {}).get('events')}")
    for path, text in pages(cat, res).items():
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            problems.append(f"{path.relative_to(ROOT)} is stale - run: rasd build")
    for path in _page_files():
        if path not in pages(cat, res):
            problems.append(f"{path.relative_to(ROOT)} is no longer generated - delete it")
    return problems


def _page_files() -> list[Path]:
    return sorted([*DETECTIONS.glob(f"*/{PAGE}"), *(CORRELATIONS.glob(f"*/{PAGE}") if CORRELATIONS.exists() else [])])


def public_events() -> list[tuple[str, dict]]:
    """Every committed extract event, normalised with its dataset's profile: real attack telemetry for
    the parity corpus."""
    cat = load_catalog()
    out: list[tuple[str, dict]] = []
    for ds in cat.datasets:
        if ds.extract is None or not ds.extract.exists():
            continue
        prof = profiles.load(ds.profile)
        for row in read_extract(ds.extract):
            ev = profiles.normalize({k: v for k, v in row.items() if k != "_rasd"}, prof)
            out.append((f"public:{ds.id}#{row['_rasd'].get('record')}", ev))
    return out


# --------------------------------------------------------------------------- #
# summary and pages
# --------------------------------------------------------------------------- #
def _is_copy(result: dict) -> bool:
    """Every record of the file was already read in an earlier file of the catalog."""
    shared = sum(x.get("same", 0) + x.get("edited", 0) for x in (result.get("overlap") or {}).values())
    return bool(shared) and shared >= result.get("events", 0) - result.get("duplicates", 0)


def summary(cat: Catalog | None = None, res: dict | None = None) -> dict[str, dict]:
    """Per detection, over the catalog: the files that record its behaviour, the ones among them that
    add new evidence (an alert on a record no earlier file holds) and the alerts there; the files of
    its technique where it stays quiet, by kind; and its alerts on the other files by kind (benign,
    test harness, false positive). Every count is of records no earlier file of the catalog holds."""
    cat = cat or load_catalog()
    res = res if res is not None else (load_results() or {})
    recorded = res.get("datasets") or {}
    out: dict[str, dict] = {rid: {"expected": [], "fired": [], "independent": [], "copies": [], "alerts": 0, "quiet": [],
                                  "quiet_kinds": Counter(), "benign": 0, "harness": 0, "false_positives": 0,
                                  "fp_datasets": [], "sources": set(), "changed": cat.changed.get(rid),
                                  "holdout": {"expected": [], "met": [], "missed": [], "found": [], "quiet": [], "alerts": 0,
                                              "other": 0, "false_positives": 0}} for rid in known_ids()}
    for ds in cat.datasets:
        r = recorded.get(ds.id)
        if ds.holdout:                               # held out: counted on its own, never in the in-sample figures
            for rid in ds.expect:
                h = out[rid]["holdout"]
                if r and _attack_count(r, rid) and not _attack_unique(r, rid):
                    h.setdefault("copies", []).append(ds.id)   # fired, but only on records an earlier file holds
                    continue
                h["expected"].append(ds.id)
                if r and _attack_count(r, rid):
                    h["met"].append(ds.id)
                    h["alerts"] += _attack_unique(r, rid)
                else:
                    h["missed"].append(ds.id)
            for rid in ds.found:
                out[rid]["holdout"]["found"].append(ds.id)
            for rid in ds.quiet:
                out[rid]["holdout"]["quiet"].append(ds.id)
            for rid, a in ds.also.items():
                n = _also_unique(r, rid, a) if r else 0
                out[rid]["holdout"]["false_positives" if a.get("kind") == "false-positive" else "other"] += n
            continue
        for rid in ds.expect:
            v = out[rid]
            v["expected"].append(ds.id)
            if r and _attack_count(r, rid):
                v["fired"].append(ds.id)
                n = _attack_unique(r, rid)
                if n:
                    v["independent"].append(ds.id)
                    v["alerts"] += n
                    v["sources"].add(ds.source.id)
                else:
                    v["copies"].append(ds.id)
        for rid, q in ds.quiet.items():
            out[rid]["quiet"].append(ds.id)
            if not (r and _is_copy(r)):              # a file that only repeats an earlier one is not another recording
                out[rid]["quiet_kinds"][q["kind"]] += 1
        for rid, a in ds.also.items():
            n = _also_unique(r, rid, a) if r else 0
            if a.get("kind") == "false-positive":
                out[rid]["false_positives"] += n
                out[rid]["fp_datasets"].append(ds.id)
            else:
                out[rid]["harness" if a.get("kind") == "harness" else "benign"] += n
    for v in out.values():
        v["sources"] = sorted(v["sources"])
        v["validated"] = bool(v["independent"])
        v["recordings"] = len(v["independent"]) + sum(n for k, n in v["quiet_kinds"].items() if k != "negative")
    return out


def status_counts(cat: Catalog | None = None, res: dict | None = None) -> dict[str, int]:
    cat = cat or load_catalog()
    res = res if res is not None else (load_results() or {})
    s = summary(cat, res)
    recorded = res.get("datasets") or {}
    held = [v["holdout"] for v in s.values()]
    return {"validated": sum(1 for v in s.values() if v["validated"]), "total": len(s),
            "datasets": sum(1 for ds in cat.datasets if not ds.holdout), "holdout_files": sum(1 for ds in cat.datasets if ds.holdout),
            "holdout_expected": sum(len(h["expected"]) for h in held), "holdout_met": sum(len(h["met"]) for h in held),
            "holdout_found": sum(len(h["found"]) for h in held), "holdout_other": sum(h["other"] for h in held),
            "holdout_files_expecting": len({d for h in held for d in h["expected"]}),
            "holdout_detections": sum(1 for h in held if h["expected"]),
            "holdout_fp": sum(h["false_positives"] for h in held),
            "false_positives": sum(v["false_positives"] for v in s.values()), "benign": sum(v["benign"] for v in s.values()),
            "harness": sum(v["harness"] for v in s.values()), "alerts": sum(v["alerts"] for v in s.values()),
            "sources": len({x for v in s.values() for x in v["sources"]}),
            "duplicates": sum((r or {}).get("duplicates", 0) for r in recorded.values()),
            "overlapping": sum(1 for ds in cat.datasets if ds.overlap),
            "fired_on": sum(len(v["independent"]) for v in s.values()), "recordings": sum(v["recordings"] for v in s.values())}


QUIET_LABELS = {"gap": "need a rule RASD does not have yet", "scope": "outside the rule's scope",
                "blind-spot": "a documented blind spot", "telemetry": "without the event the rule reads",
                "negative": "do not hold the behaviour"}


def quiet_phrase(kinds: Counter) -> str:
    """'4 need a rule RASD does not have yet, 1 outside the rule's scope' - the quiet recordings by kind."""
    return ", ".join(f"{kinds[k]} {QUIET_LABELS[k]}" for k in QUIET_KINDS if kinds.get(k) and k != "negative")


def _md(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _when(t: str | None) -> str:
    return t.replace("T", " ")[:19] if t else "-"


def _ds_link(ds: Dataset) -> str:
    """The dataset's id linked to its upstream file, with the file's name where the id does not show it."""
    last, name = ds.id.rsplit("/", 1)[-1], Path(ds.path).name
    hint = "" if last in (name, Path(name).stem) else f" ({'in ' if ds.member else 'file '}{name})"
    return f"[{_md(ds.short)}]({ds.link}){_md(hint)}"


def _headline(v: dict) -> str:
    """'fires on 5 of the 9 public recordings of its behaviour' with the quiet ones by kind."""
    text = f"fires on {len(v['independent'])} of the {v['recordings']} public recordings of its behaviour"
    quiet = quiet_phrase(v["quiet_kinds"])
    return text + (f" (quiet on the other {v['recordings'] - len(v['independent'])}: {quiet})" if quiet else "")


def holdout_phrase(h: dict) -> str:
    """'held-out: fires on 2 of 2 files labelled before their first replay', or ''."""
    if not h["expected"]:
        return ""
    return f"held-out: fires on {len(h['met'])} of {len(h['expected'])} files labelled before their first replay"


def render_page(rid: str, item: Any, cat: Catalog, res: dict, s: dict) -> str:
    v = s[rid]
    recorded = res.get("datasets") or {}
    by_id = {ds.id: ds for ds in cat.datasets}
    up = "../../../"
    h = v["holdout"]
    front = {"rasd_public_evidence": 2, "detection": rid, "recordings": v["recordings"], "fired_on": len(v["independent"]),
             "alerts": v["alerts"], "false_positives": v["false_positives"], "in_sample": bool(v["changed"]),
             "holdout_expected": len(h["expected"]), "holdout_fired_on": len(h["met"])}
    out = "---\n" + yaml.safe_dump(front, sort_keys=False) + "---\n" + GENERATED
    out += f"# Public dataset evidence · {item.title}\n\n"
    if rid in cat.gaps and not v["expected"]:
        out += (f"**No public dataset in the catalog exercises this detection yet.** {cat.gaps[rid]}\n\n"
                f"It stays at its maturity level and waits for the lab run ([evidence plan]({up}docs/EVIDENCE_PLAN.md)).\n")
        return _upstream_note(out + _quiet_section(rid, v, by_id) + _holdout_section(rid, cat, recorded)
                              + _also_section(rid, cat, recorded), "\n## ", cat) + FOOTER
    srcs = ", ".join(cat.sources[x].title for x in v["sources"]) or "none"
    other = v["benign"] + v["harness"]
    if other or v["false_positives"]:
        elsewhere = (f"beyond the recorded attacks: {other} alert{'s' if other != 1 else ''} on the labs' own activity, "
                     f"each explained ({v['harness']} from the test harness, {v['benign']} benign), and "
                     f"{v['false_positives']} labelled false positive")
    else:
        elsewhere = "no alert beyond the recorded attacks"
    held = holdout_phrase(h)
    out += (f"**Public dataset validation: {_headline(v)}**{' · **' + held + '**' if held else ''} · {v['alerts']} alerts · "
            f"sources: {srcs} · {elsewhere}.\n\n"
            "Public data replayed through the tested rule, not lab evidence: the maturity level does not change "
            f"([what public data proves and what it does not]({up}datasets/README.md#what-public-data-proves)). Alerts are "
            "counted once per record: a record a file repeats, or that an earlier file of the catalog already holds, is not "
            "new evidence.\n\n")
    if v["changed"]:
        out += (f"**In-sample:** this rule was changed after these files were replayed: {_md(v['changed'])}. Its result on "
                "them confirms the change; it is not an independent test.\n\n")
    out += "| Validation | Status |\n|---|---|\n"
    out += f"| Public datasets | fires on {len(v['independent'])} of {v['recordings']} recordings |\n"
    if h["expected"]:
        out += f"| Held-out public files | fires on {len(h['met'])} of {len(h['expected'])} |\n"
    langs = "KQL, SPL and Defender" if _defender(item) else "KQL and SPL"
    out += (f"| Query parity on these events | `rasd parity` evaluates the generated {langs} queries on every committed "
            "extract event of this log source, with RASD's model of each language's semantics (not on a SIEM) |\n")
    out += f"| Validated (lab evidence) | pending ([evidence plan]({up}docs/EVIDENCE_PLAN.md)) |\n"
    out += f"| SIEM replay | pending ([replay checklist]({up}docs/PUBLIC_DATA_VALIDATION.md#siem-replay-checklist)) |\n"
    out += "| Production | pending |\n\n"
    who = "Client (group)" if isinstance(item, Correlation) else "Host"
    out += (f"## Result per dataset\n\n| Dataset | Source | Recorded (UTC) | Events routed | Alerts | New evidence | "
            f"First alert (UTC) | {who} |\n|---|---|---|---:|---:|---|---|---|\n")
    for did in v["expected"]:
        ds, r = by_id[did], recorded.get(did) or {}
        info = (r.get("alerts") or {}).get(rid)
        wins = (r.get("correlations") or {}).get(rid) or []
        count = _attack_count(r, rid) if r else 0
        span = (info.get("attack") or info) if info else None      # the recorded attack's alerts, without the harness
        first_t = span["first"] if span else (wins[0]["crossed_at"] if wins else None)
        if not ds.source.redistribute:
            host = "-"                     # see run_dataset: no field value is quoted from these files
        else:
            host = (", ".join(span["hosts"][:2]) if span else
                    ("; ".join(", ".join(str(x) for x in w.get("group", {}).values()) for w in wins[:2]) or "-"))
        new = _attack_unique(r, rid) if r else 0
        fresh = (f"{new}" if new == count else f"{new} ({count - new} on records already in "
                 + ", ".join(by_id[x].short for x in (r.get("overlap") or {}) if x in by_id) + ")") if r else "-"
        routed = sum((r.get("routed") or {}).values())
        split = ds.explained(rid)
        alerts_cell = f"{count}" + (f" (+{_also_part(r, rid)[0]} {split['kind']}, see below)" if split and r else "")
        out += (f"| {_ds_link(ds)} | {_md(ds.source.title)} ({ds.source.license}) | {_when(r.get('start'))} | {routed:,} | "
                f"{alerts_cell} | {_md(fresh)} | {_when(first_t)} | {_md(host)} |\n")
    for did in v["expected"]:
        r = recorded.get(did) or {}
        if r.get("duplicates"):
            edits = f", {r['duplicates_edited']} of them with a field edited" if r.get("duplicates_edited") else ""
            out += (f"\n{by_id[did].short} repeats records: {r['duplicates']:,} repeats are read once{edits}; the alerts above "
                    "are on distinct records.\n")
    out += _quiet_section(rid, v, by_id)
    out += _holdout_section(rid, cat, recorded)
    tun = _tuning_rows(rid, cat, recorded)
    if tun:
        out += ("\n## Tuning measured on public data\n\nWhat each applied filter kept quiet on every dataset in the catalog, and "
                "what each exception took back - the labs' background activity and the recorded attacks, not samples (values "
                "are quoted only from sources whose license allows redistribution):\n\n"
                "| Tuning | Kind | Events | Most frequent values of the fields it reads |\n|---|---|---:|---|\n" + tun)
    out += _also_section(rid, cat, recorded)
    sample = _first_extract_event(rid, v, by_id, recorded)
    if sample:
        out += ("\n## First match\n\nThe first event that fired, from the committed extract (reduced to the fields the rules read; "
                f"record {sample[1]} of `{sample[0]}`, SHA-256 of the original record `{sample[2][:16]}…`):\n\n"
                "```json\n" + json.dumps(sample[3], indent=1, ensure_ascii=False) + "\n```\n")
    nexts = [n for n in cat.next if n.get("detection") == rid]
    if nexts:
        out += "\n## What public data asks for next\n\nBehaviours of this technique, seen in public data, that no RASD rule reads yet:\n\n"
        for n in nexts:
            out += f"- **{n['id']}**: {_md(n['rule'])} ({len(n.get('evidence') or [])} file{'s' if len(n.get('evidence') or []) != 1 else ''})\n"
    out += (f"\n## Reproduce\n\n```\nrasd datasets fetch --only {rid}\nrasd datasets run --only {rid} -v\n```\n")
    return _upstream_note(out, "| Validation |", cat) + FOOTER


def _upstream_note(page: str, anchor: str, cat: Catalog) -> str:
    """Names that come from outside the mapping keep their published form: a source's folder named after an ATT&CK
    v18 technique or tactic, or a detection ID in held-out labels written before the v19 mapping. Where a page shows
    one, a line before `anchor` says what it is and what it maps to now (intel/mappings/attack_v18_aliases.yml), so
    it is not read as a second name for a v19 detection."""
    al = attack_aliases()
    items = []
    for new, old in al["techniques"].items():
        if f"[{old}/" in page:
            srcs = sorted({ds.source.title for ds in cat.datasets if f"/{old}/" in f"/{ds.id}/"})
            items.append(f"`{old}/` ({' and '.join(srcs)} folder, now {new})")
    for tactic, new_tactics in al["tactics"].items():
        if f"[{tactic}/" in page:
            ups = sorted({(ds.source.title, Path(ds.path).parts[0]) for ds in cat.datasets if f"/{tactic}/" in f"/{ds.id}/"})
            items.append(f"`{tactic}/` (from the {', '.join(f'{src} folder `{up}/`' for src, up in ups)}, now "
                         f"{' or '.join(new_tactics)})")
    for rid, legacy in al["detections"].items():
        if re.search(rf"\b{re.escape(legacy)}\b", page):
            items.append(f"`{legacy}` (the detection ID in labels written before this mapping, now {rid})")
    if not items:
        return page
    named = items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]
    note = (f"Names from outside the mapping are kept as published, in ATT&CK v{al['legacy_version']} terms: {named}. "
            f"RASD maps every file by ATT&CK v{al['attack_version']}.\n\n")
    at = page.find(anchor)
    at = at if at >= 0 else len(page)
    return page[:at] + note + page[at:]


def _holdout_section(rid: str, cat: Catalog, recorded: dict) -> str:
    rows = ""
    for ds in cat.datasets:
        if not ds.holdout or not (rid in ds.expect or rid in ds.quiet or rid in ds.found or rid in ds.also):
            continue
        r = recorded.get(ds.id) or {}
        n = _attack_unique(r, rid) if r else 0
        if rid in ds.expect:
            label = "attack: must fire"
            split = ds.explained(rid)
            extra = (f"; {_also_part(r, rid)[1]} more on non-attack activity ({split['kind']}): {_md(split['reason'])}"
                     if split and r else "")
            if n:
                result = f"fired, {n} alert{'s' if n != 1 else ''} on the recorded attack{extra}"
            elif _attack_count(r, rid):
                result = "fired, but only on records an earlier file holds: not counted"
            else:
                result = f"**missed**: {_md(ds.missed.get(rid, ''))}"
        elif rid in ds.quiet:
            label = f"{ds.quiet[rid]['kind']}: not expected"
            result = f"fired: {_md(ds.found[rid])}" if rid in ds.found else "quiet"
            split = ds.explained(rid)
            if split and rid not in ds.found:
                result += f" on the attack; {_also_unique(r, rid, split)} alerts on non-attack activity ({split['kind']})"
        elif rid in ds.found:
            label = "-"
            result = f"fired: {_md(ds.found[rid])}"
        else:
            label = "-"
            n = _also_unique(r, rid, ds.also[rid])
            result = f"{n} alert{'s' if n != 1 else ''} on non-attack activity ({ds.also[rid]['kind']}): {_md(ds.also[rid]['reason'])}"
        rows += f"| {ds.holdout} | {_ds_link(ds)} | {label} | {result} |\n"
    if not rows:
        return ""
    return ("\n## Held-out files\n\nFiles added after the rule changes, labelled from their raw events and this detection's "
            "README before RASD first replayed them, and replayed once: an independent test "
            "([protocol](../../../datasets/README.md#held-out-files), [labels](../../../datasets/holdout_labels.json)).\n\n"
            "| Label | File | Before the replay | Result |\n|---|---|---|---|\n" + rows)


def _why(q: dict) -> str:
    text = _md(q["reason"]).rstrip()
    if q.get("next"):
        text += ("" if text.endswith((".", ":", ")")) else ".") + f" Next rule: **{q['next']}**."
    return text


def _explained_note(ds: Dataset, rid: str) -> str:
    """' It fires only on ...' for a quiet detection whose alerts on the file an `also` entry's where explains."""
    entry = ds.explained(rid)
    return (f" It fires only on non-attack activity the catalog explains ({entry['kind']}, listed under other alerts)."
            if entry else "")


def _quiet_section(rid: str, v: dict, by_id: dict) -> str:
    if not v["quiet"]:
        return ""
    kinds = [k for k in QUIET_KINDS if any(by_id[d].quiet[rid]["kind"] == k for d in v["quiet"])]
    out = ("\n## Where it stays quiet\n\nRecordings of this technique in the catalog where the rule does not fire on the recorded "
           "attack, each with the reason, re-checked on every run. " + "; ".join(f"**{k}**: {QUIET_KINDS[k]}" for k in kinds)
           + ".\n\n| Dataset | Kind | Why |\n|---|---|---|\n")
    for did in v["quiet"]:
        q = by_id[did].quiet[rid]
        out += f"| {_ds_link(by_id[did])} | {q['kind']} | {_why(q)}{_explained_note(by_id[did], rid)} |\n"
    return out


def _defender(item: Any) -> bool:
    try:
        from parity import defender_spec
        return defender_spec(item.rule) is not None
    except (AttributeError, ImportError, KeyError):
        return False


def _tuning_rows(rid: str, cat: Catalog, recorded: dict) -> str:
    """One row per applied tuning: events it kept quiet (or took back) over the whole catalog, and the
    most frequent values of each field it reads, counted case-insensitively."""
    agg: dict[str, dict] = {}
    for ds in cat.datasets:
        for tid, t in ((recorded.get(ds.id) or {}).get("tuning") or {}).get(rid, {}).items():
            slot = agg.setdefault(tid, {"kind": t["kind"], "events": 0, "values": defaultdict(Counter), "shown": {}})
            slot["events"] += t["events"]
            for f, rows in t["values"].items():
                for value, n in rows:
                    key = str(value).lower()
                    slot["values"][f][key] += n
                    slot["shown"].setdefault((f, key), str(value))
    rows = ""
    for tid, a in sorted(agg.items()):
        parts = []
        for f, cnt in a["values"].items():
            if f == "CallTrace":
                parts.append(f"{f}: {sum(cnt.values())} traces through {len(cnt)} distinct stacks")
                continue
            vals = ", ".join(f"`{_md(_short(a['shown'][(f, k)]))}` ×{n}" for k, n in cnt.most_common(3))
            parts.append(f"{f}: {vals}")
        rows += f"| {tid} | {a['kind']} | {a['events']} | {'<br>'.join(parts)} |\n"
    return rows


def _short(text: str, limit: int = 90) -> str:
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _also_section(rid: str, cat: Catalog, recorded: dict) -> str:
    rows = ""
    for ds in cat.datasets:
        if rid in ds.also:
            r = recorded.get(ds.id) or {}
            entry = ds.also[rid]
            which = ""
            if entry.get("where"):
                which = ("The alerts whose " + " and ".join(f"{f} contains " + " or ".join(f"`{_md(t)}`" for t in texts)
                                                          for f, texts in entry["where"].items())
                         + (", beside the recorded attack: " if rid in ds.expect else ": "))
            rows += (f"| {_ds_link(ds)} | {_also_unique(r, rid, entry)} | {entry['kind']} | "
                     f"{which}{_md(entry['reason'])} |\n")
    if not rows:
        return ""
    return ("\n## Other alerts on public data\n\nAlerts on activity that is not the recorded attack, each explained in the catalog: "
            "`harness` when the lab's test harness did what the rule looks for (its automation setting up, launching and "
            "cleaning up the recorded attack), `benign` when other legitimate activity did (an agent, a log reset), "
            "`false-positive` when the behaviour did not happen. Counted once per record.\n\n"
            "| Dataset | Alerts | Kind | Reason |\n|---|---:|---|---|\n" + rows)


def _first_extract_event(rid: str, v: dict, by_id: dict, recorded: dict) -> tuple[str, int, str, dict] | None:
    for did in v["fired"]:
        ds = by_id[did]
        if ds.extract is None or not ds.extract.exists():
            continue
        for row in read_extract(ds.extract):
            meta = row["_rasd"]
            if (rid in (meta.get("fires") or []) and rid not in (meta.get("also") or [])) or rid in (meta.get("counts") or []):
                return ds.short, int(meta.get("record", 0)), str(meta.get("sha256", "")), {k: x for k, x in row.items() if k != "_rasd"}
    return None


def render_doc(cat: Catalog, res: dict) -> str:
    s = summary(cat, res)
    sc = status_counts(cat, res)
    recorded = res.get("datasets") or {}
    items = known_ids()
    by_id = {ds.id: ds for ds in cat.datasets}
    out = "<!-- Generated by tools/datasets.py from datasets/results.json - do not edit by hand. -->\n\n# Public Data Validation\n\n"
    held = (f" · **Held-out: {sc['holdout_met']} of {sc['holdout_expected']}** expectations met (in {sc['holdout_files_expecting']} "
            f"of {sc['holdout_files']} files labelled before their first replay, {sc['holdout_detections']} of {sc['total']} detections)"
            if sc["holdout_expected"] else "")
    out += (f"**Public dataset validation: {sc['validated']} of {sc['total']} detections** fire on the pinned public attack data "
            f"that records their behaviour{held} · **Validated (lab evidence): 0 of {sc['total']}** (pending the lab run) · "
            "**SIEM replay: pending** · **Production: pending**\n\n")
    out += ("A dataset is not evidence; a dataset every rule ran on, with the result recorded where anyone can check it, is. "
            "Every file below is pinned to a commit of its source and to its SHA-256 ([catalog](../datasets/catalog.yml)); "
            "`rasd datasets run` replays all of them through every detection and correlation, and CI re-checks the "
            "committed extracts and fails when a rule changes without a new run ([how it works](../datasets/README.md)).\n\n")
    elsewhere = sc["benign"] + sc["harness"]
    out += (f"{sc['datasets']} files from {len(cat.sources)} sources · {sc['alerts']} alerts on the recorded attacks · {elsewhere} more "
            f"on the labs' own activity, each explained ({sc['harness']} from the test harness that set up, launched and "
            f"cleaned up the attacks, {sc['benign']} benign) · {sc['false_positives']} labelled false positive · 0 alerts left "
            "unexplained. These are labels on short lab captures, one per alert: not an estate's false-positive rate.\n\n")
    out += (f"Every count is of distinct records: {sc['duplicates']:,} records that a file repeats are read once, and "
            f"{sc['overlapping']} files that hold records of an earlier file are declared below - an alert on such a record "
            "is not new evidence.\n\n")
    out += ("## By detection\n\n*Recordings*: the files that record the behaviour, without copies. *Quiet* by kind: a rule "
            "public data asks for, outside the rule's scope, a documented blind spot, the event the rule reads missing. "
            "*In-sample*: the rule was changed after these files were replayed.\n\n"
            "| Detection | Fired on · recordings | Alerts | Quiet (gap · scope · blind spot · telemetry) | Harness | Benign | "
            "False positives | In-sample | Page |\n|---|---:|---:|---|---:|---:|---:|---|---|\n")
    for rid, v in s.items():
        item = items[rid]
        where = "detections" if not isinstance(item, Correlation) else "correlations"
        state = f"{len(v['independent'])} of {v['recordings']}" if v["expected"] else "no public data"
        q = v["quiet_kinds"]
        quiet = " · ".join(str(q.get(k, 0)) for k in ("gap", "scope", "blind-spot", "telemetry")) if sum(q.values()) else "-"
        out += (f"| {rid} | {state} | {v['alerts']} | {quiet} | {v['harness']} | {v['benign']} | {v['false_positives']} | "
                f"{'yes' if v['changed'] else '-'} | [evidence](../detect/{where}/{rid}/{PAGE}) |\n")
    out += _holdout_doc(cat, recorded, sc)
    if cat.changed:
        out += ("\n## Rules changed after these files were replayed\n\nTheir result on these files is in-sample: the files "
                "showed the gap, the rule was changed, the same files confirm the change.\n\n")
        for rid, why in cat.changed.items():
            out += f"- **{rid}**: {_md(why)}\n"
    out += "\n## Sources\n\n| Source | Pinned commit | License | Files | Extracts committed |\n|---|---|---|---:|---|\n"
    for sid, src in cat.sources.items():
        n = sum(1 for ds in cat.datasets if ds.source.id == sid)
        lic = f"[{src.license}](../{src.license_file})" if src.license_file else src.license
        out += (f"| [{_md(src.title)}]({src.home}) | [`{src.commit[:12]}`]({src.repo}/tree/{src.commit}) | {lic} | {n} | "
                f"{'yes, reduced' if src.redistribute else 'no: the license does not allow it here; fetch and run locally'} |\n")
    out += ("\n## Every dataset\n\n| Dataset | Technique | Reader · profile | Events | Read twice | Routed | Fired (alerts) | Expected |\n"
            "|---|---|---|---:|---:|---:|---|---|\n")
    for ds in cat.datasets:
        if ds.holdout:
            continue                                 # listed with their labels under Held-out files
        r = recorded.get(ds.id) or {}
        fired = sorted(set(r.get("alerts") or {}) | set(r.get("correlations") or {}))
        cells = "<br>".join(f"{x} ({_fired_count(r, x)}" + (f", {_also_part(r, x)[0]} of them {ds.also[x]['kind']}"
                                                            if ds.explained(x) else "") + ")" for x in fired) or "-"
        exp = "<br>".join(ds.expect) or "-"
        out += (f"| {_ds_link(ds)} | {ds.technique} | {ds.format} · {ds.profile} | {r.get('events', 0):,} | "
                f"{r.get('duplicates', 0):,} | {sum((r.get('routed') or {}).values()):,} | {cells} | {exp} |\n")
    shared = [(x, other, why) for x in cat.datasets for other, why in x.overlap.items()]
    if shared:
        out += ("\n## Files that hold records of another file\n\nFound by record identity (host, channel, record number and "
                "time): the same record, or the same record with a field edited. Alerts on these records are counted in the "
                "earlier file only.\n\n| File | Earlier file | Same records | Edited records | Why |\n|---|---|---:|---:|---|\n")
        for later, other, why in shared:
            both = ((recorded.get(later.id) or {}).get("overlap") or {}).get(other) or {}
            out += (f"| {_ds_link(later)} | {_ds_link(by_id[other])} | "
                    f"{both.get('same', 0):,} | {both.get('edited', 0):,} | {_md(why)} |\n")
    repeats = [(x, recorded.get(x.id) or {}) for x in cat.datasets if (recorded.get(x.id) or {}).get("duplicates")]
    if repeats:
        out += ("\n## Files that repeat records\n\nA record a file holds more than once - the same record number, host, channel "
                "and time, or the same content where the file carries no record number - is read once. A repeat with a field "
                "edited is a copy someone changed: only the first one is read.\n\n"
                "| File | Records | Repeats read once | Repeats with a field edited |\n|---|---:|---:|---:|\n")
        for x, r in repeats:
            out += f"| {_ds_link(x)} | {r.get('events', 0):,} | {r['duplicates']:,} | {r.get('duplicates_edited', 0):,} |\n"
    if cat.gaps:
        out += "\n## Not covered by public data yet\n\n"
        for rid, why in cat.gaps.items():
            out += f"- **{rid}**: {_md(why)}\n"
    quiet_rows = [(ds, rid, q) for ds in cat.datasets for rid, q in ds.quiet.items()]
    if quiet_rows:
        out += ("\n## Where detections stay quiet\n\nPublic recordings of a detection's technique where it does not fire on the "
                "recorded attack, and why. Each is a documented limit, not a hidden one.\n\n"
                "| Dataset | Detection | Kind | Why |\n|---|---|---|---|\n")
        for ds, rid, q in quiet_rows:
            out += f"| {_ds_link(ds)} | {rid} | {q['kind']} | {_why(q)}{_explained_note(ds, rid)} |\n"
    if cat.next:
        by_id = {ds.id: ds for ds in cat.datasets}
        out += ("\n## Next rules from public data\n\nBehaviours of covered techniques that public data shows and no RASD rule reads "
                "yet. Each is a candidate for the next round, with the files to validate it on.\n\n"
                "| Next rule | Technique | Extends | What it reads | Public files |\n|---|---|---|---|---|\n")
        for nx in cat.next:
            files = "<br>".join(_ds_link(by_id[d]) for d in nx.get("evidence") or [] if d in by_id)
            out += f"| {nx['id']} | {nx['technique']} | {nx['detection']} | {_md(nx['rule'])} | {files} |\n"
    rows = [(ds, (recorded.get(ds.id) or {})) for ds in cat.datasets if ds.splunk and ds.expect]
    if rows:
        out += ("\n## SIEM replay checklist\n\nThe next validation level, in your own Splunk: index a file with the sourcetype and "
                "source its upstream metadata names (Splunk Add-on for Microsoft Windows installed), run the generated query "
                "over the file's time range and compare the count with the one RASD's engine produced here. A match is "
                "SIEM replay evidence for that detection; a difference is a field extraction or mapping problem to fix before "
                "the lab run.\n\n| Dataset | sourcetype · source | Query | Alerts expected |\n|---|---|---|---:|\n")
        for ds, r in rows:
            for rid in ds.expect:
                sub = "correlations/" if isinstance(items[rid], Correlation) else ""
                q = f"[{rid}.spl](../queries/spl/{sub}{rid}.spl)"
                spl = ds.splunk or {}
                out += (f"| {_ds_link(ds)} | `{_md(spl.get('sourcetype'))}` · `{_md(spl.get('source'))}` | {q} | "
                        f"{_fired_count(r, rid)} |\n")
    return _upstream_note(out, "## By detection", cat) + FOOTER


def _holdout_doc(cat: Catalog, recorded: dict, sc: dict) -> str:
    held = [ds for ds in cat.datasets if ds.holdout]
    if not held:
        return ""
    doc = holdout_doc()
    demoted = [ds for ds in cat.datasets if ds.demoted_from]
    copies = [(ds, rid) for ds in held for rid in ds.expect
              if _attack_count(recorded.get(ds.id) or {}, rid) and not _attack_unique(recorded.get(ds.id) or {}, rid)]
    missed = sum(len(ds.missed) for ds in held)
    out = ("\n## Held-out files\n\nThe files above were chosen and their rules tuned in view of each other. These "
           f"{len(held)} were not. {_md(doc.get('selection', ''))} They were added after the rule changes and labelled before RASD "
           "first replayed them - from the raw events and each detection's README, by reviewers without access to the rules, "
           "tests or results ([labels and protocol](../datasets/holdout_labels.json)). Their expected and quiet entries are the "
           "labels, unchanged; what the replay did beyond them is recorded, not relabelled.\n\n")
    kinds = Counter(q["kind"] for ds in held for q in ds.quiet.values())
    labelled = sum(len(ds.expect) for ds in held)
    labelled_files = sum(1 for ds in held if ds.expect)
    counted = (f"{sc['holdout_expected']} of them, in {sc['holdout_files_expecting']} files, are counted: "
               + ("the other one" if len(copies) == 1 else f"the other {len(copies)}")
               + " fired only on records an earlier file of the catalog holds, which is not new evidence. " if copies else "")
    out += (f"The labels expect {labelled} detections to fire, in {labelled_files} of the {len(held)} files. {counted}The counted "
            f"ones cover {sc['holdout_detections']} of the {sc['total']} detections. The other labels say why a "
            f"detection is not expected: {kinds.get('telemetry', 0)} times the file lacks the event it reads, "
            f"{kinds.get('scope', 0)} times the behaviour is outside its documented scope, {kinds.get('blind-spot', 0)} times it is "
            "a documented blind spot. So the held-out set tests whether each rule does what its README says on files nobody "
            "tuned it on, and shows how much of the recorded attacks falls outside the rules' telemetry and scope; it is not a "
            "detection rate on an estate. One reviewer labelled each file, and every file comes from one source.\n\n")
    found = [(ds, rid) for ds in held for rid in ds.found]
    beyond = (f"{len(found)} time{'s' if len(found) != 1 else ''} a detection fired beyond the labels "
              f"({len({r for _d, r in found})} detections, {len({d.id for d, _r in found})} files), each on the recorded attack "
              "and explained" if found else "no detection fired beyond the labels")
    out += (f"**{sc['holdout_met']} of {sc['holdout_expected']} expectations met**, {missed} missed · {beyond} · "
            f"{sc['holdout_other']} alerts on non-attack activity, each explained · {sc['holdout_fp']} "
            "labelled false positive. A held-out miss that later fires fails the run: fixing a rule or a reader on a held-out "
            "file takes the file out of this set.\n\n")
    for rnd in doc.get("rounds") or []:
        fr = rnd.get("first_replay") or {}
        if fr:
            out += (f"- First replay of {rnd['labels']} ({_md(rnd.get('note', ''))}): {fr.get('met')} of {fr.get('expected')} "
                    "expectations met" + (" (" + "; ".join(_md(m) for m in fr["copies"]) + ")" if fr.get("copies") else "")
                    + (": missed " + "; ".join(_md(m) for m in fr.get("missed") or []) if fr.get("missed") else "") + ".\n")
    for ds, rid in copies:
        out += (f"- {ds.holdout}: {rid} fired, but only on records an earlier file of the catalog holds, so it is not counted "
                "as a held-out result.\n")
    gone = doc.get("demoted") or {}
    for ds in demoted:
        out += f"- {ds.demoted_from}, taken out of the held-out set after its first replay: {_md(gone.get(ds.demoted_from, ''))}.\n"
    if copies or demoted:
        out += "\n"
    out += "| Label | File | Expected before the replay | Fired | Beyond the labels |\n|---|---|---|---|---|\n"
    for ds in held:
        r = recorded.get(ds.id) or {}
        fired = sorted(set(r.get("alerts") or {}) | set(r.get("correlations") or {}))
        exp = "<br>".join([(f"{x} (met)" if _attack_unique(r, x) else f"{x} (fired only on records an earlier file holds: not counted)")
                           if _attack_count(r, x) else f"**{x} (missed)**" for x in ds.expect]
                          + [f"not expected, {q['kind']}: {x}" for x, q in ds.quiet.items()]) or "-"
        cells = "<br>".join(f"{x} ({_unique_count(r, x)}" + (f", {_also_part(r, x)[1]} of them {ds.also[x]['kind']}"
                                                             if ds.explained(x) else "") + ")" for x in fired) or "-"
        beyond = "<br>".join([f"found {x}" for x in ds.found] + [f"{a['kind']}: {x}" for x, a in ds.also.items()]) or "-"
        out += f"| {ds.holdout} | [{_md(ds.title)}]({ds.link}) | {exp} | {cells} | {beyond} |\n"
    return out


def pages(cat: Catalog, res: dict) -> dict[Path, str]:
    s = summary(cat, res)
    out = {VALIDATION_DOC: render_doc(cat, res)}
    for rid, item in known_ids().items():
        out[item.folder / PAGE] = render_page(rid, item, cat, res, s)
    return out


def render(cat: Catalog | None = None, res: dict | None = None, check_only: bool = False) -> int:
    cat = cat or load_catalog()
    res = res if res is not None else load_results()
    if res is None:
        return 0
    n = 0
    for path, text in pages(cat, res).items():
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            n += 1
            if not check_only:
                path.write_text(text, encoding="utf-8")
    return n


# --------------------------------------------------------------------------- #
# leak scan: nothing from a file that cannot be redistributed ends up in the repository
# --------------------------------------------------------------------------- #
IDENTITY_FIELDS = ("Computer", "Hostname", "TargetUserName", "SubjectUserName", "User", "AccountName", "WorkstationName",
                   "TargetDomainName", "SubjectDomainName", "IpAddress", "SourceIp", "DestinationIp", "DestinationHostname",
                   "ServiceName", "TargetUserSid", "SubjectUserSid", "LogonGuid", "ProcessGuid", "ParentProcessGuid",
                   "SourceProcessGUID", "TargetProcessGUID")
PATH_FIELDS = ("Image", "ParentImage", "SourceImage", "TargetImage", "TargetFilename", "ImagePath")
GENERIC = {"system", "local service", "network service", "administrator", "anonymous logon", "nt authority", "workgroup",
           "builtin", "window manager", "font driver host", "localhost", "127.0.0.1", "::1", "s-1-5-18", "s-1-5-19", "s-1-5-20"}
_TOKEN = re.compile(r"[a-z0-9_$.\-]+")


def _scalars(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        for v in value.values():
            yield from _scalars(v)
    elif isinstance(value, list):
        for v in value:
            yield from _scalars(v)
    elif isinstance(value, str):
        yield value


_OS_PATH = re.compile(r"(\\\\\?\\)?(c:\\windows\\|c:\\program files( \(x86\))?\\|%systemroot%|%windir%|\\systemroot\\)")
_PLACEHOLDER = re.compile(r"(user|test|admin|guest|lab|demo)[._-]?\d{1,3}")
_KNOWN_KEY = re.compile(r"hk[a-z_]*\\software\\(wow6432node\\)?microsoft\\windows\\currentversion\\run(once)?\\?")


def _distinctive(v: str) -> bool:
    """A host, account, domain, address, GUID or file name specific enough that finding it here means
    it was copied: not a common word, placeholder account, short code or mask."""
    if len(v) < 5 or v in GENERIC or " " in v or _PLACEHOLDER.fullmatch(v) or re.fullmatch(r"[0-9a-fx.:-]{1,10}", v):
        return False
    return bool(re.search(r"[0-9_.-]", v)) or len(v) >= 10


def _record_values(ev: dict) -> tuple[set[str], set[str]]:
    """A record's identities (hosts, accounts, domains, addresses, GUIDs, names of files outside the
    Windows and Program Files folders) and its long values (command lines, registry data, stack frames)."""
    ident: set[str] = set()
    for f in IDENTITY_FIELDS:
        v = str(ev.get(f) or "").strip().lower()
        if not v:
            continue
        ident.add(v)
        ident.update(x for x in re.split(r"[\\@]", v) if x)            # DOMAIN\user, user@domain
        if f in ("Computer", "Hostname", "DestinationHostname") and "." in v:
            ident.add(v.split(".", 1)[0])
    for f in PATH_FIELDS:
        v = str(ev.get(f) or "").strip().strip('"').lower()
        if v and not _OS_PATH.match(v):                                  # an OS or installed binary is not specific
            ident.add(re.split(r"[\\/]", v)[-1])
    whole: set[str] = set()
    for v in ev.values():
        for x in str(v).split("|") if isinstance(v, str) else ():
            x = x.strip().lower()
            if (len(x) >= 12 and re.search(r"[0-9\\/+=:]", x) and not _KNOWN_KEY.fullmatch(x)
                    and not (" " not in x and "+" not in x and _OS_PATH.match(x))):
                whole.add(x)
    return ident, whole


def _tracked_files() -> list[Path]:
    git = shutil.which("git")
    if git and (ROOT / ".git").exists():
        out = subprocess.run([git, "-C", str(ROOT), "ls-files", "-z"], check=True, capture_output=True).stdout
        return [ROOT / x for x in out.decode("utf-8", "replace").split("\0") if x]
    return [x for x in ROOT.rglob("*") if x.is_file() and ".git" not in x.parts and "cache" not in x.parts]


def leak_scan(cat: Catalog, cache: Path) -> list[str]:
    """Every value distinctive of a file that cannot be redistributed - an identity seen nowhere in the
    redistributable files, or a long value (command line, registry data, stack frame) seen only there -
    that appears in a file of the repository. Needs the cached files, so it runs with `run --write`."""
    ident: set[str] = set()
    whole: set[str] = set()
    for ds in cat.datasets:
        if not ds.source.redistribute:
            for _n, _sha, ev in records(ds, cache):
                if ev:
                    i, w = _record_values(ev)
                    ident |= i
                    whole |= w
    for ds in cat.datasets:                         # a value also seen in a redistributable file is not distinctive
        if ds.source.redistribute:
            for _n, _sha, ev in records(ds, cache):
                if ev:
                    values = [str(v).lower() for v in ev.values() if isinstance(v, str)]
                    ident -= {t for v in values for t in re.split(r"[^a-z0-9_$.-]+", v) if t}
                    ident -= {v.strip() for v in values}
                    whole -= {x.strip() for v in values for x in v.split("|")}
    ident = {v for v in ident if _distinctive(v)}
    hits: list[str] = []
    for path in _tracked_files():
        if path.suffix.lower() not in (".md", ".yml", ".yaml", ".json", ".jsonl", ".txt", ".csv", ".kql", ".spl", ".py",
                                       ".ps1", ".psm1", ".xml", ".html", ".conf", ".toml", ".cfg", ".sh"):
            continue
        try:
            text = path.read_text(encoding="utf-8").lower()
        except (OSError, UnicodeDecodeError):
            continue
        plain = text.replace("\\\\", "\\")
        tokens = set(_TOKEN.findall(plain))
        tokens |= {part for t in list(tokens) for part in re.split(r"[.\\]", t) if part}
        found = sorted({v for v in ident if (v in tokens if _TOKEN.fullmatch(v) else v in plain)})
        if path.suffix in (".json", ".jsonl", ".yml", ".yaml"):
            docs: list[Any] = []
            try:
                if path.suffix == ".jsonl":
                    docs = [json.loads(line) for line in text.splitlines() if line.strip()]
                elif path.suffix == ".json":
                    docs = [json.loads(text)]
                else:
                    docs = list(yaml.safe_load_all(text))
            except (ValueError, yaml.YAMLError):
                docs = []
            found += sorted({x.strip() for d in docs for v in _scalars(d) for x in v.split("|") if x.strip() in whole})
        hits += [f"{path.relative_to(ROOT)}: {v[:80]}" for v in found]
    return hits


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def list_catalog(cat: Catalog, cache: Path) -> int:
    print(f"{BOLD}Public dataset catalog{RESET} {DIM}{CATALOG.relative_to(ROOT)}{RESET}\n")
    for sid, src in cat.sources.items():
        items = [ds for ds in cat.datasets if ds.source.id == sid]
        cached = sum(1 for ds in items if ds.cached(cache).exists())
        print(f"  {BOLD}{src.title}{RESET} · {src.license} · commit {src.commit[:12]} · {len(items)} files, {cached} cached"
              f"{'' if src.redistribute else ' · extracts not redistributed'}")
        for ds in items:
            mark = f"{GREEN}●{RESET}" if ds.cached(cache).exists() else f"{DIM}○{RESET}"
            print(f"    {mark} {ds.id} {DIM}{ds.size:,} bytes · {ds.format} · {', '.join(ds.expect) or 'documents a limit'}{RESET}")
    for e in cat.errors:
        print(f"  {RED}✗ {e}{RESET}")
    return 1 if cat.errors else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")
    f = sub.add_parser("fetch", help="download the pinned files and verify their SHA-256")
    r = sub.add_parser("run", help="replay every rule over the cached files and compare with the catalog")
    for p in (f, r):
        p.add_argument("--only", help="datasets whose id, technique, title or listed detections contain this text")
        p.add_argument("--cache", default=str(CACHE), help="download folder (default datasets/cache, not committed)")
    f.add_argument("--git", action="store_true", help="check files out with git instead of the https download (not for LFS)")
    r.add_argument("--write", action="store_true", help="write results.json, the extracts and the pages")
    r.add_argument("-v", "--verbose", action="store_true", help="list alerts and tuning effects per dataset")
    r.add_argument("--case-dir", help="also write replay case folders, one per dataset with alerts")
    lk = sub.add_parser("leaks", help="scan the repository for values distinctive of files that cannot be redistributed")
    lk.add_argument("--cache", default=str(CACHE), help="download folder (default datasets/cache, not committed)")
    sub.add_parser("check", help="CI: catalog, recorded results, extracts and pages")
    sub.add_parser("render", help="regenerate the pages from results.json")
    args = ap.parse_args()
    cat = load_catalog()
    if args.cmd == "fetch":
        return fetch(cat, Path(args.cache), args.only, args.git)
    if args.cmd == "run":
        return run_all(cat, Path(args.cache), args.only, args.verbose, args.write, args.case_dir)
    if args.cmd == "leaks":
        if not evtx_available():
            print(f"{RED}the scan reads every file: pip install python-evtx (or pip install -e .[datasets]){RESET}")
            return 1
        found = leak_scan(cat, Path(args.cache))
        for line in found:
            print(f"  {RED}✗{RESET} {line}")
        print(f"{GREEN + '✓ no value' if not found else RED + f'{len(found)} value(s)'}{RESET} distinctive of a file that "
              "cannot be redistributed in the repository")
        return 1 if found else 0
    if args.cmd == "render":
        n = render(cat)
        print(f"{n} page(s) updated")
        return 0
    if args.cmd == "check":
        problems = check()
        sc = status_counts(cat) if not cat.errors else {}
        for problem in problems:
            print(f"  {RED}✗{RESET} {problem}")
        if not problems:
            print(f"{GREEN}✓{RESET} public datasets: catalog valid, results current, every extract fires as recorded · "
                  f"{sc.get('validated')}/{sc.get('total')} detections fire on public data")
        return 1 if problems else 0
    return list_catalog(cat, CACHE)


if __name__ == "__main__":
    sys.exit(main())
