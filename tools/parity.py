#!/usr/bin/env python3
"""
parity.py - prove that the queries you deploy behave exactly like the rules you tested.

Every test in this repository runs the Sigma rule through the offline engine. The SOC
never runs the Sigma rule: it runs the KQL in Sentinel and the SPL in Splunk that
convert.py generates. A converter bug (escaping, operator precedence, null handling)
would leave the tested rule green while the deployed query is blind or noisy.

parity.py closes that gap. It takes the query text convert.py produces (the same text
`rasd build` writes to queries/ and CI drift-checks), parses the rule's `where` clause
back, evaluates it with each SIEM's own semantics, and compares the verdict with the
engine on a large corpus:

  samples     every true positive and true negative of every rule on the same log source
  mutations   hand-written technique mutations and generic case mutations
  fuzz        every evasion-fuzzer variant of the true positives
  probes      each sample with each field the rule uses removed, then set to "" -
              this is where SIEMs differ: in SPL a missing field is NULL and NOT NULL is
              still NULL, so a naive `NOT match(...)` silently drops the event
  replay      the replay corpus events routed to the rule's log source
  public      every committed public dataset extract event routed to the rule's log source
              (real attack telemetry from datasets/extracts, normalised with its profile)

For the rules on a log source a Microsoft Defender XDR table carries (process creation,
registry), the generated advanced hunting query is checked the same way: its extend and its
filter are parsed back and run on every corpus event written as Defender writes it - paths
split into folder and file name (the folder alone, and the full path), accounts into domain
and name, registry keys with Defender's hive names.

SIEM semantics modelled
  KQL  string columns are never null (missing = ""), a numeric comparison on a missing
       value is null; contains / startswith / endswith / =~ ignore case; *_cs and == do
       not; `matches regex` is a regex search.
  SPL  a missing or empty field is null, every function over null returns null, `where`
       keeps only true, NOT null is null; = is case-sensitive; match() is a regex search.
  Both use three-valued logic: false AND null = false, true OR null = true.

The log-source base of each query (table, index, EventID pre-filter) is environment
configuration from tools/mappings.yml and is not part of the comparison - with one check:
on SecurityEvent / Event, every field the rule reads that is not a native column must be
extended from EventData before the filter, or the stock table would compare it as empty.

Usage
  rasd parity
  rasd parity --filter T1218 -v
  rasd parity --json
"""
from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from pathlib import Path
from typing import Any
from collections.abc import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BOLD, DIM, GREEN, RED, RESET, ROOT, load_detections, load_jsonl
from convert import DEFENDER, MAPPINGS, convert, logsource_key, referenced_fields
from fuzz import variants
from mutation_test import generic_mutations, technique_mutations
from replay import route
from sigma_engine import SigmaError, _get_field, matches
from validate import rule_fields

Node = Callable[[dict], Any]          # event -> True / False / None (null)
REPLAY_CORPUS = ROOT / "samples" / "replay" / "lab-day.jsonl"


class ParseError(Exception):
    pass


# --------------------------------------------------------------------------- #
# Three-valued logic shared by both SIEMs
# --------------------------------------------------------------------------- #
def AND(nodes: list[Node]) -> Node:
    def f(ev):
        vals = [n(ev) for n in nodes]
        return False if False in vals else (None if None in vals else True)
    return f


def OR(nodes: list[Node]) -> Node:
    def f(ev):
        vals = [n(ev) for n in nodes]
        return True if True in vals else (None if None in vals else False)
    return f


def NOT(node: Node) -> Node:
    def f(ev):
        v = node(ev)
        return None if v is None else not v
    return f


class Parser:
    """Recursive descent over a token list; subclasses supply the atoms."""
    AND_KW = OR_KW = NOT_KW = ""

    def __init__(self, text: str, lookup: Callable[[dict, str], Any]):
        self.text, self.lookup = text, lookup
        self.t = self.tokenize(text)
        self.i = 0

    def tokenize(self, text: str) -> list[str]:
        raise NotImplementedError

    def peek(self, k: int = 0) -> str | None:
        return self.t[self.i + k] if self.i + k < len(self.t) else None

    def take(self, expected: str | None = None) -> str:
        tok = self.peek()
        if tok is None or (expected is not None and tok != expected):
            raise ParseError(f"expected {expected or 'token'} at token {self.i}, got {tok!r} in: {self.text[:120]}")
        self.i += 1
        return tok

    def parse(self) -> Node:
        node = self.expr()
        if self.i != len(self.t):
            raise ParseError(f"trailing tokens from {self.t[self.i]!r}")
        return node

    def expr(self) -> Node:
        parts = [self.term()]
        while self.peek() == self.OR_KW:
            self.take()
            parts.append(self.term())
        return parts[0] if len(parts) == 1 else OR(parts)

    def term(self) -> Node:
        parts = [self.factor()]
        while self.peek() == self.AND_KW:
            self.take()
            parts.append(self.factor())
        return parts[0] if len(parts) == 1 else AND(parts)

    def factor(self) -> Node:
        if self.peek() == self.NOT_KW:
            self.take()
            return NOT(self.factor())
        if self.peek() == "(":
            self.take("(")
            node = self.expr()
            self.take(")")
            return node
        return self.atom()

    def atom(self) -> Node:
        raise NotImplementedError


# --------------------------------------------------------------------------- #
# KQL
# --------------------------------------------------------------------------- #
KQL_TOKEN = re.compile(r'\s*(@"(?:[^"]|"")*"|-?\d+(?:\.\d+)?(?![\w.])|=~|==|!=|\(|\)|[A-Za-z_][\w.]*)')
KQL_STRING_OPS = {
    "contains": lambda a, e: e.lower() in a.lower(), "contains_cs": lambda a, e: e in a,
    "startswith": lambda a, e: a.lower().startswith(e.lower()), "startswith_cs": lambda a, e: a.startswith(e),
    "endswith": lambda a, e: a.lower().endswith(e.lower()), "endswith_cs": lambda a, e: a.endswith(e),
    "=~": lambda a, e: a.lower() == e.lower(), "==": lambda a, e: a == e,
}


def _tokens(pattern: re.Pattern, text: str) -> list[str]:
    pos, out, text = 0, [], text.strip()
    while pos < len(text):
        m = pattern.match(text, pos)
        if not m:
            raise ParseError(f"cannot tokenize near {text[pos:pos + 40]!r}")
        out.append(m.group(1))
        pos = m.end()
    return out


class KQLParser(Parser):
    AND_KW, OR_KW, NOT_KW = "and", "or", "not"

    def tokenize(self, text):
        return _tokens(KQL_TOKEN, text)

    @staticmethod
    def literal(tok: str) -> str:
        if not (tok.startswith('@"') and tok.endswith('"')):
            raise ParseError(f"expected verbatim string, got {tok!r}")
        return tok[2:-1].replace('""', '"')

    def factor(self) -> Node:
        if self.peek() == "not":                  # KQL negation is the function not(...)
            self.take()
            self.take("(")
            node = self.expr()
            self.take(")")
            return NOT(node)
        return super().factor()

    def atom(self) -> Node:
        tok = self.take()
        if tok in ("isempty", "isnotempty"):
            self.take("(")
            field = self.take()
            self.take(")")
            want_empty = tok == "isempty"
            return lambda ev: (self._raw(ev, field) in (None, "")) == want_empty
        field, op = tok, self.take()
        if op == "matches":
            self.take("regex")
            rx = re.compile(self.literal(self.take()))
            return lambda ev: rx.search(self._str(ev, field)) is not None
        rhs = self.take()
        if op == "==" and re.fullmatch(r"-?\d+(\.\d+)?", rhs):
            num = float(rhs)
            return lambda ev: self._num_eq(ev, field, num)
        if op not in KQL_STRING_OPS:
            raise ParseError(f"unsupported KQL operator {op!r}")
        fn, lit = KQL_STRING_OPS[op], self.literal(rhs)
        return lambda ev: fn(self._str(ev, field), lit)

    def _raw(self, ev, field):
        return self.lookup(ev, field)

    def _str(self, ev, field) -> str:              # string columns: missing -> ""
        v = self._raw(ev, field)
        return "" if v is None else str(v)

    def _num_eq(self, ev, field, num):             # numeric columns: missing -> null
        v = self._raw(ev, field)
        if v in (None, ""):
            return None
        try:
            return float(v) == num
        except (TypeError, ValueError):
            return False


class KQLTableFilter(KQLParser):
    """The table's own filter in mappings.yml (`ActionType == "RegistryValueSet"`), which uses a plain
    string. Rule filters stay on KQLParser, which accepts only the verbatim strings the converter writes."""
    TOKEN = re.compile(r'\s*("(?:[^"\\]|\\.)*"|==|=~|\(|\)|[A-Za-z_][\w.]*)')

    def tokenize(self, text):
        return _tokens(self.TOKEN, text)

    @staticmethod
    def literal(tok: str) -> str:
        if not (len(tok) >= 2 and tok[0] == tok[-1] == '"'):
            raise ParseError(f"expected a string, got {tok!r}")
        return re.sub(r"\\(.)", r"\1", tok[1:-1])


# --------------------------------------------------------------------------- #
# SPL
# --------------------------------------------------------------------------- #
SPL_TOKEN = re.compile(r"""\s*("(?:[^"\\]|\\.)*"|'[^']*'|-?\d+(?:\.\d+)?(?![\w.])|!=|=|\(|\)|,|[A-Za-z_]\w*)""")


class SPLParser(Parser):
    AND_KW, OR_KW, NOT_KW = "AND", "OR", "NOT"

    def tokenize(self, text):
        return _tokens(SPL_TOKEN, text)

    @staticmethod
    def literal(tok: str) -> str:
        if not (tok.startswith('"') and tok.endswith('"')):
            raise ParseError(f"expected string literal, got {tok!r}")
        out, body, i = [], tok[1:-1], 0
        while i < len(body):
            ch = body[i]
            if ch == "\\":
                nxt = body[i + 1] if i + 1 < len(body) else ""
                if nxt not in ('\\', '"'):
                    raise ParseError(f"ambiguous escape '\\{nxt}' in SPL string {tok[:60]!r}")
                out.append(nxt)
                i += 2
                continue
            out.append(ch)
            i += 1
        return "".join(out)

    @staticmethod
    def field(tok: str) -> str:
        if not (tok.startswith("'") and tok.endswith("'")):
            raise ParseError(f"expected 'field' reference, got {tok!r}")
        return tok[1:-1]

    def value(self) -> Callable[[dict], str | None]:
        """'F' | coalesce('F', "lit") | lower(<value>)"""
        tok = self.take()
        if tok == "lower":
            self.take("(")
            inner = self.value()
            self.take(")")
            return lambda ev: None if (v := inner(ev)) is None else v.lower()
        if tok == "coalesce":
            self.take("(")
            field = self.field(self.take())
            self.take(",")
            default = self.literal(self.take())
            self.take(")")
            return lambda ev: default if (v := self._val(ev, field)) is None else v
        field = self.field(tok)
        return lambda ev: self._val(ev, field)

    def atom(self) -> Node:
        tok = self.peek()
        if tok == "match":
            self.take()
            self.take("(")
            value = self.value()
            self.take(",")
            rx = re.compile(self.literal(self.take()))
            self.take(")")
            return lambda ev: None if (v := value(ev)) is None else rx.search(v) is not None
        if tok in ("isnull", "isnotnull"):
            self.take()
            self.take("(")
            field = self.field(self.take())
            self.take(")")
            want_null = tok == "isnull"
            return lambda ev: (self._val(ev, field) is None) == want_null
        value = self.value()
        if self.peek() == "!=":                    # 'F'!="lit": null when F is null, like =
            self.take()
            lit = self.literal(self.take())
            return lambda ev: None if (v := value(ev)) is None else v != lit
        self.take("=")
        rhs = self.take()
        if re.fullmatch(r"-?\d+(\.\d+)?", rhs):
            num = float(rhs)

            def num_eq(ev):
                v = value(ev)
                if v is None:
                    return None
                try:
                    return float(v) == num
                except ValueError:
                    return v == rhs
            return num_eq
        lit = self.literal(rhs)
        return lambda ev: None if (v := value(ev)) is None else v == lit

    def _val(self, ev, field) -> str | None:       # missing or empty -> null
        v = self.lookup(ev, field)
        return None if v in (None, "") else str(v)


# --------------------------------------------------------------------------- #
# Corpus and comparison
# --------------------------------------------------------------------------- #
def where_clause(query: str) -> str:
    return query.rsplit("\n| where ", 1)[1]


def make_lookup(backend: str) -> Callable[[dict, str], Any]:
    reverse = {v: k for k, v in (MAPPINGS[backend].get("fields") or {}).items()}
    return lambda ev, f: _get_field(ev, reverse.get(f, f))


def compile_query(rule: dict, backend: str) -> Node:
    cls = KQLParser if backend == "kql" else SPLParser
    return cls(where_clause(convert(rule, backend)), make_lookup(backend)).parse()


# --------------------------------------------------------------------------- #
# Microsoft Defender XDR advanced hunting (optional backend)
# --------------------------------------------------------------------------- #
DEFENDER_HIVES = (("HKLM\\", "HKEY_LOCAL_MACHINE\\"), ("HKU\\", "HKEY_CURRENT_USER\\"), ("HKCR\\", "HKEY_CLASSES_ROOT\\"))


def defender_action(rule: dict) -> str | None:
    """The ActionType the rule's Defender table is filtered on (registry value sets), if any."""
    m = re.search(r'ActionType == "([^"]+)"', str(MAPPINGS[DEFENDER]["logsources"].get(logsource_key(rule), "")))
    return m.group(1) if m else None


def defender_spec(rule: dict) -> dict | None:
    """The extend map of the rule's log source, or None when no Defender table carries it."""
    key = logsource_key(rule)
    if key not in MAPPINGS[DEFENDER]["logsources"]:
        return None
    return (MAPPINGS[DEFENDER].get("extend") or {}).get(key) or {}


EXTEND_TOKEN = re.compile(r'\s*(@"(?:[^"]|"")*"|"(?:[^"\\]|\\.)*"|\(|\)|,|=|[A-Za-z_]\w*)')


class KQLExtend:
    """The `| extend` of a generated Defender query, parsed back and evaluated with Kusto
    semantics: a missing string column reads as "", endswith ignores case, trim_end and
    replace_regex take a regular expression. Only the functions the converter writes parse."""

    def __init__(self, text: str):
        self.text, self.t, self.i = text, _tokens(EXTEND_TOKEN, text), 0
        self.columns: dict[str, Callable[[dict], Any]] = {}
        while self.i < len(self.t):
            name = self.take()
            self.take("=")
            self.columns[name] = self.expr()
            if self.peek() is not None:
                self.take(",")

    def peek(self) -> str | None:
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self, expected: str | None = None) -> str:
        tok = self.peek()
        if tok is None or (expected is not None and tok != expected):
            raise ParseError(f"extend: expected {expected or 'token'}, got {tok!r} in: {self.text[:120]}")
        self.i += 1
        return tok

    def expr(self) -> Callable[[dict], Any]:
        parts = [self.conj()]
        while self.peek() == "or":
            self.take()
            parts.append(self.conj())
        if len(parts) == 1:
            return parts[0]
        return lambda row: any(p(row) for p in parts)

    def conj(self) -> Callable[[dict], Any]:
        parts = [self.comparison()]
        while self.peek() == "and":
            self.take()
            parts.append(self.comparison())
        if len(parts) == 1:
            return parts[0]
        return lambda row: all(p(row) for p in parts)

    def comparison(self) -> Callable[[dict], Any]:
        left = self.primary()
        if self.peek() == "endswith":
            self.take()
            right = self.primary()
            return lambda row: str(left(row)).lower().endswith(str(right(row)).lower())
        return left

    @staticmethod
    def constant(node: Callable[[dict], Any]) -> str:
        return str(node({}))

    def primary(self) -> Callable[[dict], Any]:
        tok = self.take()
        if tok == "(":
            node = self.expr()
            self.take(")")
            return node
        if tok.startswith('@"'):
            text = tok[2:-1].replace('""', '"')
            return lambda row: text
        if tok.startswith('"'):
            text = re.sub(r"\\(.)", r"\1", tok[1:-1])
            return lambda row: text
        if self.peek() == "(":
            self.take("(")
            args = [self.expr()]
            while self.peek() == ",":
                self.take(",")
                args.append(self.expr())
            self.take(")")
            return self.call(tok, args)
        return lambda row: "" if row.get(tok) is None else str(row.get(tok))

    def call(self, name: str, args: list) -> Callable[[dict], Any]:
        if name == "tostring" and len(args) == 1:
            return lambda row: str(args[0](row))
        if name == "isempty" and len(args) == 1:
            return lambda row: args[0](row) in (None, "")
        if name == "strcat":
            return lambda row: "".join(str(a(row)) for a in args)
        if name == "iff" and len(args) == 3:
            return lambda row: args[1](row) if args[0](row) else args[2](row)
        if name == "trim_end" and len(args) == 2:
            rx = re.compile(f"(?:{self.constant(args[0])})$")
            return lambda row: rx.sub("", str(args[1](row)))
        if name == "replace_regex" and len(args) == 3:
            rx, rewrite = re.compile(self.constant(args[1])), self.constant(args[2])
            return lambda row: rx.sub(rewrite, str(args[0](row)))
        raise ParseError(f"extend: unsupported function {name}() with {len(args)} argument(s)")


def defender_row(ev: dict, spec: dict, full_path: bool, action: str | None = None) -> dict:
    """A test event written the way Defender writes it: paths split into folder and file name
    (the folder alone, or the full path, as exports vary), accounts into domain and name,
    registry keys with Defender's hive names and the value name apart, and the ActionType of
    the event kind the test corpus holds (a Sysmon 13 value set is a RegistryValueSet)."""
    row: dict = {"ActionType": action} if action else {}
    for field, how in spec.items():
        value = _get_field(ev, field)
        if value is None:
            continue
        text = str(value)
        if isinstance(how, str):
            row[how] = value
        elif "path" in how:
            folder, sep, file = text.rpartition("\\")
            row[how["path"][0]] = (text if full_path else folder) if sep else ""
            row[how["path"][1]] = file if sep else text
        elif "account" in how:
            domain, sep, name = text.partition("\\")
            row[how["account"][0]], row[how["account"][1]] = (domain, name) if sep else ("", text)
        elif "registry" in how:
            key, sep, name = text.rpartition("\\")
            key, name = (key, name) if sep else (text, "")
            if name.lower() == "(default)":         # Defender leaves the default value's name empty
                name = ""
            for short, long in DEFENDER_HIVES:
                if key.upper().startswith(short):
                    key = long + key[len(short):]
                    break
            row[how["registry"][0]], row[how["registry"][1]] = key, name
    return row


def compile_defender(rule: dict) -> Node:
    """The generated advanced hunting query, parsed back: the table's own filter (ActionType) runs
    on the Defender row, its extend rebuilds the rule's fields from that row, then its filter runs
    with Kusto semantics."""
    head, where = convert(rule, DEFENDER).rsplit("\n| where ", 1)
    m = re.search(r"\n\| extend (.*)$", head, re.S)
    table = head[:m.start()] if m else head
    columns = KQLExtend(m.group(1)).columns if m else {}
    gates = [KQLTableFilter(w, lambda row, f: row.get(f)).parse() for w in re.findall(r"\| where (.+)", table)]
    lookup = lambda row, f: columns[f](row) if f in columns else row.get(f)
    rule_filter = KQLParser(where, lookup).parse()
    return lambda row: rule_filter(row) if all(g(row) is True for g in gates) else False


def base_errors(rule: dict) -> list[str]:
    """KQL on an EventData table: each non-column field is extracted before the filter."""
    cfg = MAPPINGS["kql"].get("eventdata") or {}
    key = logsource_key(rule)
    if key not in cfg.get("logsources", []):
        return []
    query, fmap, native = convert(rule, "kql"), MAPPINGS["kql"].get("fields") or {}, set(cfg.get("native", []))
    head = query.rsplit("\n| where ", 1)[0]
    return [f"KQL reads {col} but the stock table has no such column and it is not extracted from EventData"
            for col in (fmap.get(f, f) for f in referenced_fields(rule["detection"]))
            if col not in native and f"| extend {col} = " not in head]


def corpus_for(det, dets, replay_events, public_events=()) -> list[tuple[str, dict]]:
    key = logsource_key(det.rule)
    out: list[tuple[str, dict]] = []
    for other in dets:
        if logsource_key(other.rule) != key:
            continue
        for kind, tag in (("true_positive", "TP"), ("true_negative", "TN")):
            out += [(f"{other.id} {tag}#{i}", ev) for i, ev in enumerate(other.tests(kind), 1)]
    tps = det.tests("true_positive")
    out += [(f"mutation:{n}", ev) for n, ev, _ in generic_mutations(tps)]
    out += [(f"mutation:{n}", ev) for n, ev, _ in technique_mutations(det.folder, tps)]
    for i, ev in enumerate(tps, 1):
        out += [(f"TP#{i}~{n}", v) for n, _c, v in variants(ev)]
    fields = rule_fields(det.rule["detection"])
    for kind, tag in (("true_positive", "TP"), ("true_negative", "TN")):
        for i, ev in enumerate(det.tests(kind), 1):
            for f in sorted(fields):
                k = next((k for k in ev if k.lower() == f.lower()), None)
                if k is None:
                    continue
                dropped = {kk: vv for kk, vv in ev.items() if kk != k}
                out.append((f"{tag}#{i} without {k}", dropped))
                blank = copy.deepcopy(ev)
                blank[k] = ""
                out.append((f"{tag}#{i} with empty {k}", blank))
    out += [(f"replay:{i}", ev) for i, ev in enumerate(replay_events, 1) if route(ev) == key]
    out += [(label, ev) for label, ev in public_events if route(ev) == key]
    seen, unique = set(), []
    for label, ev in out:
        sig = json.dumps(ev, sort_keys=True, default=str)
        if sig not in seen:
            seen.add(sig)
            unique.append((label, ev))
    return unique


def check(filter_: str | None = None) -> dict:
    dets = load_detections()
    replay_events = load_jsonl(REPLAY_CORPUS) if REPLAY_CORPUS.exists() else []
    from datasets import public_events as public       # imported here: datasets imports this module's neighbours
    public_events = public()
    report = {}
    for det in dets:
        if filter_ and filter_.lower() not in det.id.lower():
            continue
        r: dict[str, Any] = {"events": 0, "kql": [], "spl": [], "errors": [], "mde": None, "mde_rows": 0}
        try:
            queries = {b: compile_query(det.rule, b) for b in ("kql", "spl")}
            spec = defender_spec(det.rule)
            defender = compile_defender(det.rule) if spec is not None else None
        except (ParseError, SigmaError, re.error) as e:
            r["errors"].append(str(e))
            report[det.id] = r
            continue
        if defender is not None:
            r["mde"] = []
        action = defender_action(det.rule)
        r["errors"] += base_errors(det.rule)
        for label, ev in corpus_for(det, dets, replay_events, public_events):
            try:
                expected = matches(det.rule, ev)
            except SigmaError as e:
                r["errors"].append(f"{label}: {e}")
                continue
            r["events"] += 1
            for b, q in queries.items():
                got = q(ev) is True
                if got != expected:
                    r[b].append({"event": label, "engine": expected, b: got, "raw": ev})
            if defender is not None and spec is not None:
                for full_path in (False, True):
                    row = defender_row(ev, spec, full_path, action)
                    r["mde_rows"] += 1
                    got = defender(row) is True
                    if got != expected:
                        r["mde"].append({"event": f"{label} ({'full path' if full_path else 'folder'} in FolderPath)",
                                         "engine": expected, "mde": got, "raw": row})
        report[det.id] = r
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--filter")
    ap.add_argument("-v", "--verbose", action="store_true", help="print every divergent event")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    report = check(args.filter)
    def bad_of(v: dict) -> int:
        return len(v["kql"]) + len(v["spl"]) + len(v["errors"]) + len(v["mde"] or [])

    if args.json:
        strip = lambda rows: [{x: y for x, y in d.items() if x != "raw"} for d in rows]
        print(json.dumps({k: {**v, "kql": strip(v["kql"]), "spl": strip(v["spl"]),
                              "mde": None if v["mde"] is None else strip(v["mde"])}
                          for k, v in report.items()}, indent=2))
        return 1 if any(bad_of(v) for v in report.values()) else 0

    print(f"{BOLD}Query parity · deployed KQL / SPL / Defender advanced hunting vs tested rule{RESET}\n")
    width = max(len(k) for k in report) if report else 10
    total = bad = 0
    for det, r in report.items():
        total += r["events"]
        n = bad_of(r)
        bad += n
        mark = f"{GREEN}✓{RESET}" if not n else f"{RED}✗{RESET}"
        defender = "" if r["mde"] is None else " · Defender identical (both FolderPath forms)"
        detail = (f"{DIM}{r['events']} events · KQL identical · SPL identical{defender}{RESET}" if not n else
                  f"KQL {len(r['kql'])} divergent · SPL {len(r['spl'])} divergent"
                  + ("" if r["mde"] is None else f" · Defender {len(r['mde'])} divergent")
                  + (f" · {len(r['errors'])} error(s)" if r["errors"] else ""))
        print(f"  {mark} {det:<{width}}  {detail}")
        for e in r["errors"]:
            print(f"      {RED}{e}{RESET}")
        for b in ("kql", "spl", "mde"):
            for d in (r[b] or [])[: None if args.verbose else 3]:
                print(f"      {RED}{b.upper()}{RESET} {d['event']}: engine={'match' if d['engine'] else 'no match'}"
                      f" {b}={'match' if d[b] else 'no match'}")
                if args.verbose:
                    print(f"        {DIM}{json.dumps(d['raw'])[:300]}{RESET}")
    verdict = f"{GREEN}0 divergences{RESET}" if not bad else f"{RED}{bad} divergence(s){RESET}"
    print(f"\n{BOLD}{total} event verdicts compared per backend · {verdict}{RESET}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
