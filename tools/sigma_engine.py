"""
sigma_engine.py - a minimal, dependency-light Sigma rule evaluator.

Why build our own instead of only relying on a SIEM?
  * Lets CI *execute* every rule against sample telemetry offline,
    with zero SIEM required -> real unit tests for detections.
  * Keeps matching semantics transparent and auditable.

Supported Sigma features (docs/SIGMA_SUPPORT.md, generated and proven by tools/sigma_support.py)
  * Selections as maps (AND across fields) or lists of maps (OR)
  * Value lists (OR) and the |all modifier (AND)
  * Modifiers: contains, startswith, endswith, re (with i / m / s), all, cased, exists
  * |re follows the Sigma specification: case-sensitive unless the pattern starts
    with (?i) or the i sub-modifier is used (re|i), exactly like pySigma and every SIEM
  * Wildcards * and ? in plain values
  * null values (field must be absent/empty)
  * Conditions: and / or / not / parentheses,
    "1 of <pattern>", "all of <pattern>", "1 of them", "all of them"; a list of conditions is OR

Everything else is refused with SigmaError - other modifiers, Sigma v1 aggregations
(| count() ... and detection.timeframe), and values the Sigma specification reads differently
from a literal string (the escapes \\*, \\? and \\\\, and wildcards inside contains / startswith /
endswith) - so no rule is ever evaluated approximately.
"""
from __future__ import annotations

import fnmatch
import functools
import re
from collections.abc import Callable, Sequence
from typing import Any, cast

SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "re", "all", "cased", "exists", "i", "m", "s"}
RE_FLAGS = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}


class SigmaError(Exception):
    """Raised when a rule uses unsupported or malformed syntax."""


# --------------------------------------------------------------------------- #
# Field / value matching
# --------------------------------------------------------------------------- #
def _get_field(event: dict, field: str) -> Any:
    """Case-insensitive field lookup with dotted-path support."""
    if field in event:
        return event[field]
    for k, v in event.items():
        if k.lower() == field.lower():
            return v
    cur: Any = event
    for part in field.split("."):
        if not isinstance(cur, dict):
            return None
        nxt = None
        for k, v in cur.items():
            if k.lower() == part.lower():
                nxt = v
                break
        if nxt is None:
            return None
        cur = nxt
    return cur


def _match_single(actual: Any, expected: Any, mods: Sequence[str]) -> bool:
    if "exists" in mods:
        present = actual is not None and actual != ""
        return present == bool(expected)

    if expected is None:
        return actual is None or actual == ""
    if actual is None:
        return False

    cased = "cased" in mods
    a, e = str(actual), str(expected)

    if "re" in mods:
        return _regex(e, sum(RE_FLAGS[m] for m in set(mods) & RE_FLAGS.keys())).search(a) is not None

    if not cased:
        a, e = a.lower(), e.lower()

    if "contains" in mods:
        return e in a
    if "startswith" in mods:
        return a.startswith(e)
    if "endswith" in mods:
        return a.endswith(e)

    # Plain equality, with Sigma wildcard support: only * and ? are special
    # (fnmatch would also treat [...] as a character class, which Sigma does not)
    if "*" in e or "?" in e:
        return _wildcard(e).fullmatch(a) is not None
    return a == e


@functools.lru_cache(maxsize=4096)
def _wildcard(value: str) -> re.Pattern[str]:
    return re.compile(re.escape(value).replace(r"\*", ".*").replace(r"\?", "."), re.DOTALL)


@functools.lru_cache(maxsize=4096)
def _regex(pattern: str, flags: int = 0) -> re.Pattern[str]:
    try:
        return re.compile(pattern, flags)
    except re.error as e:
        raise SigmaError(f"Invalid regular expression {pattern!r}: {e}") from e


@functools.lru_cache(maxsize=4096)
def _parse_key(key: str) -> tuple[str, tuple[str, ...]]:
    """'CommandLine|contains|all' -> ('CommandLine', ('contains', 'all')), validated once per key."""
    field, *mods = key.split("|")
    unknown = set(mods) - SUPPORTED_MODIFIERS
    if unknown:
        raise SigmaError(f"Unsupported modifier(s) {sorted(unknown)} on field '{field}'")
    if set(mods) & RE_FLAGS.keys() and "re" not in mods:
        raise SigmaError(f"Modifiers i / m / s only apply to |re (field '{field}')")
    return field, tuple(mods)


_SIGMA_ESCAPE = re.compile(r"\\[\\*?]")
_AFFIX = {"contains", "startswith", "endswith"}


@functools.lru_cache(maxsize=4096)
def _check_scalar(field: str, mods: tuple[str, ...], value: Any) -> None:
    if not isinstance(value, str) or "re" in mods or "exists" in mods:
        return
    if _SIGMA_ESCAPE.search(value):
        raise SigmaError(f"Field '{field}': value {value!r} holds a Sigma escape (\\*, \\? or \\\\), which Sigma reads "
                         "as an escape and RASD would read literally; write single backslashes, or use |re")
    if ("*" in value or "?" in value) and _AFFIX & set(mods):
        raise SigmaError(f"Field '{field}': value {value!r} has a wildcard inside |{'|'.join(sorted(_AFFIX & set(mods)))}, "
                         "which Sigma expands and RASD would compare literally; split the value, or use |re")


def check_values(field: str, mods: tuple[str, ...], expected: Any) -> None:
    """Refuse the values RASD would read differently from the Sigma specification."""
    for v in expected if isinstance(expected, list) else [expected]:
        if isinstance(v, (str, int, float, bool)) or v is None:
            _check_scalar(field, mods, v)


def check_keywords(words: list) -> None:
    """Keywords are searched as plain substrings; Sigma would expand wildcards and escapes in them."""
    for w in words:
        if isinstance(w, str) and ("*" in w or "?" in w or _SIGMA_ESCAPE.search(w)):
            raise SigmaError(f"Keyword {w!r} has a wildcard or a Sigma escape, which RASD would search literally; "
                             "write a field condition instead")


def _match_field(event: dict, key: str, expected: Any) -> bool:
    field, mods = _parse_key(key)
    check_values(field, mods, expected)

    actual = _get_field(event, field)
    values = expected if isinstance(expected, list) else [expected]
    actual_values = actual if isinstance(actual, list) else [actual]

    def one(v: Any) -> bool:
        return any(_match_single(av, v, mods) for av in actual_values)

    return all(one(v) for v in values) if "all" in mods else any(one(v) for v in values)


def _match_selection(event: dict, selection: Any) -> bool:
    if isinstance(selection, dict):
        return all(_match_field(event, k, v) for k, v in selection.items())
    if isinstance(selection, list):
        if all(isinstance(s, dict) for s in selection):      # list of maps -> OR
            return any(_match_selection(event, s) for s in selection)
        check_keywords(selection)
        blob = " ".join(str(v) for v in event.values()).lower()  # keywords
        return any(str(s).lower() in blob for s in selection)
    raise SigmaError(f"Invalid selection type: {type(selection).__name__}")


# --------------------------------------------------------------------------- #
# Condition parsing (recursive descent)
#   expr   := term ( 'or' term )*
#   term   := factor ( 'and' factor )*
#   factor := 'not' factor | '(' expr ')' | quant | IDENT
#   quant  := ('1'|'all') 'of' (PATTERN | 'them')
# --------------------------------------------------------------------------- #
_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_\*]+)")


def tokenize(condition: str) -> list[str]:
    return list(_tokenize(condition))


@functools.lru_cache(maxsize=1024)
def _tokenize(condition: str) -> tuple[str, ...]:
    pos, tokens = 0, []
    condition = condition.strip()
    while pos < len(condition):
        m = _TOKEN.match(condition, pos)
        if not m:
            raise SigmaError(f"Cannot parse condition near: {condition[pos:]!r}")
        tokens.append(m.group(1))
        pos = m.end()
    return tuple(tokens)


def conditions(detection: dict) -> list[str]:
    """The rule's conditions, refusing what this engine does not evaluate."""
    if "timeframe" in detection:
        raise SigmaError("detection.timeframe belongs to the Sigma v1 aggregations, removed in Sigma v2: "
                         "write a correlation rule")
    condition = detection.get("condition")
    if not condition:
        raise SigmaError("Rule has no detection.condition")
    conds = condition if isinstance(condition, list) else [condition]
    for c in conds:
        if not isinstance(c, str) or not c.strip():
            raise SigmaError("detection.condition must be a string or a list of strings")
        if "|" in c:
            raise SigmaError("aggregations in a condition (| count() ...) were removed in Sigma v2: "
                             "write a correlation rule")
    return conds


def selection_names(detection: dict) -> list[str]:
    return [k for k in detection if k not in ("condition", "timeframe")]


def resolve_pattern(detection: dict, target: str) -> list[str]:
    names = selection_names(detection)
    if target.lower() == "them":
        return names
    found = [n for n in names if fnmatch.fnmatchcase(n, target)]
    if not found:
        raise SigmaError(f"No selections match pattern '{target}'")
    return found


class _Parser:
    def __init__(self, tokens: list[str], detection: dict, event: dict):
        self.t, self.i = tokens, 0
        self.det = detection
        self.event = event

    def peek(self) -> str | None:
        return self.t[self.i].lower() if self.i < len(self.t) else None

    def take(self) -> str:
        if self.i >= len(self.t):
            raise SigmaError("Unexpected end of condition")
        tok = self.t[self.i]
        self.i += 1
        return tok

    def parse(self) -> bool:
        result = self.expr()
        if self.i != len(self.t):
            raise SigmaError(f"Unexpected token: {self.t[self.i]!r}")
        return result

    def expr(self) -> bool:
        val = self.term()
        while self.peek() == "or":
            self.take()
            rhs = self.term()          # always evaluate -> full syntax validation
            val = val or rhs
        return val

    def term(self) -> bool:
        val = self.factor()
        while self.peek() == "and":
            self.take()
            rhs = self.factor()
            val = val and rhs
        return val

    def factor(self) -> bool:
        tok = self.peek()
        if tok is None:
            raise SigmaError("Unexpected end of condition")
        if tok == "not":
            self.take()
            return not self.factor()
        if tok == "(":
            self.take()
            val = self.expr()
            if self.peek() != ")":
                raise SigmaError("Missing closing parenthesis")
            self.take()
            return val
        if tok in ("1", "all") and self.i + 1 < len(self.t) and self.t[self.i + 1].lower() == "of":
            quant = self.take().lower()
            self.take()  # 'of'
            names = resolve_pattern(self.det, self.take())
            results = [_match_selection(self.event, self.det[n]) for n in names]
            return all(results) if quant == "all" else any(results)
        name = self.take()
        if name not in self.det or name in ("condition", "timeframe"):
            raise SigmaError(f"Condition references unknown selection '{name}'")
        return _match_selection(self.event, self.det[name])


def matches(rule: dict, event: dict) -> bool:
    """Return True if `event` satisfies the Sigma `rule`."""
    detection = rule.get("detection") or {}
    return any(_Parser(tokenize(c), detection, event).parse() for c in conditions(detection))


# --------------------------------------------------------------------------- #
# Compiled rules: the same semantics, resolved once per rule instead of per event
# --------------------------------------------------------------------------- #
# matches() re-reads the rule for every event: it splits keys, tokenizes and parses the
# condition, lowercases every expected value. compile_rule() does that once and returns a
# closure - several times faster for replay, evidence and benchmark, which run every rule
# over large exports. matches() stays the reference: the unit tests prove both return the
# same verdict on every test, mutation, fuzz variant, replay event and rule mutant.
def _getter(field: str):
    lower = field.lower()
    parts = [p.lower() for p in field.split(".")] if "." in field else None

    def get(event: dict) -> Any:
        if field in event:
            return event[field]
        for k, v in event.items():
            if k.lower() == lower:
                return v
        if parts is None:                      # a plain name was already compared above
            return None
        cur: Any = event
        for part in parts:
            if not isinstance(cur, dict):
                return None
            nxt = None
            for k, v in cur.items():
                if k.lower() == part:
                    nxt = v
                    break
            if nxt is None:
                return None
            cur = nxt
        return cur
    return get


def _compile_single(expected: Any, mods: tuple[str, ...]):
    if "exists" in mods:
        want = bool(expected)
        return lambda a: (a is not None and a != "") == want
    if expected is None:
        return lambda a: a is None or a == ""
    cased = "cased" in mods
    e = str(expected)
    if "re" in mods:
        rx = _regex(e, sum(RE_FLAGS[m] for m in set(mods) & RE_FLAGS.keys()))
        return lambda a: a is not None and rx.search(str(a)) is not None
    if not cased:
        e = e.lower()
    text = str if cased else (lambda a: str(a).lower())
    if "contains" in mods:
        return lambda a: a is not None and e in text(a)
    if "startswith" in mods:
        return lambda a: a is not None and text(a).startswith(e)
    if "endswith" in mods:
        return lambda a: a is not None and text(a).endswith(e)
    if "*" in e or "?" in e:
        w = _wildcard(e)
        return lambda a: a is not None and w.fullmatch(text(a)) is not None
    return lambda a: a is not None and text(a) == e


def _compile_field(key: str, expected: Any):
    field, mods = _parse_key(key)
    check_values(field, mods, expected)
    get = _getter(field)
    singles = [_compile_single(v, mods) for v in (expected if isinstance(expected, list) else [expected])]
    if "all" in mods:
        def match_all(event: dict) -> bool:
            actual = get(event)
            values = actual if isinstance(actual, list) else [actual]
            return all(any(s(av) for av in values) for s in singles)
        return match_all

    def match_any(event: dict) -> bool:
        actual = get(event)
        for av in (actual if isinstance(actual, list) else (actual,)):
            for s in singles:
                if s(av):
                    return True
        return False
    return match_any


def _compile_selection(selection: Any):
    if isinstance(selection, dict):
        fields = [_compile_field(k, v) for k, v in selection.items()]

        def all_fields(event: dict) -> bool:
            # an explicit loop: this is the hot path, and it beats all() over a generator
            for f in fields:  # noqa: SIM110
                if not f(event):
                    return False
            return True
        return all_fields
    if isinstance(selection, list):
        if all(isinstance(s, dict) for s in selection):
            subs = [_compile_selection(s) for s in selection]
            return lambda event: any(f(event) for f in subs)
        check_keywords(selection)
        words = [str(s).lower() for s in selection]

        def keywords(event: dict) -> bool:
            blob = " ".join(str(v) for v in event.values()).lower()
            return any(w in blob for w in words)
        return keywords
    raise SigmaError(f"Invalid selection type: {type(selection).__name__}")


class _Compiler(_Parser):
    """The condition grammar of _Parser, producing closures instead of verdicts."""

    def __init__(self, tokens: list[str], detection: dict, cache: dict):
        super().__init__(tokens, detection, {})
        self.cache = cache

    def selection(self, name: str):
        if name not in self.cache:
            self.cache[name] = _compile_selection(self.det[name])
        return self.cache[name]

    def expr(self):
        parts = [self.term()]
        while self.peek() == "or":
            self.take()
            parts.append(self.term())
        return parts[0] if len(parts) == 1 else (lambda event: any(p(event) for p in parts))

    def term(self):
        parts = [self.factor()]
        while self.peek() == "and":
            self.take()
            parts.append(self.factor())
        return parts[0] if len(parts) == 1 else (lambda event: all(p(event) for p in parts))

    def factor(self):
        tok = self.peek()
        if tok is None:
            raise SigmaError("Unexpected end of condition")
        if tok == "not":
            self.take()
            inner = self.factor()
            return lambda event: not inner(event)
        if tok == "(":
            self.take()
            val = self.expr()
            if self.peek() != ")":
                raise SigmaError("Missing closing parenthesis")
            self.take()
            return val
        if tok in ("1", "all") and self.i + 1 < len(self.t) and self.t[self.i + 1].lower() == "of":
            quant = self.take().lower()
            self.take()  # 'of'
            sels = [self.selection(n) for n in resolve_pattern(self.det, self.take())]
            if quant == "all":
                return lambda event: all(f(event) for f in sels)
            return lambda event: any(f(event) for f in sels)
        name = self.take()
        if name not in self.det or name in ("condition", "timeframe"):
            raise SigmaError(f"Condition references unknown selection '{name}'")
        return self.selection(name)


def compile_rule(rule: dict):
    """A function event -> bool with exactly the verdicts of matches(rule, event).
    The rule is read now: change it later and compile it again."""
    detection = rule.get("detection") or {}
    cache: dict = {}
    conds = [cast("Callable[[dict], bool]", _Compiler(tokenize(c), detection, cache).parse())
             for c in conditions(detection)]
    return conds[0] if len(conds) == 1 else (lambda event: any(c(event) for c in conds))


# --------------------------------------------------------------------------- #
# Explainability: why did (or didn't) a rule match this event?
# --------------------------------------------------------------------------- #
def _explain_field(event: dict, key: str, expected: Any) -> dict:
    field, *mods = key.split("|")
    actual = _get_field(event, field)
    values = expected if isinstance(expected, list) else [expected]
    actual_values = actual if isinstance(actual, list) else [actual]
    hits = [v for v in values if any(_match_single(av, v, mods) for av in actual_values)]
    ok = (len(hits) == len(values)) if "all" in mods else bool(hits)
    return {"field": field, "modifiers": mods, "actual": actual, "expected": values,
            "matched_values": hits, "result": ok}


def _explain_selection(event: dict, selection: Any) -> dict:
    if isinstance(selection, dict):
        fields = [_explain_field(event, k, v) for k, v in selection.items()]
        return {"type": "all-of", "result": all(f["result"] for f in fields), "fields": fields}
    if isinstance(selection, list) and all(isinstance(s, dict) for s in selection):
        alts = [_explain_selection(event, s) for s in selection]
        return {"type": "any-of", "result": any(a["result"] for a in alts), "alternatives": alts}
    return {"type": "keywords", "result": _match_selection(event, selection), "keywords": selection}


def explain(rule: dict, event: dict) -> dict:
    """Evaluate a rule with a full trace of every selection and field check."""
    detection = rule.get("detection") or {}
    return {
        "rule": rule.get("title"),
        "condition": detection.get("condition"),
        "matched": matches(rule, event),
        "selections": {name: _explain_selection(event, detection[name]) for name in selection_names(detection)},
    }
