"""
automata.py - exact finite automata for the patterns RASD rules use.

certify.py proves statements about rules: an event that fires a rule, an event that slips
past it, a whole family of attacker command lines that can never slip past it. Each proof
needs every pattern of the rule as a finite automaton that accepts exactly the strings the
engine accepts. This module builds those automata and answers questions about them.

What "exactly" means here
  * The alphabet is every character a Python string can hold: all 1,114,112 code points,
    surrogates included. Nothing is sampled, so a statement about "every string" is a
    statement about every string.
  * A pattern is read by Python's own regular expression parser (re._parser), so the
    structure reasoned about is the structure the engine runs.
  * Whether one character matches one atom (a literal, a class, \\d, \\w, the dot) under the
    pattern's flags is decided by the engine itself: the atom is compiled with those flags and
    run once over the whole code space. Case folding quirks are measured, not assumed: under
    IGNORECASE `k` also matches the Kelvin sign U+212A, and str.lower() turns U+0130 into two
    characters.
  * Anchors and word boundaries follow the engine's own definitions (_sre.c, SRE(at)): ^ and
    \\A at position 0, $ at the end or before a final newline, \\Z at the end, \\b between a word
    and a non-word character. Everything else (backreferences, lookarounds, \\B, conditional and
    atomic groups, possessive repeats, the ASCII and LOCALE flags) is refused, never approximated.

Characters that no pattern tells apart form one class (a minterm of the atoms), so an
automaton has a few dozen classes instead of a million letters and still covers every code point.

Constructions (the theory is in docs/CERTIFY.md)
  Thompson      pattern -> automaton with epsilon moves, one small fragment per operator
  Rabin-Scott   subset construction -> deterministic automaton; anchors and \\b become
                obligations on the next character, carried with each thread
  Moore         partition refinement -> the minimal automaton (Myhill-Nerode)
  product       automata in lockstep: intersection, union, difference, equivalence, solving
  counting      transfer-matrix powers: how many strings of length n an automaton accepts,
                and uniform random strings of a given length
"""
from __future__ import annotations

import bisect
import functools
import importlib
import random
import re
import unicodedata
from collections import deque
from collections.abc import Callable, Iterable, Sequence
from typing import Any


class AutomataError(Exception):
    """A pattern uses something that cannot be turned into an exact automaton."""


def _sre() -> tuple[Any, Any]:
    """Python's own regular expression parser and its opcode table."""
    for parser, constants in (("re._parser", "re._constants"), ("sre_parse", "sre_constants")):
        try:
            return importlib.import_module(parser), importlib.import_module(constants)
        except ImportError:
            continue
    raise ImportError("Python's regular expression parser was not found")


_SP, _SC = _sre()
LITERAL, NOT_LITERAL, ANY, IN = _SC.LITERAL, _SC.NOT_LITERAL, _SC.ANY, _SC.IN
BRANCH, SUBPATTERN, AT = _SC.BRANCH, _SC.SUBPATTERN, _SC.AT
MAX_REPEAT, MIN_REPEAT, MAXREPEAT = _SC.MAX_REPEAT, _SC.MIN_REPEAT, _SC.MAXREPEAT
NEGATE, RANGE, CATEGORY = _SC.NEGATE, _SC.RANGE, _SC.CATEGORY
_CHAR_OPS = (LITERAL, NOT_LITERAL, ANY, IN)
_REFUSED = {"GROUPREF": "a backreference", "GROUPREF_EXISTS": "a conditional group",
            "ASSERT": "a lookahead or lookbehind", "ASSERT_NOT": "a negative lookahead or lookbehind",
            "ATOMIC_GROUP": "an atomic group", "POSSESSIVE_REPEAT": "a possessive repeat"}
_CATEGORY_SOURCE = {"CATEGORY_DIGIT": r"\d", "CATEGORY_NOT_DIGIT": r"\D", "CATEGORY_SPACE": r"\s",
                    "CATEGORY_NOT_SPACE": r"\S", "CATEGORY_WORD": r"\w", "CATEGORY_NOT_WORD": r"\W"}
_ALLOWED_FLAGS = re.IGNORECASE | re.MULTILINE | re.DOTALL | re.UNICODE | re.VERBOSE

UNIVERSE = 0x110000             # every code point a Python string can hold, surrogates included
REPEAT_LIMIT = 1000             # {m,n} bounds that are unrolled; larger bounds are refused
STATE_LIMIT = 200_000           # a construction that grows past this is refused, never cut short
SMALL_SIGMA, FINAL_SIGMA = 0x3C3, 0x3C2

# Characters a witness prefers, in order, so that the strings certify prints stay readable.
_PREFERRED = ("abcdefghijklmnopqrstuvwxyz" "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "0123456789"
              " -_./\\:\"'=,;+*#%&()[]{}<>!?@$^|~`\t\n\r"
              "éÉßİıſKΣσςπжЖ"
              "٣٠０–—―  ​€中\U0001f600")


# --------------------------------------------------------------------------- #
# Sets of code points
# --------------------------------------------------------------------------- #
class CharSet:
    """A set of code points: sorted, disjoint, non-touching half-open intervals [a, b)."""

    __slots__ = ("bounds",)

    def __init__(self, bounds: Iterable[int] = ()):
        self.bounds = tuple(bounds)

    @classmethod
    def points(cls, cps: Iterable[int]) -> CharSet:
        bounds: list[int] = []
        for cp in sorted(set(cps)):
            if bounds and bounds[-1] == cp:
                bounds[-1] = cp + 1
            else:
                bounds += (cp, cp + 1)
        return cls(bounds)

    @classmethod
    def full(cls) -> CharSet:
        return cls((0, UNIVERSE))

    def __contains__(self, cp: object) -> bool:
        return isinstance(cp, int) and bisect.bisect_right(self.bounds, cp) % 2 == 1

    def __len__(self) -> int:
        return sum(self.bounds[i + 1] - self.bounds[i] for i in range(0, len(self.bounds), 2))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CharSet) and self.bounds == other.bounds

    def __hash__(self) -> int:
        return hash(self.bounds)

    def __repr__(self) -> str:
        spans = [f"{self.bounds[i]:X}-{self.bounds[i + 1] - 1:X}" for i in range(0, min(len(self.bounds), 8), 2)]
        return f"CharSet({', '.join(spans)}{', ...' if len(self.bounds) > 8 else ''})"

    def _combine(self, other: CharSet, keep: Callable[[bool, bool], bool]) -> CharSet:
        out: list[int] = []
        inside = False
        for p in sorted(set(self.bounds) | set(other.bounds)):
            now = keep(p in self, p in other)
            if now != inside:
                out.append(p)
                inside = now
        return CharSet(out)

    def __or__(self, other: CharSet) -> CharSet:
        return self._combine(other, lambda a, b: a or b)

    def __and__(self, other: CharSet) -> CharSet:
        return self._combine(other, lambda a, b: a and b)

    def __sub__(self, other: CharSet) -> CharSet:
        return self._combine(other, lambda a, b: a and not b)


@functools.lru_cache(maxsize=1)
def universe_text() -> str:
    """Every code point once, in order: index i holds chr(i)."""
    return "".join(map(chr, range(UNIVERSE)))


@functools.lru_cache(maxsize=1)
def _lowered() -> tuple[str, dict[int, str]]:
    lows = [ch.lower() for ch in universe_text()]
    multi = {cp: low for cp, low in enumerate(lows) if len(low) != 1}
    for cp in multi:
        lows[cp] = chr(cp)            # a placeholder never read: these code points are classes of their own
    return "".join(lows), multi


def lowered_text() -> str:
    """Index i holds str.lower(chr(i)) when that is one character."""
    return _lowered()[0]


def multi_lower() -> dict[int, str]:
    """The code points str.lower() turns into more than one character (U+0130 -> 'i' + U+0307)."""
    return _lowered()[1]


@functools.cache
def scan(atom: str, flags: int = 0, lowered: bool = False) -> CharSet:
    """The code points c for which the one-character pattern `atom` matches c, or matches
    c.lower() when lowered is set - decided by the engine itself over the whole code space."""
    rx = re.compile(f"(?:{atom})+", flags)
    bounds: list[int] = []
    for m in rx.finditer(lowered_text() if lowered else universe_text()):
        bounds += (m.start(), m.end())
    found = CharSet(bounds)
    if lowered and multi_lower():
        found = found - CharSet.points(multi_lower())
    return found


def word_chars() -> CharSet:
    """The characters \\b counts as word characters (the engine's \\w)."""
    return scan(r"\w")


NEWLINE = CharSet((10, 11))


# --------------------------------------------------------------------------- #
# Alphabets: the classes of characters no pattern of interest tells apart
# --------------------------------------------------------------------------- #
class Alphabet:
    """A partition of all code points into classes. Two characters share a class exactly when
    every set the alphabet was built from holds both or neither, so any automaton built over
    those sets reads them the same way. Class 0 has the most readable representative."""

    def __init__(self, sets: Iterable[CharSet], forced: Iterable[int] = ()):
        self.forced = frozenset(forced)
        self.sets = tuple(dict.fromkeys([*sets, *(CharSet.points([cp]) for cp in sorted(self.forced))]))
        self._index = {cs: j for j, cs in enumerate(self.sets)}
        self._masks: dict[CharSet, int] = {}
        toggles: dict[int, int] = {}
        for j, cs in enumerate(self.sets):
            for p in cs.bounds:
                toggles[p] = toggles.get(p, 0) ^ (1 << j)
        starts, sigs, sig = [0], [0], 0
        for p in sorted(toggles):
            if p >= UNIVERSE:
                break
            sig ^= toggles[p]
            if p == starts[-1]:
                sigs[-1] = sig
            elif sig != sigs[-1]:
                starts.append(p)
                sigs.append(sig)
        ends = starts[1:] + [UNIVERSE]
        groups: dict[int, list[int]] = {}
        for i, s in enumerate(sigs):
            groups.setdefault(s, []).append(i)
        rep: dict[int, int] = {}
        rank: dict[int, int] = {}
        for r, ch in enumerate(_PREFERRED):
            s = sigs[bisect.bisect_right(starts, ord(ch)) - 1]
            if s not in rep:
                rep[s], rank[s] = ord(ch), r
        for s, segs in groups.items():
            if s not in rep:
                rep[s] = _plain_member([(starts[i], ends[i]) for i in segs])
        order = sorted(groups, key=lambda s: (rank.get(s, len(_PREFERRED)), rep[s]))
        number = {s: k for k, s in enumerate(order)}
        self.starts = starts
        self.seg_class = [number[s] for s in sigs]
        self.size = len(order)
        self.signature = order
        self.rep = [rep[s] for s in order]
        self.segments = [[(starts[i], ends[i]) for i in groups[s]] for s in order]
        self.weight = [sum(b - a for a, b in segs) for segs in self.segments]

    def classify(self, cp: int) -> int:
        return self.seg_class[bisect.bisect_right(self.starts, cp) - 1]

    def mask(self, cs: CharSet) -> int:
        """The classes inside `cs`, as a bit mask (cs must be one of the alphabet's sets)."""
        if cs not in self._masks:
            if cs not in self._index:
                raise AutomataError(f"{cs!r} is not one of the sets this alphabet was built from")
            bit = 1 << self._index[cs]
            self._masks[cs] = sum(1 << k for k, s in enumerate(self.signature) if s & bit)
        return self._masks[cs]

    def refines(self, other: Alphabet) -> bool:
        return set(other.sets) <= set(self.sets)

    def member(self, k: int, rng: random.Random) -> int:
        """A code point of class k, uniformly at random."""
        r = rng.randrange(self.weight[k])
        for a, b in self.segments[k]:
            if r < b - a:
                return a + r
            r -= b - a
        raise AssertionError("class weight does not match its segments")

    def text(self, word: Sequence[int]) -> str:
        """A word of classes written with each class's representative character."""
        return "".join(chr(self.rep[k]) for k in word)


def _plain_member(segments: list[tuple[int, int]]) -> int:
    """The first assigned, printable code point of a class, else its first code point."""
    budget = 4096
    for a, b in segments:
        for cp in range(a, min(b, a + budget)):
            if unicodedata.category(chr(cp))[0] not in "CZ":
                return cp
        budget -= min(b - a, budget)
        if budget <= 0:
            break
    return segments[0][0]


def joint(alphabets: Iterable[Alphabet], extra: Iterable[CharSet] = ()) -> Alphabet:
    """The coarsest alphabet that refines every given alphabet (and the extra sets)."""
    sets: list[CharSet] = []
    forced: set[int] = set()
    for ab in alphabets:
        sets += ab.sets
        forced |= ab.forced
    return Alphabet([*sets, *extra], forced)


# --------------------------------------------------------------------------- #
# Patterns
# --------------------------------------------------------------------------- #
A_BEGIN, A_BEGIN_LINE, A_END, A_END_LINE, A_END_STRING, A_BOUNDARY = range(6)


def _escape(cp: int) -> str:
    return f"\\u{cp:04x}" if cp < 0x10000 else f"\\U{cp:08x}"


def _atom_source(op: Any, av: Any) -> str:
    """One parsed character atom written back as a pattern the parser reads to the same atom."""
    if op is LITERAL:
        return f"[{_escape(av)}]"
    if op is NOT_LITERAL:
        return f"[^{_escape(av)}]"
    if op is ANY:
        return "."
    parts, negate = [], False
    for i, (iop, iav) in enumerate(av):
        if iop is NEGATE and i == 0:
            negate = True
        elif iop is LITERAL:
            parts.append(_escape(iav))
        elif iop is RANGE:
            parts.append(f"{_escape(iav[0])}-{_escape(iav[1])}")
        elif iop is CATEGORY and str(iav) in _CATEGORY_SOURCE:
            parts.append(_CATEGORY_SOURCE[str(iav)])
        else:
            raise AutomataError(f"character class item {iop} {iav} is not supported")
    return "[" + ("^" if negate else "") + "".join(parts) + "]"


def _assertion(av: Any, flags: int) -> int:
    name = str(av)
    if name == "AT_BEGINNING":
        return A_BEGIN_LINE if flags & re.MULTILINE else A_BEGIN
    if name == "AT_BEGINNING_STRING":
        return A_BEGIN
    if name == "AT_END":
        return A_END_LINE if flags & re.MULTILINE else A_END
    if name == "AT_END_STRING":
        return A_END_STRING
    if name == "AT_BOUNDARY":
        return A_BOUNDARY
    if name == "AT_NON_BOUNDARY":
        raise AutomataError("\\B is refused: its result on the empty string differs between Python versions")
    raise AutomataError(f"anchor {name} is not supported")


def _nullable(items: Sequence[Any]) -> bool:
    for op, av in items:
        if op in _CHAR_OPS:
            return False
        if op is BRANCH:
            if not any(_nullable(alt) for alt in av[1]):
                return False
        elif op is SUBPATTERN:
            if not _nullable(av[3]):
                return False
        elif op in (MAX_REPEAT, MIN_REPEAT) and av[0] > 0 and not _nullable(av[2]):
            return False
    return True


class Regex:
    """One pattern, read by Python's parser, ready to become an automaton.

    search=True  : the language of strings s with re.search(pattern, s, flags)
    search=False : the language of strings s with re.fullmatch(pattern, s, flags)
    lowered=True : the pattern is matched against s.lower() instead of s (anchors refused)
    """

    def __init__(self, pattern: str, flags: int = 0, *, search: bool, lowered: bool = False):
        self.pattern, self.flags, self.search, self.lowered = pattern, flags, search, lowered
        if flags & ~_ALLOWED_FLAGS:
            raise AutomataError(f"flags {flags:#x} include one certify does not model")
        try:
            parsed = _SP.parse(pattern, flags)
        except re.error as e:
            raise AutomataError(f"invalid pattern {pattern!r}: {e}") from e
        state = getattr(parsed, "state", None) or parsed.pattern
        self.global_flags = int(state.flags)
        if self.global_flags & (re.ASCII | re.LOCALE):
            raise AutomataError("the ASCII and LOCALE flags change what \\w and case folding mean; refused")
        self.items = list(parsed)
        self.needs_word = self.needs_newline = False
        self._sets: dict[CharSet, None] = {}
        self._walk(self.items, self.global_flags)
        self.charsets = tuple(self._sets)
        self.forced = frozenset(multi_lower()) if lowered else frozenset()
        self._dfa: DFA | None = None

    def __repr__(self) -> str:
        return f"Regex({self.pattern!r}, {self.flags}, search={self.search}, lowered={self.lowered})"

    def charset(self, op: Any, av: Any, flags: int) -> CharSet:
        return scan(_atom_source(op, av), flags & (re.IGNORECASE | re.DOTALL), self.lowered)

    def _walk(self, items: Sequence[Any], flags: int) -> None:
        for op, av in items:
            if op in _CHAR_OPS:
                self._sets[self.charset(op, av, flags)] = None
            elif op is BRANCH:
                for alt in av[1]:
                    self._walk(alt, flags)
            elif op is SUBPATTERN:
                _group, add, remove, sub = av
                if add & (re.ASCII | re.LOCALE):
                    raise AutomataError("the ASCII and LOCALE flags are refused")
                self._walk(sub, (flags | add) & ~remove)
            elif op in (MAX_REPEAT, MIN_REPEAT):
                lo, hi, sub = av
                if lo > REPEAT_LIMIT or (hi != MAXREPEAT and hi > REPEAT_LIMIT):
                    raise AutomataError(f"repeat bounds above {REPEAT_LIMIT} are refused")
                if (hi == MAXREPEAT or hi > 1) and _nullable(sub):
                    raise AutomataError("a repeated group that can match the empty string is refused "
                                        "(the engine stops such loops early, so its language is not the textbook one)")
                self._walk(sub, flags)
            elif op is AT:
                if self.lowered:
                    raise AutomataError("anchors are not supported on a lowered value")
                kind = _assertion(av, flags)
                if kind == A_BOUNDARY:
                    self.needs_word = True
                if kind in (A_BEGIN_LINE, A_END, A_END_LINE):
                    self.needs_newline = True
            else:
                raise AutomataError(f"{_REFUSED.get(str(op), str(op))} is not supported")

    def alphabet_sets(self) -> list[CharSet]:
        return [*self.charsets, *([word_chars()] if self.needs_word else []),
                *([NEWLINE] if self.needs_newline else [])]

    def alphabet(self) -> Alphabet:
        return Alphabet(self.alphabet_sets(), self.forced)

    def dfa(self) -> DFA:
        """The minimal automaton over the pattern's own alphabet (built once)."""
        if self._dfa is None:
            ab = self.alphabet()
            if self.lowered and ab.classify(SMALL_SIGMA) != ab.classify(FINAL_SIGMA):
                raise AutomataError("this lowered value tells σ from ς apart, and str.lower() picks one of them "
                                    "from the neighbouring letters (Final_Sigma), so no fixed automaton is exact")
            self._dfa = _Builder(self, ab).build().minimize()
        return self._dfa


@functools.cache
def compile_regex(pattern: str, flags: int = 0, search: bool = True, lowered: bool = False) -> Regex:
    return Regex(pattern, flags, search=search, lowered=lowered)


# --------------------------------------------------------------------------- #
# Thompson construction and the subset construction with obligations
# --------------------------------------------------------------------------- #
Obligation = tuple[int, bool, bool]     # (classes the next character may be in, rest must then be empty, end allowed)


class _Builder:
    def __init__(self, rx: Regex, alphabet: Alphabet):
        self.rx, self.ab = rx, alphabet
        self.eps: list[list[int]] = []
        self.asserts: list[list[tuple[int, int]]] = []
        self.chars: list[list[tuple[int, int]]] = []

    def new(self) -> int:
        self.eps.append([])
        self.asserts.append([])
        self.chars.append([])
        return len(self.eps) - 1

    def seq(self, items: Sequence[Any], flags: int) -> tuple[int, int]:
        start = cur = self.new()
        for op, av in items:
            s, e = self.item(op, av, flags)
            self.eps[cur].append(s)
            cur = e
        return start, cur

    def item(self, op: Any, av: Any, flags: int) -> tuple[int, int]:
        if op in _CHAR_OPS:
            s, e = self.new(), self.new()
            self.chars[s].append((self.ab.mask(self.rx.charset(op, av, flags)), e))
            return s, e
        if op is BRANCH:
            s, e = self.new(), self.new()
            for alt in av[1]:
                a, b = self.seq(alt, flags)
                self.eps[s].append(a)
                self.eps[b].append(e)
            return s, e
        if op is SUBPATTERN:
            _group, add, remove, sub = av
            return self.seq(sub, (flags | add) & ~remove)
        if op in (MAX_REPEAT, MIN_REPEAT):       # greedy or lazy: the same language for a yes/no search
            lo, hi, sub = av
            s = cur = self.new()
            for _ in range(lo):
                a, b = self.seq(sub, flags)
                self.eps[cur].append(a)
                cur = b
            end = self.new()
            if hi == MAXREPEAT:
                loop = self.new()
                self.eps[cur].append(loop)
                a, b = self.seq(sub, flags)
                self.eps[loop] += (a, end)
                self.eps[b].append(loop)
            else:
                for _ in range(hi - lo):
                    a, b = self.seq(sub, flags)
                    self.eps[cur] += (a, end)
                    cur = b
                self.eps[cur].append(end)
            return s, end
        s, e = self.new(), self.new()
        self.asserts[s].append((_assertion(av, flags), e))
        return s, e

    def build(self) -> DFA:
        ab, rx = self.ab, self.rx
        size = ab.size
        every = (1 << size) - 1
        start, final = self.seq(rx.items, rx.global_flags)
        if rx.search:                          # unanchored: any prefix before, anything after a match
            pre = self.new()
            self.chars[pre].append((every, pre))
            self.eps[pre].append(start)
            start = pre
            self.chars[final].append((every, final))
        word = ab.mask(word_chars()) if rx.needs_word else 0
        newline = ab.mask(NEWLINE) if rx.needs_newline else 0
        top: Obligation = (every, False, True)
        rest_empty: Obligation = (0, True, True)
        accepted: frozenset = frozenset({(-1, top)})

        def conj(a: Obligation, b: Obligation) -> Obligation | None:
            out = (a[0] & b[0], a[1] or b[1], a[2] and b[2])
            return None if out[0] == 0 and not out[2] else out

        def close(threads: Iterable[tuple[int, Obligation]], at_start: bool, prev_word: bool,
                  prev_newline: bool) -> frozenset:
            seen = set(threads)
            stack = list(seen)
            while stack:
                q, ob = stack.pop()
                nxt: list[tuple[int, Obligation]] = [(t, ob) for t in self.eps[q]]
                for kind, t in self.asserts[q]:
                    new: Obligation | None
                    if kind == A_BEGIN:
                        new = ob if at_start else None
                    elif kind == A_BEGIN_LINE:
                        new = ob if at_start or prev_newline else None
                    elif kind == A_END:            # at the end, or before a final newline
                        new = conj(ob, (newline, True, True))
                    elif kind == A_END_LINE:
                        new = conj(ob, (newline, False, True))
                    elif kind == A_END_STRING:
                        new = conj(ob, rest_empty)
                    else:                          # \b: the next character must differ in wordness
                        new = conj(ob, (every & ~word, False, True)) if prev_word else conj(ob, (word, False, False))
                    if new is not None:
                        nxt.append((t, new))
                for th in nxt:
                    if th not in seen:
                        seen.add(th)
                        stack.append(th)
            if rx.search and (final, top) in seen:
                return accepted
            return frozenset(seen)

        def step(key: frozenset, k: int) -> frozenset:
            if key is accepted:
                return accepted
            moved = set()
            for q, (allowed, then_empty, _end) in key:
                if not allowed >> k & 1:
                    continue
                ob = rest_empty if then_empty else top
                for mask, t in self.chars[q]:
                    if mask >> k & 1:
                        moved.add((t, ob))
            return close(moved, False, bool(word >> k & 1), bool(newline >> k & 1))

        composite: dict[int, list[int]] = {}
        if rx.lowered:
            for cp, low in multi_lower().items():
                k = ab.classify(cp)
                if ab.weight[k] != 1 or any(ch.lower() != ch for ch in low):
                    raise AssertionError(f"U+{cp:04X} must be a class of its own with a lowercase image")
                composite[k] = [ab.classify(ord(ch)) for ch in low]

        first = close({(start, top)}, True, False, False)
        index = {first: 0}
        order = [first]
        delta: list[list[int]] = []
        i = 0
        while i < len(order):
            key = order[i]
            i += 1
            row = []
            for k in range(size):
                if k in composite:
                    nxt_key = key
                    for c in composite[k]:
                        nxt_key = step(nxt_key, c)
                else:
                    nxt_key = step(key, k)
                j = index.get(nxt_key)
                if j is None:
                    if len(order) >= STATE_LIMIT:
                        raise AutomataError(f"the automaton of {rx.pattern!r} grows past {STATE_LIMIT} states; refused")
                    j = index[nxt_key] = len(order)
                    order.append(nxt_key)
                row.append(j)
            delta.append(row)
        accept = [key is accepted or any(q == final and ob[2] for q, ob in key) for key in order]
        return DFA(ab, delta, accept)


# --------------------------------------------------------------------------- #
# Deterministic automata
# --------------------------------------------------------------------------- #
class DFA:
    """A complete deterministic automaton over the classes of an alphabet. State 0 is the start."""

    __slots__ = ("_dead", "_universal", "accept", "alphabet", "delta")

    def __init__(self, alphabet: Alphabet, delta: list[list[int]], accept: list[bool]):
        self.alphabet, self.delta, self.accept = alphabet, delta, accept
        self._dead: frozenset[int] | None = None
        self._universal: frozenset[int] | None = None

    @property
    def states(self) -> int:
        return len(self.delta)

    @classmethod
    def constant(cls, alphabet: Alphabet, value: bool) -> DFA:
        """Every string (value=True) or no string."""
        return cls(alphabet, [[0] * alphabet.size], [value])

    @classmethod
    def empty_string(cls, alphabet: Alphabet, accept_empty: bool = True) -> DFA:
        """Only the empty string (accept_empty) or every non-empty string."""
        return cls(alphabet, [[1] * alphabet.size, [1] * alphabet.size], [accept_empty, not accept_empty])

    def run(self, text: str) -> bool:
        s, classify, delta = 0, self.alphabet.classify, self.delta
        for ch in text:
            s = delta[s][classify(ord(ch))]
        return self.accept[s]

    def accepts(self, word: Sequence[int]) -> bool:
        s = 0
        for k in word:
            s = self.delta[s][k]
        return self.accept[s]

    def minimize(self) -> DFA:
        """Moore's partition refinement: states merge exactly when no suffix tells them apart."""
        part = [1 if a else 0 for a in self.accept]
        blocks = len(set(part))
        while True:
            sigs: dict[tuple, int] = {}
            new = [sigs.setdefault((part[s], *(part[t] for t in row)), len(sigs)) for s, row in enumerate(self.delta)]
            if len(sigs) == blocks:
                break
            part, blocks = new, len(sigs)
        number = {part[0]: 0}
        order = [0]
        i = 0
        while i < len(order):
            for t in self.delta[order[i]]:
                if part[t] not in number:
                    number[part[t]] = len(order)
                    order.append(t)
            i += 1
        delta = [[number[part[t]] for t in self.delta[s]] for s in order]
        return DFA(self.alphabet, delta, [self.accept[s] for s in order])

    def lift(self, alphabet: Alphabet) -> DFA:
        """The same automaton over a finer alphabet."""
        if alphabet is self.alphabet:
            return self
        if not alphabet.refines(self.alphabet):
            raise AutomataError("the target alphabet does not refine this automaton's alphabet")
        cls = [self.alphabet.classify(cp) for cp in alphabet.rep]
        return DFA(alphabet, [[row[c] for c in cls] for row in self.delta], list(self.accept))

    def complement(self) -> DFA:
        return DFA(self.alphabet, self.delta, [not a for a in self.accept])

    def _reach_back(self, targets: Iterable[int]) -> set[int]:
        back: list[list[int]] = [[] for _ in self.delta]
        for s, row in enumerate(self.delta):
            for t in set(row):
                back[t].append(s)
        seen = set(targets)
        stack = list(seen)
        while stack:
            for s in back[stack.pop()]:
                if s not in seen:
                    seen.add(s)
                    stack.append(s)
        return seen

    def dead_states(self) -> frozenset[int]:
        """States from which no continuation is ever accepted."""
        if self._dead is None:
            alive = self._reach_back(s for s, a in enumerate(self.accept) if a)
            self._dead = frozenset(range(self.states)) - alive
        return self._dead

    def universal_states(self) -> frozenset[int]:
        """States from which every continuation is accepted."""
        if self._universal is None:
            spoilable = self._reach_back(s for s, a in enumerate(self.accept) if not a)
            self._universal = frozenset(range(self.states)) - spoilable
        return self._universal

    def is_empty(self) -> bool:
        return 0 in self.dead_states()

    def shortest(self) -> list[int] | None:
        return solve([(self, True)])

    def count(self, n: int, weights: Sequence[int] | None = None) -> int:
        """How many strings of length n the automaton accepts (each class counts with its weight:
        by default its number of code points, so this counts real strings)."""
        w = self.alphabet.weight if weights is None else weights
        moves = _moves(self, w)
        vec = {0: 1}
        for _ in range(n):
            nxt: dict[int, int] = {}
            for s, c in vec.items():
                for t, m in moves[s]:
                    nxt[t] = nxt.get(t, 0) + c * m
            vec = nxt
        return sum(c for s, c in vec.items() if self.accept[s])

    def count_all(self, weights: Sequence[int] | None = None) -> int | None:
        """How many strings the automaton accepts in all, or None when there are infinitely many
        (a cycle among states that can still reach acceptance)."""
        w = self.alphabet.weight if weights is None else weights
        dead = self.dead_states()
        if 0 in dead:
            return 0
        moves = _moves(self, w)
        order: list[int] = []
        mark: dict[int, int] = {}                     # 1: on the current path, 2: finished
        stack: list[tuple[int, int]] = [(0, 0)]
        while stack:                                  # depth-first, iterative: a back edge is a cycle
            s, i = stack.pop()
            if i == 0:
                if mark.get(s) == 2:
                    continue
                mark[s] = 1
            targets = [t for t, _m in moves[s] if t not in dead]
            if i < len(targets):
                stack.append((s, i + 1))
                t = targets[i]
                if mark.get(t) == 1:
                    return None
                if mark.get(t) != 2:
                    stack.append((t, 0))
            else:
                mark[s] = 2
                order.append(s)
        total: dict[int, int] = {}
        for s in order:                               # children first
            total[s] = (1 if self.accept[s] else 0) + sum(m * total[t] for t, m in moves[s] if t not in dead)
        return total[0]

    def sample(self, n: int, rng: random.Random, weights: Sequence[int] | None = None) -> list[int] | None:
        """A uniformly random accepted word of length n (each class with its weight), or None."""
        w = self.alphabet.weight if weights is None else weights
        completions = [[1 if a else 0 for a in self.accept]]
        for _ in range(n):
            prev = completions[-1]
            completions.append([sum(w[k] * prev[t] for k, t in enumerate(row)) for row in self.delta])
        if completions[n][0] == 0:
            return None
        s, out = 0, []
        for i in range(n, 0, -1):
            r = rng.randrange(completions[i][s])
            for k, t in enumerate(self.delta[s]):
                c = w[k] * completions[i - 1][t]
                if r < c:
                    out.append(k)
                    s = t
                    break
                r -= c
        return out


def _moves(dfa: DFA, weights: Sequence[int]) -> list[list[tuple[int, int]]]:
    out = []
    for row in dfa.delta:
        agg: dict[int, int] = {}
        for k, t in enumerate(row):
            if weights[k]:
                agg[t] = agg.get(t, 0) + weights[k]
        out.append(list(agg.items()))
    return out


_TRUE, _FALSE = -1, -2          # a component settled for good: it accepts (or rejects) whatever follows


def product(dfas: Sequence[DFA], accept: Callable[[tuple[bool, ...]], bool]) -> DFA:
    """The automaton of a Boolean combination of languages, minimized.

    A component that reaches a state from which every continuation is accepted (or none is)
    is replaced by that constant, so finished components stop multiplying the state space; for
    `any` and `all` a settled component decides the whole product at once."""
    ab = dfas[0].alphabet
    if any(d.alphabet is not ab for d in dfas):
        raise AutomataError("product of automata over different alphabets")
    settled = [(d.universal_states(), d.dead_states()) for d in dfas]

    def norm(states: Sequence[int]) -> tuple[int, ...]:
        out = tuple(s if s < 0 else _TRUE if s in settled[i][0] else _FALSE if s in settled[i][1] else s
                    for i, s in enumerate(states))
        if accept is any and _TRUE in out:
            return (_TRUE,)
        if accept is all and _FALSE in out:
            return (_FALSE,)
        return out

    def value(st: tuple[int, ...]) -> bool:
        if len(st) == 1 and len(dfas) != 1 and st[0] < 0:
            return st[0] == _TRUE
        return accept(tuple(s == _TRUE if s < 0 else dfas[i].accept[s] for i, s in enumerate(st)))

    first = norm([0] * len(dfas))
    index = {first: 0}
    order: list[tuple[int, ...]] = [first]
    delta: list[list[int]] = []
    i = 0
    while i < len(order):
        st = order[i]
        i += 1
        row = []
        for k in range(ab.size):
            nxt: tuple[int, ...]
            if len(st) == 1 and len(dfas) != 1 and st[0] < 0:
                nxt = st
            else:
                nxt = norm([s if s < 0 else dfas[c].delta[s][k] for c, s in enumerate(st)])
            j = index.get(nxt)
            if j is None:
                if len(order) >= STATE_LIMIT:
                    raise AutomataError(f"a product grows past {STATE_LIMIT} states; refused")
                j = index[nxt] = len(order)
                order.append(nxt)
            row.append(j)
        delta.append(row)
    return DFA(ab, delta, [value(st) for st in order]).minimize()


class _Constraints:
    """Automata read in lockstep, each wanted to accept or to reject. A component that is settled
    (it accepts or rejects whatever follows, as wanted) drops out; a combination that can never
    succeed is pruned. Both keep the searches below small without leaving anything out."""

    def __init__(self, constraints: Sequence[tuple[DFA, bool]]):
        self.ab = constraints[0][0].alphabet
        if any(d.alphabet is not self.ab for d, _w in constraints):
            raise AutomataError("constraints over different alphabets")
        self.plan = [(d, want, d.dead_states() if want else d.universal_states(),
                      d.universal_states() if want else d.dead_states()) for d, want in constraints]

    def norm(self, states: Sequence[int | None]) -> tuple[int | None, ...] | None:
        out: list[int | None] = []
        for (_d, _want, bad, done), s in zip(self.plan, states, strict=True):
            if s is None:
                out.append(None)
            elif s in bad:
                return None
            else:
                out.append(None if s in done else s)
        return tuple(out)

    def first(self) -> tuple[int | None, ...] | None:
        return self.norm([0] * len(self.plan))

    def step(self, st: tuple[int | None, ...], k: int) -> tuple[int | None, ...] | None:
        return self.norm([None if s is None else self.plan[i][0].delta[s][k] for i, s in enumerate(st)])

    def ok(self, st: tuple[int | None, ...]) -> bool:
        return all(s is None or self.plan[i][0].accept[s] == self.plan[i][1] for i, s in enumerate(st))


def _walk_back(parent: dict, node: tuple) -> list:
    """The labels on the path a search recorded from its start to `node`."""
    out = []
    step = parent[node]
    while step is not None:
        prev, label = step
        out.append(label)
        step = parent[prev]
    return out[::-1]


def solve(constraints: Sequence[tuple[DFA, bool]]) -> list[int] | None:
    """A shortest word (as classes) that each automaton accepts exactly when wanted.

    None means no string at all satisfies every constraint: the breadth-first search visits
    every reachable combination of states, a finite set, so None is a proof, not a timeout."""
    if not constraints:
        return []
    cs = _Constraints(constraints)
    first = cs.first()
    if first is None:
        return None
    if cs.ok(first):
        return []
    parent: dict[tuple, tuple[tuple, int] | None] = {first: None}
    queue = deque([first])
    while queue:
        st = queue.popleft()
        for k in range(cs.ab.size):
            nxt = cs.step(st, k)
            if nxt is None or nxt in parent:
                continue
            parent[nxt] = (st, k)
            if cs.ok(nxt):
                return _walk_back(parent, nxt)
            if len(parent) >= STATE_LIMIT:
                raise AutomataError(f"a search grows past {STATE_LIMIT} combinations; refused")
            queue.append(nxt)
    return None


def nearest(constraints: Sequence[tuple[DFA, bool]], text: str) -> tuple[int, str] | None:
    """The fewest single-character edits (insert, delete, substitute) that turn `text` into a
    string satisfying every constraint, with that string; None when no string satisfies them.

    Wagner's correction algorithm for regular languages: a shortest path over (position in
    text, combination of states), where keeping a character costs 0 and each edit costs 1
    (0-1 breadth-first search, so the first goal reached is optimal). Kept characters are the
    original characters, edits use each class's representative."""
    cs = _Constraints(constraints) if constraints else None
    n = len(text)
    first = cs.first() if cs else ()
    if first is None:
        return None
    start = (0, first)
    dist = {start: 0}
    parent: dict[tuple, tuple[tuple, str] | None] = {start: None}
    queue = deque([start])
    size = cs.ab.size if cs else 0
    while queue:
        node = queue.popleft()
        i, st = node
        d = dist[node]
        if i == n and (cs is None or cs.ok(st)):
            return d, "".join(_walk_back(parent, node))
        moves: list[tuple[tuple, int, str]] = []
        keep = -1
        if i < n:
            keep = cs.ab.classify(ord(text[i])) if cs else -1
            if cs is None:
                moves.append(((i + 1, st), 0, text[i]))
            else:
                nxt = cs.step(st, keep)
                if nxt is not None:
                    moves.append(((i + 1, nxt), 0, text[i]))
            moves.append(((i + 1, st), 1, ""))
        for k in range(size):
            nxt = cs.step(st, k) if cs else None
            if nxt is None:
                continue
            rep = chr(cs.ab.rep[k]) if cs else ""
            moves.append(((i, nxt), 1, rep))                       # insert
            if i < n and k != keep:
                moves.append(((i + 1, nxt), 1, rep))               # substitute
        for nxt_node, cost, ch in moves:
            nd = d + cost
            if nd < dist.get(nxt_node, nd + 1):
                dist[nxt_node] = nd
                parent[nxt_node] = (node, ch)
                if cost:
                    queue.append(nxt_node)
                else:
                    queue.appendleft(nxt_node)
                if len(dist) >= STATE_LIMIT:
                    raise AutomataError(f"a correction search grows past {STATE_LIMIT} nodes; refused")
    return None


def equivalent(a: DFA, b: DFA) -> list[int] | None:
    """None when both accept exactly the same strings, else a shortest word only one accepts."""
    for want_a in (True, False):
        word = solve([(a, want_a), (b, not want_a)])
        if word is not None:
            return word
    return None


# --------------------------------------------------------------------------- #
# Transducers: languages seen through a program's own reading of its input
# --------------------------------------------------------------------------- #
Move = tuple[CharSet, "int | None", str, bool]    # (characters, next state or None to reject, prefix written, copy the character)


class Transducer:
    """A deterministic finite-state transducer over code points. In each state, a character of
    one of the listed sets moves to the next state and writes a fixed prefix followed, when
    `copy` is set, by the character itself. A character no move lists, or a move to None,
    rejects the input: it is outside the transducer's domain. Every state may end the input
    when it is in `final`."""

    def __init__(self, start: int, final: Iterable[int], moves: dict[int, list[Move]]):
        self.start, self.final, self.moves = start, frozenset(final), moves
        for state, ms in moves.items():
            seen = CharSet()
            for cs, _nxt, _prefix, _copy in ms:
                if cs & seen != CharSet():
                    raise AutomataError(f"transducer state {state}: overlapping character sets")
                seen = seen | cs

    def sets(self) -> list[CharSet]:
        return [cs for ms in self.moves.values() for cs, _n, _p, _c in ms]

    def move(self, state: int, cp: int) -> tuple[int, str, bool] | None:
        for cs, nxt, prefix, copy in self.moves.get(state, []):
            if cp in cs:
                return None if nxt is None else (nxt, prefix, copy)
        return None

    def apply(self, text: str) -> str | None:
        """The output for an input, or None outside the domain (a direct reading, used to check
        the automaton built by preimage)."""
        state, out = self.start, []
        for ch in text:
            step = self.move(state, ord(ch))
            if step is None:
                return None
            state, prefix, copy = step
            out.append(prefix + (ch if copy else ""))
        return "".join(out) if state in self.final else None


def preimage(t: Transducer, target: DFA) -> DFA:
    """The automaton of every input the transducer maps into the target's language.

    Inverse images of regular languages under finite-state transductions are regular (Elgot
    and Mezei, 1965; Nivat, 1968): run the transducer and the target side by side, feeding the
    target whatever the transducer writes. The alphabet refines both the target's classes and
    the transducer's sets, so a copied character lands in one target class."""
    ab = joint([target.alphabet], t.sets())
    reject = (-1, -1)
    first = (t.start, 0)
    index = {first: 0}
    order = [first]
    delta: list[list[int]] = []
    i = 0
    while i < len(order):
        st = order[i]
        i += 1
        row = []
        for k in range(ab.size):
            nxt = reject
            if st != reject:
                step = t.move(st[0], ab.rep[k])
                if step is not None:
                    state, prefix, copy = step
                    d = st[1]
                    for ch in prefix:
                        d = target.delta[d][target.alphabet.classify(ord(ch))]
                    if copy:
                        d = target.delta[d][target.alphabet.classify(ab.rep[k])]
                    nxt = (state, d)
            j = index.get(nxt)
            if j is None:
                if len(order) >= STATE_LIMIT:
                    raise AutomataError(f"a transducer preimage grows past {STATE_LIMIT} states; refused")
                j = index[nxt] = len(order)
                order.append(nxt)
            row.append(j)
        delta.append(row)
    accept = [st != reject and st[0] in t.final and target.accept[st[1]] for st in order]
    return DFA(ab, delta, accept).minimize()


# --------------------------------------------------------------------------- #
# Conformance testing: words that tell an automaton apart from any other of its size
# --------------------------------------------------------------------------- #
def access_words(dfa: DFA) -> list[list[int]]:
    """A shortest word reaching each state (breadth-first, readable classes first)."""
    words: list[list[int] | None] = [None] * dfa.states
    words[0] = []
    queue = deque([0])
    while queue:
        s = queue.popleft()
        for k, t in enumerate(dfa.delta[s]):
            if words[t] is None:
                words[t] = [*words[s], k]  # type: ignore[misc]
                queue.append(t)
    return [w if w is not None else [] for w in words]


def separating_words(dfa: DFA) -> dict[tuple[int, int], list[int]]:
    """For every pair of states of a minimal automaton, a shortest word accepted from exactly
    one of them, read off Moore's refinement levels."""
    levels = [[1 if a else 0 for a in dfa.accept]]
    while True:
        prev = levels[-1]
        sigs: dict[tuple, int] = {}
        new = [sigs.setdefault((prev[s], *(prev[t] for t in row)), len(sigs)) for s, row in enumerate(dfa.delta)]
        if len(sigs) == len(set(prev)):
            break
        levels.append(new)
    memo: dict[tuple[int, int], list[int]] = {}

    def sep(p: int, q: int) -> list[int]:
        if (p, q) in memo:
            return memo[(p, q)]
        level = next(i for i, part in enumerate(levels) if part[p] != part[q])
        if level == 0:
            word: list[int] = []
        else:
            below = levels[level - 1]
            k = next(k for k in range(dfa.alphabet.size) if below[dfa.delta[p][k]] != below[dfa.delta[q][k]])
            word = [k, *sep(dfa.delta[p][k], dfa.delta[q][k])]
        memo[(p, q)] = memo[(q, p)] = word
        return word

    n = dfa.states
    for p in range(n):
        for q in range(p + 1, n):
            if levels[-1][p] == levels[-1][q]:
                raise AutomataError("separating words need a minimal automaton")
            sep(p, q)
    return memo


def _run_from(dfa: DFA, s: int, word: Sequence[int]) -> int:
    for k in word:
        s = dfa.delta[s][k]
    return s


def characterization_set(dfa: DFA) -> list[list[int]]:
    """Words that together tell every pair of states of a minimal automaton apart: while two
    states still share a block, the shortest word separating them is added and splits every
    block it can, so at most states - 1 words are needed."""
    n = dfa.states
    if n == 1:
        return [[]]
    seps = separating_words(dfa)
    blocks = [list(range(n))]
    chosen: list[list[int]] = []
    while True:
        wide = next((b for b in blocks if len(b) > 1), None)
        if wide is None:
            return chosen
        word = seps[(wide[0], wide[1])]
        chosen.append(word)
        verdict = [dfa.accept[_run_from(dfa, st, word)] for st in range(n)]
        blocks = [part for b in blocks for part in ([st for st in b if verdict[st]], [st for st in b if not verdict[st]])
                  if part]


def conformance_suite(dfa: DFA) -> list[tuple[tuple[int, ...], bool]]:
    """Chow's W-method test suite (1978) with the automaton's verdict on each word: the
    transition cover (a shortest word to every state, then every class from it) followed by
    every word of a characterization set. Any automaton with at most as many states that gives
    the same verdict on every word of the suite accepts exactly the same language, so the suite
    is complete for that class of implementations."""
    dfa = dfa.minimize()
    access = access_words(dfa)
    cover = {tuple(a): s for s, a in enumerate(access)}
    for s, a in enumerate(access):
        for k, t in enumerate(dfa.delta[s]):
            cover.setdefault((*a, k), t)
    chars = [tuple(w) for w in characterization_set(dfa)]
    outcome = {w: [dfa.accept[_run_from(dfa, s, w)] for s in range(dfa.states)] for w in chars}
    suite = {(*a, *w): outcome[w][s] for a, s in cover.items() for w in chars}
    return list(suite.items())
