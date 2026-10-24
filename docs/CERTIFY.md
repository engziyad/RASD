# Certify: proofs about every event a rule can see

A test proves that a rule fires on the events someone wrote down. `rasd certify` proves statements about **every** event. It compiles each Sigma rule into exact finite automata over every character a string can hold, then decides questions about the rule by exhaustive search over finite state spaces. Each answer is either a proof that no such event exists or a concrete event, and every concrete event is replayed through the engine before it is reported.

An example: certify works out that the encoded PowerShell rule needs at least sixteen Base64 characters after the flag. It fires on `{"Image": "\\pwsh.exe", "CommandLine": " -e aaaaaaaaaaaaaaaa"}` and stays quiet one edit away, with fifteen. Nobody wrote those two events: the automata produced them, and the engine confirmed both verdicts.

```bash
rasd certify            # compile every rule, build and replay a firing event and its nearest quiet event
rasd certify -v         # also print the events
rasd certify --json
rasd certify --check    # CI: a refusal, an engine disagreement or a stale page fails the build
```

## What it proves on every build

| Statement | How |
|---|---|
| The rule is translated exactly | Every atom of the rule becomes an automaton that accepts exactly the values `tools/sigma_engine.py` accepts. What cannot be modelled exactly is refused with the reason, never approximated |
| The rule can fire | An event built from the automata (the shortest values they allow), replayed through the engine |
| The rule can stay quiet, and where its edge is | The event closest to the firing one, in single-character edits, on which the rule stays quiet; replayed through the engine |
| No rule is dead or matches everything | If no firing event (or no quiet event) existed, the search would prove it and the build would fail |

The generated part of this page, at the end, lists every rule with the size of its automata and both events.

## The model

An **event** is a partial map from field names to strings: a field is either missing (written ⊥) or holds a string. Field names are compared without case, as the engine does when the exact name is not present. Values are single strings, as in Sysmon, Windows Security and web server logs; a field holding a list is refused rather than guessed at. A number in a log is the string Python's `str()` gives it, which is what the engine compares.

A **value test** is a set of strings L (a language) plus a verdict for a missing field. An **atom** is one `field|modifiers: values` line of a selection: the union of its value tests, or their intersection under `|all`. A **rule** is a Boolean formula over atoms, built with the engine's own condition grammar (`not` before `and` before `or`, parentheses, `1 of`, `all of`, `them`, a list of conditions read as `or`). The rule fires on an event exactly when the formula is true for the atoms' verdicts on that event.

### Every Sigma test is a regular language

Σ is the set of all 1,114,112 code points, Σ* the strings over it, ε the empty string, h the lowercase map below.

| Rule syntax | Accepted values | Missing field |
|---|---|---|
| `F: v` | h⁻¹({lower(v)}) | false |
| `F: v` with `*` or `?` | h⁻¹(W): W reads `*` as any string and `?` as one character of the lowered value | false |
| `F\|contains: v` | h⁻¹(Σ* lower(v) Σ*) | false |
| `F\|startswith: v` · `F\|endswith: v` | h⁻¹(lower(v) Σ*) · h⁻¹(Σ* lower(v)) | false |
| any of the above with `\|cased` | the same language without lowering | false |
| `F\|re: p` (sub-modifiers `i`, `m`, `s`) | { s : `re.search(p, s, flags)` finds a match } | false |
| `F\|exists: true` · `F\|exists: false` | Σ* without ε · {ε} | false · true |
| `F: null` | {ε} | true |
| a list of values | the union of their languages | true if any value is |
| a list with `\|all` | the intersection | true if every value is |

Each row mirrors one branch of `sigma_engine._match_single`, in the engine's order: `exists` first, then `null`, then `re`, then lowering, then `contains`, `startswith`, `endswith`, wildcards and equality. Unsupported modifiers, Sigma escapes and wildcards inside `contains` are refused by the engine's own checks before any automaton is built.

**Kleene's theorem** (1956) says a language is regular exactly when a finite automaton accepts it. Literal strings, unions, concatenation and repetition are regular, and so is the search language of a pattern built from them: "some substring matches p" is Σ* p Σ* read with the anchors in place. What breaks regularity is refused: backreferences, lookahead and lookbehind, `\B`, conditional groups, atomic groups, possessive repeats, the ASCII and LOCALE flags, and a repeated group that can match the empty string (the engine stops such loops early, so its language is not the textbook one). RASD's own lint already rejects most of these for RE2 compatibility, so no RASD rule is refused.

### Case-insensitive matching is an inverse homomorphism

The engine compares most values after `str.lower()` on both sides. Lowering acts character by character, h(xy) = h(x)h(y), so h is a monoid homomorphism, and the values a lowered test accepts form the preimage h⁻¹(L). Preimages of regular languages under a homomorphism are regular, by a one-line construction: a new automaton reads a character c by running the old one over h(c), δ'(q, c) = δ(q, h(c)).

Two facts of Python's `str.lower()` make this precise:

* U+0130 (capital I with dot above) lowers to two characters, `i` and U+0307. certify gives it a class of its own and its transition reads both characters, so `contains: "i̇"` matches `İ` exactly as the engine does.
* Capital sigma lowers to final sigma ς at the end of a word and to σ elsewhere (Unicode Final_Sigma), which depends on the neighbouring letters and is not a homomorphism. certify refuses any lowered test that tells σ and ς apart; when no test does, the choice cannot change a verdict. A unit test checks every code point beside cased letters on either side: no other character's lowercase depends on its neighbours.

`|re` with the `i` flag is different: the engine's regular expression module compares characters by simple case folding, so `(?i)k` also matches the Kelvin sign U+212A, `(?i)i` matches both `İ` and `ı`, and `(?i)s` matches the long s `ſ`. certify does not assume any of this; it measures it, as the next section explains.

### A million letters, a few dozen classes

An automaton over 1,114,112 letters would be useless, and a sample of letters would not be a proof. The way out is a partition. For one field, collect the character sets its patterns use: each literal, class, `\d`, `\w`, `\s`, the dot, under the flags in force. Two characters that fall in exactly the same sets are interchangeable for every automaton of that field, because every transition reads a set. The non-empty cells of this Boolean algebra (the minterms) are the field's **classes**: a few dozen per field, together covering every code point.

Membership is decided by the engine itself. Each atom is written back as a one-character pattern, compiled with the pattern's flags and run once over a string holding every code point; the runs of matches are the set. So the Kelvin sign, the dotless i, non-ASCII digits that `\d` matches and spaces that `\s` matches land in the classes the engine puts them in, on every Python version, without a table of exceptions kept by hand. Patterns are read by Python's own parser (`re._parser`), so the structure certify reasons about is the structure the engine runs.

### From a pattern to its minimal automaton

1. **Thompson's construction** (1968) turns the parsed pattern into an automaton with ε-moves: one small fragment per literal, concatenation, alternation and repetition. Bounded repeats such as `{16,}` are unrolled.
2. **Anchors and word boundaries** are positions, not characters, so they need care. The engine's definitions (`_sre.c`, `SRE(at)`) are taken literally:

   | Pattern | Holds at position i of string s |
   |---|---|
   | `^` · `\A` | i = 0 (with the m flag, `^` also after a newline) |
   | `$` | i = len(s), or i = len(s) - 1 and s[i] is a newline (with the m flag: before any newline) |
   | `\Z` | i = len(s) |
   | `\b` | exactly one of s[i-1], s[i] is a word character (outside the string counts as non-word) |

   The left side of each test is known when the position is reached. The right side is not, so it becomes an **obligation** carried by the thread: "the next character must be a word character", "the rest must be empty or one newline". Obligations are met or broken by the next character read, or at the end of the string.
3. **The subset construction** of Rabin and Scott (1959) turns the threads, with their obligations, into a deterministic automaton. For a search, a thread that reaches the end of the pattern with no obligation left accepts whatever follows, so all such states merge into one.
4. **Minimization.** By the Myhill-Nerode theorem every regular language has a unique smallest deterministic automaton, whose states are the classes of strings no suffix tells apart. Moore's partition refinement (1956) computes it.

### Deciding a statement

A statement such as "some event fires the rule" asks whether a set of events is empty. The formula, or its negation for a quiet event, is written in disjunctive normal form: an OR of terms, each an AND of literals "atom a is true" or "atom a is false". The search then works term by term.

Atoms on different fields read different parts of the event, and an event can combine any value of one field with any value of another. So a term is satisfiable exactly when, field by field, some value satisfies that field's literals, or a missing field does. For one field this is the emptiness of an intersection of regular languages and complements: the automata run in lockstep, and a breadth-first search over the reachable combinations of states either reaches a combination where every automaton gives the wanted verdict, which spells out a shortest value, or exhausts them. The set of combinations is finite, so exhausting it is a proof that no value exists, not a timeout. Two reductions keep it small without leaving anything out: an automaton in a state that accepts (or rejects) whatever follows is settled and drops out, and a combination where a wanted verdict has become impossible is cut.

The quiet event is chosen to be close to the firing one. Given a string w and automata, **Wagner's correction algorithm** (1974) finds the fewest single-character insertions, deletions and substitutions that turn w into a string with the wanted verdicts: a shortest path over (position in w, combination of states), where keeping a character costs nothing and each edit costs one. certify tries each term of the negated formula on the firing event and keeps the cheapest.

## Why the answers can be trusted

1. **Replay.** Every event certify builds goes through `sigma_engine.matches` and through the automata. If the verdicts differ, the build fails: an automaton bug cannot produce a report.
2. **Conformance testing.** For every value test of every rule, the unit tests compare the automaton with the engine on its complete **W-method suite** (Chow, 1978): a shortest word to each state, every class read from there, then words that tell every pair of states apart. Any automaton with at most as many states that agrees on the whole suite accepts the same language, so for that class of implementations the suite is a proof, not a sample. Random strings drawn uniformly from each automaton and from its complement, with random members of each class, come on top.
3. **Differential corpus.** Every rule's verdict computed from its automata alone equals the engine's on every true positive, true negative, technique and case mutation, fuzzer variant, correlation scenario event, replay event and thousands of synthetic events.
4. **Python's own facts, on every code point.** The characters `\b` treats as word characters are exactly those `\w` matches, and `str.lower()` depends on neighbouring characters only for capital sigma.
5. **Refusals.** Keyword selections (which search every field joined together), list-valued fields and every construct listed above are refused with the reason. Nothing is approximated.
6. **Versions.** The construction reads Python's parser and engine, so its classes follow the Unicode tables of the running version; the report is identical on Python 3.10, 3.12 and 3.13, which CI runs.

## Limits

* certify proves facts about **rules**. Whether a rule catches a technique also depends on every way the technique can be written, which needs a formal model of the behaviour, not just of the rule.
* It proves the rule as the engine evaluates it. The generated SPL and KQL are tied to the engine by `rasd parity` (RASD's model of each query language), and running them in a live SIEM is part of the lab evidence.

## References

* S. C. Kleene, *Representation of events in nerve nets and finite automata*, Automata Studies, 1956.
* M. O. Rabin and D. Scott, *Finite automata and their decision problems*, IBM Journal of Research and Development, 1959.
* E. F. Moore, *Gedanken-experiments on sequential machines*, Automata Studies, 1956. J. Myhill, 1957, and A. Nerode, *Linear automaton transformations*, 1958.
* K. Thompson, *Regular expression search algorithm*, Communications of the ACM, 1968.
* R. A. Wagner, *Order-n correction for regular languages*, Communications of the ACM, 1974.
* T. S. Chow, *Testing software design modeled by finite-state machines*, IEEE Transactions on Software Engineering, 1978.
* J. E. Hopcroft, R. Motwani and J. D. Ullman, *Introduction to Automata Theory, Languages, and Computation* (closure under Boolean operations and inverse homomorphism, decision properties).
* The Unicode Standard, SpecialCasing.txt (Final_Sigma, U+0130); Python's `re` module and `_sre.c`.
* The Sigma specification, with the subset RASD evaluates in [SIGMA_SUPPORT](SIGMA_SUPPORT.md).

## The rules, compiled

<!-- certify:start (generated by tools/certify.py) -->

**18/18 Sigma rules compiled exactly** (14 single-event rules and 4 correlation base rules): 100 atoms, 203 value tests, 2603 automaton states in total. 36 witness events, one that fires and one that stays quiet per rule, each replayed through the engine with the verdict the automata predicted.

| Rule | Fields | Atoms | Tests | States | Classes (largest field) |
|---|---:|---:|---:|---:|---:|
| `T1003.001_lsass_memory_access` | 4 | 9 | 21 | 259 | 33 |
| `T1021.006_wsmprovhost_suspicious_child` | 4 | 8 | 19 | 204 | 26 |
| `T1053.003_crontab_noninteractive_install` | 2 | 3 | 3 | 67 | 13 |
| `T1053.005_powershell_scheduled_task_creation` | 3 | 6 | 12 | 159 | 29 |
| `T1053.005_schtasks_suspicious_creation` | 3 | 6 | 21 | 226 | 37 |
| `T1059.001_powershell_encoded_command` | 4 | 4 | 6 | 120 | 15 |
| `T1059.004_linux_suspicious_shell_execution` | 2 | 4 | 10 | 91 | 26 |
| `T1218.011_rundll32_suspicious_execution` | 3 | 11 | 13 | 379 | 49 |
| `T1547.001_registry_run_key_persistence` | 2 | 7 | 18 | 447 | 42 |
| `T1558.003_kerberoasting_rc4_tgs` | 5 | 6 | 16 | 46 | 10 |
| `T1569.002_suspicious_service_installation` | 4 | 9 | 18 | 275 | 42 |
| `T1685.005_event_log_clearing` | 3 | 7 | 12 | 130 | 20 |
| `T1685.005_security_log_cleared` | 1 | 1 | 1 | 6 | 5 |
| `T1685.005_system_log_cleared` | 2 | 2 | 2 | 33 | 18 |
| `T1110.003_password_spray_burst` (base rule) | 5 | 8 | 18 | 73 | 14 |
| `T1190_object_id_enumeration` (base rule) | 2 | 2 | 2 | 35 | 20 |
| `T1558.003_kerberoasting_volume` (base rule) | 4 | 5 | 8 | 39 | 9 |
| `T1595.003_api_auth_probing` (base rule) | 2 | 2 | 3 | 14 | 8 |

<details><summary>The witness events (shortest values the automata allow)</summary>

- `T1003.001_lsass_memory_access` fires on `{"GrantedAccess": "0xba", "TargetImage": "\\lsass.exe"}`, stays quiet on `{"GrantedAccess": "0xba", "TargetImage": "\\lsass.ex"}`
- `T1021.006_wsmprovhost_suspicious_child` fires on `{"Image": "\\cmd.exe", "ParentImage": "\\winrshost.exe"}`, stays quiet on `{"Image": "\\cmd.exe", "ParentImage": "\\winrshost.ex"}`
- `T1053.003_crontab_noninteractive_install` fires on `{"CommandLine": "crontab -", "Image": "/crontab"}`, stays quiet on `{"CommandLine": "crontab -", "Image": "/cronta"}`
- `T1053.005_powershell_scheduled_task_creation` fires on `{"CommandLine": "new-scheduledtaskactionset-scheduledtask", "Image": "\\pwsh.exe"}`, stays quiet on `{"CommandLine": "new-scheduledtaskactionset-scheduledtas", "Image": "\\pwsh.exe"}`
- `T1053.005_schtasks_suspicious_creation` fires on `{"CommandLine": "cmd /change", "Image": "\\schtasks.exe"}`, stays quiet on `{"CommandLine": "cmd /chang", "Image": "\\schtasks.exe"}`
- `T1059.001_powershell_encoded_command` fires on `{"CommandLine": " -e aaaaaaaaaaaaaaaa", "Image": "\\pwsh.exe"}`, stays quiet on `{"CommandLine": " -e aaaaaaaaaaaaaaa", "Image": "\\pwsh.exe"}`
- `T1059.004_linux_suspicious_shell_execution` fires on `{"CommandLine": "base64 -d\|sh"}`, stays quiet on `{"CommandLine": "base64 -d sh"}`
- `T1218.011_rundll32_suspicious_execution` fires on `{"CommandLine": "vbscript:", "Image": "\\rundll32.exe"}`, stays quiet on `{"CommandLine": "vbscript:", "Image": "\\rundll32.ex"}`
- `T1547.001_registry_run_key_persistence` fires on `{"Details": "pwsh", "TargetObject": "\\software\\microsoft\\windows\\currentversion\\run\\"}`, stays quiet on `{"Details": "pwsh", "TargetObject": "\\software\\microsoft\\windows\\currentversion\\ru\\"}`
- `T1558.003_kerberoasting_rc4_tgs` fires on `{"EventID": "4769", "Status": "0", "TicketEncryptionType": "1"}`, stays quiet on `{"EventID": "476", "Status": "0", "TicketEncryptionType": "1"}`
- `T1569.002_suspicious_service_installation` fires on `{"EventID": "7045", "ImagePath": "mshta", "Provider_Name": "service control manager"}`, stays quiet on `{"EventID": "7045", "ImagePath": "mshta", "Provider_Name": "service control manage"}`
- `T1685.005_event_log_clearing` fires on `{"CommandLine": "cleareventlog"}`, stays quiet on `{"CommandLine": "cleareventlo"}`
- `T1685.005_security_log_cleared` fires on `{"EventID": "1102"}`, stays quiet on `{"EventID": "110"}`
- `T1685.005_system_log_cleared` fires on `{"EventID": "104", "Provider_Name": "microsoft-windows-eventlog"}`, stays quiet on `{"EventID": "10", "Provider_Name": "microsoft-windows-eventlog"}`
- `T1110.003_password_spray_burst` fires on `{"EventID": "4771", "Status": "24"}`, stays quiet on `{"EventID": "477", "Status": "24"}`
- `T1190_object_id_enumeration` fires on `{"cs-method": "get", "cs-uri-stem": "/user/0"}`, stays quiet on `{"cs-method": "ge", "cs-uri-stem": "/user/0"}`
- `T1558.003_kerberoasting_volume` fires on `{"EventID": "4769", "Status": "0"}`, stays quiet on `{"EventID": "476", "Status": "0"}`
- `T1595.003_api_auth_probing` fires on `{"sc-status": "401"}`, stays quiet on `{"sc-status": "40"}`

</details>

<!-- certify:end -->
