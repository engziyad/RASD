# RASD-Trace: Evidence Survivability

Every other proof in RASD is about the rule: does it fire, on every variant, in every backend. RASD-Trace is about what comes after the alert and what an intruder can do about it. For each detection it asks whether the evidence an investigation needs can be taken away, how many actions that costs, and whether a tested rule sees the attempt.

```bash
rasd trace                                   # the survivability table, the quiet sequences, the rules that close them
rasd trace T1053.005_schtasks                # one detection: its witnesses per question, in collection order
rasd trace T1059.001 --lost sysmon_log,siem  # logs are already gone: what can still be proven, and from where
rasd trace --check                           # the model against the rules, the forwarder inputs and the engine (in CI)
```

The results for this build are in [dfir/trace](../dfir/trace/README.md).

## The model

Three things are written down once, in [`dfir/trace/model.yml`](../dfir/trace/model.yml).

**Stores** are the containers evidence lives in: an event log channel, the Prefetch folder, a registry key, the change journal. A store is either on the host, where an administrator can reach it, or somewhere else: the domain controller, the file server, the decoy host, the SIEM.

**Artifacts** are the records an investigator reads from a store, and each one lists the questions it can answer:

| Question | Meaning |
|---|---|
| `alert` | Does the detection raise its alert |
| `ran` | Did the behaviour happen on this host |
| `when` | At what time |
| `who` | Under which account |
| `how` | With which command line, value or configuration |
| `origin` | From which remote host |

An artifact answers only what it really holds. A Prefetch file answers `ran` and `when` and nothing else: it has no arguments and no account. A Run key value answers `how` and gives a time only through its key's last write. These limits are part of the model and are printed beside each witness.

**Erasures** are the anti-forensic actions RASD knows. Each one says what it does and what it leaves:

| Field | Meaning |
|---|---|
| `destroys` | Stores it empties of everything they held |
| `blinds` | Stores that record nothing new once it has run (`still_written` lists the records that are written anyway, such as Security 1102 after the audit policy is cleared) |
| `stops_forwarding` | Shipping to the SIEM ends |
| `traces` | What the action itself leaves: an artifact, the moment it is written (`start`, before the action takes effect, or `effect`), and the rule that reads it, if one does |

[`dfir/trace/footprints.yml`](../dfir/trace/footprints.yml) then names, for each detection, the artifact its rule reads and the other artifacts the technique writes on the way.

## The search

A sequence is any number of erasures, in any order, with the technique somewhere among them. The tool explores every state such sequences can reach. A state records whether the technique has run, which blinding actions are in effect, whether the forwarder still ships, which of the technique's artifacts are still on the host, which are out of reach, and whether any alert has been raised. The space is finite, so the exploration is complete: a result is not a sample of sequences.

The rules of the world are these:

- When the technique runs, each artifact of its footprint is written unless its store is blinded. If the store is forwarded and the forwarder still ships, a copy leaves the host and is out of reach from then on. An artifact written on another machine is out of reach from the start.
- The detection's alert exists when the artifact its rule reads has left the host.
- An erasure removes the technique's artifacts from the stores it destroys. It cannot remove what has already left.
- An erasure's own trace raises an alert when it is written, leaves the host, and a rule reads it. A trace written at `start` leaves before the action takes effect, so clearing the Sysmon log does not hide the process record of the command that cleared it from the SIEM, although it does remove it from the host.

For each question the search then reports the cheapest sequence after which no surviving artifact answers it:

| Verdict | Meaning |
|---|---|
| out of reach | No sequence removes the answer |
| evident | Sequences exist, and every one of them raises a RASD alert: the detection's own, or the alert of a rule that read an erasure's trace |
| exposed (n) | A sequence of n actions removes the answer and raises no alert at all. The sequence is printed |

## What makes a trace count

A trace that names a detection carries a sample event, and `rasd trace --check` replays that event through the engine: the named rule must fire. A trace with a sample event and no detection must fire no rule. So when the model says clearing the System log is seen by `T1685.005_system_log_cleared`, the engine has confirmed it on this build; and when a rule is later written that reads a trace the model calls unread, CI fails until the model names it, and the results change with it.

The same check holds the model in step with the rest of the repository: the forwarded channels must be the ones the generated forwarder inputs ship, the artifact a footprint says the rule reads must belong to the rule's log source, and every detection must have a footprint or a stated reason for not having one.

## The rules that close the exposure

For every exposed pair the tool looks at the cheapest quiet sequence and at the traces that sequence sends to the SIEM unread. It supposes a rule for the trace that appears in the most sequences, searches again, and repeats until nothing is exposed or the sequences that remain leave nothing a SIEM rule could read. The result is an ordered list of the next rules to write, each with the number of pairs still exposed after it. A rule on an artifact (Sysmon 4, whatever stopped the service) is preferred to a rule on one command line.

## Evidence depth on the host

The same search is run on a host that forwards nothing, counting alerts as allowed. The number it gives is the depth of the evidence the host itself holds: how many actions it takes to remove every witness of an answer. A depth of 1 marks an answer that rests on a single store, which is where an investigation is most fragile and where collecting an optional artifact pays first.

## What an incident uses

`rasd trace <detection>` prints the witnesses of each question in collection order, the stores that roll over soonest first, with what each shows for this technique and what it cannot show. `--lost` removes the stores an incident has already lost (`siem` removes the forwarded copies) and prints what is left: the answers that can still be given, and the ones that cannot.

## The evidence request of a case

`rasd replay <export> --case-dir reports/cases` writes `evidence_request.md` into every case folder. It is the hand-over from the analyst who triaged the alerts to whoever collects from the host: every artifact the model says the fired detections leave, the stores that roll over first at the top, each with the questions it answers and what it cannot show. When the storyline itself contains a log clear (a Security 1102, or a System 104 naming its channel), every record written to that store on that host before the clear is marked as cleared, with whether the SIEM copy remains or the record is lost. A command line that asks for a clear is not counted as one; only the clear records are. The file ends with the answers that rest on a single artifact.

## Limits

- **The attacker's position is fixed.** Results assume an administrator on the host where the technique ran, with no reach to the domain controller, the file server, the decoy host or the SIEM. An intruder who also holds the domain controller turns its records into host records; the model would need that position added.
- **The catalogue is finite.** A verdict of out of reach or evident holds for the catalogued actions. Kernel tampering, patching event tracing in memory, editing single records inside a log file and attacks on the SIEM itself are not catalogued. Adding an action re-opens every result, which is how the model is meant to grow.
- **Forwarding is treated as immediate.** A record written while the forwarder ships is counted as shipped. A real forwarder has a delay, and an action inside that delay can win the race. The one place the model decides the race for the attacker is the forwarder's own stop.
- **Documented behaviour, not lab evidence.** Each entry carries its source and its basis: `vendor` for behaviour the vendor documents, `practitioner` for behaviour the DFIR community reports. The lab run that reproduces each erasure and confirms its traces is pending with the rest of the lab evidence, and nothing here raises a detection's maturity.
- **Windows hosts only.** The Linux and web detections are listed as not modelled, with the artifacts each needs.

## Extending the model

1. Add the store and the artifact to `model.yml`, with the questions the artifact answers, its basis and its source.
2. Add the artifact to the footprints of the detections whose technique writes it.
3. For a new anti-forensic action, add an erasure with its traces. Give every event-log trace a sample event, so the engine decides whether a rule reads it.
4. Run `rasd trace --check`, then `rasd build`.
