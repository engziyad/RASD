# RASD-Health: Is Every Detection Still Being Fed?

A detection is the last link of a chain: the sensor writes the event, the forwarder ships it, the index receives it in time, the fields keep their names, the scheduled search runs. Every link breaks without an error, and a rule whose chain is broken answers exactly as it does on a quiet day: no alert. RASD-Health watches the chain, and gives every break the names of the detections it blinds.

```bash
rasd health --sample                                               # three ordinary days, then the day the pipeline breaks
rasd health last-week.jsonl --save-baseline health-baseline.json   # what healthy looked like: counts, not events
rasd health today.jsonl --baseline health-baseline.json            # a verdict for every detection
rasd health today.jsonl --baseline health-baseline.json --scheduler scheduler.jsonl --json health.json --strict
rasd health --check                                                # the watchdogs match the library (in CI)
```

The watchdogs for the SIEM, and the result on the sample, are in [queries/health](../queries/health/README.md).

## Where it stands among the other tools

| Tool | When | The question |
|---|---|---|
| [`rasd doctor`](COMMANDS.md) | once, before deployment | Will the rules work on this telemetry at all? |
| **`rasd health`** | every day, while they run | Is each rule fed today the way it was when it was last known to work? |
| [`rasd silence`](SILENCE.md) | afterwards, host by host | What does a month without an alert prove? |

Doctor reads one export against the contracts. Silence reads record numbers to prove nothing was removed. Health reads two moments, a baseline and today, and reports the difference in the only unit that matters to a SOC: detections that can no longer fire.

## The checks

| Check | A detection is touched when | Verdict |
|---|---|---|
| **silent** | a host that fed it in the baseline has sent nothing over a stretch in which the baseline, at the same hours, saw at least 20 events | degraded; blind when every host that fed it is silent |
| **volume** | what it reads arrives at under a quarter of what the baseline saw over the same hours, on the hosts still sending | degraded |
| **fields** | a field it reads is filled in 20 points fewer events, or in none. A name that appeared in its place is given as the rename to map | degraded; blind when the contract says the rule cannot work without the field |
| **truncation** | command lines pile up at one length the baseline did not show | degraded |
| **delay** | a host's events on a channel reach the index later than the scheduled search waits (5 minutes for a rule, 3 for a correlation) | degraded; blind when no sender's events arrive in time |
| **schedule** | the SIEM's own record shows the search did not run, or skipped more than 5% of its runs | degraded; blind when it never ran or skipped half |

Three decisions keep the verdicts honest.

**Silence is judged against the same hours.** A workstation that sleeps every night is not silent at 03:00, and one that stops at 10:30 on a working day is. The baseline keeps, for every host and kind of event, how many events each hour of the week saw. A baseline of a week or more is read by hour of the week; a shorter one by hour of the day, and then a Saturday judged against working days will look quiet, so take the baseline over whole weeks.

**A rare event is judged by its channel.** A cleared Security log may not happen once in a year, so its absence says nothing. What can be known is whether the Security log of each host still arrives, and that is what is checked. The verdict says so: `judged by its channel, security`.

**Nothing to compare is not healthy.** A detection whose kind of event is absent from the baseline gets `unknown`, never a green mark. Whether it is collected at all is doctor's question.

## The baseline

`--save-baseline` writes a small JSON profile: per kind of event and per host, the count for each hour of the week, how often each field the rules read was filled, the field names seen, the usual delay. No event, no command line and no user name is kept, so the profile can be stored beside the detections and compared against every day's export. An earlier raw export works as a baseline too.

The current side is always an export of events, in the SIEM's own field names when a [telemetry profile](../profiles/README.md) is given (`--profile auto`). Add the time each event was indexed (`_indextime`, `event.ingested`, `_TimeReceived`) to the export and the delay check runs; add the scheduler's record (`index=_internal sourcetype=scheduler`, or Sentinel's `SentinelHealth`) with `--scheduler` and the schedule check runs. Without them those two checks say nothing, and the others still hold.

## The watchdogs

The same watch, kept inside the SIEM. `rasd health --write` generates five searches in SPL and KQL from what the library's own rules read: their log sources and event ids ([`tools/mappings.yml`](../tools/mappings.yml)), their contracts' fields, the Splunk app's schedule. The app schedules the SPL ones and writes every row to the alert index with the detections it blinds; a detection added to the library is watched from the build that adds it, and `rasd health --check` fails the build when the two disagree.

They are deliberately simpler than the offline judge: yesterday against the same day last week, a fixed four hours of silence for hosts that normally report around the clock. Thresholds that need a real baseline belong to `rasd health`.

Two of them wait before they speak, because a deployment is new exactly once. `schedule` reads the scheduler's record up to the present, and does not name a search that has no run until Splunk has been up longer than the longest schedule of the app and its wait (15 minutes with today's library). `delay` does not judge a channel in the hour Splunk first hears from it: what a new host sends first is its backlog, days old on a machine that was logging before Splunk read it. Both rules come from the lab's own Splunk, where the first forms of these searches raised an alarm over a deployment that was in order.

## Limits

- The SPL watchdogs have run on a live Splunk only in the lab, beside hosts made for one run ([what Splunk answered](../queries/health/README.md)). That shows Splunk accepts them, and that they are quiet over a lab in order. It does not show one of them catching its fault: no feed was broken on purpose, `silent` and `volume` compare with a week such a host has not lived, and the two rules above keep `schedule` and `delay` from judging a Splunk that young. The KQL searches have **not yet run on a live Sentinel**, and the KQL `delay` has no first-hour rule yet.
- Health sees that telemetry stopped, not why, and not whether someone stopped it on purpose. A log cleared or a sensor killed by an intruder is [RASD-Silence](SILENCE.md)'s subject, and the steps that survive it are [RASD-Trace](TRACE.md)'s.
- A baseline taken while something was already broken makes the break normal. Take it from a period the detections were known to work: a lab run that fired them is the strongest one.
- Volume is compared per host. A fleet that halves in size because half the hosts were retired is reported as silent hosts, which is true, and is yours to dismiss.

<sub>RASD · Continuous Detection Assurance Framework</sub>
