# Public datasets

A dataset is not evidence. A dataset every rule ran on, with the result recorded where anyone can check it, is.

This folder holds what RASD needs to replay public attack recordings through every detection and correlation and to keep the result honest:

| File | What it is |
|---|---|
| [`catalog.yml`](catalog.yml) | Every file RASD replays: its source repository, the pinned commit, its SHA-256, the reader and telemetry profile it needs, and what RASD must do on it (`expect`, `also`, `quiet`), the earlier files it shares records with (`overlap`), the detections no public dataset exercises yet (`gaps`), the rules public data asks for (`next`), the rules changed after these files were replayed (`changed_after_replay`), and which files are held out (`holdout`, with `missed` and `found` from their first replay) |
| [`holdout_labels.json`](holdout_labels.json) | The labels of the held-out files, written from their raw events before RASD first replayed them, with the records behind each label, round by round ([held-out files](#held-out-files)) |
| [`results.json`](results.json) | The last full run: events, repeats, shared records, routed events, alerts per detection (and how many are new evidence) with first and last time, correlation windows, and what each applied tuning kept quiet. It records the SHA-256 of every rule, tuning, profile and catalog entry that produced it |
| [`extracts/`](extracts/) | The events that fired or that a firing correlation window counted, reduced to the fields the rules read (only for sources whose license allows redistribution) |
| [`LICENSES/`](LICENSES/) and [`NOTICE.md`](NOTICE.md) | The upstream licenses and what was changed |
| `cache/` | Downloads (not committed) |

The result, per detection: [docs/PUBLIC_DATA_VALIDATION.md](../docs/PUBLIC_DATA_VALIDATION.md) and a `public_evidence.md` page in every detection folder.

## Run it

```bash
rasd datasets                  # the catalog: sources, licenses, what is cached
rasd datasets fetch            # download every file and verify its SHA-256
rasd datasets run              # replay all of them and compare with the catalog
rasd datasets run --only T1003.001 -v
rasd datasets run --write      # after a rule change: leak scan, then new results.json, extracts and pages
rasd datasets leaks            # the leak scan on its own
rasd datasets check            # what CI runs, offline
```

`fetch` downloads Splunk Attack Data files from GitHub's LFS media host pinned to the commit (the SHA-256 of each file equals its Git LFS object id, so the hash ties the file to the commit). One Splunk file, a capattack zip, is kept in the repository itself rather than in LFS (`lfs: false` in the catalog); it comes from raw.githubusercontent.com at the pinned commit, as the OTRF and EVTX-ATTACK-SAMPLES files do, and its SHA-256 and the SHA-256 of each log read inside it are pinned. Where that host is blocked but git works, `fetch --git` checks those files out of the pinned commit with a blob-less fetch. A file whose hash does not match is deleted, and `run` refuses a file it cannot verify.

The EVTX files need `pip install python-evtx`. python-evtx writes hex values with every byte (`0x001fffff`, `0x00000018`); Windows, and every pipeline fed from Windows, writes them without leading zeros (`0x1fffff`, `0x18`), so the reader renders them the Windows way. Without that, the access mask of every LSASS handle and the status code of every Kerberos failure in those files would read differently from what a SIEM receives.

## What `run` checks

Each file is read, normalised with its profile (`nxlog-windows` for the OTRF JSON, `windows-security-4688` for a Security 4688 export, native names otherwise) and replayed through every detection and correlation. The run fails when:

- a detection listed under `expect` stays quiet: the file records that behaviour, checked event by event, so the rule must fire;
- a detection fires and the catalog does not explain it: every alert is either the recorded attack (`expect`) or listed under `also` as `harness` (the lab's test harness did what the rule looks for: the automation that set up, launched and cleaned up the recorded attack), `benign` (other legitimate activity did it: an agent, a log reset) or `false-positive` (the behaviour did not happen). Where the harness fires an expected detection beside the attack, the `also` entry says which alerts are the harness with `where` - the fields such an alert carries, for example the Ansible launcher's `-NonInteractive -ExecutionPolicy Unrestricted -EncodedCommand` in `CommandLine` - and only the other alerts count for the attack: an expected detection that fires on the harness alone is missed, and a detection listed as quiet may fire only on what its `where` explains;
- a detection listed as `quiet` fires on anything an `also` entry's `where` does not explain (on a held-out file, any alert of a quiet-labelled detection goes under `found`), or one listed under `also` no longer does: the documented limits are re-checked on every run;
- the file holds records of an earlier file that the catalog does not declare under `overlap`, or a declared overlap is gone.

Each `quiet` entry has a kind: `gap` (public data shows the behaviour in telemetry RASD reads and no rule reads it yet; it names the next rule), `scope` (the behaviour is outside what the rule is written to detect), `blind-spot` (a limit the rule documents), `telemetry` (the recording lacks the event the rule reads) or `negative` (the file does not hold the behaviour). The pages count a detection's result over every recording of its behaviour - "fires on 8 of the 16 public recordings" - with the quiet ones by kind, rather than over the files it fires on.

The applied tunings are measured on the same events: what each filter kept quiet, and what each exception took back.

## Every record counts once

Public files repeat records, and some files are copies of others. A record is identified as Windows numbered it - host, channel, record number and time - or by its content where the file carries no record number:

- a record a file holds more than once is read once. The OTRF compound LSASS captures repeat thousands of records, and one Splunk Kerberos file repeats one record 86 times with the service name edited in 85 of the copies; both are listed in the [validation page](../docs/PUBLIC_DATA_VALIDATION.md#files-that-repeat-records);
- a record an earlier file of the catalog already holds - copied, or copied with a field edited - still runs through every rule, but its alert is not new evidence. The files that hold records of an earlier one are declared under `overlap`, among them two PurpleSharp spray files that are the same 137 records with one status code edited, a doctored service record and target-side task events exported twice in two formats.

A file whose alerts are all on records of an earlier file is not counted as another recording of the behaviour, and the alert totals count each record once.

## Held-out files

The rules were changed after the in-sample files showed their gaps, so their result on those files is in-sample. The catalog's other 105 files are held out: every Splunk Attack Data file under the folders of the techniques RASD covers, listed in the upstream metadata or not and not already in the in-sample set, that holds Windows Sysmon, Security or System events or Sysmon for Linux events in a format RASD reads (XML, Splunk's classic WinEventLog text, NXLog JSON, EVTX inside a zip), up to 60 MB - added after the rule changes. The labels file states the selection exactly, with every file left out and why; a file read before its labels were written is in-sample, never held out. Before RASD first replayed them, reviewers without access to the rules, tests, catalog or results labelled every file from its raw events against each detection's README: `attack` (the recorded attack produced an event inside the documented scope, so the detection must fire), `other` (non-attack activity did), or why a detection is not expected (`scope`, `telemetry`, `blind-spot`), each with the records that show it. The labels are committed as they were written ([`holdout_labels.json`](holdout_labels.json); passwords, a 64-character hex argument and one offensive task name redacted), and the loader refuses a catalog whose `expect` and `quiet` entries for these files differ from them. They predate the ATT&CK v19 mapping, so they name the log-clearing detections by the IDs the reviewers saw (`T1070.001_*`); the loader maps those through [`intel/mappings/attack_v18_aliases.yml`](../intel/mappings/attack_v18_aliases.yml) to `T1685.005_*`, and the file stays byte for byte the one the reviewers wrote.

What a replay does beyond the labels is recorded, never relabelled: an expected detection that stayed quiet goes under `missed`, a detection that fired where the labels did not expect it goes under `found` (with the reason), and every other alert is explained under `also`. A held-out miss that later fires fails the run: fixing a rule or a reader on a held-out file takes that file out of the held-out set, in the open (`demoted_from`). An expected detection that fires only on records an earlier file holds is not counted.

Results, by round of labelling, each on its first replay:

- round 1, the 44 metadata-listed XML files: 8 of 8 expectations met. On one file (H34, a gh0st RAT run) two detections fired beyond the labels, on the recorded attack: the rundll32 rule matches a writable path anywhere in the command line and the Run key rule counts rundll32 as a launcher, which their READMEs did not say; the READMEs were corrected;
- round 2, the 44 files the metadata does not list, most in the classic text format: 16 of 18, one of the 16 (H75) only on a record an earlier held-out file holds, so not counted. H50 missed because the classic reader kept only the first line of a multi-line command line - the reader was fixed and H50 left the held-out set - and H86 missed because the Kerberoasting RC4 rule drops tickets requested from the domain controller itself, which its README did not say (the README now lists it as a blind spot; the rule was not changed). The WinRM rule fired beyond the labels on two files (H47, H48), on the recorded attacks seen through Security 4688, which its README did not name; the README was corrected;
- round 3, 18 files: the T1190 folder's Windows and Linux telemetry (left out of the first two rounds because RASD's T1190 rules read web logs, though the other rules read these files), an NXLog JSON scheduled-task file and the Sysmon and Security logs inside a capattack zip: 3 of 3 met, nothing beyond the labels. The alerts the labels expected from the test harness (Ansible, and a capture tool clearing every log before it records) came as expected.

A later reader fix was checked against every held-out file: none changed its result. The labels also say how much of the recorded attacks the rules cannot see: most held-out files record their technique through telemetry or variants no RASD rule reads - exploited servers above all - which is why only 24 of the 105 files carry an expectation (27 expected detections, of which 26, in 23 files, are counted: H75's fired only on a copied record).

## What public data proves

It proves that a rule fires on telemetry recorded from real attack tooling, in somebody else's lab, with their Windows builds, Sysmon versions and pipeline quirks, and it measures every applied tuning against that lab's background activity. Replaying public data has already changed rules here: the LSASS rule's System32 filter hid Invoke-Mimikatz, a migrated Meterpreter session, nanodump dropped into System32 and PPLdump; the service rule missed a bare `cmd.exe` service binary and `C:\Temp`; the rundll32 rule missed three LOLBAS proxy exports; the password spray correlation missed sprays over unknown and disabled accounts (the disabled-account case is also recorded, unedited, in the classic export of a separate PurpleSharp run). Each change was proven on the public events and on new tests - which makes those rules' results on these files in-sample: the catalog lists them under `changed_after_replay` and their pages say so.

It does not prove the SIEM side: ingestion, field extraction, latency and alerting are proven by the lab run (`rasd evidence`) and by a SIEM replay ([checklist](../docs/PUBLIC_DATA_VALIDATION.md#siem-replay-checklist)). A lab's background activity is not an estate's noise, the false-positive label is one per alert on short lab captures rather than a rate, and the attacks are the ones somebody chose to record. A detection's maturity level does not change with public data; only lab evidence raises it to Validated.

## How an extract is built

Each committed event keeps only the fields any rule or correlation reads, the profile's source field names, and the time, host and user context. Values longer than 300 characters (encoded PowerShell stagers above all) are cut to their first 200 and last 60 characters. The reduced event is checked to decide exactly what the full event decided - its route, every rule's verdict, every correlation's group and counted value, its time - and a value that cannot be cut without changing a verdict is kept whole. Each line carries the ordinal of its record in the original file and the SHA-256 of that record, so every event can be traced to the record it came from, names the earlier file that holds the same record when there is one (`seen_in`), and names the detections whose alert on it the catalog's `also` entry explains by `where` (`also`); the fields a `where` reads are kept, and the reduced event must fall under the same entries as the full one.

`rasd datasets check` replays every extract on every CI run: each event must still fire exactly as recorded, each correlation window must come back with the same count, the alerts on records no earlier file holds must match the new-evidence counts, the alerts a `where` explains must match the harness counts, and `results.json` must have been produced by the rules, tunings, profiles and catalog in the repository - a changed rule fails CI until the public data is replayed again. `rasd parity` also evaluates the generated KQL, SPL and Defender queries on every extract event, with RASD's own model of each language's semantics (not on a SIEM).

## Sources

The three sources in use are listed, with their pinned commits and licenses, in [docs/PUBLIC_DATA_VALIDATION.md](../docs/PUBLIC_DATA_VALIDATION.md#sources). EVTX-ATTACK-SAMPLES is GPL-3.0, so neither its events nor any field value from them (host names, accounts, addresses) is committed here: its results are recorded as counts, alert times and record numbers, and anyone can fetch and replay the files. `run --write` enforces it with a leak scan: every host, account, domain, address, GUID and file name in those files that appears in no redistributable file, and every long value (command line, registry data, stack frame) seen only there, is searched for in every file of the repository, and nothing is written while one is found. `rasd datasets check` also fails when `results.json` quotes a field value from such a source.

Other public sources and lab tools, and why they are not used yet:

| Source | Status |
|---|---|
| Splunk BOTS v1/v3 | A full Splunk index of a scenario (gigabytes); it needs a Splunk instance to read. A candidate for the SIEM replay level |
| Malware-Traffic-Analysis.net, CIC-IDS2017 | Packet captures and network flows: RASD has no network detections yet |
| Microsoft Sentinel sample data | Connector samples for parser tests rather than attack recordings |
| Splunk Attack Range, Atomic Red Team, MITRE CALDERA | Lab tools, not datasets: they generate the lab evidence (`red/` holds RASD's own tests) |
