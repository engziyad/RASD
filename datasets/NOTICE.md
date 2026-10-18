# Notice

`datasets/extracts/` holds events reduced from two public datasets. They are redistributed under their own licenses, not under this repository's MIT license for its code.

## Splunk Attack Data

- Source: https://github.com/splunk/attack_data (files under `datasets/attack_techniques/`)
- Copyright 2023 Splunk Inc, as written in the upstream LICENSE (the repository ships no NOTICE file at the pinned commit)
- License: Apache License 2.0, [LICENSES/splunk-attack-data.txt](LICENSES/splunk-attack-data.txt)
- Extracts: `extracts/splunk/`

## OTRF Security-Datasets

- Source: https://github.com/OTRF/Security-Datasets (files under `datasets/atomic/` and `datasets/compound/`)
- Copyright (c) 2021 Open Threat Research Forge
- License: MIT, [LICENSES/otrf-security-datasets.txt](LICENSES/otrf-security-datasets.txt)
- Extracts: `extracts/otrf/`

## Changes made

The extracts are modified: each keeps only the events that fired or that a firing correlation window counted, each event only the fields RASD's rules and profiles read plus time, host and user context, and values longer than 300 characters are cut to their first 200 and last 60 characters. Each event carries the ordinal and the SHA-256 of its original record. The full files are not redistributed; `rasd datasets fetch` downloads them from their sources at the pinned commits listed in [catalog.yml](catalog.yml).

## Not redistributed

EVTX-ATTACK-SAMPLES (https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) is licensed under the GNU GPL v3. No event or record from it is committed here: the catalog lists its files by path and SHA-256 and describes each one in its own words, and `results.json` keeps only what RASD produced on them (counts, alert times and record numbers).
