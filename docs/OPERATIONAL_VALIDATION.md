# Operational Validation

How to move a detection from *SIEM-Ready* to *Validated*: run the attack in a lab, export the telemetry, and let `rasd evidence` decide whether the rule really fired.

RASD tracks four validation levels, and only the lab run moves the maturity level:

| Level | What proves it | Where |
|---|---|---|
| Public datasets | Every rule replayed on pinned public attack recordings, every alert explained | [PUBLIC_DATA_VALIDATION](PUBLIC_DATA_VALIDATION.md) (`rasd datasets`) |
| Validated (lab evidence) | The attack run on your lab VM and the rule firing on events bound to that run | this page (`rasd evidence`) |
| SIEM replay | The generated query run in your Splunk or Sentinel over replayed data, counts compared with the engine | [checklist](PUBLIC_DATA_VALIDATION.md#siem-replay-checklist), SIEM alerts in `rasd evidence` |
| Production | The detection tuned and running on an estate's own telemetry | [ENTERPRISE_ADOPTION](ENTERPRISE_ADOPTION.md) |

**Fast path with Splunk:** the [lab kit](../red/lab/README.md) does steps 1-3 in two commands (`Test-LabReadiness.ps1 -Fix`, `Invoke-RasdLabRun.ps1 -LabConfirmed`), and [`queries/splunk_app`](../queries/splunk_app/README.md) installs every detection in Splunk as a scheduled alert named after its detection id, with the report whose CSV export is the `--siem-alerts` input. The steps below are the same run done by hand.

## 1 · Prepare the lab
- A disposable Windows 10/11 or Server VM joined to a lab domain, with Sysmon installed (a configuration that logs process creation, process access to lsass.exe and Run-key writes) and command-line auditing on.
- Sysmon with [`red/lab/sysmon-rasd.xml`](../red/lab/sysmon-rasd.xml) or any configuration that logs the same events; `red/lab/Test-LabReadiness.ps1` proves it with a live probe.
- Audit policy on the DC: Kerberos Service Ticket Operations (4769), Kerberos Authentication Service and Credential Validation failures (4771, 4776), Logon failures (4625).
- For the Linux tests: a disposable Linux VM with Sysmon for Linux logging process creation (event 1) to syslog or journald.
- For the web tests: a lab copy of a web application (for example OWASP Juice Shop) on localhost or a private address, with its access log in combined format.
- Optional: the VM's logs forwarded to your SIEM, so the SIEM result can be scored too.
- Never a production host, and never a VM whose credentials exist anywhere else.

## 2 · Run the offensive tests
```powershell
.\red\Invoke-RasdEmulation.ps1 -List
.\red\Invoke-RasdEmulation.ps1 -Technique All -LabConfirmed -DryRun        # see what would run and why
.\red\Invoke-RasdEmulation.ps1 -Technique All -LabConfirmed -Spn MSSQLSvc/sql01.lab.local:1433
```
Credential access (`-IncludeCredentialAccess`) and the Security-log clear (`-IncludeSecurityLogClear`) are opt-in. The runner writes `emulation-results.json` with each step's UTC window, expected detections, collected artifacts (SHA-256) and cleanup status (verified / manual / failed).

Web and Linux tests run with `python3 red/run_red.py` and write the same results format.

## 3 · Export the telemetry
```powershell
.\red\Export-LabTelemetry.ps1 -Since '<start time printed by the runner>'
```
On the domain controller, for Kerberoasting and the password spray: `.\Export-LabTelemetry.ps1 -LogName Security -EventId 4768,4769,4771,4776,4625 -OutFile .\dc-export.jsonl`.

On a Linux lab host with Sysmon for Linux, after `run_red.py`:

```bash
python3 red/linux/export_sysmon_linux.py --since '<start time printed by the runner>' --out linux-export.jsonl
journalctl -t sysmon -o cat --since '-2h' | python3 red/linux/export_sysmon_linux.py --input - --out linux-export.jsonl   # journald hosts
```

On the web application's host, after the web tests (every request carries the run marker in its User-Agent):

```bash
python3 red/web/export_access_log.py --input access.log --marker <run marker> --out web-export.jsonl
```

## 4 · Turn the run into evidence
```bash
rasd doctor lab-export.jsonl                       # fields intact? aliases? truncation?
rasd evidence --run lab-20261012-101500.zip dc-export.jsonl siem-alerts.csv --dry-run
rasd evidence --run lab-20261012-101500.zip dc-export.jsonl siem-alerts.csv
```
`--run` takes the zip `Invoke-RasdLabRun.ps1` packed, or a run folder, plus the exports made after it. Before anything is evaluated it refuses:

| Refused | Checked against |
|---|---|
| A zip that differs from the `.sha256` beside it | The sha256sum line the lab run writes next to its zip. Without one the run is still read, the output says the zip was not compared, and `evidence.md` records `sha256_file: absent` |
| A manifest that lists no files, or a file it lists that is missing or changed | The SHA-256 in `lab-run-manifest.json`. `Invoke-RasdLabRun.ps1` writes it; `run_red.py` (Linux and web) does not, and the output says so |
| A file inside the zip that the manifest does not list | The manifest. In a run folder, a file added after the run (a DC export dropped next to the results) is read and labelled as added; it is not counted as verified |
| A collected artifact that differs from its recorded hash | The SHA-256 `emulation-results.json` recorded for it. Artifacts left out of the run are named in the output; `evidence.md` keeps the recorded hashes |
| A zip member outside the run folder, or twice in the zip | Its path |
| More or fewer than one `emulation-results.json`, no telemetry, two exports with one name | The files found |
| An export given beside the run whose `.sha256` differs | The sha256sum line `Export-LabTelemetry.ps1` writes next to each export |

For tamper-evident evidence add `--strict`: every input must be anchored by a hash recorded when it was written. It also refuses a zip without its `.sha256`, a run without a manifest or whose manifest does not list `emulation-results.json`, any file in the run folder the manifest does not list (a folder run as much as a zip), an artifact the runner recorded that is not in the run, and an export beside the run without its `.sha256` (`Export-LabTelemetry.ps1` writes one; for the Splunk alert export, `sha256sum siem-alerts.csv > siem-alerts.csv.sha256` on the machine that exported it). `evidence.md` then records `verification: strict`, and its re-run command carries `--strict`.

```bash
rasd evidence --run lab-20261012-101500.zip dc-export.jsonl siem-alerts.csv --strict
```

It then takes JSON lines exports as telemetry and CSV or JSON alert exports (an alert name and time, no event fields) as SIEM alerts, prints what it found and where each file came from, and records the zip, its SHA-256 and whether the `.sha256` file was there in every `evidence.md` it writes. The separate form gives each file by hand:

```bash
rasd evidence --results emulation-results.json --logs lab-export.jsonl dc-export.jsonl --siem-alerts siem-alerts.csv
```
When the telemetry comes out of a SIEM or EDR in its own field names (Elastic ECS, Splunk CIM, Sentinel ASIM, Defender advanced hunting), add `--profile <name>` (or `--profile auto`): the [telemetry profile](../profiles/README.md) gives the rules their field names, and the profile used is recorded in `evidence.md`.

For every detection a step was expected to trigger, `rasd evidence` reports **FIRED** (and writes `evidence.md`) or **MISSED** (and fails). A miss is never written down as evidence: check the audit policy, the export window and the field mapping, in that order.

An event counts as evidence of the run only when it is bound to it:

| Binding | Rule |
|---|---|
| Time | Inside the step's UTC window (5 s before it, `--grace` seconds after) |
| Host | Logged on the emulation host - or, for an event a DC or target logs about a client (4768, 4769, 4771, 4776, 4624, 4625) or a web request (`c-ip`), its client address is one of the host's own addresses (`host_ips`, recorded by the runner) or its workstation is the host. When the web target is on the same host, the runner adds 127.0.0.1 and ::1 to `host_ips`. A remote step (WinRM, `-Target`) records its target as `targets`: an event logged on that target counts only when it carries the step's token |
| Token | Where the test's step declares `bind`, the event carries this run's token: the marker itself, its random part (`R{hex}` for the test event log), or the Base64 of the encoded payload. A detection firing on something the run did not create is not counted |

Each test's `detection_links.md` shows which binding applies to each detection, and `rasd red --check` proves that the true positive mirroring the test carries the token.

A step can also name **correlations** (the password spray step names `T1110.003_password_spray_burst`; the web steps name `T1190_api_auth_probing` and `T1190_object_id_enumeration`). A correlation fires as evidence only when the base-rule events bound to the run - inside the step window, logged on the host or naming it as the client - reach its threshold on their own; another client spraying in the same minutes does not help. Its evidence goes to `detect/correlations/<id>/evidence.md` and records the window, the group, the count and the moment the threshold was reached; latency runs to that moment. With the RASD Splunk app, the correlation alert carries the client address as `alert_host`, which is matched against the host's addresses.

`--siem-alerts` takes a Splunk or Sentinel alert export (CSV or JSON); an alert counts when its name contains the detection's id, title or rule UUID and its time falls inside the step's window. With the RASD Splunk app, run the report **RASD - alert export** (`index=rasd_alerts`, written by each alert's Log Event action, with the alerting host) over the run window and export it as CSV. If that index is unavailable, **RASD - alert export (audit)** (`index=_audit action=alert_fired`) and **RASD - alert export (scheduler)** (`index=_internal sourcetype=scheduler`) read two independent sources.

## 5 · Commit and rebuild
```bash
rasd build && rasd chain
git add detect/detections/*/evidence.md detect/correlations/*/evidence.md && git commit -m "Lab evidence: <date>"
```
The Operational Score, the evidence and latency matrices, the maturity levels and the metrics update from the committed evidence files.

## What each evidence file proves
`evidence.md` front matter records the run, host, test and step, the marker and how the events were bound to the run (`bound_by`), the number of matching events, the telemetry latency, SIEM alert latency and SIEM pipeline delay, cleanup status, the artifacts' hashes and the SHA-256 of every input file. Anyone holding the raw exports can re-run `rasd evidence --dry-run` and get the same verdict. The hashes make the file verifiable; they are not a digital signature.
