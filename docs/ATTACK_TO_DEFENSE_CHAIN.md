# Attack-to-Defense Chain

```text
Adversary Behavior
   ↓
Controlled Offensive Validation      red/<platform>/<test>/          rasd red
   ↓
Expected Telemetry                   expected_telemetry.md           rasd doctor
   ↓
Detection Logic                      detect/detections/<id>/rule.yml rasd lint · prove · fuzz
                                     detect/correlations/<id>/       rasd correlate
   ↓
SPL / KQL                            queries/spl · queries/kql       rasd build · parity
   ↓
Tests                                tests/true_positive|negative    rasd test
   ↓
Mutation Testing                     tests/mutations.yml             rasd mutate · prove
   ↓
Triage                               triage.md                       generated from contract.yml
   ↓
Response / DFIR Playbook             response.md · dfir/playbooks    generated + playbooks
   ↓
Closure / Escalation                 closure.md                      generated from contract.yml + tuning.yml
   ↓
CTI Mapping                          intel/mappings                  rasd chain
   ↓
Purple Scenario                      purple/scenarios                rasd chain
   ↓
Operational Evidence                 evidence.md                     rasd evidence
   ↓
Metrics                              docs/RASD_METRICS.md            rasd chain · score
```

## How the links are enforced

A chain is only as strong as its links, so each link is checked by CI rather than promised in prose:

| Link | Check |
|---|---|
| Red → Telemetry | `rasd red --check`: every test declares its telemetry, logging requirements, cleanup and safety notes |
| Red → Detect | Every red test's sample event **is** one of the detection's true positives, and CI proves it matches the rule |
| Detect → SIEM | `rasd parity`: the generated KQL and SPL return exactly what the rule returns on thousands of events, with each SIEM's null semantics; `rasd correlate`: the generated aggregations return exactly the correlation engine's alerts |
| Red → Correlate | A red test that names a correlation references one of its scenarios, and CI proves the scenario fires it |
| Detect → Tests | `rasd prove`: every value, field and branch of every rule is killed-tested; `rasd fuzz --check`: no new evasion bypass |
| Detect → DFIR | Every technique has a DFIR playbook with an evidence table; playbooks reference only detections and tests that exist |
| Detect → Intel | Every technique appears in the actor tradecraft map, with the ATT&CK group page as source |
| Purple → all | Every technique has a purple scenario linking existing detections, red test and playbook |
| Evidence → Score | The Operational Score is read only from `evidence.md` front matter written by `rasd evidence` from a real run, with SHA-256 of every input |
| Docs → files | `rasd links`: every relative link in every Markdown file resolves |

`rasd chain` prints the 20-point completeness map per technique and writes the [validation matrix](../purple/validation_matrix.md).
