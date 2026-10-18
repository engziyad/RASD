# Investigation Flow

How an alert moves from the queue to closure in RASD. Every step points to the artifact that supports it.

```text
Alert fires
   │   triage card: detect/detections/<id>/triage.md (correlations: detect/correlations/<id>/triage.md)
   ▼
L1 validation ── benign and verified? ──► closure note (Benign / False Positive) + tuning proposal
   │   contract.yml response.l1_action
   ▼
L2 investigation
   │   DFIR playbook (dfir/playbooks), pivot queries (dfir/queries)
   │   timeline (models/timeline_model.md), evidence table (templates/evidence_table.md)
   ▼
Confirmed malicious? ── no ──► closure note with what was checked
   │ yes
   ▼
Incident response
   │   contract.yml response.ir_action, containment plan (templates/containment_plan.md)
   ▼
Containment → eradication → recovery
   ▼
Lessons for detection
       missed step → new red test or detection; noisy rule → tuning.yml; missing log → telemetry gap
```

| Stage | Owner | Leaves behind |
|---|---|---|
| Validation | SOC L1 | Triage notes, disposition or escalation |
| Investigation | SOC L2 | Timeline, evidence table, playbook checklist |
| Response | IR | Containment plan, incident summary |
| Improvement | Detection engineering | Pull request: rule, tests, tuning, red test |
