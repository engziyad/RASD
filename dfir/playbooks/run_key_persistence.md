---
playbook: run_key_persistence
techniques: [T1547.001, T1112]
detections: [T1547.001_registry_run_key_persistence]
red_tests: [run_key_persistence]
---

# DFIR Playbook: Run Key Persistence

## Trigger
A Run or RunOnce value was written that starts a script interpreter or a binary in a user-writable folder.

## Required Data
- Registry value set events (Sysmon 13) with the writer process
- Process creation at the next logons (did the payload run?)
- The referenced file

## First 15 Minutes
1. Check which process wrote the value (Sysmon 13 `Image`).
2. Read the full key and data; hash the referenced file and check its signer.
3. Check whether it already ran at a logon after the write.
4. Search the same user and host ±30 minutes for the delivery.

## Deep Investigation
- Delivery chain of the writer process (download, macro, archive)
- Network activity of the payload when it ran
- Other persistence on the host ([`persistence_sweep`](../queries/kql/persistence_sweep.kql))
- The same value name or payload hash on other hosts

## Evidence to Collect
| Evidence | Source | Purpose |
|---|---|---|
| Registry event | Sysmon EID 13 | Full key, data and the writer process |
| Referenced binary | Disk / EDR | Hash, signer, first-seen date |
| Payload executions | Sysmon EID 1 at logon | Whether persistence already fired |
| Writer process tree | Sysmon EID 1 | How the value got there |

## Escalate If
- The writer is reg.exe, PowerShell or an unsigned binary
- The referenced file is unsigned or new to the environment
- The value data runs a script interpreter
- The value name imitates a known application but the path does not match it

## Closure Guidance
Close as benign only for a per-user application whose binary is signed by its vendor and lives in that vendor's folder. Export the key into the ticket before removing anything, and propose the filter in the detection's `tuning.yml` so it is measured before it is applied.
