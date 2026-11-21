---
doc_id: RUN-RS-001
title: Runbook - Restore a Workload from the Approved Baseline
classification: internal
trust_level: authoritative
version: "3.1"
owner: platform-reliability@xyz.example
---
# Runbook: Restore from the Approved Baseline

## Principle

Restoration must rebuild the workload from the approved baseline. It must never copy
the current observed state, because that state may contain attacker persistence.

## Inputs

- approved image registry reference and digest;
- approved configuration hash;
- approved port set;
- approved process inventory and executable paths;
- validation rule set;
- remaining restore retry budget.

## Steps

1. Confirm the resource is QUARANTINED.
2. Execute ACT-006 RESTORE_FROM_BASELINE.
3. Materialise the workload from the approved image digest and configuration.
4. Record the restored image digest, configuration hash, port set and process count.
5. Transition to RESTORING.
6. Proceed to ACT-007 VALIDATE_RESOURCE.

## Failure handling

If the artefact source serves a tampered image, restoration may appear to succeed
while the digest remains invalid. Validation must catch this. A failed restore or
validation transitions to FAILED. If the retry budget remains, the resource returns
to QUARANTINED for another attempt. When the budget is exhausted, escalate and keep
the resource isolated.

The retry budget is the minimum of the action catalogue limit, the baseline policy
limit and the platform configuration. It is never unbounded.
