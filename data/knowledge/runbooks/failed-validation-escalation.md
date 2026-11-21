---
doc_id: RUN-ESC-001
title: Runbook - Failed Validation and Escalation
classification: internal
trust_level: authoritative
version: "2.2"
owner: security-operations@xyz.example
---
# Runbook: Failed Validation and Escalation

## Immediate actions

1. Keep the resource quarantined. Do not attach it to the load balancer.
2. Record the failed rule identifiers, observed values and expected values.
3. Record the attempt number and remaining retry budget.
4. If budget remains, retry restoration from the approved baseline.
5. If the budget is exhausted, execute ACT-009 ESCALATE_INCIDENT.

## Root-cause hypotheses

- poisoned or unavailable artefact source (image digest mismatch persists);
- baseline configuration incompatible with the current service version;
- health probe dependency unavailable;
- incomplete baseline (missing approved process or port).

## Human decision options

- refresh the artefact mirror and retry;
- correct the baseline through change management;
- rebuild the workload on a clean host;
- delete the resource (ACT-010) only with approver authorization.

## Prohibited actions

- Do not force the resource to HEALTHY.
- Do not suppress the failed validation to unblock deployment.
- Do not disable telemetry or auditing to hide the failure.
- Do not approve your own remediation.
