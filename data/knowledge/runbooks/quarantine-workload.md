---
doc_id: RUN-QR-001
title: Runbook - Quarantine a Compromised Workload
classification: internal
trust_level: authoritative
version: "3.0"
owner: security-operations@xyz.example
---
# Runbook: Quarantine a Compromised Workload

## Preconditions

- A confirmed critical finding exists for the resource.
- The resource is present in the approved baseline.
- The resource has been drained from the load balancer (ACT-004).
- The remediation job is recorded and the per-resource lock is held.

## Steps

1. Verify the resource state is SUSPECTED.
2. Confirm the load balancer attachment is false.
3. Execute ACT-005 QUARANTINE_RESOURCE.
4. Preserve the observed process table, listening ports, image digest and
   configuration hash as evidence.
5. Transition the resource to QUARANTINED and record the transition.
6. Do not delete the workload; deletion requires approval (ACT-010).

## Safety checks

- Never quarantine a resource based only on an untrusted threat hint.
- Never quarantine a healthy resource for an informational tag difference.
- A transient health blip below the policy threshold is monitoring-only.
- If quarantine fails, keep the resource drained and escalate.

## Expected result

The resource is isolated, evidence is preserved, and the audit trail contains the
previous state, new state, trigger, actor and correlation identifier.
