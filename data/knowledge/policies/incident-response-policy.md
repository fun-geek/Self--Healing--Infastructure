---
doc_id: POL-IR-001
title: Incident Response and Self-Healing Policy
classification: internal
trust_level: authoritative
version: "2.3"
owner: security-operations@xyz.example
---
# Incident Response and Self-Healing Policy

## Purpose and scope

This policy governs automated containment and recovery for the XYZ Industries
customer-order platform. It applies to every virtual machine and container that is
registered in the approved infrastructure baseline. The approved baseline is the
only source of truth for trusted image digests, configuration hashes, listening
ports and process inventories.

## Mandatory workflow

Every confirmed compromise follows the same ordered workflow:

1. DETECT using deterministic baseline comparison.
2. DRAIN the resource from the load balancer (ACT-004).
3. QUARANTINE the resource while preserving evidence (ACT-005).
4. RESTORE from the approved baseline image and configuration (ACT-006).
5. VALIDATE every mandatory rule (ACT-007).
6. RETURN TO SERVICE only when every mandatory validation passes (ACT-008).

Restarting a compromised workload in place is prohibited. A restart can preserve
attacker modifications, scheduled tasks, injected binaries and persistence.

## Authority and automation limits

The remediation orchestrator may autonomously execute ACT-004 through ACT-008
when a critical finding is confirmed and the resource has an approved baseline.
Actions ACT-010 (DELETE_RESOURCE) and ACT-011 (DISABLE_TELEMETRY) always require a
recorded human approval from the approver role. The orchestrator cannot approve
its own actions, and an LLM cannot authorize any action.

## Evidence preservation

Quarantine must retain the observed process table, listening ports, image report,
configuration hash, health state and the identifiers of the telemetry events that
produced each finding. Evidence is immutable. Audit records are append-only and
hash-chained; any modification is detectable.

## Escalation

If restoration or validation fails, the resource stays isolated. A bounded retry
budget of two restore attempts applies. When the budget is exhausted, the incident
is escalated to a human responder and the resource remains quarantined. The
platform must never mark an unvalidated resource as healthy.
