---
doc_id: RUN-VAL-001
title: Runbook - Validate Recovery Before Return to Service
classification: internal
trust_level: authoritative
version: "2.6"
owner: security-operations@xyz.example
---
# Runbook: Validate Recovery

## Mandatory rules

Every resource must pass all mandatory validation rules attached to it:

- VAL-IMG-001 image digest and reference match the approved baseline;
- VAL-CFG-001 configuration hash matches the approved baseline;
- VAL-PORT-001 no unapproved listening ports;
- VAL-PROC-001 no unapproved processes;
- VAL-PROC-002 approved processes run from approved binaries and users;
- VAL-HLTH-001 health checks pass with zero consecutive failures;
- VAL-PROBE-001 the simulated service probe returns HTTP 200.

## Fail-closed semantics

A missing result is a failure. An exception inside a check is a failure. A check
that cannot observe the required field is a failure. Only an explicit pass for every
mandatory rule permits the RECOVERED state.

## Return to service

ACT-008 RETURN_TO_SERVICE is permitted only when:

- the resource state is RECOVERED;
- every mandatory validation for the latest attempt passed;
- no open critical findings remain;
- the resource is still drained from the load balancer.

The policy engine re-checks these conditions at execution time. The dashboard cannot
override them.

## Evidence

Record each rule result with observed value, expected value, timestamp and attempt
number. Failed validations remain visible in the audit trail even after a later
attempt succeeds.
