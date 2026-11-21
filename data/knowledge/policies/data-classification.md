---
doc_id: POL-DATA-001
title: Data Classification and Evidence Handling Standard
classification: internal
trust_level: authoritative
version: "1.1"
owner: data-governance@xyz.example
---
# Data Classification and Evidence Handling

## Classes

Resources are classified as public, internal, confidential or restricted. The
order-payments and order-db workloads are restricted. Order-api workloads are
confidential. Evidence from restricted resources must not be sent to external LLM
providers without an approved data-processing agreement.

## Evidence handling

Security evidence includes telemetry payloads, findings, validation results, tool
execution records and audit entries. Evidence is immutable. Deletion of evidence is
not an automated action and requires approval.

## Audit requirements

Every state-changing operation records: timestamp, resource identifier, trigger,
action, previous state, new state, result, failure reason, correlation identifier and
the actor. Audit entries are hash-chained. Verification failure is a security
incident in its own right and must be escalated.

## Retention

Prototype retention is the lifetime of the local database. Enterprise deployment
must define retention, legal hold and secure deletion procedures before processing
production data.
