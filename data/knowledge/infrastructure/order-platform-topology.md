---
doc_id: INF-TOP-001
title: Order Platform Topology and Trust Boundaries
classification: internal
trust_level: authoritative
version: "1.5"
owner: platform-architecture@xyz.example
---
# Order Platform Topology

## Workloads

Virtual machines: order-api (two nodes), order-db, order-cache. Containers:
order-gateway, order-payments, order-search, order-worker, order-reports,
order-notifications. All workloads are registered in the approved baseline.

## Trust boundaries

1. Public edge to gateway: untrusted traffic, terminated at the gateway.
2. Gateway to order-api: internal service network.
3. Order-api to order-db and order-cache: restricted data network.
4. Telemetry agents to ingestion: telemetry is untrusted input.
5. Agent and RAG to LLM provider: untrusted context, structured output only.
6. Policy engine to simulator: the only authorized state-changing path.

## Data flow

Telemetry events are validated, deduplicated and projected into observed state.
The deterministic detector compares observed state to the approved baseline and
emits findings with evidence. The orchestrator requests authorization from the
policy engine, then drives the simulator through drain, quarantine, restore,
validation and return to service. Every step is persisted and audited.

## Simulator boundary

The prototype executes against a local simulator only. There is no live
hypervisor, container runtime or cloud adapter. The simulator must never claim that
a real machine was rebuilt; all results are labelled as simulated.
