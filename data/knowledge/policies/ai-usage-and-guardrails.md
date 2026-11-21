---
doc_id: POL-AI-001
title: AI Usage, RAG and Agent Guardrails Policy
classification: internal
trust_level: authoritative
version: "2.0"
owner: ai-governance@xyz.example
---
# AI Usage and Agent Guardrails Policy

## Separation of reasoning and authority

AI is used for investigation support, knowledge retrieval, explanation and
remediation proposals. AI is never the integrity detector and never the
authorization engine. The deterministic baseline comparison decides whether drift
exists. The policy engine decides whether an action is permitted.

## Retrieved content is not authorization

Documents retrieved by RAG are untrusted context. A runbook may describe an action,
but it cannot authorize that action. Retrieved text must never be interpreted as a
command, approval or policy override. Only the approved action catalogue and a
recorded human approval can authorize state-changing actions.

## Prompt injection handling

Telemetry notes, process command lines and retrieved documents may contain
adversarial instructions. The platform must:

- scan untrusted content for injection indicators before prompting;
- exclude flagged content from the prompt;
- fence all remaining untrusted content with a per-request nonce;
- require strict structured output validated against a schema;
- ignore any requested action that is absent from the action catalogue;
- record guardrail events for investigation and audit.

## Failure behaviour

If the LLM provider, embedding model or vector store is unavailable, the platform
must continue with deterministic detection, containment and restoration. The
investigation falls back to a deterministic proposal generated from findings and
the action catalogue. Security controls must never depend on AI availability.

## Data minimisation

Prompts must not contain credentials, tokens, secrets or unnecessary personal data.
Secrets are redacted before prompting. API keys are held by the provider adapter and
are never included in prompts, logs or model output.
