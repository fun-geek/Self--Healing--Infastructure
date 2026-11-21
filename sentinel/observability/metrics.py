"""Prometheus metrics.

Only low-cardinality labels are used (resource IDs and free-form error text are
never labels) to keep the exposition endpoint cheap and safe.
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

SCANS_TOTAL = Counter("sentinel_scans_total", "Detection scans executed", ["result"])
SCAN_DURATION = Histogram(
    "sentinel_scan_duration_seconds",
    "Wall-clock duration of a detection scan",
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)
EVENTS_INGESTED = Counter("sentinel_events_ingested_total", "Events accepted", ["outcome"])
FINDINGS_TOTAL = Counter("sentinel_findings_total", "Findings emitted", ["severity", "rule_id"])
RESOURCE_STATE = Gauge(
    "sentinel_resources", "Resources by remediation state", ["state"]
)
REMEDIATION_TOTAL = Counter(
    "sentinel_remediation_total", "Remediation jobs by terminal outcome", ["outcome"]
)
REMEDIATION_DURATION = Histogram(
    "sentinel_remediation_duration_seconds",
    "End-to-end remediation duration",
    buckets=(1, 5, 10, 20, 30, 60, 120, 300),
)
VALIDATION_TOTAL = Counter(
    "sentinel_validation_total", "Mandatory validation checks", ["rule_id", "result"]
)
TOOL_TOTAL = Counter(
    "sentinel_tool_executions_total", "Tool invocations", ["tool", "decision"]
)
POLICY_DECISIONS = Counter(
    "sentinel_policy_decisions_total", "Policy decisions", ["action", "decision"]
)
LLM_TOTAL = Counter("sentinel_llm_calls_total", "LLM calls", ["provider", "result"])
RAG_TOTAL = Counter("sentinel_rag_queries_total", "RAG queries", ["backend", "result"])
INJECTION_BLOCKED = Counter(
    "sentinel_prompt_injection_blocked_total", "Untrusted content flagged by guardrails"
)
AUDIT_CHAIN_VALID = Gauge(
    "sentinel_audit_chain_valid", "1 if the audit hash chain verifies, else 0"
)
ACTIVE_JOBS = Gauge("sentinel_active_jobs", "Remediation jobs currently queued or running")
