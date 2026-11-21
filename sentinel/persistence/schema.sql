-- SENTINEL AI schema (SQLite, migration 1).
-- Design notes:
--  * audit_log is append-only (triggers below) and hash-chained.
--  * events are immutable evidence; duplicates are recorded separately.
--  * one active remediation job per resource is enforced by a partial index.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS resources (
    resource_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    service TEXT NOT NULL,
    host TEXT NOT NULL,
    state TEXT NOT NULL,
    observed_json TEXT,
    baseline_version INTEGER NOT NULL,
    in_load_balancer INTEGER NOT NULL DEFAULT 1,
    network_isolated INTEGER NOT NULL DEFAULT 0,
    version INTEGER NOT NULL DEFAULT 1,
    last_scan_id TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ingest_runs (
    run_id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    source_file TEXT NOT NULL,
    source_sha256 TEXT NOT NULL,
    accepted INTEGER NOT NULL DEFAULT 0,
    rejected INTEGER NOT NULL DEFAULT 0,
    duplicates INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    error TEXT
);

CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    resource_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    source TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    evidence_sha256 TEXT NOT NULL,
    source_file TEXT NOT NULL,
    source_sha256 TEXT NOT NULL,
    record_index INTEGER NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    ingested_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_resource_ts ON events(resource_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);

CREATE TRIGGER IF NOT EXISTS events_no_update
BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT, 'events are immutable evidence'); END;

CREATE TRIGGER IF NOT EXISTS events_no_delete
BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'events are immutable evidence'); END;

CREATE TABLE IF NOT EXISTS ingest_rejects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    source_file TEXT NOT NULL,
    record_index INTEGER NOT NULL,
    event_id TEXT,
    resource_id TEXT,
    error_code TEXT NOT NULL,
    reason TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL,
    detected_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ingest_duplicates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    duplicate_of TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    detected_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    baseline_id TEXT NOT NULL,
    baseline_version INTEGER NOT NULL,
    as_of TEXT NOT NULL,
    events_considered INTEGER NOT NULL DEFAULT 0,
    duplicates INTEGER NOT NULL DEFAULT 0,
    rejected INTEGER NOT NULL DEFAULT 0,
    findings_total INTEGER NOT NULL DEFAULT 0,
    open_findings INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    error TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    scan_id TEXT,
    resource_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    status TEXT NOT NULL,
    suppression_reason TEXT,
    remediation_blocked INTEGER NOT NULL DEFAULT 0,
    detected_at TEXT NOT NULL,
    baseline_version INTEGER NOT NULL,
    tags_json TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_findings_resource_status ON findings(resource_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity, status);

CREATE TABLE IF NOT EXISTS investigations (
    investigation_id TEXT PRIMARY KEY,
    resource_id TEXT NOT NULL,
    trigger_finding_id TEXT,
    status TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT,
    diagnosis TEXT,
    confidence REAL,
    proposal_json TEXT,
    citations_json TEXT NOT NULL DEFAULT '[]',
    guardrail_json TEXT NOT NULL DEFAULT '[]',
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_investigations_resource ON investigations(resource_id, finished_at DESC);

CREATE TABLE IF NOT EXISTS remediation_jobs (
    job_id TEXT PRIMARY KEY,
    resource_id TEXT NOT NULL,
    trigger TEXT NOT NULL,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    last_error TEXT,
    finding_ids_json TEXT NOT NULL DEFAULT '[]',
    initiated_by TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_jobs_resource ON remediation_jobs(resource_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS ux_jobs_active
    ON remediation_jobs(resource_id)
    WHERE status IN ('QUEUED', 'RUNNING');

CREATE TABLE IF NOT EXISTS job_steps (
    step_id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    result_json TEXT NOT NULL DEFAULT '{}',
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_steps_job ON job_steps(job_id, started_at);

CREATE TABLE IF NOT EXISTS validations (
    validation_id TEXT PRIMARY KEY,
    job_id TEXT,
    resource_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    passed INTEGER NOT NULL,
    mandatory INTEGER NOT NULL,
    attempt INTEGER NOT NULL DEFAULT 1,
    detail TEXT NOT NULL,
    observed TEXT,
    expected TEXT,
    checked_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_validations_job ON validations(job_id);
CREATE INDEX IF NOT EXISTS idx_validations_resource ON validations(resource_id, checked_at DESC);

CREATE TABLE IF NOT EXISTS state_transitions (
    transition_id TEXT PRIMARY KEY,
    resource_id TEXT NOT NULL,
    job_id TEXT,
    from_state TEXT,
    to_state TEXT NOT NULL,
    trigger TEXT NOT NULL,
    actor TEXT NOT NULL,
    result TEXT NOT NULL,
    failure_reason TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_transitions_resource ON state_transitions(resource_id, created_at);

CREATE TABLE IF NOT EXISTS tool_executions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool TEXT NOT NULL,
    actor TEXT NOT NULL,
    resource_id TEXT,
    job_id TEXT,
    request_json TEXT NOT NULL,
    response_json TEXT NOT NULL DEFAULT '{}',
    decision TEXT NOT NULL,
    denial_reason TEXT,
    correlation_id TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tools_resource ON tool_executions(resource_id, created_at);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    job_id TEXT,
    approved_by TEXT NOT NULL,
    role TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS idempotency (
    key TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    jti TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id, expires_at);

CREATE TABLE IF NOT EXISTS audit_log (
    seq INTEGER PRIMARY KEY,
    entry_id TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_id TEXT,
    job_id TEXT,
    correlation_id TEXT NOT NULL,
    previous_state TEXT,
    new_state TEXT,
    result TEXT NOT NULL,
    failure_reason TEXT,
    details_json TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
