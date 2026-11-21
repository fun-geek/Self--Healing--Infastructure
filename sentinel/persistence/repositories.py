"""Persistence repositories.

All state-changing methods take an explicit transaction connection so callers can
compose resource updates, audit entries and job bookkeeping atomically.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime
from typing import Any, Iterable

from sentinel.domain.state_machine import assert_transition, is_isolated
from sentinel.errors import ResourceNotFound, StateConflict
from sentinel.models.actions import (
    Approval,
    JobStep,
    RemediationJob,
    ValidationResult,
)
from sentinel.models.common import ResourceState, iso, utcnow
from sentinel.models.events import Event
from sentinel.models.findings import Evidence, Finding
from sentinel.models.state import ObservedResource, ResourceView
from sentinel.observability.logging import get_correlation_id
from sentinel.persistence.audit import AuditRepository
from sentinel.persistence.db import Database

_log = __import__("logging").getLogger(__name__)


def _json(value: Any) -> str:
    return json.dumps(value, default=str, separators=(",", ":"))


def _loads(value: str | None) -> Any:
    if not value:
        return None
    return json.loads(value)


class ResourceRepository:
    def __init__(self, db: Database, audit: AuditRepository) -> None:
        self.db = db
        self.audit = audit

    # -- reads ------------------------------------------------------------
    def get(self, resource_id: str) -> ResourceView | None:
        row = self.db.query_one("SELECT * FROM resources WHERE resource_id = ?", (resource_id,))
        return self._row_to_view(row) if row else None

    def list(self) -> list[ResourceView]:
        rows = self.db.query("SELECT * FROM resources ORDER BY resource_id")
        return [self._row_to_view(row) for row in rows]

    def counts_by_state(self) -> dict[str, int]:
        rows = self.db.query("SELECT state, COUNT(*) AS n FROM resources GROUP BY state")
        return {str(row["state"]): int(row["n"]) for row in rows}

    # -- writes -----------------------------------------------------------
    def sync_baseline(self, baseline_resources: dict[str, Any], baseline_version: int) -> int:
        created = 0
        with self.db.tx() as conn:
            for resource_id, resource in baseline_resources.items():
                existing = conn.execute(
                    "SELECT resource_id FROM resources WHERE resource_id = ?", (resource_id,)
                ).fetchone()
                if existing:
                    conn.execute(
                        "UPDATE resources SET kind=?, service=?, host=?, baseline_version=?, updated_at=? WHERE resource_id=?",
                        (
                            resource.kind.value,
                            resource.service,
                            resource.host,
                            baseline_version,
                            iso(utcnow()),
                            resource_id,
                        ),
                    )
                    continue
                conn.execute(
                    """
                    INSERT INTO resources (
                        resource_id, kind, service, host, state, observed_json,
                        baseline_version, in_load_balancer, network_isolated, version, updated_at
                    ) VALUES (?, ?, ?, ?, ?, NULL, ?, 1, 0, 1, ?)
                    """,
                    (
                        resource_id,
                        resource.kind.value,
                        resource.service,
                        resource.host,
                        ResourceState.HEALTHY.value,
                        baseline_version,
                        iso(utcnow()),
                    ),
                )
                created += 1
            self.audit.append(
                conn,
                actor="system",
                action="RESOURCE_INVENTORY_SYNCED",
                result="success",
                correlation_id=get_correlation_id(),
                details={"baseline_version": baseline_version, "created": created},
            )
        return created

    def set_observed(
        self,
        conn: sqlite3.Connection,
        resource_id: str,
        observed: ObservedResource,
        scan_id: str | None,
    ) -> None:
        cursor = conn.execute(
            """
            UPDATE resources SET observed_json=?, version=version+1, last_scan_id=COALESCE(?, last_scan_id), updated_at=?
            WHERE resource_id=?
            """,
            (_json(observed.model_dump(mode="json")), scan_id, iso(utcnow()), resource_id),
        )
        if cursor.rowcount != 1:
            raise ResourceNotFound(resource_id)

    def set_load_balancer(
        self,
        conn: sqlite3.Connection,
        resource_id: str,
        attached: bool,
        *,
        actor: str,
        job_id: str | None = None,
    ) -> None:
        row = conn.execute(
            "SELECT in_load_balancer FROM resources WHERE resource_id = ?", (resource_id,)
        ).fetchone()
        if row is None:
            raise ResourceNotFound(resource_id)
        previous = bool(row["in_load_balancer"])
        if previous == attached:
            return
        conn.execute(
            "UPDATE resources SET in_load_balancer=?, version=version+1, updated_at=? WHERE resource_id=?",
            (int(attached), iso(utcnow()), resource_id),
        )
        self.audit.append(
            conn,
            actor=actor,
            action="LOAD_BALANCER_ATTACH" if attached else "LOAD_BALANCER_DRAIN",
            result="success",
            resource_id=resource_id,
            job_id=job_id,
            correlation_id=get_correlation_id(),
            details={"attached": attached},
        )

    def transition(
        self,
        conn: sqlite3.Connection,
        *,
        resource_id: str,
        to_state: ResourceState,
        trigger: str,
        actor: str,
        result: str = "success",
        failure_reason: str | None = None,
        job_id: str | None = None,
        expected_version: int | None = None,
        require_validation: bool = False,
    ) -> tuple[ResourceState, ResourceState]:
        row = conn.execute("SELECT * FROM resources WHERE resource_id = ?", (resource_id,)).fetchone()
        if row is None:
            raise ResourceNotFound(resource_id)
        current = ResourceState(row["state"])
        version = int(row["version"])
        if expected_version is not None and version != expected_version:
            raise StateConflict(
                "resource state changed concurrently; retry",
                detail={"expected_version": expected_version, "actual_version": version},
            )
        assert_transition(current, to_state)

        if to_state is ResourceState.RECOVERED:
            if not job_id or not self._mandatory_validations_passed(conn, job_id, resource_id):
                raise StateConflict(
                    "cannot mark RECOVERED without a complete passing mandatory validation set"
                )
        if to_state is ResourceState.HEALTHY and current is ResourceState.RECOVERED:
            if not job_id or not self._mandatory_validations_passed(conn, job_id, resource_id):
                raise StateConflict("cannot return to service without validated recovery")
            if require_validation and not self._latest_mandatory_passed(conn, resource_id):
                raise StateConflict("return to service blocked: validation evidence missing")

        isolated = is_isolated(to_state)
        conn.execute(
            """
            UPDATE resources SET state=?, network_isolated=?, version=version+1, updated_at=?
            WHERE resource_id=?
            """,
            (to_state.value, int(isolated), iso(utcnow()), resource_id),
        )
        transition_id = f"trn-{uuid.uuid4().hex}"
        now = iso(utcnow())
        conn.execute(
            """
            INSERT INTO state_transitions (
                transition_id, resource_id, job_id, from_state, to_state, trigger, actor,
                result, failure_reason, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                transition_id,
                resource_id,
                job_id,
                current.value,
                to_state.value,
                trigger,
                actor,
                result,
                failure_reason,
                now,
            ),
        )
        self.audit.append(
            conn,
            actor=actor,
            action="STATE_TRANSITION",
            result=result,
            resource_id=resource_id,
            job_id=job_id,
            previous_state=current.value,
            new_state=to_state.value,
            failure_reason=failure_reason,
            correlation_id=get_correlation_id(),
            details={"trigger": trigger, "transition_id": transition_id},
        )
        return current, to_state

    @staticmethod
    def _mandatory_validations_passed(
        conn: sqlite3.Connection, job_id: str, resource_id: str
    ) -> bool:
        row = conn.execute(
            """
            SELECT COUNT(*) AS total, SUM(CASE WHEN passed = 0 THEN 1 ELSE 0 END) AS failed
            FROM validations
            WHERE job_id = ? AND resource_id = ? AND mandatory = 1
              AND attempt = (SELECT MAX(attempt) FROM validations WHERE job_id = ? AND resource_id = ?)
            """,
            (job_id, resource_id, job_id, resource_id),
        ).fetchone()
        if row is None:
            return False
        total = int(row["total"] or 0)
        failed = int(row["failed"] or 0)
        return total > 0 and failed == 0

    @staticmethod
    def _latest_mandatory_passed(conn: sqlite3.Connection, resource_id: str) -> bool:
        row = conn.execute(
            """
            SELECT COUNT(*) AS total, SUM(CASE WHEN passed = 0 THEN 1 ELSE 0 END) AS failed
            FROM validations v
            WHERE v.resource_id = ? AND v.mandatory = 1
              AND v.checked_at = (SELECT MAX(checked_at) FROM validations WHERE resource_id = ?)
            """,
            (resource_id, resource_id),
        ).fetchone()
        if row is None:
            return False
        return int(row["total"] or 0) > 0 and int(row["failed"] or 0) == 0

    @staticmethod
    def _row_to_view(row: sqlite3.Row) -> ResourceView:
        observed = None
        raw = row["observed_json"]
        if raw:
            observed = ObservedResource.model_validate(json.loads(raw))
        return ResourceView(
            resource_id=row["resource_id"],
            kind=row["kind"],
            service=row["service"],
            host=row["host"],
            state=row["state"],
            observed=observed,
            baseline_version=int(row["baseline_version"]),
            in_load_balancer=bool(row["in_load_balancer"]),
            version=int(row["version"]),
            updated_at=row["updated_at"],
            last_scan_id=row["last_scan_id"],
        )


class EventRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def start_run(self, run_id: str, source_file: str, source_sha256: str) -> None:
        with self.db.tx() as conn:
            conn.execute(
                """
                INSERT INTO ingest_runs (run_id, started_at, source_file, source_sha256, status)
                VALUES (?, ?, ?, ?, 'RUNNING')
                """,
                (run_id, iso(utcnow()), source_file, source_sha256),
            )

    def finish_run(
        self,
        run_id: str,
        *,
        accepted: int,
        rejected: int,
        duplicates: int,
        status: str = "SUCCEEDED",
        error: str | None = None,
    ) -> None:
        with self.db.tx() as conn:
            conn.execute(
                """
                UPDATE ingest_runs SET finished_at=?, accepted=?, rejected=?, duplicates=?, status=?, error=?
                WHERE run_id=?
                """,
                (iso(utcnow()), accepted, rejected, duplicates, status, error, run_id),
            )

    def known_event_ids(self) -> set[str]:
        return {str(row["event_id"]) for row in self.db.query("SELECT event_id FROM events")}

    def known_fingerprints(self) -> set[str]:
        return {str(row["fingerprint"]) for row in self.db.query("SELECT fingerprint FROM events")}

    def insert_accepted(
        self,
        conn: sqlite3.Connection,
        events: Iterable[tuple[Event, str, str, str, int]],
        *,
        ingested_at: str,
    ) -> int:
        from sentinel.models.common import sha256_ref

        count = 0
        for event, fingerprint, source_file, source_sha256, index in events:
            payload = event.model_dump(mode="json")
            conn.execute(
                """
                INSERT INTO events (
                    event_id, resource_id, timestamp, event_type, source, payload_json,
                    evidence_sha256, source_file, source_sha256, record_index, fingerprint, ingested_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.resource_id,
                    iso(event.timestamp),
                    event.event_type,
                    event.source,
                    _json(payload),
                    sha256_ref(_json(payload)),
                    source_file,
                    source_sha256,
                    index,
                    fingerprint,
                    ingested_at,
                ),
            )
            count += 1
        return count

    def insert_duplicate(
        self, conn: sqlite3.Connection, *, run_id: str, event_id: str, duplicate_of: str, fingerprint: str
    ) -> None:
        conn.execute(
            """
            INSERT INTO ingest_duplicates (run_id, event_id, duplicate_of, fingerprint, detected_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (run_id, event_id, duplicate_of, fingerprint, iso(utcnow())),
        )

    def insert_reject(
        self,
        conn: sqlite3.Connection,
        *,
        run_id: str,
        source_file: str,
        record_index: int,
        event_id: str | None,
        resource_id: str | None,
        error_code: str,
        reason: str,
        raw_sha256: str,
    ) -> None:
        conn.execute(
            """
            INSERT INTO ingest_rejects (
                run_id, source_file, record_index, event_id, resource_id, error_code, reason, raw_sha256, detected_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                source_file,
                record_index,
                event_id,
                resource_id,
                error_code,
                reason[:1000],
                raw_sha256,
                iso(utcnow()),
            ),
        )

    def events_for_projection(self) -> list[Event]:
        rows = self.db.query("SELECT payload_json FROM events ORDER BY timestamp ASC, event_id ASC")
        return [Event.model_validate(json.loads(row["payload_json"])) for row in rows]

    def count(self) -> int:
        row = self.db.query_one("SELECT COUNT(*) AS n FROM events")
        return int(row["n"]) if row else 0

    def reject_count(self) -> int:
        row = self.db.query_one("SELECT COUNT(*) AS n FROM ingest_rejects")
        return int(row["n"]) if row else 0

    def duplicate_count(self) -> int:
        row = self.db.query_one("SELECT COUNT(*) AS n FROM ingest_duplicates")
        return int(row["n"]) if row else 0

    def list_rejects(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.db.query(
            "SELECT * FROM ingest_rejects ORDER BY id DESC LIMIT ?", (min(limit, 500),)
        )
        return [dict(row) for row in rows]

    def latest_event_at(self) -> datetime | None:
        row = self.db.query_one("SELECT MAX(timestamp) AS ts FROM events")
        if row is None or row["ts"] is None:
            return None
        from sentinel.models.common import ensure_utc

        return ensure_utc(datetime.fromisoformat(str(row["ts"]).replace("Z", "+00:00")))


class FindingRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def upsert_many(self, conn: sqlite3.Connection, findings: Iterable[Finding], scan_id: str) -> int:
        count = 0
        for finding in findings:
            conn.execute(
                """
                INSERT INTO findings (
                    finding_id, scan_id, resource_id, rule_id, severity, confidence, title,
                    description, evidence_json, status, suppression_reason, remediation_blocked,
                    detected_at, baseline_version, tags_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(finding_id) DO UPDATE SET
                    scan_id=excluded.scan_id,
                    severity=excluded.severity,
                    confidence=excluded.confidence,
                    description=excluded.description,
                    evidence_json=excluded.evidence_json,
                    status=excluded.status,
                    suppression_reason=excluded.suppression_reason,
                    remediation_blocked=excluded.remediation_blocked,
                    tags_json=excluded.tags_json
                """,
                (
                    finding.finding_id,
                    scan_id,
                    finding.resource_id,
                    finding.rule_id,
                    finding.severity.value,
                    finding.confidence,
                    finding.title,
                    finding.description,
                    _json([item.model_dump(mode="json") for item in finding.evidence]),
                    finding.status,
                    finding.suppression_reason,
                    int(finding.remediation_blocked),
                    iso(finding.detected_at),
                    finding.baseline_version,
                    _json(finding.tags),
                ),
            )
            count += 1
        return count

    def list(
        self,
        *,
        status: str | None = None,
        resource_id: str | None = None,
        severity: str | None = None,
        limit: int = 200,
    ) -> list[Finding]:
        clauses: list[str] = []
        params: list[Any] = []
        if status:
            clauses.append("status = ?")
            params.append(status)
        if resource_id:
            clauses.append("resource_id = ?")
            params.append(resource_id)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(min(max(limit, 1), 1000))
        rows = self.db.query(
            f"SELECT * FROM findings {where} ORDER BY detected_at DESC, severity DESC LIMIT ?",
            params,
        )
        return [self._row(row) for row in rows]

    def open_for_resource(self, resource_id: str) -> list[Finding]:
        return [
            self._row(row)
            for row in self.db.query(
                "SELECT * FROM findings WHERE resource_id = ? AND status = 'open' ORDER BY detected_at DESC",
                (resource_id,),
            )
        ]

    def resolve_for_resource(self, conn: sqlite3.Connection, resource_id: str) -> int:
        cursor = conn.execute(
            "UPDATE findings SET status='resolved' WHERE resource_id=? AND status='open'",
            (resource_id,),
        )
        return cursor.rowcount

    def counts_by_severity(self) -> dict[str, int]:
        rows = self.db.query(
            "SELECT severity, COUNT(*) AS n FROM findings WHERE status='open' GROUP BY severity"
        )
        return {str(row["severity"]): int(row["n"]) for row in rows}

    def count_open(self) -> int:
        row = self.db.query_one("SELECT COUNT(*) AS n FROM findings WHERE status='open'")
        return int(row["n"]) if row else 0

    @staticmethod
    def _row(row: sqlite3.Row) -> Finding:
        evidence = [
            Evidence.model_validate(item) for item in json.loads(row["evidence_json"])
        ]
        return Finding(
            finding_id=row["finding_id"],
            resource_id=row["resource_id"],
            rule_id=row["rule_id"],
            severity=row["severity"],
            confidence=float(row["confidence"]),
            title=row["title"],
            description=row["description"],
            evidence=evidence,
            status=row["status"],
            suppression_reason=row["suppression_reason"],
            remediation_blocked=bool(row["remediation_blocked"]),
            detected_at=row["detected_at"],
            baseline_version=int(row["baseline_version"]),
            tags=json.loads(row["tags_json"]),
        )


class ScanRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create(self, conn: sqlite3.Connection, scan_id: str, baseline_id: str, baseline_version: int, as_of: str) -> None:
        conn.execute(
            """
            INSERT INTO scans (scan_id, started_at, baseline_id, baseline_version, as_of, status)
            VALUES (?, ?, ?, ?, ?, 'RUNNING')
            """,
            (scan_id, iso(utcnow()), baseline_id, baseline_version, as_of),
        )

    def finish(
        self,
        conn: sqlite3.Connection,
        scan_id: str,
        *,
        events_considered: int,
        duplicates: int,
        rejected: int,
        findings_total: int,
        open_findings: int,
        status: str = "SUCCEEDED",
        error: str | None = None,
    ) -> None:
        conn.execute(
            """
            UPDATE scans SET finished_at=?, events_considered=?, duplicates=?, rejected=?,
                findings_total=?, open_findings=?, status=?, error=?
            WHERE scan_id=?
            """,
            (
                iso(utcnow()),
                events_considered,
                duplicates,
                rejected,
                findings_total,
                open_findings,
                status,
                error,
                scan_id,
            ),
        )

    def get(self, scan_id: str) -> dict[str, Any] | None:
        row = self.db.query_one("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
        return dict(row) if row else None

    def latest(self) -> dict[str, Any] | None:
        row = self.db.query_one("SELECT * FROM scans ORDER BY started_at DESC LIMIT 1")
        return dict(row) if row else None

    def list(self, limit: int = 20) -> list[dict[str, Any]]:
        return [dict(row) for row in self.db.query("SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,))]


class JobRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create(self, conn: sqlite3.Connection, job: RemediationJob) -> None:
        conn.execute(
            """
            INSERT INTO remediation_jobs (
                job_id, resource_id, trigger, status, attempts, max_attempts, created_at,
                updated_at, idempotency_key, last_error, finding_ids_json, initiated_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                job.job_id,
                job.resource_id,
                job.trigger,
                job.status,
                job.attempts,
                job.max_attempts,
                iso(job.created_at),
                iso(job.updated_at),
                job.idempotency_key,
                job.last_error,
                _json(job.finding_ids),
                job.initiated_by,
            ),
        )

    def get(self, job_id: str) -> RemediationJob | None:
        row = self.db.query_one("SELECT * FROM remediation_jobs WHERE job_id = ?", (job_id,))
        return self._row(row) if row else None

    def get_by_idempotency(self, key: str) -> RemediationJob | None:
        row = self.db.query_one(
            "SELECT * FROM remediation_jobs WHERE idempotency_key = ?", (key,)
        )
        return self._row(row) if row else None

    def get_active_for_resource(self, resource_id: str) -> RemediationJob | None:
        row = self.db.query_one(
            "SELECT * FROM remediation_jobs WHERE resource_id = ? AND status IN ('QUEUED','RUNNING') ORDER BY created_at DESC LIMIT 1",
            (resource_id,),
        )
        return self._row(row) if row else None

    def list(self, limit: int = 100, resource_id: str | None = None) -> list[RemediationJob]:
        if resource_id:
            rows = self.db.query(
                "SELECT * FROM remediation_jobs WHERE resource_id = ? ORDER BY created_at DESC LIMIT ?",
                (resource_id, min(limit, 500)),
            )
        else:
            rows = self.db.query(
                "SELECT * FROM remediation_jobs ORDER BY created_at DESC LIMIT ?", (min(limit, 500),)
            )
        return [self._row(row) for row in rows]

    def set_status(
        self,
        conn: sqlite3.Connection,
        job_id: str,
        status: str,
        *,
        error: str | None = None,
        attempts: int | None = None,
    ) -> None:
        if attempts is None:
            conn.execute(
                "UPDATE remediation_jobs SET status=?, last_error=?, updated_at=? WHERE job_id=?",
                (status, error, iso(utcnow()), job_id),
            )
        else:
            conn.execute(
                "UPDATE remediation_jobs SET status=?, last_error=?, attempts=?, updated_at=? WHERE job_id=?",
                (status, error, attempts, iso(utcnow()), job_id),
            )

    def increment_attempts(self, conn: sqlite3.Connection, job_id: str) -> int:
        conn.execute(
            "UPDATE remediation_jobs SET attempts=attempts+1, updated_at=? WHERE job_id=?",
            (iso(utcnow()), job_id),
        )
        row = conn.execute(
            "SELECT attempts FROM remediation_jobs WHERE job_id=?", (job_id,)
        ).fetchone()
        return int(row["attempts"]) if row else 0

    def add_step(self, conn: sqlite3.Connection, step: JobStep) -> None:
        conn.execute(
            """
            INSERT INTO job_steps (
                step_id, job_id, action_id, attempt, status, started_at, finished_at, result_json, error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                step.step_id,
                step.job_id,
                step.action_id,
                step.attempt,
                step.status,
                iso(step.started_at),
                iso(step.finished_at) if step.finished_at else None,
                _json(step.result),
                step.error,
            ),
        )

    def steps(self, job_id: str) -> list[JobStep]:
        rows = self.db.query(
            "SELECT * FROM job_steps WHERE job_id = ? ORDER BY started_at ASC, step_id ASC", (job_id,)
        )
        return [
            JobStep(
                step_id=row["step_id"],
                job_id=row["job_id"],
                action_id=row["action_id"],
                attempt=int(row["attempt"]),
                status=row["status"],
                started_at=row["started_at"],
                finished_at=row["finished_at"],
                result=json.loads(row["result_json"]),
                error=row["error"],
            )
            for row in rows
        ]

    def active_count(self) -> int:
        row = self.db.query_one(
            "SELECT COUNT(*) AS n FROM remediation_jobs WHERE status IN ('QUEUED','RUNNING')"
        )
        return int(row["n"]) if row else 0

    def counts_by_status(self) -> dict[str, int]:
        rows = self.db.query("SELECT status, COUNT(*) AS n FROM remediation_jobs GROUP BY status")
        return {str(row["status"]): int(row["n"]) for row in rows}

    @staticmethod
    def _row(row: sqlite3.Row) -> RemediationJob:
        return RemediationJob(
            job_id=row["job_id"],
            resource_id=row["resource_id"],
            trigger=row["trigger"],
            status=row["status"],
            attempts=int(row["attempts"]),
            max_attempts=int(row["max_attempts"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            idempotency_key=row["idempotency_key"],
            last_error=row["last_error"],
            finding_ids=json.loads(row["finding_ids_json"]),
            initiated_by=row["initiated_by"],
        )


class ValidationRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def insert_many(self, conn: sqlite3.Connection, results: Iterable[ValidationResult]) -> None:
        for result in results:
            conn.execute(
                """
                INSERT INTO validations (
                    validation_id, job_id, resource_id, rule_id, passed, mandatory, attempt, detail,
                    observed, expected, checked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.validation_id,
                    result.job_id,
                    result.resource_id,
                    result.rule_id,
                    int(result.passed),
                    int(result.mandatory),
                    result.attempt,
                    result.detail,
                    result.observed,
                    result.expected,
                    iso(result.checked_at),
                ),
            )

    def for_job(self, job_id: str) -> list[ValidationResult]:
        rows = self.db.query(
            "SELECT * FROM validations WHERE job_id = ? ORDER BY checked_at ASC, rule_id ASC", (job_id,)
        )
        return [self._row(row) for row in rows]

    def latest_for_resource(self, resource_id: str) -> list[ValidationResult]:
        row = self.db.query_one(
            "SELECT MAX(checked_at) AS ts FROM validations WHERE resource_id = ?", (resource_id,)
        )
        if not row or not row["ts"]:
            return []
        rows = self.db.query(
            "SELECT * FROM validations WHERE resource_id = ? AND checked_at = ? ORDER BY rule_id",
            (resource_id, row["ts"]),
        )
        return [self._row(row) for row in rows]

    def failures_count(self) -> int:
        row = self.db.query_one(
            "SELECT COUNT(*) AS n FROM validations WHERE mandatory = 1 AND passed = 0"
        )
        return int(row["n"]) if row else 0

    @staticmethod
    def _row(row: sqlite3.Row) -> ValidationResult:
        return ValidationResult(
            validation_id=row["validation_id"],
            job_id=row["job_id"],
            resource_id=row["resource_id"],
            rule_id=row["rule_id"],
            passed=bool(row["passed"]),
            mandatory=bool(row["mandatory"]),
            attempt=int(row["attempt"]),
            detail=row["detail"],
            observed=row["observed"],
            expected=row["expected"],
            checked_at=row["checked_at"],
        )


class ApprovalRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create(self, conn: sqlite3.Connection, approval: Approval) -> None:
        conn.execute(
            """
            INSERT INTO approvals (
                approval_id, action_id, resource_id, job_id, approved_by, role, reason,
                created_at, expires_at, consumed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                approval.approval_id,
                approval.action_id,
                approval.resource_id,
                approval.job_id,
                approval.approved_by,
                approval.role.value,
                approval.reason,
                iso(approval.created_at),
                iso(approval.expires_at),
                int(approval.consumed),
            ),
        )

    def get(self, approval_id: str) -> Approval | None:
        row = self.db.query_one("SELECT * FROM approvals WHERE approval_id = ?", (approval_id,))
        if row is None:
            return None
        return Approval(
            approval_id=row["approval_id"],
            action_id=row["action_id"],
            resource_id=row["resource_id"],
            job_id=row["job_id"],
            approved_by=row["approved_by"],
            role=row["role"],
            reason=row["reason"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            consumed=bool(row["consumed"]),
        )

    def consume(self, conn: sqlite3.Connection, approval_id: str) -> None:
        conn.execute("UPDATE approvals SET consumed=1 WHERE approval_id=?", (approval_id,))

    def list(self, limit: int = 100) -> list[Approval]:
        rows = self.db.query("SELECT * FROM approvals ORDER BY created_at DESC LIMIT ?", (limit,))
        return [
            Approval(
                approval_id=row["approval_id"],
                action_id=row["action_id"],
                resource_id=row["resource_id"],
                job_id=row["job_id"],
                approved_by=row["approved_by"],
                role=row["role"],
                reason=row["reason"],
                created_at=row["created_at"],
                expires_at=row["expires_at"],
                consumed=bool(row["consumed"]),
            )
            for row in rows
        ]


class IdempotencyRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def get(self, key: str) -> dict[str, Any] | None:
        row = self.db.query_one("SELECT * FROM idempotency WHERE key = ?", (key,))
        if row is None:
            return None
        return {"scope": row["scope"], "response": json.loads(row["response_json"])}

    def put(self, conn: sqlite3.Connection, key: str, scope: str, response: dict[str, Any]) -> None:
        conn.execute(
            "INSERT OR REPLACE INTO idempotency (key, scope, response_json, created_at) VALUES (?, ?, ?, ?)",
            (key, scope, _json(response), iso(utcnow())),
        )


class InvestigationRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def save(self, conn: sqlite3.Connection, result: Any) -> None:
        conn.execute(
            """
            INSERT OR REPLACE INTO investigations (
                investigation_id, resource_id, trigger_finding_id, status, provider, model,
                diagnosis, confidence, proposal_json, citations_json, guardrail_json,
                started_at, finished_at, error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.investigation_id,
                result.resource_id,
                None,
                result.status,
                result.provider,
                result.model,
                result.proposal.diagnosis if result.proposal else None,
                result.proposal.confidence if result.proposal else None,
                _json(result.proposal.model_dump(mode="json")) if result.proposal else None,
                _json([citation.model_dump(mode="json") for citation in result.citations]),
                _json([event.model_dump(mode="json") for event in result.guardrail_events]),
                iso(result.started_at),
                iso(result.finished_at),
                result.error,
            ),
        )

    def get(self, investigation_id: str) -> dict[str, Any] | None:
        row = self.db.query_one(
            "SELECT * FROM investigations WHERE investigation_id = ?", (investigation_id,)
        )
        return self._decode(row) if row else None

    def latest_for_resource(self, resource_id: str) -> dict[str, Any] | None:
        row = self.db.query_one(
            "SELECT * FROM investigations WHERE resource_id = ? ORDER BY finished_at DESC LIMIT 1",
            (resource_id,),
        )
        return self._decode(row) if row else None

    def list(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.db.query(
            "SELECT * FROM investigations ORDER BY finished_at DESC LIMIT ?", (min(limit, 200),)
        )
        return [self._decode(row) for row in rows]

    @staticmethod
    def _decode(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "investigation_id": row["investigation_id"],
            "resource_id": row["resource_id"],
            "status": row["status"],
            "provider": row["provider"],
            "model": row["model"],
            "diagnosis": row["diagnosis"],
            "confidence": row["confidence"],
            "proposal": json.loads(row["proposal_json"]) if row["proposal_json"] else None,
            "citations": json.loads(row["citations_json"]),
            "guardrail_events": json.loads(row["guardrail_json"]),
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
            "error": row["error"],
        }


class ToolExecutionRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def record(
        self,
        conn: sqlite3.Connection,
        *,
        tool: str,
        actor: str,
        request: dict[str, Any],
        response: dict[str, Any],
        decision: str,
        resource_id: str | None = None,
        job_id: str | None = None,
        denial_reason: str | None = None,
        correlation_id: str | None = None,
    ) -> None:
        conn.execute(
            """
            INSERT INTO tool_executions (
                tool, actor, resource_id, job_id, request_json, response_json, decision,
                denial_reason, correlation_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tool,
                actor,
                resource_id,
                job_id,
                _json(request),
                _json(response),
                decision,
                denial_reason,
                correlation_id or get_correlation_id(),
                iso(utcnow()),
            ),
        )

    def list(self, limit: int = 100, resource_id: str | None = None) -> list[dict[str, Any]]:
        if resource_id:
            rows = self.db.query(
                "SELECT * FROM tool_executions WHERE resource_id = ? ORDER BY id DESC LIMIT ?",
                (resource_id, min(limit, 500)),
            )
        else:
            rows = self.db.query(
                "SELECT * FROM tool_executions ORDER BY id DESC LIMIT ?", (min(limit, 500),)
            )
        return [
            {
                "id": row["id"],
                "tool": row["tool"],
                "actor": row["actor"],
                "resource_id": row["resource_id"],
                "job_id": row["job_id"],
                "request": json.loads(row["request_json"]),
                "response": json.loads(row["response_json"]),
                "decision": row["decision"],
                "denial_reason": row["denial_reason"],
                "correlation_id": row["correlation_id"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]
