"""Tamper-evident, append-only audit logging.

Each entry commits to its predecessor:

    entry_hash = SHA256(prev_hash || canonical_json(entry_without_hash))

The database enforces append-only semantics with triggers. ``verify_chain``
recomputes every link and detects mutation, deletion and reordering.
"""

from __future__ import annotations

import sqlite3
import uuid
from typing import Any

from sentinel.models.audit import AuditEntry
from sentinel.models.common import canonical_json, iso, sha256_hex, utcnow
from sentinel.persistence.db import Database

GENESIS_HASH = "0" * 64


def _entry_payload(
    *,
    seq: int,
    entry_id: str,
    timestamp: str,
    actor: str,
    action: str,
    resource_id: str | None,
    job_id: str | None,
    correlation_id: str,
    previous_state: str | None,
    new_state: str | None,
    result: str,
    failure_reason: str | None,
    details: dict[str, Any],
) -> dict[str, Any]:
    return {
        "seq": seq,
        "entry_id": entry_id,
        "timestamp": timestamp,
        "actor": actor,
        "action": action,
        "resource_id": resource_id,
        "job_id": job_id,
        "correlation_id": correlation_id,
        "previous_state": previous_state,
        "new_state": new_state,
        "result": result,
        "failure_reason": failure_reason,
        "details": details,
    }


class AuditRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def append(
        self,
        conn: sqlite3.Connection,
        *,
        actor: str,
        action: str,
        result: str,
        correlation_id: str,
        resource_id: str | None = None,
        job_id: str | None = None,
        previous_state: str | None = None,
        new_state: str | None = None,
        failure_reason: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEntry:
        if conn.in_transaction is False:  # pragma: no cover - programming error
            raise RuntimeError("audit entries must be written inside a transaction")
        row = conn.execute(
            "SELECT seq, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        seq = (int(row["seq"]) + 1) if row else 1
        prev_hash = str(row["entry_hash"]) if row else GENESIS_HASH
        timestamp = iso(utcnow())
        entry_id = f"aud-{uuid.uuid4().hex}"
        details_payload = details or {}
        payload = _entry_payload(
            seq=seq,
            entry_id=entry_id,
            timestamp=timestamp,
            actor=actor,
            action=action,
            resource_id=resource_id,
            job_id=job_id,
            correlation_id=correlation_id,
            previous_state=previous_state,
            new_state=new_state,
            result=result,
            failure_reason=failure_reason,
            details=details_payload,
        )
        entry_hash = sha256_hex(prev_hash + canonical_json(payload))
        conn.execute(
            """
            INSERT INTO audit_log (
                seq, entry_id, timestamp, actor, action, resource_id, job_id,
                correlation_id, previous_state, new_state, result, failure_reason,
                details_json, prev_hash, entry_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                seq,
                entry_id,
                timestamp,
                actor,
                action,
                resource_id,
                job_id,
                correlation_id,
                previous_state,
                new_state,
                result,
                failure_reason,
                canonical_json(details_payload),
                prev_hash,
                entry_hash,
            ),
        )
        return AuditEntry(
            seq=seq,
            entry_id=entry_id,
            timestamp=timestamp,
            actor=actor,
            action=action,
            resource_id=resource_id,
            job_id=job_id,
            correlation_id=correlation_id,
            previous_state=previous_state,
            new_state=new_state,
            result=result,
            failure_reason=failure_reason,
            details=details_payload,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )

    def list_entries(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        resource_id: str | None = None,
        job_id: str | None = None,
    ) -> list[AuditEntry]:
        clauses: list[str] = []
        params: list[Any] = []
        if resource_id:
            clauses.append("resource_id = ?")
            params.append(resource_id)
        if job_id:
            clauses.append("job_id = ?")
            params.append(job_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([min(max(limit, 1), 500), max(offset, 0)])
        rows = self.db.query(
            f"SELECT * FROM audit_log {where} ORDER BY seq DESC LIMIT ? OFFSET ?",
            params,
        )
        return [self._row_to_entry(row) for row in rows]

    def count(self) -> int:
        row = self.db.query_one("SELECT COUNT(*) AS n FROM audit_log")
        return int(row["n"]) if row else 0

    def verify_chain(self) -> tuple[bool, str]:
        rows = self.db.query("SELECT * FROM audit_log ORDER BY seq ASC")
        prev_hash = GENESIS_HASH
        expected_seq = 1
        for row in rows:
            if int(row["seq"]) != expected_seq:
                return False, f"sequence gap at seq {row['seq']} (expected {expected_seq})"
            payload = _entry_payload(
                seq=int(row["seq"]),
                entry_id=row["entry_id"],
                timestamp=row["timestamp"],
                actor=row["actor"],
                action=row["action"],
                resource_id=row["resource_id"],
                job_id=row["job_id"],
                correlation_id=row["correlation_id"],
                previous_state=row["previous_state"],
                new_state=row["new_state"],
                result=row["result"],
                failure_reason=row["failure_reason"],
                details=_json_load(row["details_json"]),
            )
            if row["prev_hash"] != prev_hash:
                return False, f"broken link at seq {row['seq']}"
            expected_hash = sha256_hex(prev_hash + canonical_json(payload))
            if row["entry_hash"] != expected_hash:
                return False, f"hash mismatch at seq {row['seq']}"
            prev_hash = str(row["entry_hash"])
            expected_seq += 1
        return True, f"chain valid ({len(rows)} entries)"

    @staticmethod
    def _row_to_entry(row: sqlite3.Row) -> AuditEntry:
        return AuditEntry(
            seq=int(row["seq"]),
            entry_id=row["entry_id"],
            timestamp=row["timestamp"],
            actor=row["actor"],
            action=row["action"],
            resource_id=row["resource_id"],
            job_id=row["job_id"],
            correlation_id=row["correlation_id"],
            previous_state=row["previous_state"],
            new_state=row["new_state"],
            result=row["result"],
            failure_reason=row["failure_reason"],
            details=_json_load(row["details_json"]),
            prev_hash=row["prev_hash"],
            entry_hash=row["entry_hash"],
        )


def _json_load(value: str) -> dict[str, Any]:
    import json

    parsed = json.loads(value)
    return parsed if isinstance(parsed, dict) else {"value": parsed}
