"""Audit log entry schema (tamper-evident hash chain)."""

from __future__ import annotations

from typing import Any

from pydantic import AwareDatetime, Field

from sentinel.models.common import StrictModel


class AuditEntry(StrictModel):
    seq: int = Field(ge=1)
    entry_id: str
    timestamp: AwareDatetime
    actor: str
    action: str
    resource_id: str | None = None
    job_id: str | None = None
    correlation_id: str
    previous_state: str | None = None
    new_state: str | None = None
    result: str
    failure_reason: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str
    entry_hash: str
