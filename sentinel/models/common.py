"""Shared value objects, enums and helpers."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def max_severity(values: list[Severity] | tuple[Severity, ...]) -> Severity:
    if not values:
        return Severity.INFO
    return max(values, key=lambda item: SEVERITY_RANK[item])


class ResourceState(StrEnum):
    HEALTHY = "HEALTHY"
    SUSPECTED = "SUSPECTED"
    QUARANTINED = "QUARANTINED"
    RESTORING = "RESTORING"
    VALIDATING = "VALIDATING"
    RECOVERED = "RECOVERED"
    FAILED = "FAILED"
    ESCALATED = "ESCALATED"


class ResourceKind(StrEnum):
    VM = "vm"
    CONTAINER = "container"


class Role(StrEnum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    RESPONDER = "responder"
    APPROVER = "approver"
    ADMIN = "admin"


ROLE_RANK: dict[Role, int] = {
    Role.VIEWER: 10,
    Role.ANALYST: 20,
    Role.RESPONDER: 30,
    Role.APPROVER: 40,
    Role.ADMIN: 50,
}


def role_at_least(actual: Role, required: Role) -> bool:
    return ROLE_RANK[actual] >= ROLE_RANK[required]


class StrictModel(BaseModel):
    """Reject unknown fields: authoritative inputs must be exact."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def utcnow() -> datetime:
    return datetime.now(UTC)


def ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def iso(value: datetime) -> str:
    return ensure_utc(value).isoformat().replace("+00:00", "Z")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=True)


def sha256_hex(value: str | bytes) -> str:
    data = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


def sha256_ref(value: str | bytes) -> str:
    return f"sha256:{sha256_hex(value)}"


def short_id(prefix: str, *parts: str, length: int = 12) -> str:
    digest = sha256_hex("|".join(parts))[:length]
    return f"{prefix}-{digest}"


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,95}$")


def is_safe_id(value: str) -> bool:
    return bool(_SAFE_ID.match(value))
