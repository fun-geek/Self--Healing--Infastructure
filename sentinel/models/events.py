"""Infrastructure telemetry event schema.

Telemetry is **untrusted input**. Fields such as ``labels``, ``notes`` and
``observation.health.detail`` may contain attacker-controlled text and are never
interpreted as instructions or authorization.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import AwareDatetime, ConfigDict, Field, model_validator

from sentinel.models.common import ResourceKind, StrictModel, is_safe_id

_DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
_CONFIG_PATTERN = r"^sha256:[0-9a-f]{64}$"


class ObservedImage(StrictModel):
    reference: str = Field(min_length=3, max_length=255)
    tag: str = Field(min_length=1, max_length=64)
    digest: str = Field(pattern=_DIGEST_PATTERN)
    pulled_at: AwareDatetime | None = None


class ObservedProcess(StrictModel):
    name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._@/-]+$")
    pid: int = Field(ge=1, le=4_194_304)
    executable: str = Field(min_length=1, max_length=512)
    user: str = Field(min_length=1, max_length=64)
    started_at: AwareDatetime | None = None
    cmdline: str | None = Field(default=None, max_length=2000)


class ObservedPort(StrictModel):
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    state: Literal["listening", "established", "closed"] = "listening"
    bound_process: str | None = Field(default=None, max_length=64)
    bound_pid: int | None = Field(default=None, ge=1, le=4_194_304)


class HealthStatus(StrictModel):
    status: Literal["passing", "degraded", "failing", "unknown"]
    consecutive_failures: int = Field(default=0, ge=0, le=10_000)
    last_check_at: AwareDatetime | None = None
    detail: str | None = Field(default=None, max_length=2000)


class Observation(StrictModel):
    image: ObservedImage | None = None
    config_hash: str | None = Field(default=None, pattern=_CONFIG_PATTERN)
    processes: list[ObservedProcess] | None = Field(default=None, max_length=512)
    ports: list[ObservedPort] | None = Field(default=None, max_length=512)
    health: HealthStatus | None = None
    metrics: dict[str, float] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _has_content(self) -> Observation:
        if not any(
            value is not None
            for value in (self.image, self.config_hash, self.processes, self.ports, self.health)
        ) and not self.metrics:
            raise ValueError("observation must contain at least one field")
        return self


EventType = Literal[
    "telemetry_snapshot",
    "process_observed",
    "port_observed",
    "image_report",
    "health_check",
    "config_change",
]


class Event(StrictModel):
    """A single telemetry record.

    ``extra="allow"`` keeps forward-compatible vendor fields, but they are only
    stored as evidence and never used for decisions.
    """

    model_config = ConfigDict(extra="allow", str_strip_whitespace=True)

    event_id: str = Field(min_length=3, max_length=96)
    timestamp: AwareDatetime
    resource_id: str = Field(min_length=3, max_length=64)
    resource_type: ResourceKind
    source: str = Field(min_length=2, max_length=64)
    event_type: EventType
    observation: Observation
    labels: dict[str, str] = Field(default_factory=dict)
    notes: str | None = Field(default=None, max_length=2000)

    @model_validator(mode="after")
    def _safe_identifiers(self) -> Event:
        if not is_safe_id(self.event_id):
            raise ValueError("event_id contains unsupported characters")
        if not is_safe_id(self.resource_id):
            raise ValueError("resource_id contains unsupported characters")
        if len(self.labels) > 32:
            raise ValueError("too many labels")
        for key, value in self.labels.items():
            if len(key) > 64 or len(value) > 512:
                raise ValueError("label exceeds size limits")
        return self


class EventsDocument(StrictModel):
    schema_version: Literal["1.0"]
    generated_at: AwareDatetime
    as_of: AwareDatetime
    events: list[Event] = Field(max_length=100_000)

    @model_validator(mode="after")
    def _timestamps_not_after_as_of(self) -> EventsDocument:
        from sentinel.models.common import ensure_utc

        cutoff = ensure_utc(self.as_of)
        for event in self.events:
            if ensure_utc(event.timestamp) > cutoff:
                raise ValueError(f"event {event.event_id} is newer than as_of")
        return self


class RawEventRecord(StrictModel):
    """Evidence wrapper: original payload hash + provenance, never mutated."""

    event: Event
    source_file: str
    source_sha256: str
    record_index: int
    received_at: datetime
    fingerprint: str
