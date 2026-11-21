"""Observed-state projection and persisted resource view."""

from __future__ import annotations

from datetime import datetime

from pydantic import AwareDatetime, Field

from sentinel.models.common import ResourceKind, ResourceState, StrictModel
from sentinel.models.events import (
    HealthStatus,
    ObservedImage,
    ObservedPort,
    ObservedProcess,
)


class ObservedResource(StrictModel):
    """Current observed state derived by replaying telemetry in timestamp order."""

    resource_id: str
    resource_type: ResourceKind | None = None
    image: ObservedImage | None = None
    config_hash: str | None = None
    processes: list[ObservedProcess] = Field(default_factory=list)
    ports: list[ObservedPort] = Field(default_factory=list)
    health: HealthStatus | None = None
    last_event_at: AwareDatetime | None = None
    event_ids: list[str] = Field(default_factory=list)
    field_evidence: dict[str, list[str]] = Field(default_factory=dict)
    untrusted_hints: list[str] = Field(default_factory=list)
    untrusted_notes: list[str] = Field(default_factory=list)

    def evidence_for(self, field_name: str) -> list[str]:
        return list(self.field_evidence.get(field_name, []))

    def listening_ports(self) -> list[ObservedPort]:
        return [port for port in self.ports if port.state == "listening"]


class ResourceView(StrictModel):
    resource_id: str
    kind: ResourceKind
    service: str
    host: str
    state: ResourceState
    observed: ObservedResource | None
    baseline_version: int
    in_load_balancer: bool
    version: int
    updated_at: AwareDatetime
    last_scan_id: str | None = None


class StateTransition(StrictModel):
    transition_id: str
    resource_id: str
    job_id: str | None
    from_state: ResourceState | None
    to_state: ResourceState
    trigger: str
    actor: str
    result: str
    failure_reason: str | None
    created_at: AwareDatetime
