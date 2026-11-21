"""Approved-baseline schema.

The baseline is the single source of truth for trust. It is generated from an
independent desired-state specification (see ``sentinel.synth``) and is never
derived from observed telemetry.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import AwareDatetime, Field, model_validator

from sentinel.models.common import (
    ResourceKind,
    Severity,
    StrictModel,
    ensure_utc,
)

_DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
_CONFIG_PATTERN = r"^sha256:[0-9a-f]{64}$"


class ImageSpec(StrictModel):
    reference: str = Field(min_length=3, max_length=255)
    tag: str = Field(min_length=1, max_length=64)
    digest: str = Field(pattern=_DIGEST_PATTERN)


class PortSpec(StrictModel):
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    purpose: str = Field(min_length=3, max_length=120)
    exposure: Literal["internal", "public", "management"] = "internal"


class ProcessSpec(StrictModel):
    name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._@/-]+$")
    executable: str = Field(min_length=2, max_length=255, pattern=r"^/")
    user: str = Field(min_length=1, max_length=64)
    sha256: str | None = Field(default=None, pattern=_DIGEST_PATTERN)


class ValidationRule(StrictModel):
    rule_id: str = Field(pattern=r"^VAL-[A-Z]+-[0-9]{3}$")
    title: str = Field(min_length=5, max_length=120)
    description: str = Field(min_length=10, max_length=1000)
    check: Literal[
        "image_digest",
        "config_hash",
        "ports",
        "processes",
        "health",
        "service_probe",
    ]
    mandatory: bool = True
    severity: Severity = Severity.HIGH
    remediation_hint: str = Field(min_length=5, max_length=500)
    params: dict[str, object] = Field(default_factory=dict)


class ResourceBaseline(StrictModel):
    resource_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    kind: ResourceKind
    service: str = Field(min_length=2, max_length=64)
    host: str = Field(min_length=2, max_length=255)
    approved_image: ImageSpec
    config_hash: str = Field(pattern=_CONFIG_PATTERN)
    approved_ports: list[PortSpec] = Field(min_length=1)
    approved_processes: list[ProcessSpec] = Field(min_length=1)
    validation_rule_ids: list[str] = Field(min_length=1)
    owner: str = Field(min_length=2, max_length=120)
    data_classification: Literal["public", "internal", "confidential", "restricted"] = "internal"

    @model_validator(mode="after")
    def _unique_ports(self) -> ResourceBaseline:
        keys = {(port.port, port.protocol) for port in self.approved_ports}
        if len(keys) != len(self.approved_ports):
            raise ValueError("approved_ports contains duplicates")
        return self

    @property
    def approved_port_keys(self) -> set[tuple[int, str]]:
        return {(port.port, port.protocol) for port in self.approved_ports}

    @property
    def approved_process_names(self) -> set[str]:
        return {process.name for process in self.approved_processes}

    @property
    def approved_executables(self) -> dict[str, str]:
        return {process.name: process.executable for process in self.approved_processes}


class ApprovedChange(StrictModel):
    change_id: str = Field(pattern=r"^CHG-[0-9]{4,8}$")
    resource_id: str
    field: Literal["config_hash", "approved_image", "ports", "processes"]
    approved_value: str = Field(min_length=1, max_length=512)
    approved_by: str = Field(min_length=2, max_length=120)
    approved_at: AwareDatetime
    expires_at: AwareDatetime | None = None
    ticket: str = Field(min_length=3, max_length=255)

    def covers(self, resource_id: str, field: str, value: str, at: datetime) -> bool:
        if self.resource_id != resource_id or self.field != field:
            return False
        if self.approved_value != value:
            return False
        if ensure_utc(self.approved_at) > ensure_utc(at):
            return False
        return self.expires_at is None or ensure_utc(self.expires_at) >= ensure_utc(at)


class BaselinePolicy(StrictModel):
    health_failure_threshold: int = Field(default=3, ge=1, le=100)
    stale_telemetry_minutes: int = Field(default=30, ge=1, le=1440)
    auto_remediate_severities: list[Severity] = Field(default_factory=lambda: [Severity.CRITICAL])
    max_restore_attempts: int = Field(default=2, ge=0, le=5)
    require_approval_for_quarantine: bool = False
    allow_auto_return_to_service: bool = True
    forbidden_process_prefixes: list[str] = Field(
        default_factory=lambda: ["/tmp/", "/dev/shm/", "/var/tmp/"]
    )
    privileged_users: list[str] = Field(default_factory=lambda: ["root", "0"])
    high_risk_ports: list[int] = Field(
        default_factory=lambda: [4444, 1337, 31337, 5555, 6667, 4443, 9001]
    )


class Baseline(StrictModel):
    schema_version: Literal["1.0"]
    baseline_id: str = Field(pattern=r"^baseline-[a-z0-9.-]{3,80}$")
    version: int = Field(ge=1)
    generated_at: AwareDatetime
    as_of: AwareDatetime
    resources: dict[str, ResourceBaseline]
    validation_rules: dict[str, ValidationRule]
    approved_changes: list[ApprovedChange] = Field(default_factory=list)
    policy: BaselinePolicy = Field(default_factory=BaselinePolicy)

    @model_validator(mode="after")
    def _referential_integrity(self) -> Baseline:
        for key, resource in self.resources.items():
            if key != resource.resource_id:
                raise ValueError(f"resource key {key!r} does not match resource_id")
            missing = [rule for rule in resource.validation_rule_ids if rule not in self.validation_rules]
            if missing:
                raise ValueError(f"{key} references unknown validation rules: {missing}")
        for change in self.approved_changes:
            if change.resource_id not in self.resources:
                raise ValueError(f"approved change {change.change_id} references unknown resource")
        if not any(rule.mandatory for rule in self.validation_rules.values()):
            raise ValueError("baseline must define at least one mandatory validation rule")
        return self

    def resource(self, resource_id: str) -> ResourceBaseline | None:
        return self.resources.get(resource_id)

    def mandatory_rules_for(self, resource_id: str) -> list[ValidationRule]:
        resource = self.resources.get(resource_id)
        if resource is None:
            return []
        return [
            self.validation_rules[rule_id]
            for rule_id in resource.validation_rule_ids
            if self.validation_rules[rule_id].mandatory
        ]

    def approved_change_for(self, resource_id: str, field: str, value: str, at: datetime) -> ApprovedChange | None:
        for change in self.approved_changes:
            if change.covers(resource_id, field, value, at):
                return change
        return None
