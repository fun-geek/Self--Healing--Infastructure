"""Action catalogue, policy decisions and remediation job schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import AwareDatetime, Field, model_validator

from sentinel.models.common import ResourceState, Role, Severity, StrictModel

JobStatus = Literal["QUEUED", "RUNNING", "SUCCEEDED", "FAILED", "ESCALATED", "CANCELLED"]


class ActionSpec(StrictModel):
    action_id: str = Field(pattern=r"^ACT-[0-9]{3}$")
    action: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,63}$")
    description: str = Field(min_length=5, max_length=500)
    allowed_from_states: list[ResourceState] = Field(min_length=1)
    requires_approval: bool = False
    approval_role: Role | None = None
    required_role: Role = Role.RESPONDER
    preconditions: list[str] = Field(default_factory=list)
    expected_result: str = Field(min_length=3, max_length=500)
    max_retries: int = Field(default=0, ge=0, le=10)
    timeout_seconds: int = Field(default=30, ge=1, le=3600)
    reversible: bool = False
    automatable: bool = False
    state_change: ResourceState | None = None
    notes: str = Field(default="", max_length=500)

    @model_validator(mode="after")
    def _approval_consistency(self) -> ActionSpec:
        if self.requires_approval and self.approval_role is None:
            raise ValueError("approval_role is required when requires_approval is true")
        if self.automatable and self.requires_approval:
            # Automatable actions may still need approval; the orchestrator must
            # obtain a recorded approval before execution. This is allowed.
            pass
        return self


class ActionCatalogue(StrictModel):
    actions: dict[str, ActionSpec]
    source_sha256: str

    @model_validator(mode="after")
    def _unique(self) -> ActionCatalogue:
        seen: set[str] = set()
        for key, action in self.actions.items():
            if key != action.action_id:
                raise ValueError("catalogue key must equal action_id")
            if action.action in seen:
                raise ValueError(f"duplicate action name {action.action}")
            seen.add(action.action)
        return self

    def by_name(self, name: str) -> ActionSpec | None:
        for action in self.actions.values():
            if action.action == name:
                return action
        return None


class ActionRequest(StrictModel):
    action_id: str
    resource_id: str
    actor: str = Field(min_length=2, max_length=120)
    role: Role
    job_id: str | None = None
    attempt: int = Field(default=1, ge=1, le=20)
    idempotency_key: str | None = Field(default=None, max_length=200)
    approval_id: str | None = None
    expected_version: int | None = Field(default=None, ge=1)
    autonomous: bool = False
    correlation_id: str | None = None


class PolicyDecision(StrictModel):
    allowed: bool
    action_id: str
    resource_id: str
    reasons: list[str] = Field(default_factory=list)
    requires_approval: bool = False
    approval_satisfied: bool = False
    duplicate: bool = False
    cached_result: dict[str, object] | None = None
    policy_version: str = "1"
    decided_at: AwareDatetime


class RemediationJob(StrictModel):
    job_id: str
    resource_id: str
    trigger: str
    status: JobStatus
    attempts: int
    max_attempts: int
    created_at: AwareDatetime
    updated_at: AwareDatetime
    idempotency_key: str
    last_error: str | None = None
    finding_ids: list[str] = Field(default_factory=list)
    initiated_by: str


class JobStep(StrictModel):
    step_id: str
    job_id: str
    action_id: str
    attempt: int
    status: Literal["PENDING", "RUNNING", "SUCCEEDED", "FAILED", "DENIED", "SKIPPED"]
    started_at: AwareDatetime
    finished_at: AwareDatetime | None = None
    result: dict[str, object] = Field(default_factory=dict)
    error: str | None = None


class ValidationResult(StrictModel):
    validation_id: str
    job_id: str | None
    resource_id: str
    rule_id: str
    passed: bool
    mandatory: bool
    attempt: int = 1
    detail: str
    observed: str | None = None
    expected: str | None = None
    checked_at: AwareDatetime


class Approval(StrictModel):
    approval_id: str
    action_id: str
    resource_id: str
    job_id: str | None
    approved_by: str
    role: Role
    reason: str
    created_at: AwareDatetime
    expires_at: AwareDatetime
    consumed: bool = False


class ActionResult(StrictModel):
    action_id: str
    resource_id: str
    success: bool
    message: str
    previous_state: ResourceState | None = None
    new_state: ResourceState | None = None
    details: dict[str, object] = Field(default_factory=dict)
    executed_at: AwareDatetime
