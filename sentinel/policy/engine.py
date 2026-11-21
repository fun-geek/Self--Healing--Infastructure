"""Independent security policy enforcement.

This engine is the only component allowed to authorize a state-changing action.
The LLM is never consulted here. Deny-by-default: every check must pass.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime

from sentinel.domain.state_machine import can_transition
from sentinel.errors import PolicyDenied
from sentinel.models.actions import (
    ActionCatalogue,
    ActionRequest,
    ActionSpec,
    PolicyDecision,
)
from sentinel.models.baseline import Baseline
from sentinel.models.common import (
    ResourceState,
    Severity,
    SEVERITY_RANK,
    ensure_utc,
    max_severity,
    role_at_least,
    utcnow,
)
from sentinel.persistence.repositories import (
    ApprovalRepository,
    FindingRepository,
    IdempotencyRepository,
    JobRepository,
    ResourceRepository,
    ValidationRepository,
)


class PolicyEngine:
    def __init__(
        self,
        *,
        baseline: Baseline,
        catalogue: ActionCatalogue,
        resources: ResourceRepository,
        findings: FindingRepository,
        validations: ValidationRepository,
        approvals: ApprovalRepository,
        jobs: JobRepository,
        idempotency: IdempotencyRepository,
        settings_max_restore_attempts: int,
    ) -> None:
        self.baseline = baseline
        self.catalogue = catalogue
        self.resources = resources
        self.findings = findings
        self.validations = validations
        self.approvals = approvals
        self.jobs = jobs
        self.idempotency = idempotency
        self.settings_max_restore_attempts = settings_max_restore_attempts

    @property
    def version(self) -> str:
        return (
            f"{self.baseline.baseline_id}:v{self.baseline.version}:"
            f"catalogue-{self.catalogue.source_sha256[:12]}"
        )

    def authorize(self, request: ActionRequest) -> PolicyDecision:
        now = utcnow()
        reasons: list[str] = []
        action = self.catalogue.actions.get(request.action_id)

        if action is None:
            return self._deny(request, now, ["action is not present in the approved action catalogue"])

        if not role_at_least(request.role, action.required_role):
            reasons.append(
                f"role {request.role.value} is insufficient; {action.required_role.value} required"
            )
        if request.autonomous and not action.automatable:
            reasons.append("action is not permitted for autonomous execution")

        resource = self.resources.get(request.resource_id)
        if resource is None:
            reasons.append("resource does not exist")
            return self._deny(request, now, reasons)

        if resource.state not in action.allowed_from_states:
            reasons.append(
                f"action not allowed from state {resource.state.value}"
            )
        if (
            request.expected_version is not None
            and request.expected_version != resource.version
        ):
            reasons.append("resource version changed concurrently")

        if action.state_change is not None and not can_transition(
            resource.state, action.state_change
        ):
            reasons.append(
                f"illegal transition {resource.state.value} -> {action.state_change.value}"
            )

        approval_satisfied = False
        if action.requires_approval:
            if not request.approval_id:
                reasons.append("a recorded human approval is required")
            else:
                approval = self.approvals.get(request.approval_id)
                if approval is None:
                    reasons.append("approval record not found")
                elif approval.consumed:
                    reasons.append("approval has already been consumed")
                elif ensure_utc(approval.expires_at) < now:
                    reasons.append("approval has expired")
                elif approval.action_id != action.action_id or approval.resource_id != request.resource_id:
                    reasons.append("approval does not match this action and resource")
                elif action.approval_role and not role_at_least(approval.role, action.approval_role):
                    reasons.append("approval was granted by an insufficient role")
                else:
                    approval_satisfied = True

        reasons.extend(self._action_specific_checks(request, action, resource, now))

        if reasons:
            return self._deny(request, now, reasons, requires_approval=action.requires_approval)

        if request.idempotency_key:
            cached = self.idempotency.get(request.idempotency_key)
            if cached is not None:
                return PolicyDecision(
                    allowed=True,
                    action_id=request.action_id,
                    resource_id=request.resource_id,
                    reasons=["duplicate request: returning recorded result"],
                    requires_approval=action.requires_approval,
                    approval_satisfied=approval_satisfied,
                    duplicate=True,
                    cached_result=cached["response"],
                    policy_version=self.version,
                    decided_at=now,
                )

        return PolicyDecision(
            allowed=True,
            action_id=request.action_id,
            resource_id=request.resource_id,
            reasons=[],
            requires_approval=action.requires_approval,
            approval_satisfied=approval_satisfied,
            policy_version=self.version,
            decided_at=now,
        )

    def require(self, request: ActionRequest) -> PolicyDecision:
        decision = self.authorize(request)
        if not decision.allowed:
            raise PolicyDenied(
                "policy denied the requested action",
                detail={"reasons": decision.reasons, "action_id": request.action_id},
            )
        return decision

    # -- action-specific preconditions ------------------------------------
    def _action_specific_checks(
        self,
        request: ActionRequest,
        action: ActionSpec,
        resource: object,
        now: datetime,
    ) -> list[str]:
        reasons: list[str] = []
        name = action.action
        from sentinel.models.state import ResourceView

        assert isinstance(resource, ResourceView)
        resource_baseline = self.baseline.resource(request.resource_id)

        if name == "REMOVE_FROM_LOAD_BALANCER" and not resource.in_load_balancer:
            reasons.append("resource is already drained from the load balancer")

        if name == "QUARANTINE_RESOURCE":
            if resource.in_load_balancer:
                reasons.append("resource must be drained from the load balancer before quarantine")
            open_findings = self.findings.open_for_resource(request.resource_id)
            if not open_findings:
                reasons.append("resource has no confirmed active finding")
            elif max_severity([finding.severity for finding in open_findings]) in {
                Severity.INFO,
                Severity.LOW,
                Severity.MEDIUM,
            }:
                reasons.append("no high or critical finding justifies quarantine")

        if name in {"RESTORE_FROM_BASELINE", "VALIDATE_RESOURCE", "RETURN_TO_SERVICE"}:
            if resource_baseline is None:
                reasons.append("no approved baseline exists for this resource")
            if not request.job_id:
                reasons.append("a remediation job is required")
            elif self.jobs.get(request.job_id) is None:
                reasons.append("remediation job not found")

        if name == "RESTORE_FROM_BASELINE":
            budget = max(
                1,
                min(
                    action.max_retries,
                    self.baseline.policy.max_restore_attempts,
                    self.settings_max_restore_attempts,
                ),
            )
            if request.attempt > budget:
                reasons.append(
                    f"restore retry budget exhausted ({request.attempt} > {budget})"
                )
            if resource_baseline is None:
                reasons.append("cannot restore without an approved baseline")

        if name == "VALIDATE_RESOURCE":
            if not request.job_id:
                reasons.append("validation requires a job context")
            elif not self._has_successful_restore(request.job_id):
                reasons.append("validation requires a completed restore step")

        if name == "RETURN_TO_SERVICE":
            if resource_baseline is None:
                reasons.append("cannot validate return to service without a baseline")
            elif not self.baseline.policy.allow_auto_return_to_service and request.autonomous:
                reasons.append("policy forbids automatic return to service")
            if request.job_id:
                mandatory = {
                    rule.rule_id for rule in self.baseline.mandatory_rules_for(request.resource_id)
                }
                all_results = self.validations.for_job(request.job_id)
                latest_attempt = max(
                    (result.attempt for result in all_results), default=0
                )
                results = [
                    result for result in all_results if result.attempt == latest_attempt
                ]
                passed = {result.rule_id for result in results if result.passed and result.mandatory}
                failed = {result.rule_id for result in results if not result.passed and result.mandatory}
                if not mandatory:
                    reasons.append("no mandatory validation rules defined")
                if failed:
                    reasons.append(f"mandatory validation failed: {', '.join(sorted(failed))}")
                missing = mandatory - passed
                if missing:
                    reasons.append(f"mandatory validation missing: {', '.join(sorted(missing))}")
            if resource.in_load_balancer:
                reasons.append("resource is unexpectedly attached to the load balancer")
            critical = [
                finding
                for finding in self.findings.open_for_resource(request.resource_id)
                if SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[Severity.CRITICAL]
            ]
            if critical:
                reasons.append("open critical findings still exist for the resource")

        if name == "DELETE_RESOURCE" and not action.requires_approval:
            reasons.append("destructive action must require approval")

        return reasons

    def _has_successful_restore(self, job_id: str) -> bool:
        rows = self._job_steps(job_id)
        return any(
            step["action_id"] in {"ACT-006", "ACT-012"} and step["status"] == "SUCCEEDED"
            for step in rows
        )

    def _job_steps(self, job_id: str) -> list[dict[str, object]]:
        rows = self.jobs.db.query(
            "SELECT action_id, status FROM job_steps WHERE job_id = ?", (job_id,)
        )
        return [dict(row) for row in rows]

    def _deny(
        self,
        request: ActionRequest,
        now: datetime,
        reasons: list[str],
        *,
        requires_approval: bool = False,
    ) -> PolicyDecision:
        return PolicyDecision(
            allowed=False,
            action_id=request.action_id,
            resource_id=request.resource_id,
            reasons=reasons,
            requires_approval=requires_approval,
            approval_satisfied=False,
            policy_version=self.version,
            decided_at=now,
        )


def assert_action_in_catalogue(catalogue: ActionCatalogue, action_id: str) -> ActionSpec:
    action = catalogue.actions.get(action_id)
    if action is None:
        raise PolicyDenied(
            "proposed action is not present in the approved action catalogue",
            detail={"action_id": action_id},
        )
    return action
