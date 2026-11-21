"""Findings produced by the deterministic detection engine."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import AwareDatetime, Field

from sentinel.models.common import Severity, StrictModel, max_severity


class Evidence(StrictModel):
    kind: str = Field(min_length=2, max_length=64)
    source_event_ids: list[str] = Field(default_factory=list, max_length=64)
    field: str | None = Field(default=None, max_length=64)
    observed: str | None = Field(default=None, max_length=2000)
    expected: str | None = Field(default=None, max_length=2000)
    note: str | None = Field(default=None, max_length=1000)


class Finding(StrictModel):
    finding_id: str
    resource_id: str
    rule_id: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    title: str = Field(min_length=5, max_length=200)
    description: str = Field(min_length=5, max_length=2000)
    evidence: list[Evidence] = Field(default_factory=list, max_length=64)
    status: Literal["open", "suppressed", "resolved"] = "open"
    suppression_reason: str | None = Field(default=None, max_length=500)
    remediation_blocked: bool = False
    detected_at: AwareDatetime
    baseline_version: int = Field(ge=1)
    tags: list[str] = Field(default_factory=list, max_length=16)


class ResourceAssessment(StrictModel):
    resource_id: str
    severity: Severity
    confirmed: bool
    requires_remediation: bool
    findings: list[Finding]
    evidence_event_ids: list[str]
    summary: str = Field(max_length=1000)
    assessed_at: AwareDatetime

    @classmethod
    def build(
        cls,
        *,
        resource_id: str,
        findings: list[Finding],
        assessed_at: datetime,
        auto_remediate_severities: list[Severity],
    ) -> ResourceAssessment:
        active = [finding for finding in findings if finding.status == "open"]
        severity = max_severity([finding.severity for finding in active])
        corroborating_rules = {finding.rule_id for finding in active}
        confirmed = bool(active) and (
            severity is Severity.CRITICAL
            or (severity is Severity.HIGH and len(corroborating_rules) >= 2)
        )
        blocked = any(finding.remediation_blocked for finding in active)
        requires = (
            confirmed
            and severity in auto_remediate_severities
            and not blocked
            and bool(active)
        )
        event_ids: list[str] = []
        for finding in active:
            for evidence in finding.evidence:
                for event_id in evidence.source_event_ids:
                    if event_id not in event_ids:
                        event_ids.append(event_id)
        if active:
            summary = (
                f"{len(active)} active finding(s); max severity {severity.value}; "
                f"rules: {', '.join(sorted(corroborating_rules))}"
            )
        else:
            summary = "No active findings"
        return cls(
            resource_id=resource_id,
            severity=severity,
            confirmed=confirmed,
            requires_remediation=requires,
            findings=findings,
            evidence_event_ids=event_ids[:128],
            summary=summary[:1000],
            assessed_at=assessed_at,
        )


class DetectionReport(StrictModel):
    scan_id: str
    started_at: AwareDatetime
    finished_at: AwareDatetime
    baseline_id: str
    baseline_version: int
    as_of: AwareDatetime
    resources_assessed: int
    assessments: list[ResourceAssessment]
    events_considered: int
    duplicates: int
    rejected: int
    findings_total: int
    open_findings: int
