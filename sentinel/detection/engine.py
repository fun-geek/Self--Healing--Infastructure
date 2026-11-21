"""Detection engine: baseline comparison + severity aggregation."""

from __future__ import annotations

from datetime import datetime

from sentinel.detection.rules import evaluate_rules
from sentinel.models.baseline import Baseline
from sentinel.models.common import ensure_utc, utcnow
from sentinel.models.findings import DetectionReport, ResourceAssessment
from sentinel.models.state import ObservedResource
from sentinel.observability.metrics import FINDINGS_TOTAL


class DetectionEngine:
    def __init__(self, baseline: Baseline) -> None:
        self.baseline = baseline

    def assess(self, observed: ObservedResource, as_of: datetime) -> ResourceAssessment:
        resource = self.baseline.resource(observed.resource_id)
        if resource is None:
            raise ValueError(f"resource {observed.resource_id} is not in the approved baseline")
        findings = evaluate_rules(self.baseline, resource, observed, ensure_utc(as_of))
        return ResourceAssessment.build(
            resource_id=observed.resource_id,
            findings=findings,
            assessed_at=utcnow(),
            auto_remediate_severities=self.baseline.policy.auto_remediate_severities,
        )

    def scan(
        self,
        observations: dict[str, ObservedResource],
        *,
        as_of: datetime,
        scan_id: str,
        events_considered: int,
        duplicates: int,
        rejected: int,
    ) -> DetectionReport:
        started = utcnow()
        assessments: list[ResourceAssessment] = []
        for resource_id in sorted(self.baseline.resources):
            observed = observations.get(resource_id) or ObservedResource(resource_id=resource_id)
            assessment = self.assess(observed, as_of)
            assessments.append(assessment)
            for finding in assessment.findings:
                FINDINGS_TOTAL.labels(
                    severity=finding.severity.value, rule_id=finding.rule_id
                ).inc()

        findings_total = sum(len(item.findings) for item in assessments)
        open_findings = sum(
            1
            for item in assessments
            for finding in item.findings
            if finding.status == "open"
        )
        return DetectionReport(
            scan_id=scan_id,
            started_at=started,
            finished_at=utcnow(),
            baseline_id=self.baseline.baseline_id,
            baseline_version=self.baseline.version,
            as_of=ensure_utc(as_of),
            resources_assessed=len(assessments),
            assessments=assessments,
            events_considered=events_considered,
            duplicates=duplicates,
            rejected=rejected,
            findings_total=findings_total,
            open_findings=open_findings,
        )
