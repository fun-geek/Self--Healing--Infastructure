"""Explainable, deterministic detection rules.

No ML is used. The approved baseline is authoritative; telemetry is only ever
compared against it. Every finding carries evidence with source event IDs.

MITRE ATT&CK tags are descriptive metadata for analysts, not decision inputs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

from sentinel.models.baseline import Baseline, ResourceBaseline
from sentinel.models.common import (
    Severity,
    canonical_json,
    ensure_utc,
    short_id,
    utcnow,
)
from sentinel.models.findings import Evidence, Finding
from sentinel.models.state import ObservedResource


@dataclass(frozen=True)
class RuleContext:
    baseline: Baseline
    resource: ResourceBaseline
    observed: ObservedResource
    as_of: datetime


@dataclass
class FindingDraft:
    rule_id: str
    severity: Severity
    confidence: float
    title: str
    description: str
    evidence: list[Evidence] = field(default_factory=list)
    status: str = "open"
    suppression_reason: str | None = None
    remediation_blocked: bool = False
    tags: list[str] = field(default_factory=list)


RuleFn = Callable[[RuleContext], list[FindingDraft]]


def _fmt(value: object) -> str:
    if isinstance(value, str):
        return value[:2000]
    return json.dumps(value, sort_keys=True, default=str)[:2000]


def _is_forbidden(executable: str, prefixes: list[str]) -> bool:
    normalized = executable.replace("\\", "/")
    return any(normalized.startswith(prefix) for prefix in prefixes)


def rule_unauthorized_ports(ctx: RuleContext) -> list[FindingDraft]:
    approved = ctx.resource.approved_port_keys
    approved_names = ctx.resource.approved_process_names
    privileged = set(ctx.baseline.policy.privileged_users)
    high_risk = set(ctx.baseline.policy.high_risk_ports)
    drafts: list[FindingDraft] = []

    for port in ctx.observed.listening_ports():
        if (port.port, port.protocol) in approved:
            continue
        bound = next(
            (
                process
                for process in ctx.observed.processes
                if (port.bound_pid is not None and process.pid == port.bound_pid)
                or (port.bound_process is not None and process.name == port.bound_process)
            ),
            None,
        )
        reasons = [f"port {port.port}/{port.protocol} is not approved"]
        severity = Severity.HIGH
        if port.port in high_risk:
            severity = Severity.CRITICAL
            reasons.append("port is on the high-risk list")
        if bound is not None and bound.name not in approved_names:
            severity = Severity.CRITICAL
            reasons.append(f"bound to unapproved process {bound.name}")
        if bound is not None and bound.user in privileged:
            severity = Severity.CRITICAL
            reasons.append(f"bound process runs as {bound.user}")
        drafts.append(
            FindingDraft(
                rule_id="RULE-PORT-001",
                severity=severity,
                confidence=0.95 if severity is Severity.CRITICAL else 0.85,
                title=f"Unauthorized listening port {port.port}/{port.protocol}",
                description=(
                    f"Resource {ctx.resource.resource_id} exposes {port.port}/{port.protocol} "
                    f"which is absent from the approved baseline. " + "; ".join(reasons) + "."
                ),
                evidence=[
                    Evidence(
                        kind="unauthorized_port",
                        source_event_ids=ctx.observed.evidence_for("ports"),
                        field="ports",
                        observed=_fmt(port.model_dump(mode="json")),
                        expected=_fmt(
                            [
                                {"port": item.port, "protocol": item.protocol}
                                for item in ctx.resource.approved_ports
                            ]
                        ),
                        note="; ".join(reasons),
                    )
                ],
                tags=["T1571", "network"],
            )
        )
    return drafts


def rule_processes(ctx: RuleContext) -> list[FindingDraft]:
    approved_names = ctx.resource.approved_process_names
    approved_exec = ctx.resource.approved_executables
    privileged = set(ctx.baseline.policy.privileged_users)
    forbidden = ctx.baseline.policy.forbidden_process_prefixes
    drafts: list[FindingDraft] = []

    for process in ctx.observed.processes:
        if process.name not in approved_names:
            severity = Severity.HIGH
            reasons = [f"process {process.name} is not approved"]
            if _is_forbidden(process.executable, forbidden):
                severity = Severity.CRITICAL
                reasons.append(f"executable runs from forbidden path {process.executable}")
            if process.user in privileged:
                severity = Severity.CRITICAL
                reasons.append(f"runs as privileged user {process.user}")
            drafts.append(
                FindingDraft(
                    rule_id="RULE-PROC-001",
                    severity=severity,
                    confidence=0.95,
                    title=f"Unapproved process {process.name}",
                    description=(
                        f"Resource {ctx.resource.resource_id} runs {process.name} "
                        f"(pid {process.pid}, executable {process.executable}, user {process.user}) "
                        f"which is absent from the approved baseline. " + "; ".join(reasons) + "."
                    ),
                    evidence=[
                        Evidence(
                            kind="unknown_process",
                            source_event_ids=ctx.observed.evidence_for("processes"),
                            field="processes",
                            observed=_fmt(process.model_dump(mode="json")),
                            expected=_fmt(
                                [
                                    {"name": item.name, "executable": item.executable, "user": item.user}
                                    for item in ctx.resource.approved_processes
                                ]
                            ),
                            note="; ".join(reasons),
                        )
                    ],
                    tags=["T1059", "T1496", "execution"],
                )
            )
            continue

        expected_executable = approved_exec.get(process.name)
        approved_users = {
            item.user for item in ctx.resource.approved_processes if item.name == process.name
        }
        if expected_executable is not None and process.executable != expected_executable:
            severity = Severity.CRITICAL if process.user in privileged else Severity.HIGH
            drafts.append(
                FindingDraft(
                    rule_id="RULE-PROC-002",
                    severity=severity,
                    confidence=0.9,
                    title=f"Process masquerading as {process.name}",
                    description=(
                        f"Resource {ctx.resource.resource_id} runs a process named {process.name} "
                        f"from {process.executable}, but the approved binary is {expected_executable}."
                    ),
                    evidence=[
                        Evidence(
                            kind="masquerading_process",
                            source_event_ids=ctx.observed.evidence_for("processes"),
                            field="processes",
                            observed=_fmt(process.model_dump(mode="json")),
                            expected=expected_executable,
                            note="approved name executed from an unapproved binary path",
                        )
                    ],
                    tags=["T1036.005", "defense-evasion"],
                )
            )
        elif approved_users and process.user not in approved_users:
            drafts.append(
                FindingDraft(
                    rule_id="RULE-PROC-002",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    title=f"Process {process.name} runs as unexpected user",
                    description=(
                        f"Process {process.name} runs as {process.user}; approved user(s): "
                        f"{', '.join(sorted(approved_users))}."
                    ),
                    evidence=[
                        Evidence(
                            kind="process_user_mismatch",
                            source_event_ids=ctx.observed.evidence_for("processes"),
                            field="processes",
                            observed=process.user,
                            expected=", ".join(sorted(approved_users)),
                        )
                    ],
                    tags=["T1036", "defense-evasion"],
                )
            )
    return drafts


def rule_image(ctx: RuleContext) -> list[FindingDraft]:
    approved = ctx.resource.approved_image
    observed = ctx.observed.image
    if observed is None:
        return [
            FindingDraft(
                rule_id="RULE-IMG-001",
                severity=Severity.HIGH,
                confidence=0.6,
                title="Image identity cannot be verified",
                description=(
                    f"No image telemetry is available for {ctx.resource.resource_id}; "
                    "integrity cannot be established."
                ),
                evidence=[
                    Evidence(
                        kind="missing_telemetry",
                        field="image",
                        expected=approved.digest,
                        note="image report missing",
                    )
                ],
                remediation_blocked=True,
                tags=["T1525", "integrity"],
            )
        ]

    drafts: list[FindingDraft] = []
    if observed.digest != approved.digest or observed.reference != approved.reference:
        drafts.append(
            FindingDraft(
                rule_id="RULE-IMG-001",
                severity=Severity.CRITICAL,
                confidence=0.99,
                title="Image digest does not match approved baseline",
                description=(
                    f"Resource {ctx.resource.resource_id} runs {observed.reference}:{observed.tag} "
                    f"({observed.digest}), but the approved image is "
                    f"{approved.reference}:{approved.tag} ({approved.digest})."
                ),
                evidence=[
                    Evidence(
                        kind="image_mismatch",
                        source_event_ids=ctx.observed.evidence_for("image"),
                        field="image",
                        observed=_fmt(observed.model_dump(mode="json")),
                        expected=_fmt(approved.model_dump(mode="json")),
                        note="digest/reference mismatch; tags are not trusted as identity",
                    )
                ],
                tags=["T1525", "T1610", "supply-chain"],
            )
        )
    elif observed.tag != approved.tag:
        drafts.append(
            FindingDraft(
                rule_id="RULE-IMG-002",
                severity=Severity.INFO,
                confidence=0.99,
                title="Mutable image tag differs but digest matches",
                description=(
                    f"Resource {ctx.resource.resource_id} reports tag {observed.tag} instead of "
                    f"{approved.tag}, but the image digest matches the approved digest. "
                    "This is informational only."
                ),
                evidence=[
                    Evidence(
                        kind="tag_drift",
                        source_event_ids=ctx.observed.evidence_for("image"),
                        field="image.tag",
                        observed=observed.tag,
                        expected=approved.tag,
                        note="digest is authoritative; tag drift is not treated as compromise",
                    )
                ],
                tags=["integrity"],
            )
        )
    return drafts


def rule_config(ctx: RuleContext) -> list[FindingDraft]:
    observed = ctx.observed.config_hash
    approved = ctx.resource.config_hash
    if observed is None:
        return [
            FindingDraft(
                rule_id="RULE-CFG-001",
                severity=Severity.MEDIUM,
                confidence=0.6,
                title="Configuration hash cannot be verified",
                description=f"No configuration hash is available for {ctx.resource.resource_id}.",
                evidence=[
                    Evidence(
                        kind="missing_telemetry",
                        field="config_hash",
                        expected=approved,
                        note="configuration telemetry missing",
                    )
                ],
                remediation_blocked=True,
                tags=["integrity"],
            )
        ]
    if observed == approved:
        return []

    change = ctx.baseline.approved_change_for(
        ctx.resource.resource_id, "config_hash", observed, ctx.as_of
    )
    if change is not None:
        return [
            FindingDraft(
                rule_id="RULE-CFG-001",
                severity=Severity.INFO,
                confidence=0.95,
                title="Configuration differs under an approved change",
                description=(
                    f"Configuration hash for {ctx.resource.resource_id} differs from the baseline "
                    f"but is covered by approved change {change.change_id} ({change.ticket})."
                ),
                evidence=[
                    Evidence(
                        kind="approved_change",
                        source_event_ids=ctx.observed.evidence_for("config_hash"),
                        field="config_hash",
                        observed=observed,
                        expected=approved,
                        note=f"approved by {change.approved_by} under {change.change_id}",
                    )
                ],
                status="suppressed",
                suppression_reason=f"approved change {change.change_id}",
                tags=["change-management"],
            )
        ]

    return [
        FindingDraft(
            rule_id="RULE-CFG-001",
            severity=Severity.HIGH,
            confidence=0.95,
            title="Configuration hash drifted from baseline",
            description=(
                f"Resource {ctx.resource.resource_id} reports configuration hash {observed}, "
                f"but the approved baseline requires {approved}. No approved change covers this value."
            ),
            evidence=[
                Evidence(
                    kind="config_drift",
                    source_event_ids=ctx.observed.evidence_for("config_hash"),
                    field="config_hash",
                    observed=observed,
                    expected=approved,
                    note="unapproved configuration modification",
                )
            ],
            tags=["T1565.001", "integrity"],
        )
    ]


def rule_health(ctx: RuleContext) -> list[FindingDraft]:
    health = ctx.observed.health
    if health is None:
        return [
            FindingDraft(
                rule_id="RULE-HLTH-001",
                severity=Severity.MEDIUM,
                confidence=0.5,
                title="Health telemetry missing",
                description=f"No health telemetry is available for {ctx.resource.resource_id}.",
                evidence=[Evidence(kind="missing_telemetry", field="health")],
                remediation_blocked=True,
                tags=["availability"],
            )
        ]
    if health.status == "passing" and health.consecutive_failures == 0:
        return []

    threshold = ctx.baseline.policy.health_failure_threshold
    if health.consecutive_failures < threshold:
        return [
            FindingDraft(
                rule_id="RULE-HLTH-001",
                severity=Severity.INFO,
                confidence=0.6,
                title="Transient health degradation below threshold",
                description=(
                    f"{ctx.resource.resource_id} reports {health.status} with "
                    f"{health.consecutive_failures} consecutive failure(s); the policy threshold is "
                    f"{threshold}. Monitoring only."
                ),
                evidence=[
                    Evidence(
                        kind="transient_health",
                        source_event_ids=ctx.observed.evidence_for("health"),
                        field="health",
                        observed=_fmt(health.model_dump(mode="json")),
                        expected=f"passing, <{threshold} consecutive failures",
                    )
                ],
                tags=["availability", "transient"],
            )
        ]

    severity = Severity.HIGH if health.status == "failing" else Severity.MEDIUM
    return [
        FindingDraft(
            rule_id="RULE-HLTH-001",
            severity=severity,
            confidence=0.8,
            title=f"Health check {health.status}",
            description=(
                f"{ctx.resource.resource_id} reports {health.status} with "
                f"{health.consecutive_failures} consecutive failures (threshold {threshold})."
            ),
            evidence=[
                Evidence(
                    kind="health_failure",
                    source_event_ids=ctx.observed.evidence_for("health"),
                    field="health",
                    observed=_fmt(health.model_dump(mode="json")),
                    expected="passing with 0 consecutive failures",
                    note=(health.detail or "")[:500],
                )
            ],
            tags=["T1489", "availability"],
        )
    ]


def rule_untrusted_hints(ctx: RuleContext) -> list[FindingDraft]:
    if not ctx.observed.untrusted_hints:
        return []
    return [
        FindingDraft(
            rule_id="RULE-HINT-001",
            severity=Severity.INFO,
            confidence=0.99,
            title="Untrusted threat hint ignored",
            description=(
                "Telemetry carried a threat/severity hint from an untrusted source. Hints are "
                "recorded as evidence but never used for severity or authorization decisions."
            ),
            evidence=[
                Evidence(
                    kind="untrusted_hint",
                    source_event_ids=ctx.observed.evidence_for("image")
                    + ctx.observed.evidence_for("processes"),
                    field="labels",
                    observed=_fmt(ctx.observed.untrusted_hints),
                    expected="baseline-derived severity only",
                )
            ],
            status="suppressed",
            suppression_reason="untrusted hint cannot influence detection",
            tags=["prompt-injection", "untrusted-input"],
        )
    ]


def rule_staleness(ctx: RuleContext) -> list[FindingDraft]:
    if ctx.observed.last_event_at is None:
        return [
            FindingDraft(
                rule_id="RULE-TELE-001",
                severity=Severity.MEDIUM,
                confidence=0.7,
                title="No telemetry received",
                description=f"No telemetry has been received for {ctx.resource.resource_id}.",
                evidence=[Evidence(kind="missing_telemetry", field="telemetry")],
                remediation_blocked=True,
                tags=["visibility"],
            )
        ]
    age_minutes = (
        ensure_utc(ctx.as_of) - ensure_utc(ctx.observed.last_event_at)
    ).total_seconds() / 60
    threshold = ctx.baseline.policy.stale_telemetry_minutes
    if age_minutes <= threshold:
        return []
    return [
        FindingDraft(
            rule_id="RULE-TELE-001",
            severity=Severity.MEDIUM,
            confidence=0.8,
            title="Telemetry is stale",
            description=(
                f"Last telemetry for {ctx.resource.resource_id} is {age_minutes:.0f} minutes old; "
                f"policy threshold is {threshold} minutes. Integrity cannot be asserted."
            ),
            evidence=[
                Evidence(
                    kind="stale_telemetry",
                    source_event_ids=ctx.observed.evidence_for("health"),
                    field="last_event_at",
                    observed=str(ctx.observed.last_event_at),
                    expected=f"within {threshold} minutes of {ctx.as_of}",
                )
            ],
            remediation_blocked=True,
            tags=["visibility"],
        )
    ]


RULES: list[tuple[str, RuleFn]] = [
    ("RULE-PORT-001", rule_unauthorized_ports),
    ("RULE-PROC-001", rule_processes),
    ("RULE-IMG-001", rule_image),
    ("RULE-CFG-001", rule_config),
    ("RULE-HLTH-001", rule_health),
    ("RULE-HINT-001", rule_untrusted_hints),
    ("RULE-TELE-001", rule_staleness),
]

RULE_METADATA: list[dict[str, object]] = [
    {
        "rule_id": "RULE-PORT-001",
        "title": "Unauthorized listening port",
        "severity": "high/critical",
        "description": "A listening port is absent from the approved baseline port set.",
        "attack": ["T1571"],
    },
    {
        "rule_id": "RULE-PROC-001",
        "title": "Unapproved process",
        "severity": "high/critical",
        "description": "A process name is absent from the approved process list.",
        "attack": ["T1059", "T1496"],
    },
    {
        "rule_id": "RULE-PROC-002",
        "title": "Process masquerading",
        "severity": "high/critical",
        "description": "An approved process name runs from a different binary path or user.",
        "attack": ["T1036.005"],
    },
    {
        "rule_id": "RULE-IMG-001",
        "title": "Image digest mismatch",
        "severity": "critical",
        "description": "The running image digest/reference differs from the approved baseline.",
        "attack": ["T1525", "T1610"],
    },
    {
        "rule_id": "RULE-IMG-002",
        "title": "Mutable tag drift",
        "severity": "info",
        "description": "Tag differs but the approved digest matches; informational only.",
        "attack": [],
    },
    {
        "rule_id": "RULE-CFG-001",
        "title": "Configuration drift",
        "severity": "high",
        "description": "Configuration hash differs from baseline without an approved change.",
        "attack": ["T1565.001"],
    },
    {
        "rule_id": "RULE-HLTH-001",
        "title": "Health check failure",
        "severity": "high/medium/info",
        "description": "Health is degraded or failing beyond the policy threshold.",
        "attack": ["T1489"],
    },
    {
        "rule_id": "RULE-HINT-001",
        "title": "Untrusted threat hint",
        "severity": "info",
        "description": "Untrusted telemetry hints are ignored for decisions.",
        "attack": [],
    },
    {
        "rule_id": "RULE-TELE-001",
        "title": "Missing or stale telemetry",
        "severity": "medium",
        "description": "No recent telemetry; integrity cannot be asserted.",
        "attack": ["T1562.001"],
    },
]


def build_finding(
    draft: FindingDraft,
    *,
    resource_id: str,
    baseline_version: int,
    detected_at: datetime,
) -> Finding:
    evidence_key = canonical_json(
        [
            {
                "kind": item.kind,
                "field": item.field,
                "observed": item.observed,
                "expected": item.expected,
                "events": sorted(item.source_event_ids),
            }
            for item in draft.evidence
        ]
    )
    finding_id = short_id(
        "fnd", resource_id, draft.rule_id, str(baseline_version), evidence_key, length=16
    )
    return Finding(
        finding_id=finding_id,
        resource_id=resource_id,
        rule_id=draft.rule_id,
        severity=draft.severity,
        confidence=draft.confidence,
        title=draft.title,
        description=draft.description,
        evidence=draft.evidence,
        status=draft.status,  # type: ignore[arg-type]
        suppression_reason=draft.suppression_reason,
        remediation_blocked=draft.remediation_blocked,
        detected_at=detected_at,
        baseline_version=baseline_version,
        tags=draft.tags,
    )


def evaluate_rules(
    baseline: Baseline,
    resource: ResourceBaseline,
    observed: ObservedResource,
    as_of: datetime,
) -> list[Finding]:
    context = RuleContext(baseline=baseline, resource=resource, observed=observed, as_of=as_of)
    detected_at = utcnow()
    findings: list[Finding] = []
    for _, rule in RULES:
        try:
            drafts = rule(context)
        except Exception:  # fail closed: a broken rule must not silently pass
            drafts = [
                FindingDraft(
                    rule_id="RULE-ENGINE-001",
                    severity=Severity.HIGH,
                    confidence=0.5,
                    title="Detection rule failed to evaluate",
                    description="A detection rule raised an error; integrity cannot be asserted.",
                    remediation_blocked=True,
                    tags=["engine"],
                )
            ]
        for draft in drafts:
            findings.append(
                build_finding(
                    draft,
                    resource_id=resource.resource_id,
                    baseline_version=baseline.version,
                    detected_at=detected_at,
                )
            )
    return findings
