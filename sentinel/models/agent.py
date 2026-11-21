"""Agent investigation and structured proposal schemas.

The LLM's output is parsed into :class:`RemediationProposal`. Nothing in this
schema grants authority: every proposed action is re-checked by the policy engine
against the approved action catalogue.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import AwareDatetime, Field

from sentinel.models.common import Severity, StrictModel

TrustLevel = Literal["authoritative", "internal", "untrusted"]


class Citation(StrictModel):
    doc_id: str
    title: str
    chunk_id: str
    trust_level: TrustLevel
    score: float = Field(ge=0.0)
    snippet: str = Field(max_length=600)


class ProposedAction(StrictModel):
    action_id: str = Field(pattern=r"^ACT-[0-9]{3}$")
    resource_id: str
    rationale: str = Field(min_length=10, max_length=800)
    order: int = Field(ge=1, le=20)


class RemediationProposal(StrictModel):
    proposal_id: str
    resource_id: str
    diagnosis: str = Field(min_length=20, max_length=2000)
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    proposed_actions: list[ProposedAction] = Field(min_length=1, max_length=20)
    evidence_refs: list[str] = Field(default_factory=list, max_length=64)
    citations: list[Citation] = Field(default_factory=list, max_length=12)
    generated_by: str = Field(min_length=2, max_length=120)
    fallback_used: bool = False
    created_at: AwareDatetime


class GuardrailEvent(StrictModel):
    code: str
    detail: str = Field(max_length=800)
    source: str = Field(max_length=200)
    blocked: bool = True
    created_at: AwareDatetime


class InvestigationResult(StrictModel):
    investigation_id: str
    resource_id: str
    status: Literal["completed", "fallback", "failed"]
    provider: str
    model: str | None
    proposal: RemediationProposal | None
    citations: list[Citation] = Field(default_factory=list)
    guardrail_events: list[GuardrailEvent] = Field(default_factory=list)
    started_at: AwareDatetime
    finished_at: AwareDatetime
    error: str | None = None


class InvestigationSummary(StrictModel):
    investigation_id: str
    resource_id: str
    status: str
    provider: str
    model: str | None
    diagnosis: str | None
    confidence: float | None
    created_at: AwareDatetime
