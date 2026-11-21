"""Explicit remediation state machine.

Transitions are enforced in the backend. The dashboard can never request an
arbitrary state; it can only invoke actions, which are policy-checked and then
executed by the orchestrator.
"""

from __future__ import annotations

from sentinel.errors import StateConflict
from sentinel.models.common import ResourceState

ALLOWED_TRANSITIONS: dict[ResourceState, frozenset[ResourceState]] = {
    ResourceState.HEALTHY: frozenset({ResourceState.SUSPECTED}),
    ResourceState.SUSPECTED: frozenset(
        {ResourceState.QUARANTINED, ResourceState.HEALTHY, ResourceState.ESCALATED}
    ),
    ResourceState.QUARANTINED: frozenset({ResourceState.RESTORING, ResourceState.ESCALATED}),
    ResourceState.RESTORING: frozenset(
        {ResourceState.VALIDATING, ResourceState.FAILED, ResourceState.QUARANTINED}
    ),
    ResourceState.VALIDATING: frozenset(
        {ResourceState.RECOVERED, ResourceState.FAILED, ResourceState.QUARANTINED}
    ),
    ResourceState.RECOVERED: frozenset({ResourceState.HEALTHY, ResourceState.FAILED}),
    ResourceState.FAILED: frozenset({ResourceState.QUARANTINED, ResourceState.ESCALATED}),
    ResourceState.ESCALATED: frozenset({ResourceState.QUARANTINED}),
}

TERMINAL_STATES = frozenset({ResourceState.HEALTHY, ResourceState.ESCALATED})
ISOLATED_STATES = frozenset(
    {
        ResourceState.QUARANTINED,
        ResourceState.RESTORING,
        ResourceState.VALIDATING,
        ResourceState.RECOVERED,
        ResourceState.FAILED,
        ResourceState.ESCALATED,
    }
)


def can_transition(current: ResourceState, target: ResourceState) -> bool:
    return target in ALLOWED_TRANSITIONS.get(current, frozenset())


def assert_transition(current: ResourceState, target: ResourceState) -> None:
    if not can_transition(current, target):
        raise StateConflict(
            f"illegal state transition {current.value} -> {target.value}",
            detail={"from": current.value, "to": target.value},
        )


def is_isolated(state: ResourceState) -> bool:
    return state in ISOLATED_STATES
