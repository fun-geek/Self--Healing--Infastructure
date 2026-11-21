"""Typed error hierarchy.

Every error carries a stable machine code and a message that is safe to return to
an API client. Internal detail is attached separately and never includes secrets.
"""

from __future__ import annotations

from typing import Any


class SentinelError(Exception):
    """Base class for all expected application errors."""

    code = "sentinel_error"
    http_status = 500

    def __init__(self, message: str, *, detail: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail or {}

    def to_public(self) -> dict[str, Any]:
        return {"error": self.code, "message": self.message}


class ConfigError(SentinelError):
    code = "configuration_error"
    http_status = 500


class SimulationOnlyViolation(ConfigError):
    code = "simulation_only_violation"


class DatasetError(SentinelError):
    code = "dataset_error"
    http_status = 422


class BaselineIntegrityError(DatasetError):
    code = "baseline_integrity_error"


class SchemaValidationError(DatasetError):
    code = "schema_validation_error"


class DetectionError(SentinelError):
    code = "detection_error"


class PolicyDenied(SentinelError):
    code = "policy_denied"
    http_status = 403


class ActionNotPermitted(PolicyDenied):
    code = "action_not_permitted"


class ApprovalRequired(PolicyDenied):
    code = "approval_required"


class StateConflict(SentinelError):
    code = "state_conflict"
    http_status = 409


class ResourceNotFound(SentinelError):
    code = "resource_not_found"
    http_status = 404


class AuthenticationError(SentinelError):
    code = "authentication_failed"
    http_status = 401


class AuthorizationError(SentinelError):
    code = "authorization_failed"
    http_status = 403


class RateLimited(SentinelError):
    code = "rate_limited"
    http_status = 429


class AgentUnavailable(SentinelError):
    code = "agent_unavailable"
    http_status = 503


class ToolDenied(PolicyDenied):
    code = "tool_denied"
