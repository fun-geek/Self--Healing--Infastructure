"""Structured JSON logging with correlation IDs and secret redaction."""

from __future__ import annotations

import json
import logging
import sys
import uuid
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

_correlation_id: ContextVar[str | None] = ContextVar("correlation_id", default=None)

_SENSITIVE_KEYS = {
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "api_key",
    "apikey",
    "jwt",
    "cookie",
    "set-cookie",
    "private_key",
    "credential",
    "credentials",
    "session",
}
_REDACTED = "[REDACTED]"


def new_correlation_id() -> str:
    value = uuid.uuid4().hex
    _correlation_id.set(value)
    return value


def set_correlation_id(value: str | None) -> None:
    _correlation_id.set(value)


def get_correlation_id() -> str:
    current = _correlation_id.get()
    if current is None:
        current = new_correlation_id()
    return current


def _redact(value: Any, depth: int = 0) -> Any:
    if depth > 6:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        return {
            str(key): (_REDACTED if str(key).lower() in _SENSITIVE_KEYS else _redact(val, depth + 1))
            for key, val in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact(item, depth + 1) for item in value[:100]]
    if isinstance(value, str) and len(value) > 2000:
        return value[:2000] + "...[truncated]"
    return value


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": get_correlation_id(),
        }
        extra = getattr(record, "extra_fields", None)
        if isinstance(extra, dict):
            payload.update(_redact(extra))
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, separators=(",", ":"))


def configure_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    if any(isinstance(handler.formatter, JsonFormatter) for handler in root.handlers):
        root.setLevel(level.upper())
        return
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(JsonFormatter())
    root.handlers = [handler]
    root.setLevel(level.upper())
    # Access logs are emitted by uvicorn in its own format; keep JSON consistency.
    for noisy in ("uvicorn.access", "httpcore", "httpx"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def log_event(logger: logging.Logger, level: int, message: str, **fields: Any) -> None:
    logger.log(level, message, extra={"extra_fields": _redact(fields)})
