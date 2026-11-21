"""Prompt-injection and secret-leak guardrails.

Untrusted content (telemetry notes, process command lines, retrieved documents) is
scanned before it can enter an LLM prompt. Flagged content is excluded and the
event is recorded. This is defence-in-depth; authorization never depends on the
LLM, so a successful injection still cannot grant tool permissions.
"""

from __future__ import annotations

import re

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ignore_instructions", re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", re.I)),
    ("system_override", re.compile(r"system\s+override", re.I)),
    ("role_hijack", re.compile(r"\byou\s+are\s+now\b|\bdeveloper\s+mode\b|\bjailbreak\b", re.I)),
    ("tool_execution", re.compile(r"\b(execute|run|invoke)\b[^\n]{0,40}\b(shell|command|tool|bash)\b", re.I)),
    ("disable_controls", re.compile(r"disable\s+(telemetry|logging|audit)|bypass\s+(policy|approval)", re.I)),
    ("approval_bypass", re.compile(r"do\s+not\s+(ask|require)\s+(for\s+)?approval|auto[-\s]?approve", re.I)),
    ("exfiltration", re.compile(r"(curl|wget)\s+https?://|base64\s+-d\s*\|\s*sh|/dev/tcp/", re.I)),
    ("prompt_leak", re.compile(r"(reveal|print|show)\s+(the\s+)?(system\s+prompt|instructions)", re.I)),
    ("finding_tamper", re.compile(r"mark\s+(all\s+)?findings?\s+(as\s+)?resolved", re.I)),
    ("destructive", re.compile(r"rm\s+-rf\s+/|format\s+c:|drop\s+table", re.I)),
]

_SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*\S+"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._-]{16,}"),
]

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def scan_text(text: str) -> list[str]:
    if not text:
        return []
    return sorted({label for label, pattern in _PATTERNS if pattern.search(text)})


def redact_secrets(text: str) -> str:
    redacted = text
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def sanitize(text: str, limit: int = 2000) -> str:
    if not text:
        return ""
    cleaned = _CONTROL.sub(" ", text)
    cleaned = redact_secrets(cleaned)
    cleaned = " ".join(cleaned.split())
    return cleaned[:limit]


def fence(label: str, text: str, nonce: str) -> str:
    return (
        f"<untrusted-{label} nonce=\"{nonce}\">\n"
        f"{sanitize(text, 4000)}\n"
        f"</untrusted-{label} nonce=\"{nonce}\">"
    )


def safe_for_prompt(text: str, *, limit: int = 2000) -> tuple[str, list[str]]:
    """Return (safe_text, flags). Flagged text is replaced, never partially trusted."""
    flags = scan_text(text)
    if flags:
        return f"[BLOCKED UNTRUSTED CONTENT: {', '.join(flags)}]", flags
    return sanitize(text, limit), []
