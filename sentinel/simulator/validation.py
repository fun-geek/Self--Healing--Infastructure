"""Validation checks executed against a restored resource.

Every check is pure and deterministic. The service probe is explicitly labelled
as simulated: the platform never claims a real HTTP request was made.
"""

from __future__ import annotations

import json

from sentinel.models.baseline import ResourceBaseline, ValidationRule
from sentinel.models.state import ObservedResource


def _fmt(value: object) -> str:
    return json.dumps(value, sort_keys=True, default=str)[:2000]


def check_rule(
    rule: ValidationRule,
    baseline_resource: ResourceBaseline,
    observed: ObservedResource | None,
) -> tuple[bool, str, str | None, str | None]:
    if observed is None:
        return False, "no observed state available", None, rule.check

    if rule.check == "image_digest":
        image = observed.image
        expected = baseline_resource.approved_image
        if image is None:
            return False, "image telemetry missing", None, expected.digest
        reference_ok = image.reference == expected.reference
        digest_ok = image.digest == expected.digest
        if rule.params.get("require_approved_reference", True) and not reference_ok:
            return (
                False,
                f"image reference {image.reference} is not approved ({expected.reference})",
                f"{image.reference}:{image.tag} {image.digest}",
                f"{expected.reference}:{expected.tag} {expected.digest}",
            )
        if not digest_ok:
            return (
                False,
                f"image digest {image.digest} does not match approved digest {expected.digest}",
                image.digest,
                expected.digest,
            )
        return True, "image digest and reference match the approved baseline", image.digest, expected.digest

    if rule.check == "config_hash":
        expected = baseline_resource.config_hash
        if observed.config_hash is None:
            return False, "configuration hash missing", None, expected
        if observed.config_hash != expected:
            return (
                False,
                "configuration hash does not match the approved baseline",
                observed.config_hash,
                expected,
            )
        return True, "configuration hash matches the approved baseline", observed.config_hash, expected

    if rule.check == "ports":
        approved = baseline_resource.approved_port_keys
        observed_ports = [
            (port.port, port.protocol) for port in observed.listening_ports()
        ]
        unapproved = [item for item in observed_ports if item not in approved]
        if unapproved:
            return (
                False,
                "unapproved listening ports present: "
                + ", ".join(f"{port}/{protocol}" for port, protocol in unapproved),
                _fmt(observed_ports),
                _fmt(sorted(approved)),
            )
        return True, "all listening ports are approved", _fmt(observed_ports), _fmt(sorted(approved))

    if rule.check == "processes":
        approved_names = baseline_resource.approved_process_names
        approved_exec = baseline_resource.approved_executables
        approved_users: dict[str, set[str]] = {}
        for process in baseline_resource.approved_processes:
            approved_users.setdefault(process.name, set()).add(process.user)
        forbidden = list(rule.params.get("forbidden_prefixes", []))
        deny_masquerade = bool(rule.params.get("deny_masquerade", False))

        problems: list[str] = []
        for process in observed.processes:
            normalized = process.executable.replace("\\", "/")
            if any(normalized.startswith(prefix) for prefix in forbidden):
                problems.append(
                    f"{process.name} (pid {process.pid}) executes from forbidden path {process.executable}"
                )
            if process.name not in approved_names:
                problems.append(f"{process.name} (pid {process.pid}) is not approved")
                continue
            if deny_masquerade:
                expected_executable = approved_exec.get(process.name)
                if expected_executable and process.executable != expected_executable:
                    problems.append(
                        f"{process.name} runs from {process.executable}, expected {expected_executable}"
                    )
                allowed_users = approved_users.get(process.name, set())
                if allowed_users and process.user not in allowed_users:
                    problems.append(
                        f"{process.name} runs as {process.user}, expected one of {sorted(allowed_users)}"
                    )
        if problems:
            return (
                False,
                "; ".join(problems[:10]),
                _fmt([process.model_dump(mode="json") for process in observed.processes]),
                _fmt(
                    [process.model_dump(mode="json") for process in baseline_resource.approved_processes]
                ),
            )
        return True, "process table matches the approved baseline", None, None

    if rule.check == "health":
        health = observed.health
        if health is None:
            return False, "health telemetry missing", None, "passing"
        require_status = str(rule.params.get("require_status", "passing"))
        max_failures = int(rule.params.get("max_consecutive_failures", 0))
        if health.status != require_status or health.consecutive_failures > max_failures:
            return (
                False,
                f"health is {health.status} with {health.consecutive_failures} consecutive failures",
                _fmt(health.model_dump(mode="json")),
                f"{require_status} with <= {max_failures} failures",
            )
        return True, "health check is passing", health.status, require_status

    if rule.check == "service_probe":
        image_ok = observed.image is not None and (
            observed.image.digest == baseline_resource.approved_image.digest
        )
        config_ok = observed.config_hash == baseline_resource.config_hash
        health_ok = observed.health is not None and observed.health.status == "passing"
        path = str(rule.params.get("path", "/healthz"))
        expected_status = int(rule.params.get("expected_status", 200))
        if image_ok and config_ok and health_ok:
            return (
                True,
                f"simulated probe {path} returned {expected_status}",
                str(expected_status),
                str(expected_status),
            )
        return (
            False,
            f"simulated probe {path} returned 503 (image/config/health integrity failed)",
            "503",
            str(expected_status),
        )

    return False, f"unknown validation check {rule.check}", None, None
