"""Local infrastructure simulator.

This is the **only** execution backend. It maintains resource state in SQLite and
simulates load-balancer membership, network isolation, baseline restoration and
validation. It never contacts a hypervisor, container runtime or cloud API.

Fault injection exists solely to prove fail-closed behaviour during demonstrations
and tests. It is loaded from a separate simulator-only file and cannot be changed
through the API.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from pathlib import Path

from sentinel.errors import DatasetError, ResourceNotFound
from sentinel.models.baseline import Baseline, ResourceBaseline
from sentinel.models.common import canonical_json, ensure_utc, iso, sha256_hex, utcnow
from sentinel.models.events import (
    Event,
    HealthStatus,
    Observation,
    ObservedImage,
    ObservedPort,
    ObservedProcess,
)
from sentinel.models.state import ObservedResource, ResourceView
from sentinel.models.actions import ValidationResult
from sentinel.observability.logging import get_logger
from sentinel.persistence.audit import AuditRepository
from sentinel.persistence.db import Database
from sentinel.persistence.repositories import (
    EventRepository,
    ResourceRepository,
    ValidationRepository,
)
from sentinel.simulator.validation import check_rule

_log = get_logger(__name__)

EXECUTION_BACKEND = "simulator"


class FaultProfile:
    def __init__(self, faults: dict[str, dict[str, object]]) -> None:
        self._faults = faults

    @classmethod
    def load(cls, path: Path) -> FaultProfile:
        if not path.exists():
            return cls({})
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            faults: dict[str, dict[str, object]] = {}
            for entry in payload.get("faults", []):
                resource_id = str(entry["resource_id"])
                faults[resource_id] = {
                    "fault": str(entry["fault"]),
                    "applies_to": str(entry.get("applies_to", "restore")),
                }
            return cls(faults)
        except (OSError, KeyError, TypeError, ValueError) as exc:
            raise DatasetError("simulator fault profile is invalid") from exc

    def for_action(self, resource_id: str, action: str) -> str | None:
        entry = self._faults.get(resource_id)
        if entry is None or entry["applies_to"] != action:
            return None
        return str(entry["fault"])


class SimulatorBackend:
    def __init__(
        self,
        *,
        db: Database,
        baseline: Baseline,
        resources: ResourceRepository,
        validations: ValidationRepository,
        events: EventRepository,
        audit: AuditRepository,
        faults_path: Path,
    ) -> None:
        self.db = db
        self.baseline = baseline
        self.resources = resources
        self.validations = validations
        self.events = events
        self.audit = audit
        self.faults = FaultProfile.load(faults_path)

    # -- reads ------------------------------------------------------------
    def inspect(self, resource_id: str) -> ResourceView:
        resource = self.resources.get(resource_id)
        if resource is None:
            raise ResourceNotFound(resource_id)
        return resource

    # -- operations -------------------------------------------------------
    def drain(
        self, conn, resource_id: str, *, actor: str, job_id: str | None
    ) -> dict[str, object]:
        self.resources.set_load_balancer(conn, resource_id, False, actor=actor, job_id=job_id)
        return {"in_load_balancer": False, "simulated": True}

    def quarantine(
        self, conn, resource_id: str, *, actor: str, job_id: str | None
    ) -> dict[str, object]:
        resource = self.resources.get(resource_id)
        if resource is None:
            raise ResourceNotFound(resource_id)
        if resource.in_load_balancer:
            raise RuntimeError("refusing to quarantine a resource still attached to the load balancer")
        return {
            "network_isolated": True,
            "evidence_preserved": True,
            "observed_state_retained": resource.observed is not None,
            "simulated": True,
        }

    def restore(
        self,
        conn,
        resource_id: str,
        *,
        actor: str,
        job_id: str | None,
        clock: datetime,
    ) -> dict[str, object]:
        resource_baseline = self.baseline.resource(resource_id)
        if resource_baseline is None:
            raise RuntimeError("approved baseline missing; refusing to restore")
        observed = self._baseline_observation(resource_baseline, clock)
        fault = self.faults.for_action(resource_id, "restore")
        fault_applied: str | None = None
        if fault == "image_digest_poisoned":
            assert observed.image is not None
            observed.image = observed.image.model_copy(
                update={"digest": "sha256:" + sha256_hex(f"poisoned-artifact:{resource_id}")}
            )
            fault_applied = fault
        elif fault == "health_probe_failed":
            observed.health = HealthStatus(
                status="failing",
                consecutive_failures=3,
                last_check_at=clock,
                detail="injected probe failure",
            )
            fault_applied = fault

        event = self._append_event(conn, resource_baseline, observed, clock)
        observed.event_ids = [event.event_id]
        observed.field_evidence = {
            "image": [event.event_id],
            "config_hash": [event.event_id],
            "processes": [event.event_id],
            "ports": [event.event_id],
            "health": [event.event_id],
        }
        observed.last_event_at = clock
        self.resources.set_observed(conn, resource_id, observed, None)
        self.audit.append(
            conn,
            actor=actor,
            action="SIMULATOR_RESTORE_FROM_BASELINE",
            result="success",
            resource_id=resource_id,
            job_id=job_id,
            correlation_id="",
            details={
                "image_digest": observed.image.digest if observed.image else None,
                "config_hash": observed.config_hash,
                "fault_applied": fault_applied,
                "source": "approved_baseline",
                "simulated": True,
            },
        )
        return {
            "image_digest": observed.image.digest if observed.image else None,
            "image_reference": observed.image.reference if observed.image else None,
            "config_hash": observed.config_hash,
            "ports": [f"{port.port}/{port.protocol}" for port in observed.ports],
            "process_count": len(observed.processes),
            "fault_applied": fault_applied,
            "source": "approved_baseline",
            "simulated": True,
        }

    def validate(
        self,
        conn,
        resource_id: str,
        *,
        job_id: str,
        attempt: int,
        clock: datetime,
    ) -> list[ValidationResult]:
        resource_baseline = self.baseline.resource(resource_id)
        if resource_baseline is None:
            raise RuntimeError("approved baseline missing; cannot validate")
        resource = self.resources.get(resource_id)
        observed = resource.observed if resource else None
        results: list[ValidationResult] = []
        for rule_id in resource_baseline.validation_rule_ids:
            rule = self.baseline.validation_rules[rule_id]
            try:
                passed, detail, observed_value, expected_value = check_rule(
                    rule, resource_baseline, observed
                )
            except Exception:
                passed, detail, observed_value, expected_value = (
                    False,
                    "validation check raised an error (fail-closed)",
                    None,
                    None,
                )
            results.append(
                ValidationResult(
                    validation_id=f"val-{uuid.uuid4().hex}",
                    job_id=job_id,
                    resource_id=resource_id,
                    rule_id=rule_id,
                    passed=passed,
                    mandatory=rule.mandatory,
                    attempt=attempt,
                    detail=detail[:1000],
                    observed=observed_value[:1000] if observed_value else None,
                    expected=expected_value[:1000] if expected_value else None,
                    checked_at=clock,
                )
            )
        self.validations.insert_many(conn, results)
        self.audit.append(
            conn,
            actor="sentinel-orchestrator",
            action="SIMULATOR_VALIDATION",
            result="success" if all(item.passed for item in results if item.mandatory) else "failure",
            resource_id=resource_id,
            job_id=job_id,
            correlation_id="",
            details={
                "passed": [item.rule_id for item in results if item.passed],
                "failed": [item.rule_id for item in results if not item.passed],
                "simulated": True,
            },
        )
        return results

    def return_to_service(
        self, conn, resource_id: str, *, actor: str, job_id: str | None
    ) -> dict[str, object]:
        self.resources.set_load_balancer(conn, resource_id, True, actor=actor, job_id=job_id)
        return {"in_load_balancer": True, "serving_traffic": True, "simulated": True}

    # -- helpers ----------------------------------------------------------
    def _baseline_observation(
        self, resource: ResourceBaseline, clock: datetime
    ) -> ObservedResource:
        process_name = resource.approved_processes[0].name
        return ObservedResource(
            resource_id=resource.resource_id,
            resource_type=resource.kind,
            image=ObservedImage(
                reference=resource.approved_image.reference,
                tag=resource.approved_image.tag,
                digest=resource.approved_image.digest,
                pulled_at=clock,
            ),
            config_hash=resource.config_hash,
            processes=[
                ObservedProcess(
                    name=process.name,
                    pid=3000 + index,
                    executable=process.executable,
                    user=process.user,
                    started_at=clock,
                )
                for index, process in enumerate(resource.approved_processes)
            ],
            ports=[
                ObservedPort(
                    port=port.port,
                    protocol=port.protocol,
                    state="listening",
                    bound_process=process_name,
                    bound_pid=3000,
                )
                for port in resource.approved_ports
            ],
            health=HealthStatus(
                status="passing",
                consecutive_failures=0,
                last_check_at=clock,
                detail="restored from approved baseline",
            ),
            last_event_at=clock,
        )

    def _append_event(
        self,
        conn,
        resource: ResourceBaseline,
        observed: ObservedResource,
        clock: datetime,
    ) -> Event:
        event = Event(
            event_id=f"evt-sim-{uuid.uuid4().hex}",
            timestamp=ensure_utc(clock),
            resource_id=resource.resource_id,
            resource_type=resource.kind,
            source="simulator",
            event_type="telemetry_snapshot",
            observation=Observation(
                image=observed.image,
                config_hash=observed.config_hash,
                processes=observed.processes,
                ports=observed.ports,
                health=observed.health,
            ),
            labels={"simulated": "true"},
            notes="Post-restore telemetry produced by the local simulator.",
        )
        payload = event.model_dump(mode="json")
        fingerprint = sha256_hex(canonical_json(payload))
        self.events.insert_accepted(
            conn,
            [(event, fingerprint, "simulator", sha256_hex(canonical_json({"simulator": True})), 0)],
            ingested_at=iso(utcnow()),
        )
        return event
