"""Deterministic projection of telemetry events into current resource state.

Events are replayed in ``(timestamp, event_id)`` order. Snapshots replace whole
fields; delta events merge by stable key. Evidence provenance (event IDs) is
tracked per field so findings are explainable.
"""

from __future__ import annotations

from collections.abc import Iterable

from sentinel.models.baseline import Baseline
from sentinel.models.events import Event, ObservedPort, ObservedProcess
from sentinel.models.state import ObservedResource

_HINT_LABELS = {"threat_hint", "severity_hint", "verdict", "priority", "action"}
_MAX_EVIDENCE_PER_FIELD = 64
_MAX_NOTES = 32


def project_resources(
    events: Iterable[Event], baseline: Baseline
) -> dict[str, ObservedResource]:
    ordered = sorted(events, key=lambda event: (event.timestamp, event.event_id))
    projected: dict[str, ObservedResource] = {}

    for event in ordered:
        if baseline.resource(event.resource_id) is None:
            continue
        state = projected.get(event.resource_id)
        if state is None:
            state = ObservedResource(
                resource_id=event.resource_id,
                resource_type=event.resource_type,
            )
            projected[event.resource_id] = state

        observation = event.observation
        state.resource_type = event.resource_type
        state.last_event_at = event.timestamp
        if event.event_id not in state.event_ids:
            state.event_ids.append(event.event_id)
            state.event_ids = state.event_ids[-512:]

        if event.event_type == "telemetry_snapshot":
            if observation.image is not None:
                state.image = observation.image
                _evidence(state, "image", event.event_id)
            if observation.config_hash is not None:
                state.config_hash = observation.config_hash
                _evidence(state, "config_hash", event.event_id)
            if observation.processes is not None:
                state.processes = list(observation.processes)
                _evidence(state, "processes", event.event_id)
            if observation.ports is not None:
                state.ports = list(observation.ports)
                _evidence(state, "ports", event.event_id)
            if observation.health is not None:
                state.health = observation.health
                _evidence(state, "health", event.event_id)
        elif event.event_type == "process_observed":
            for process in observation.processes or []:
                _upsert_process(state, process)
            _evidence(state, "processes", event.event_id)
        elif event.event_type == "port_observed":
            for port in observation.ports or []:
                _upsert_port(state, port)
            _evidence(state, "ports", event.event_id)
        elif event.event_type == "image_report":
            if observation.image is not None:
                state.image = observation.image
                _evidence(state, "image", event.event_id)
        elif event.event_type == "health_check":
            if observation.health is not None:
                state.health = observation.health
                _evidence(state, "health", event.event_id)
        elif event.event_type == "config_change":
            if observation.config_hash is not None:
                state.config_hash = observation.config_hash
                _evidence(state, "config_hash", event.event_id)

        for key, value in event.labels.items():
            if key.lower() in _HINT_LABELS:
                hint = f"{key}={_sanitize(value, 200)}"
                if hint not in state.untrusted_hints:
                    state.untrusted_hints.append(hint)
                    state.untrusted_hints = state.untrusted_hints[-16:]
        if event.notes and len(state.untrusted_notes) < _MAX_NOTES:
            state.untrusted_notes.append(_sanitize(event.notes, 500))

    return projected


def _evidence(state: ObservedResource, field_name: str, event_id: str) -> None:
    current = state.field_evidence.setdefault(field_name, [])
    if event_id not in current:
        current.append(event_id)
        del current[:-_MAX_EVIDENCE_PER_FIELD]


def _upsert_process(state: ObservedResource, process: ObservedProcess) -> None:
    for index, existing in enumerate(state.processes):
        if existing.pid == process.pid:
            state.processes[index] = process
            return
    state.processes.append(process)


def _upsert_port(state: ObservedResource, port: ObservedPort) -> None:
    for index, existing in enumerate(state.ports):
        if existing.port == port.port and existing.protocol == port.protocol:
            state.ports[index] = port
            return
    state.ports.append(port)


def _sanitize(value: str, limit: int) -> str:
    printable = "".join(character if character.isprintable() else " " for character in value)
    return " ".join(printable.split())[:limit]
