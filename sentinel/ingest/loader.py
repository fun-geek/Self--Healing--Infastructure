"""Dataset loading, integrity verification and telemetry normalisation."""

from __future__ import annotations

import json
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd
from pydantic import ValidationError

from sentinel.errors import BaselineIntegrityError, DatasetError
from sentinel.models.baseline import Baseline
from sentinel.models.common import canonical_json, ensure_utc, sha256_hex, utcnow
from sentinel.models.events import Event
from sentinel.observability.logging import get_logger
from sentinel.persistence.db import Database
from sentinel.persistence.repositories import EventRepository

_log = get_logger(__name__)

CATALOGUE_COLUMNS = [
    "action_id",
    "action",
    "description",
    "allowed_from_states",
    "requires_approval",
    "approval_role",
    "required_role",
    "preconditions",
    "expected_result",
    "max_retries",
    "timeout_seconds",
    "reversible",
    "automatable",
    "state_change",
    "notes",
]


@dataclass(frozen=True)
class DatasetManifest:
    schema_version: str
    generator_version: str
    seed: int
    generated_at: datetime
    as_of: datetime
    baseline_id: str
    baseline_version: int
    files: dict[str, str]


@dataclass(frozen=True)
class VerifiedDataset:
    baseline: Baseline
    manifest: DatasetManifest | None
    baseline_sha256: str
    baseline_path: Path
    events_path: Path
    catalogue_path: Path


@dataclass
class RejectedRecord:
    record_index: int
    error_code: str
    reason: str
    event_id: str | None = None
    resource_id: str | None = None


@dataclass
class DuplicateRecord:
    event_id: str
    duplicate_of: str
    reason: str


@dataclass
class IngestionResult:
    run_id: str
    source_file: str
    source_sha256: str
    as_of: datetime
    accepted: list[str] = field(default_factory=list)
    rejected: list[RejectedRecord] = field(default_factory=list)
    duplicates: list[DuplicateRecord] = field(default_factory=list)

    @property
    def accepted_count(self) -> int:
        return len(self.accepted)

    @property
    def rejected_count(self) -> int:
        return len(self.rejected)

    @property
    def duplicate_count(self) -> int:
        return len(self.duplicates)


def _sha256_file(path: Path) -> str:
    return sha256_hex(path.read_bytes())


def _read_manifest(path: Path) -> DatasetManifest:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return DatasetManifest(
            schema_version=payload["schema_version"],
            generator_version=payload["generator_version"],
            seed=int(payload["seed"]),
            generated_at=payload["generated_at"],
            as_of=payload["as_of"],
            baseline_id=payload["baseline_id"],
            baseline_version=int(payload["baseline_version"]),
            files=dict(payload["files"]),
        )
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise DatasetError(f"dataset manifest is unreadable: {path.name}") from exc


def load_verified_dataset(
    data_dir: Path,
    *,
    strict: bool = True,
    cache: BaselineCache | None = None,
) -> VerifiedDataset:
    raw_dir = data_dir / "raw"
    baseline_path = raw_dir / "approved_baseline.json"
    events_path = raw_dir / "infrastructure_events.json"
    catalogue_path = raw_dir / "action_catalogue.csv"
    manifest_path = raw_dir / "manifest.json"

    for path in (baseline_path, events_path, catalogue_path):
        if not path.exists():
            raise DatasetError(f"required dataset is missing: {path}")

    manifest: DatasetManifest | None = None
    if manifest_path.exists():
        manifest = _read_manifest(manifest_path)
    elif strict:
        raise BaselineIntegrityError("dataset manifest is missing; refusing to trust the baseline")

    baseline_sha = _sha256_file(baseline_path)
    if manifest is not None:
        expected = manifest.files.get(baseline_path.name)
        if strict and expected != baseline_sha:
            raise BaselineIntegrityError(
                "approved baseline hash does not match the signed manifest",
                detail={"expected": expected, "actual": baseline_sha},
            )
        for path in (events_path, catalogue_path):
            expected = manifest.files.get(path.name)
            actual = _sha256_file(path)
            if expected is not None and expected != actual:
                raise DatasetIntegrityMismatch(path.name) if strict else None

    if cache is not None:
        cached = cache.get(baseline_sha)
        if cached is not None:
            return VerifiedDataset(
                baseline=cached,
                manifest=manifest,
                baseline_sha256=baseline_sha,
                baseline_path=baseline_path,
                events_path=events_path,
                catalogue_path=catalogue_path,
            )

    try:
        payload = json.loads(baseline_path.read_text(encoding="utf-8"))
        baseline = Baseline.model_validate(payload)
    except (OSError, json.JSONDecodeError) as exc:
        raise DatasetError("approved baseline is not valid JSON") from exc
    except ValidationError as exc:
        raise BaselineIntegrityError("approved baseline failed schema validation") from exc

    if manifest is not None:
        if baseline.baseline_id != manifest.baseline_id:
            raise BaselineIntegrityError("baseline_id does not match manifest")
        if baseline.version != manifest.baseline_version:
            raise BaselineIntegrityError("baseline version does not match manifest")
        if ensure_utc(baseline.as_of) != ensure_utc(manifest.as_of):
            raise BaselineIntegrityError("baseline as_of does not match manifest")

    if cache is not None:
        cache.put(baseline_sha, baseline)

    return VerifiedDataset(
        baseline=baseline,
        manifest=manifest,
        baseline_sha256=baseline_sha,
        baseline_path=baseline_path,
        events_path=events_path,
        catalogue_path=catalogue_path,
    )


class DatasetIntegrityMismatch(BaselineIntegrityError):
    def __init__(self, filename: str) -> None:
        super().__init__(f"dataset {filename} does not match the signed manifest")


class BaselineCache:
    """Immutable baseline cache keyed by file hash (thread-safe)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._values: dict[str, Baseline] = {}

    def get(self, sha256: str) -> Baseline | None:
        with self._lock:
            return self._values.get(sha256)

    def put(self, sha256: str, baseline: Baseline) -> None:
        with self._lock:
            self._values[sha256] = baseline

    def clear(self) -> None:
        with self._lock:
            self._values.clear()


def load_catalogue(path: Path, *, strict: bool = True) -> Any:
    from sentinel.models.actions import ActionCatalogue, ActionSpec
    from sentinel.models.common import ResourceState, Role

    try:
        frame = pd.read_csv(
            path,
            dtype=str,
            keep_default_na=False,
            na_filter=False,
            quotechar='"',
        )
    except Exception as exc:  # pandas raises various parser errors
        raise DatasetError("action catalogue is not readable CSV") from exc

    missing = [column for column in CATALOGUE_COLUMNS if column not in frame.columns]
    extra = [column for column in frame.columns if column not in CATALOGUE_COLUMNS]
    if missing or extra:
        raise DatasetError(
            "action catalogue schema mismatch",
            detail={"missing": missing, "unexpected": extra},
        )
    if frame.empty:
        raise DatasetError("action catalogue is empty")

    actions: dict[str, ActionSpec] = {}

    def parse_bool(value: str, field_name: str) -> bool:
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes"}:
            return True
        if lowered in {"false", "0", "no"}:
            return False
        raise DatasetError(f"invalid boolean {value!r} in column {field_name}")

    for index, row in frame.iterrows():
        try:
            states = [ResourceState(item.strip()) for item in row["allowed_from_states"].split("|") if item.strip()]
            approval_role_raw = row["approval_role"].strip()
            state_change_raw = row["state_change"].strip()
            spec = ActionSpec(
                action_id=row["action_id"].strip(),
                action=row["action"].strip(),
                description=row["description"].strip(),
                allowed_from_states=states,
                requires_approval=parse_bool(row["requires_approval"], "requires_approval"),
                approval_role=Role(approval_role_raw) if approval_role_raw else None,
                required_role=Role(row["required_role"].strip()),
                preconditions=[
                    item.strip()
                    for item in row["preconditions"].split(";")
                    if item.strip()
                ],
                expected_result=row["expected_result"].strip(),
                max_retries=int(row["max_retries"]),
                timeout_seconds=int(row["timeout_seconds"]),
                reversible=parse_bool(row["reversible"], "reversible"),
                automatable=parse_bool(row["automatable"], "automatable"),
                state_change=ResourceState(state_change_raw) if state_change_raw else None,
                notes=row["notes"].strip(),
            )
        except (ValueError, ValidationError) as exc:
            raise DatasetError(f"action catalogue row {index + 2} is invalid") from exc
        if spec.action_id in actions:
            raise DatasetError(f"duplicate action_id {spec.action_id}")
        actions[spec.action_id] = spec

    return ActionCatalogue(actions=actions, source_sha256=_sha256_file(path))


def ingest_events(
    db: Database,
    baseline: Baseline,
    events_path: Path,
    *,
    as_of: datetime,
    source_sha256: str,
    repository: EventRepository | None = None,
) -> IngestionResult:
    """Validate, deduplicate and persist telemetry.

    Malformed, orphaned, inconsistent and future-dated records are quarantined
    with an auditable reason; they never reach detection.
    """
    repo = repository or EventRepository(db)
    run_id = f"ing-{uuid.uuid4().hex}"
    repo.start_run(run_id, events_path.name, source_sha256)
    try:
        document = json.loads(events_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        repo.finish_run(run_id, accepted=0, rejected=0, duplicates=0, status="FAILED", error="unreadable JSON")
        raise DatasetError("infrastructure events file is not valid JSON") from exc

    if isinstance(document, dict):
        raw_events = document.get("events")
        if not isinstance(raw_events, list):
            repo.finish_run(run_id, accepted=0, rejected=0, duplicates=0, status="FAILED", error="missing events array")
            raise DatasetError("events document must contain an events array")
        doc_as_of = ensure_utc(datetime.fromisoformat(str(document.get("as_of", as_of)).replace("Z", "+00:00")))
    elif isinstance(document, list):
        raw_events = document
        doc_as_of = ensure_utc(as_of)
    else:
        repo.finish_run(run_id, accepted=0, rejected=0, duplicates=0, status="FAILED", error="unsupported document")
        raise DatasetError("events document must be a JSON array or object")

    result = IngestionResult(
        run_id=run_id,
        source_file=events_path.name,
        source_sha256=source_sha256,
        as_of=doc_as_of,
    )

    seen_ids = repo.known_event_ids()
    seen_fingerprints = {fp: eid for fp, eid in _fingerprint_index(repo)}
    accepted_rows: list[tuple[Event, str, str, str, int]] = []

    for index, raw in enumerate(raw_events):
        if not isinstance(raw, dict):
            result.rejected.append(
                RejectedRecord(index, "NOT_AN_OBJECT", "record is not a JSON object")
            )
            continue
        event_id = str(raw.get("event_id") or "")[:96] or None
        resource_id = str(raw.get("resource_id") or "")[:64] or None
        try:
            event = Event.model_validate(raw)
        except ValidationError as exc:
            reason = "; ".join(
                f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
                for error in exc.errors()[:3]
            )
            result.rejected.append(
                RejectedRecord(index, "SCHEMA_INVALID", reason, event_id, resource_id)
            )
            continue

        resource = baseline.resource(event.resource_id)
        if resource is None:
            result.rejected.append(
                RejectedRecord(
                    index,
                    "ORPHAN_RESOURCE",
                    f"resource {event.resource_id} is not present in the approved baseline",
                    event.event_id,
                    event.resource_id,
                )
            )
            continue
        if resource.kind is not event.resource_type:
            result.rejected.append(
                RejectedRecord(
                    index,
                    "RESOURCE_TYPE_MISMATCH",
                    f"event type {event.resource_type.value} != baseline kind {resource.kind.value}",
                    event.event_id,
                    event.resource_id,
                )
            )
            continue
        if ensure_utc(event.timestamp) > doc_as_of:
            result.rejected.append(
                RejectedRecord(
                    index,
                    "FUTURE_EVENT",
                    "event timestamp is newer than the dataset as_of",
                    event.event_id,
                    event.resource_id,
                )
            )
            continue
        inconsistency = _observation_inconsistency(event)
        if inconsistency:
            result.rejected.append(
                RejectedRecord(
                    index, "INCONSISTENT_OBSERVATION", inconsistency, event.event_id, event.resource_id
                )
            )
            continue

        fingerprint = sha256_hex(canonical_json(event.model_dump(mode="json")))
        if event.event_id in seen_ids:
            result.duplicates.append(
                DuplicateRecord(event.event_id, event.event_id, "duplicate event_id")
            )
            continue
        if fingerprint in seen_fingerprints:
            result.duplicates.append(
                DuplicateRecord(
                    event.event_id, seen_fingerprints[fingerprint], "identical payload fingerprint"
                )
            )
            continue
        seen_ids.add(event.event_id)
        seen_fingerprints[fingerprint] = event.event_id
        accepted_rows.append(
            (event, fingerprint, events_path.name, source_sha256, index)
        )
        result.accepted.append(event.event_id)

    ingested_at = utcnow().isoformat()
    with db.tx() as conn:
        repo.insert_accepted(conn, accepted_rows, ingested_at=ingested_at)
        for duplicate in result.duplicates:
            repo.insert_duplicate(
                conn,
                run_id=run_id,
                event_id=duplicate.event_id,
                duplicate_of=duplicate.duplicate_of,
                fingerprint=sha256_hex(canonical_json({"event_id": duplicate.event_id})),
            )
        for rejected in result.rejected:
            repo.insert_reject(
                conn,
                run_id=run_id,
                source_file=events_path.name,
                record_index=rejected.record_index,
                event_id=rejected.event_id,
                resource_id=rejected.resource_id,
                error_code=rejected.error_code,
                reason=rejected.reason,
                raw_sha256=sha256_hex(
                    canonical_json(
                        {
                            "index": rejected.record_index,
                            "event_id": rejected.event_id,
                            "resource_id": rejected.resource_id,
                            "reason": rejected.reason,
                        }
                    )
                ),
            )
    repo.finish_run(
        run_id,
        accepted=result.accepted_count,
        rejected=result.rejected_count,
        duplicates=result.duplicate_count,
    )
    _log.info(
        "telemetry ingested",
        extra={
            "extra_fields": {
                "run_id": run_id,
                "accepted": result.accepted_count,
                "rejected": result.rejected_count,
                "duplicates": result.duplicate_count,
            }
        },
    )
    return result


def _fingerprint_index(repo: EventRepository) -> list[tuple[str, str]]:
    rows = repo.db.query("SELECT fingerprint, event_id FROM events")
    return [(str(row["fingerprint"]), str(row["event_id"])) for row in rows]


def _observation_inconsistency(event: Event) -> str | None:
    observation = event.observation
    if observation.ports is not None:
        keys = {(port.port, port.protocol) for port in observation.ports}
        if len(keys) != len(observation.ports):
            return "duplicate port entries in one observation"
    if observation.processes is not None:
        pids = [process.pid for process in observation.processes]
        if len(set(pids)) != len(pids):
            return "duplicate pid entries in one observation"
    return None
