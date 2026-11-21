"""Trusted knowledge corpus with integrity verification.

Documents carry provenance and a trust level. Content is chunked by section,
hashed and scanned for prompt-injection indicators. Flagged chunks are never
indexed and never enter a prompt.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import yaml
from pydantic import Field

from sentinel.errors import DatasetError
from sentinel.models.common import StrictModel, sha256_hex
from sentinel.observability.logging import get_logger
from sentinel.observability.metrics import INJECTION_BLOCKED
from sentinel.security.injection import scan_text

_log = get_logger(__name__)

TrustLevel = Literal["authoritative", "internal", "untrusted"]


class KnowledgeChunk(StrictModel):
    doc_id: str
    title: str
    chunk_id: str
    trust_level: TrustLevel
    classification: str
    version: str
    source_file: str
    heading: str
    text: str = Field(max_length=4000)
    content_sha256: str
    blocked: bool = False
    flags: list[str] = Field(default_factory=list)


@dataclass
class KnowledgeCorpus:
    chunks: list[KnowledgeChunk]
    blocked_chunks: list[KnowledgeChunk]
    documents: dict[str, dict[str, str]]
    corpus_hash: str
    manifest_verified: bool

    @property
    def indexed_chunks(self) -> list[KnowledgeChunk]:
        return [chunk for chunk in self.chunks if not chunk.blocked]

    @property
    def doc_count(self) -> int:
        return len(self.documents)


class CorpusCache:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._value: KnowledgeCorpus | None = None

    def get(self) -> KnowledgeCorpus | None:
        with self._lock:
            return self._value

    def put(self, corpus: KnowledgeCorpus) -> None:
        with self._lock:
            self._value = corpus


def _parse_front_matter(text: str, path: Path) -> tuple[dict[str, object], str]:
    if not text.startswith("---"):
        raise DatasetError(f"knowledge document {path.name} is missing front matter")
    parts = text.split("---", 2)
    if len(parts) < 3:
        raise DatasetError(f"knowledge document {path.name} has malformed front matter")
    try:
        metadata = yaml.safe_load(parts[1]) or {}
    except yaml.YAMLError as exc:
        raise DatasetError(f"knowledge document {path.name} has invalid YAML") from exc
    if not isinstance(metadata, dict):
        raise DatasetError(f"knowledge document {path.name} front matter must be a mapping")
    return metadata, parts[2]


def _chunk_document(
    metadata: dict[str, object], body: str, path: Path, relative: str
) -> list[KnowledgeChunk]:
    doc_id = str(metadata.get("doc_id", "")).strip()
    title = str(metadata.get("title", "")).strip()
    trust_raw = str(metadata.get("trust_level", "")).strip()
    classification = str(metadata.get("classification", "internal")).strip()
    version = str(metadata.get("version", "")).strip()
    if not doc_id or not title or trust_raw not in {"authoritative", "internal", "untrusted"}:
        raise DatasetError(f"knowledge document {relative} has invalid metadata")
    if not version:
        raise DatasetError(f"knowledge document {relative} is missing a version")

    sections: list[tuple[str, str]] = []
    current_heading = title
    current_lines: list[str] = []
    for line in body.splitlines():
        if line.startswith("## "):
            if current_lines:
                sections.append((current_heading, "\n".join(current_lines).strip()))
            current_heading = line[3:].strip()
            current_lines = []
        else:
            current_lines.append(line)
    if current_lines:
        sections.append((current_heading, "\n".join(current_lines).strip()))
    if not sections:
        sections = [(title, body.strip())]

    chunks: list[KnowledgeChunk] = []
    for index, (heading, section_text) in enumerate(sections):
        if not section_text:
            continue
        text = f"{title} — {heading}\n{section_text}"[:4000]
        flags = scan_text(text)
        chunk = KnowledgeChunk(
            doc_id=doc_id,
            title=title,
            chunk_id=f"{doc_id}#{index}",
            trust_level=trust_raw,  # type: ignore[arg-type]
            classification=classification,
            version=version,
            source_file=relative,
            heading=heading,
            text=text,
            content_sha256=sha256_hex(text),
            blocked=bool(flags),
            flags=flags,
        )
        if flags:
            INJECTION_BLOCKED.inc()
        chunks.append(chunk)
    return chunks


def load_corpus(
    knowledge_dir: Path,
    *,
    strict: bool = True,
    cache: CorpusCache | None = None,
) -> KnowledgeCorpus:
    if cache is not None:
        cached = cache.get()
        if cached is not None:
            return cached

    if not knowledge_dir.exists():
        raise DatasetError(f"knowledge directory is missing: {knowledge_dir}")

    manifest_path = knowledge_dir / "manifest.json"
    manifest_files: dict[str, str] = {}
    manifest_verified = False
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest_files = {str(key): str(value) for key, value in manifest["files"].items()}
            manifest_verified = True
        except (OSError, KeyError, TypeError, ValueError) as exc:
            raise DatasetError("knowledge manifest is invalid") from exc
    elif strict:
        raise DatasetError("knowledge manifest is missing; refusing to trust the corpus")

    documents: dict[str, dict[str, str]] = {}
    chunks: list[KnowledgeChunk] = []
    seen_doc_ids: set[str] = set()
    hash_material: list[str] = []

    for path in sorted(knowledge_dir.rglob("*.md")):
        relative = path.relative_to(knowledge_dir).as_posix()
        file_bytes = path.read_bytes()
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        expected = manifest_files.get(relative)
        if expected is not None and expected != file_hash and strict:
            raise DatasetError(f"knowledge document {relative} does not match the manifest")
        metadata, body = _parse_front_matter(file_bytes.decode("utf-8"), path)
        doc_id = str(metadata.get("doc_id", "")).strip()
        if doc_id in seen_doc_ids:
            raise DatasetError(f"duplicate knowledge doc_id {doc_id}")
        seen_doc_ids.add(doc_id)
        documents[doc_id] = {
            "doc_id": doc_id,
            "title": str(metadata.get("title", "")),
            "trust_level": str(metadata.get("trust_level", "")),
            "classification": str(metadata.get("classification", "")),
            "version": str(metadata.get("version", "")),
            "source_file": relative,
            "sha256": file_hash,
        }
        chunks.extend(_chunk_document(metadata, body, path, relative))
        hash_material.append(f"{relative}:{file_hash}")

    if not chunks:
        raise DatasetError("knowledge corpus contains no usable chunks")

    corpus_hash = sha256_hex("|".join(sorted(hash_material)))
    corpus = KnowledgeCorpus(
        chunks=chunks,
        blocked_chunks=[chunk for chunk in chunks if chunk.blocked],
        documents=documents,
        corpus_hash=corpus_hash,
        manifest_verified=manifest_verified,
    )
    if cache is not None:
        cache.put(corpus)
    _log.info(
        "knowledge corpus loaded",
        extra={
            "extra_fields": {
                "documents": corpus.doc_count,
                "chunks": len(corpus.chunks),
                "blocked_chunks": len(corpus.blocked_chunks),
                "manifest_verified": manifest_verified,
            }
        },
    )
    return corpus
