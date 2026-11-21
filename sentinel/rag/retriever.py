"""Deterministic BM25 retrieval with an optional ChromaDB backend.

BM25 is the default because it is offline, deterministic, dependency-free and does
not download models at runtime. Chroma + sentence-transformers are optional; if they
are unavailable or fail, retrieval degrades to BM25 instead of taking the platform
down.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from pydantic import Field

from sentinel.config import Settings
from sentinel.models.common import StrictModel
from sentinel.observability.logging import get_logger
from sentinel.observability.metrics import RAG_TOTAL
from sentinel.rag.corpus import KnowledgeChunk, KnowledgeCorpus

_log = get_logger(__name__)

_TOKEN = re.compile(r"[a-z0-9][a-z0-9_-]+")
_STOPWORDS = {
    "the", "and", "for", "with", "that", "this", "from", "are", "was", "were", "has",
    "have", "had", "not", "but", "you", "your", "our", "can", "must", "should", "will",
    "into", "when", "then", "than", "them", "they", "its", "it's", "all", "any", "may",
    "use", "used", "using", "via", "per", "also", "only", "each", "which", "what",
    "how", "why", "does", "do", "is", "to", "of", "in", "on", "or", "a", "an", "be",
}


def tokenize(text: str) -> list[str]:
    return [
        token
        for token in _TOKEN.findall(text.lower())
        if token not in _STOPWORDS and len(token) > 1
    ]


class RetrievedChunk(StrictModel):
    doc_id: str
    title: str
    chunk_id: str
    trust_level: str
    score: float = Field(ge=0.0)
    text: str = Field(max_length=4000)
    heading: str = ""
    source_file: str = ""
    flags: list[str] = Field(default_factory=list)


class SearchResult(StrictModel):
    query: str
    backend: str
    chunks: list[RetrievedChunk]
    blocked_chunks: list[RetrievedChunk]
    corpus_hash: str


class BM25Retriever:
    backend = "bm25"

    def __init__(self, corpus: KnowledgeCorpus, *, k1: float = 1.5, b: float = 0.75) -> None:
        self.corpus = corpus
        self.k1 = k1
        self.b = b
        self._documents: list[KnowledgeChunk] = corpus.indexed_chunks
        self._tokens = [tokenize(chunk.text) for chunk in self._documents]
        self._lengths = [len(tokens) for tokens in self._tokens]
        self._avg_length = sum(self._lengths) / max(len(self._lengths), 1)
        self._doc_freq: Counter[str] = Counter()
        for tokens in self._tokens:
            self._doc_freq.update(set(tokens))
        self._n = len(self._documents)

    def _idf(self, term: str) -> float:
        df = self._doc_freq.get(term, 0)
        return math.log(1 + (self._n - df + 0.5) / (df + 0.5))

    def search(self, query: str, top_k: int = 4) -> SearchResult:
        terms = tokenize(query)
        scores: list[tuple[float, int]] = []
        for index, tokens in enumerate(self._tokens):
            counts = Counter(tokens)
            length = max(self._lengths[index], 1)
            score = 0.0
            for term in terms:
                frequency = counts.get(term, 0)
                if frequency == 0:
                    continue
                denominator = frequency + self.k1 * (
                    1 - self.b + self.b * (length / max(self._avg_length, 1e-9))
                )
                score += self._idf(term) * (frequency * (self.k1 + 1)) / denominator
            if score > 0:
                scores.append((score, index))
        scores.sort(key=lambda item: (-item[0], self._documents[item[1]].chunk_id))
        chunks = [
            self._to_retrieved(self._documents[index], round(score, 6))
            for score, index in scores[: max(1, top_k)]
        ]
        RAG_TOTAL.labels(backend=self.backend, result="hit" if chunks else "miss").inc()
        return SearchResult(
            query=query,
            backend=self.backend,
            chunks=chunks,
            blocked_chunks=[self._to_retrieved(chunk, 0.0) for chunk in self.corpus.blocked_chunks],
            corpus_hash=self.corpus.corpus_hash,
        )

    @staticmethod
    def _to_retrieved(chunk: KnowledgeChunk, score: float) -> RetrievedChunk:
        return RetrievedChunk(
            doc_id=chunk.doc_id,
            title=chunk.title,
            chunk_id=chunk.chunk_id,
            trust_level=chunk.trust_level,
            score=score,
            text=chunk.text,
            heading=chunk.heading,
            source_file=chunk.source_file,
            flags=chunk.flags,
        )


class ChromaRetriever:
    """Optional semantic backend.

    Requires ``chromadb`` and ``sentence-transformers`` plus explicit permission to
    download the embedding model. Any failure falls back to BM25 at construction.
    """

    backend = "chroma"

    def __init__(self, corpus: KnowledgeCorpus, settings: Settings) -> None:
        import chromadb  # noqa: PLC0415
        from chromadb.utils import embedding_functions  # noqa: PLC0415

        self.corpus = corpus
        self.settings = settings
        self._fallback = BM25Retriever(corpus)
        persist = settings.var_dir / "chroma"
        persist.mkdir(parents=True, exist_ok=True)
        self._client = chromadb.PersistentClient(path=str(persist))
        self._embedding = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name=settings.embedding_model
        )
        self._collection = self._client.get_or_create_collection(
            name="sentinel-knowledge", embedding_function=self._embedding
        )
        documents = corpus.indexed_chunks
        if self._collection.count() != len(documents):
            self._collection.upsert(
                ids=[chunk.chunk_id for chunk in documents],
                documents=[chunk.text for chunk in documents],
                metadatas=[
                    {"doc_id": chunk.doc_id, "title": chunk.title, "trust_level": chunk.trust_level}
                    for chunk in documents
                ],
            )

    def search(self, query: str, top_k: int = 4) -> SearchResult:
        try:
            result = self._collection.query(query_texts=[query], n_results=max(1, top_k))
            by_id = {chunk.chunk_id: chunk for chunk in self.corpus.indexed_chunks}
            chunks: list[RetrievedChunk] = []
            for index, chunk_id in enumerate(result.get("ids", [[]])[0]):
                chunk = by_id.get(chunk_id)
                if chunk is None:
                    continue
                distance = float(result.get("distances", [[0.0]])[0][index])
                chunks.append(
                    BM25Retriever._to_retrieved(chunk, round(max(0.0, 1.0 - distance), 6))
                )
            RAG_TOTAL.labels(backend=self.backend, result="hit" if chunks else "miss").inc()
            return SearchResult(
                query=query,
                backend=self.backend,
                chunks=chunks,
                blocked_chunks=[
                    BM25Retriever._to_retrieved(chunk, 0.0)
                    for chunk in self.corpus.blocked_chunks
                ],
                corpus_hash=self.corpus.corpus_hash,
            )
        except Exception as exc:  # degrade, never fail the investigation path
            _log.warning("chroma retrieval failed; falling back to bm25", extra={"extra_fields": {"error": str(exc)}})
            RAG_TOTAL.labels(backend=self.backend, result="fallback").inc()
            return self._fallback.search(query, top_k)


def build_retriever(settings: Settings, corpus: KnowledgeCorpus) -> BM25Retriever | ChromaRetriever:
    if settings.rag_backend == "bm25":
        return BM25Retriever(corpus)
    if not settings.allow_model_download:
        _log.warning(
            "chroma requested but model downloads are disabled; using deterministic bm25"
        )
        RAG_TOTAL.labels(backend="chroma", result="fallback").inc()
        return BM25Retriever(corpus)
    try:
        return ChromaRetriever(corpus, settings)
    except Exception as exc:
        _log.warning("chroma unavailable; using bm25", extra={"extra_fields": {"error": str(exc)}})
        RAG_TOTAL.labels(backend="chroma", result="fallback").inc()
        return BM25Retriever(corpus)
