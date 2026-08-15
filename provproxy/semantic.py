from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

import numpy as np


@dataclass(frozen=True)
class SemanticMatch:
    source_id: str
    score: float


class SemanticBackendUnavailable(RuntimeError):
    pass


class SentenceTransformerSemanticScorer:
    """Optional local semantic scorer for REVIEW-only use.

    This module deliberately does not hard-block. It computes cosine-style
    sentence similarity between registered sensitive sources and candidate
    outbound text. The caller decides whether a score crosses a REVIEW
    threshold.

    The model is loaded lazily so normal ProvProxy operation does not incur
    the dependency or startup cost unless P8 semantic review is enabled.
    """

    def __init__(
        self,
        model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
    ):
        self.model_name = model_name
        self._model = None
        self._sources: dict[str, str] = {}
        self._source_embeddings: dict[str, np.ndarray] = {}

    def _ensure_model(self):
        if self._model is not None:
            return self._model
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise SemanticBackendUnavailable(
                "sentence-transformers is not installed. "
                "Install it only for the optional P8 semantic-review experiments."
            ) from exc

        self._model = SentenceTransformer(self.model_name)
        return self._model

    def register_source(self, source_id: str, text: str) -> None:
        self._sources[source_id] = text
        # Invalidate any stale embedding if source text changes.
        self._source_embeddings.pop(source_id, None)

    def sources(self) -> list[tuple[str, str]]:
        return list(self._sources.items())

    def _embed_one(self, text: str) -> np.ndarray:
        model = self._ensure_model()
        vector = model.encode(
            [text],
            normalize_embeddings=True,
            convert_to_numpy=True,
            show_progress_bar=False,
        )[0]
        return np.asarray(vector, dtype=np.float32)

    def _source_embedding(self, source_id: str, text: str) -> np.ndarray:
        emb = self._source_embeddings.get(source_id)
        if emb is None:
            emb = self._embed_one(text)
            self._source_embeddings[source_id] = emb
        return emb

    def score_all(self, candidate_text: str) -> list[SemanticMatch]:
        if not candidate_text.strip() or not self._sources:
            return []

        candidate = self._embed_one(candidate_text)
        matches: list[SemanticMatch] = []

        for source_id, source_text in self._sources.items():
            source = self._source_embedding(source_id, source_text)
            # Embeddings are normalized, so dot product is cosine similarity.
            score = float(np.dot(candidate, source))
            matches.append(SemanticMatch(source_id=source_id, score=score))

        matches.sort(key=lambda m: m.score, reverse=True)
        return matches

    def best_match(self, candidate_text: str) -> Optional[SemanticMatch]:
        matches = self.score_all(candidate_text)
        return matches[0] if matches else None
