"""Optional session-wide cross-destination fan-out review.

This layer complements the strict per-destination V4 registry.  Per-destination
state is intentionally isolated to avoid contaminating unrelated sinks, but that
also creates a known evasion: an attacker can distribute consecutive secret
fragments across many fresh destinations so no single destination accumulates
sufficient evidence.

The fan-out guard is deliberately REVIEW-only.  It aggregates source-bound
coverage across destinations within one session and emits an early review when
both (a) cumulative source coverage crosses a configured threshold and (b) the
evidence spans a minimum number of distinct destinations.  It never turns
semantic/destination diversity alone into a hard provenance match.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass

from .approx import extract_reconstructable_value, ngrams as _ngrams
from .config import CrossCallWindowConfig


@dataclass
class _FanoutEntry:
    destination: str
    value_text: str
    observed_at: float


class FanoutWindow:
    def __init__(self, config: CrossCallWindowConfig):
        self.config = config
        self._entries: deque[_FanoutEntry] = deque()
        self._lock = threading.RLock()

    def _evict_unlocked(self) -> None:
        now = time.monotonic()
        while self._entries and (now - self._entries[0].observed_at) > self.config.window_seconds:
            self._entries.popleft()
        while len(self._entries) > self.config.window_max_calls:
            self._entries.popleft()

    def _coverage_unlocked(self, source_text: str, ngram_size: int) -> float:
        source_ngrams = _ngrams(source_text, ngram_size)
        if not source_text:
            return 0.0

        union: set[str] = set()
        covered_positions: set[int] = set()
        source_len = len(source_text)

        for entry in self._entries:
            piece = entry.value_text
            if not piece:
                continue
            union |= _ngrams(piece, ngram_size)
            start = 0
            while True:
                idx = source_text.find(piece, start)
                if idx < 0:
                    break
                covered_positions.update(range(idx, min(idx + len(piece), source_len)))
                start = idx + 1

        ngram_cov = (len(source_ngrams & union) / len(source_ngrams)) if source_ngrams else 0.0
        positional_cov = len(covered_positions) / source_len if source_len else 0.0
        return max(ngram_cov, positional_cov)

    def record_and_measure(
        self,
        payload_text: str,
        destination: str,
        source_text: str,
        ngram_size: int,
    ) -> tuple[float, float, int]:
        with self._lock:
            self._evict_unlocked()
            before = self._coverage_unlocked(source_text, ngram_size)
            cleaned = extract_reconstructable_value(payload_text)
            self._entries.append(
                _FanoutEntry(
                    destination=destination,
                    value_text=cleaned,
                    observed_at=time.monotonic(),
                )
            )
            self._evict_unlocked()
            after = self._coverage_unlocked(source_text, ngram_size)
            distinct_destinations = len({e.destination for e in self._entries})
            return before, after, distinct_destinations


class FanoutRegistry:
    """Per-(session, source) windows spanning multiple destinations."""

    def __init__(self, config: CrossCallWindowConfig):
        self._config = config
        self._windows: dict[tuple[str, str], FanoutWindow] = {}
        self._lock = threading.RLock()

    def window_for(self, session_id: str, source_id: str) -> FanoutWindow:
        key = (session_id, source_id)
        with self._lock:
            window = self._windows.get(key)
            if window is None:
                window = FanoutWindow(self._config)
                self._windows[key] = window
            return window
