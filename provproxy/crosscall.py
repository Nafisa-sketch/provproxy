"""Cross-Call Tier (T4 / V4) — accumulates evidence sent to the same
destination across multiple calls within a session, so a secret split
across several small outbound calls (none individually large enough to
trip V1-V3) still gets caught once the cumulative overlap crosses the
threshold.

## Evidence storage: ordered value text, not pre-computed n-grams

Each window entry stores the call's extracted evidence text (via
`approx.extract_reconstructable_value` — same key=value reconstruction
V3 uses, applied per call), in ARRIVAL order. `accumulated_coverage()`
computes coverage two ways and takes the max:

  1. **Ordered concatenation** — join every stored entry's text in
     arrival order and compute coverage of the joined string directly.
     This recovers n-grams that span the boundary BETWEEN two calls
     (e.g. the last 2 characters of one chunk + first 2 of the next),
     which a naive per-call n-gram union loses, since chunks sent in
     order across separate calls are exactly adjacent in the original
     secret.
  2. **Per-entry union** (the original method) — union each entry's own
     n-grams independently. Kept as a safety net for cases where calls
     don't arrive in the secret's original order, or aren't perfectly
     adjacent, so accumulation degrades gracefully rather than requiring
     strict ordering to work at all.

Window semantics (Section 5C):
  - Dual-bounded: time (default 300s) AND call-count (default 50 calls to
    the same destination) — whichever bound is hit first evicts the
    oldest entries.
  - Scoped per (session_id, destination, source_id) — never global — so
    memory is bounded to active sessions, concurrent sessions can't
    interfere, and two distinct tracked secrets heading to the same
    destination don't contaminate each other's accumulated evidence.
  - Destination identity = scheme + normalized host + port + tool/server
    identity (simplified to domain string in the current wiring — see
    pipeline.py). Redirect chains and DNS-rebinding remain out of scope.
"""
from __future__ import annotations

import time
import threading
from collections import deque
from dataclasses import dataclass, field

from .approx import extract_reconstructable_value, ngrams as _ngrams
from .config import CrossCallWindowConfig


@dataclass(frozen=True)
class DestinationId:
    scheme: str
    host: str
    port: int
    server_id: str


@dataclass
class _WindowEntry:
    value_text: str
    observed_at: float


class CrossCallWindow:
    """Per-(session, destination, source_id) accumulation window."""

    def __init__(self, config: CrossCallWindowConfig):
        self.config = config
        self._entries: deque[_WindowEntry] = deque()
        self._lock = threading.RLock()

    def record(self, payload_text: str) -> None:
        """Thread-safe record of one call's evidence."""
        with self._lock:
            self._record_unlocked(payload_text)

    def _record_unlocked(self, payload_text: str) -> None:
        self._evict_expired_unlocked()
        cleaned = extract_reconstructable_value(payload_text)
        self._entries.append(_WindowEntry(value_text=cleaned, observed_at=time.monotonic()))
        while len(self._entries) > self.config.window_max_calls:
            self._entries.popleft()

    def _evict_expired(self) -> None:
        with self._lock:
            self._evict_expired_unlocked()

    def _evict_expired_unlocked(self) -> None:
        cutoff = self.config.window_seconds
        now = time.monotonic()
        while self._entries and (now - self._entries[0].observed_at) > cutoff:
            self._entries.popleft()

    def accumulated_coverage(self, source_text: str, ngram_size: int) -> float | None:
        with self._lock:
            self._evict_expired_unlocked()
            return self._accumulated_coverage_unlocked(source_text, ngram_size)

    def record_and_measure(
        self, payload_text: str, source_text: str, ngram_size: int
    ) -> tuple[float, float]:
        """Atomically measure-before, record, and measure-after.

        This is the concurrency-critical V4 operation.  Keeping the entire
        transition inside one per-window lock prevents two simultaneous calls
        from interleaving between ``coverage_before`` and ``record`` and losing
        or duplicating threshold-crossing events.  Contention is scoped only to
        one (session, destination, source) window; unrelated destinations and
        sessions remain fully concurrent.
        """
        with self._lock:
            self._evict_expired_unlocked()
            before = self._accumulated_coverage_unlocked(source_text, ngram_size) or 0.0
            self._record_unlocked(payload_text)
            after = self._accumulated_coverage_unlocked(source_text, ngram_size) or 0.0
            return before, after

    def _accumulated_coverage_unlocked(
        self, source_text: str, ngram_size: int
    ) -> float | None:
        source_ngrams = _ngrams(source_text, ngram_size)
        if not source_ngrams:
            return None
        if not self._entries:
            return 0.0

        ordered_concat = "".join(e.value_text for e in self._entries)
        ordered_hits = len(source_ngrams & _ngrams(ordered_concat, ngram_size))
        ordered_coverage = ordered_hits / len(source_ngrams)

        union: set[str] = set()
        for entry in self._entries:
            union |= _ngrams(entry.value_text, ngram_size)
        union_coverage = len(source_ngrams & union) / len(source_ngrams)

        covered_positions: set[int] = set()
        source_len = len(source_text)
        for entry in self._entries:
            piece = entry.value_text
            if not piece:
                continue
            start = 0
            while True:
                idx = source_text.find(piece, start)
                if idx < 0:
                    break
                covered_positions.update(range(idx, min(idx + len(piece), source_len)))
                start = idx + 1

        positional_coverage = (
            len(covered_positions) / source_len if source_len else 0.0
        )
        return max(ordered_coverage, union_coverage, positional_coverage)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


class CrossCallRegistry:
    """Registry of active windows, keyed by (session_id, destination,
    source_id). source_id is included so that if a session tracks
    MULTIPLE distinct sensitive fragments and more than one gets sent
    toward the same destination, their accumulated evidence stays
    isolated per source — otherwise fragment A's evidence could
    accidentally push fragment B's cross-call coverage over the
    threshold, or vice versa, despite being unrelated secrets."""

    def __init__(self, config: CrossCallWindowConfig):
        self._windows: dict[tuple[str, str, str], CrossCallWindow] = {}
        self._config = config
        self._lock = threading.RLock()

    def window_for(self, session_id: str, destination: str, source_id: str) -> CrossCallWindow:
        key = (session_id, destination, source_id)
        with self._lock:
            window = self._windows.get(key)
            if window is None:
                window = CrossCallWindow(self._config)
                self._windows[key] = window
            return window

    def __len__(self) -> int:
        with self._lock:
            return len(self._windows)
