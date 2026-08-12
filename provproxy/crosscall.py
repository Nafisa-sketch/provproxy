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

    def record(self, payload_text: str) -> None:
        """Record one call's raw payload text. Evidence extraction
        (key=value reconstruction) happens here, once, at record time —
        so accumulated_coverage() always works from already-cleaned
        per-entry text."""
        self._evict_expired()
        cleaned = extract_reconstructable_value(payload_text)
        self._entries.append(_WindowEntry(value_text=cleaned, observed_at=time.monotonic()))
        while len(self._entries) > self.config.window_max_calls:
            self._entries.popleft()

    def _evict_expired(self) -> None:
        cutoff = self.config.window_seconds
        now = time.monotonic()
        while self._entries and (now - self._entries[0].observed_at) > cutoff:
            self._entries.popleft()

    def accumulated_coverage(self, source_text: str, ngram_size: int) -> float | None:
        """Coverage_n^cross(s, d, w), computed as the MAX of two methods
        (see module docstring): ordered concatenation (recovers cross-
        call boundary n-grams) and per-entry union (order-independent
        safety net). Never lower than the original union-only method —
        ordered concatenation is additive evidence, not a replacement."""
        self._evict_expired()
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

        return max(ordered_coverage, union_coverage)

    def __len__(self) -> int:
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

    def window_for(self, session_id: str, destination: str, source_id: str) -> CrossCallWindow:
        key = (session_id, destination, source_id)
        if key not in self._windows:
            self._windows[key] = CrossCallWindow(self._config)
        return self._windows[key]

    def __len__(self) -> int:
        return len(self._windows)
