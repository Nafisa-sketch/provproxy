"""Cross-Call Tier (T4 / V4).

P6 integration:
  * V4 state remains scoped per (session_id, destination, source_id).
  * If encrypted persistence is enabled, each evidence record is journaled
    before it becomes part of the in-memory window.
  * Existing persisted evidence is lazily hydrated when a window is first used.
  * Original wall-clock timestamps are translated back to monotonic ages so
    restart does NOT extend the TTL.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .approx import extract_reconstructable_value, ngrams as _ngrams
from .config import CrossCallWindowConfig

if TYPE_CHECKING:
    from .persistence import SecurePersistentStateRegistry


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

    def __init__(
    self,
    config: CrossCallWindowConfig,
    *,
    session_id: str = "",
    destination: str = "",
    source_id: str = "",
    persistent_state=None,
    ):
        self.config = config
        self.session_id = session_id
        self.destination = destination
        self.source_id = source_id
        self.persistent_state = persistent_state
        self._entries: deque[_WindowEntry] = deque()
        self._lock = threading.RLock()

    def hydrate_persisted(
        self, entries: list[tuple[str, float]]
    ) -> None:
        """Restore evidence without writing it back to the journal."""
        with self._lock:
            now_wall = time.time()
            now_mono = time.monotonic()
            for value_text, wall_ts in entries:
                age = max(0.0, now_wall - float(wall_ts))
                if age > self.config.window_seconds:
                    continue
                self._entries.append(
                    _WindowEntry(
                        value_text=value_text,
                        observed_at=now_mono - age,
                    )
                )
            while len(self._entries) > self.config.window_max_calls:
                self._entries.popleft()
            self._evict_expired_unlocked()

    def _append_cleaned_unlocked(
        self, cleaned: str, *, persist: bool
    ) -> None:
        self._evict_expired_unlocked()

        # Persistence is load-bearing when enabled: write/authenticate first.
        # Failure propagates, allowing the relay to fail closed rather than
        # forwarding an egress call that is not restart-recoverable.
        if persist and self.persistent_state is not None:
            self.persistent_state.add_fragment(
                self.session_id,
                self.destination,
                self.source_id,
                cleaned,
            )

        self._entries.append(
            _WindowEntry(value_text=cleaned, observed_at=time.monotonic())
        )
        while len(self._entries) > self.config.window_max_calls:
            self._entries.popleft()

    def record(self, payload_text: str) -> None:
        cleaned = extract_reconstructable_value(payload_text)
        with self._lock:
            self._append_cleaned_unlocked(cleaned, persist=True)

    def _evict_expired_unlocked(self) -> None:
        cutoff = self.config.window_seconds
        now = time.monotonic()
        while self._entries and (now - self._entries[0].observed_at) > cutoff:
            self._entries.popleft()

    def accumulated_coverage(
        self, source_text: str, ngram_size: int
    ) -> float | None:
        with self._lock:
            self._evict_expired_unlocked()
            return self._accumulated_coverage_unlocked(source_text, ngram_size)

    def record_and_measure(
        self, payload_text: str, source_text: str, ngram_size: int
    ) -> tuple[float, float]:
        """Atomic V4 before->record->after transition."""
        cleaned = extract_reconstructable_value(payload_text)
        with self._lock:
            self._evict_expired_unlocked()
            before = self._accumulated_coverage_unlocked(
                source_text, ngram_size
            ) or 0.0
            self._append_cleaned_unlocked(cleaned, persist=True)
            after = self._accumulated_coverage_unlocked(
                source_text, ngram_size
            ) or 0.0
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
        ordered_hits = len(
            source_ngrams & _ngrams(ordered_concat, ngram_size)
        )
        ordered_coverage = ordered_hits / len(source_ngrams)

        union: set[str] = set()
        for entry in self._entries:
            union |= _ngrams(entry.value_text, ngram_size)
        union_coverage = len(source_ngrams & union) / len(source_ngrams)

        # Duplicate-resistant positional coverage for short/out-of-order pieces.
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
                covered_positions.update(
                    range(idx, min(idx + len(piece), source_len))
                )
                start = idx + 1

        positional_coverage = (
            len(covered_positions) / source_len if source_len else 0.0
        )
        return max(
            ordered_coverage, union_coverage, positional_coverage
        )

    def __len__(self) -> int:
        with self._lock:
            self._evict_expired_unlocked()
            return len(self._entries)


class CrossCallRegistry:
    """Thread-safe registry keyed by (session_id, destination, source_id)."""

    def __init__(
        self,
        config: CrossCallWindowConfig,
        *,
        persistent_state: "SecurePersistentStateRegistry | None" = None,
    ):
        self._windows: dict[
            tuple[str, str, str], CrossCallWindow
        ] = {}
        self._config = config
        self._persistent_state = persistent_state
        self._lock = threading.RLock()

    def window_for(
        self, session_id: str, destination: str, source_id: str
    ) -> CrossCallWindow:
        key = (session_id, destination, source_id)
        with self._lock:
            window = self._windows.get(key)
            if window is None:
                window = CrossCallWindow(
                    self._config,
                    session_id=session_id,
                    destination=destination,
                    source_id=source_id,
                    persistent_state=self._persistent_state,
                )
                if self._persistent_state is not None:
                    window.hydrate_persisted(
                        self._persistent_state.get_accumulated_entries(
                            session_id, destination, source_id
                        )
                    )
                self._windows[key] = window
            return window

    def __len__(self) -> int:
        with self._lock:
            return len(self._windows)
