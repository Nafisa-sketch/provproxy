"""Exact Matcher (T1 / V1) — multi-pattern substring search over registered
sensitive fragments, using the Aho-Corasick algorithm for O(n) matching
regardless of pattern count.

## Matcher lifecycle (Section 5F)

The automaton is built *from* raw sensitive fragments, so clearing a delta
buffer alone does not remove that data from memory — the compiled
structure itself still encodes it. This module makes that lifecycle
explicit:

- One automaton **per session**, never global.
- On TTL expiry, the automaton is **replaced wholesale** (a fresh, empty
  one swapped in), never mutated/selectively cleared.
- A snapshot handed to an in-flight scan is a plain object reference in
  Python — the same "old reference stays valid until dropped, new scans
  see the fresh one" semantics as the Rust `Arc` version, just via normal
  Python object lifetime instead of explicit reference counting.
- Expiry also clears the session's fragment list, so no new fragment
  reaches a stale automaton after replacement.
- Process restart unconditionally clears everything.
"""
from __future__ import annotations

import re
import time
import threading
from dataclasses import dataclass, field

# pyahocorasick is a C extension — great for speed, but it needs a
# compiler to build if no pre-built wheel matches the user's Python
# version/platform (exactly the kind of toolchain problem this project
# already hit once with Rust). We use it when available for speed, and
# fall back to a pure-Python multi-pattern matcher otherwise so the
# project never *requires* a compiler to run.
try:
    import ahocorasick  # type: ignore

    _HAS_AHOCORASICK = True
except ImportError:
    _HAS_AHOCORASICK = False

# A reverse match ("is this payload text a snippet cut out of some larger
# registered secret?") is only checked for tokens at least this long —
# without a floor, trivially short/common substrings (a single space, a
# comma) would spuriously "match" almost any registered source.
_MIN_REVERSE_MATCH_LEN = 8
# A reverse substring must also cover a meaningful fraction of the registered
# source. This prevents generic prefixes such as "SYNTHETIC" from being
# treated as exact provenance merely because they happen to occur inside a
# longer sensitive source. 30% preserves useful snippet detection (e.g. one
# substantial line cut from a larger secret-bearing file) while rejecting
# small/common overlaps.
_MIN_REVERSE_SOURCE_COVERAGE = 0.30

# Same delimiter set as decode.py's candidate extractor — a real-world
# payload is rarely JUST the secret; it's usually a secret sitting inside
# a URL, a JSON body, or other surrounding text. We split on the same
# punctuation/whitespace boundaries so the reverse check looks at
# plausible individual tokens instead of the whole noisy payload at once.
_TOKEN_SPLIT_RE = re.compile(r'[\s"\'{},:]+')


@dataclass
class MatchResult:
    matched_fragment_id: str
    matched_pattern: str


class MatcherSnapshot:
    """Immutable-by-convention compiled snapshot. Never mutated after
    construction — updates happen by building a new snapshot and replacing
    the reference held by SessionMatcher, per the lifecycle above."""

    def __init__(self, fragments: list[tuple[str, str]]):
        # fragments: (fragment_id, raw_pattern)
        self._fragments = [(fid, p) for fid, p in fragments if p]
        self._automaton = None
        if _HAS_AHOCORASICK and self._fragments:
            automaton = ahocorasick.Automaton()
            for fragment_id, pattern in self._fragments:
                automaton.add_word(pattern, (fragment_id, pattern))
            automaton.make_automaton()
            self._automaton = automaton

    def scan(self, text: str) -> list[MatchResult]:
        """Two directions, both real attack shapes:

        1. FORWARD — a registered secret appears verbatim somewhere inside
           the payload (e.g. a short API key copied whole into a larger
           outbound message). This is what the Aho-Corasick automaton (or
           its pure-Python fallback) checks natively.
        2. REVERSE — the payload itself is a small snippet cut out of a
           much larger registered secret (e.g. the whole contents of a
           file were registered, but the attacker only copied one line of
           it out). The automaton can't find this on its own, since it
           searches for the registered pattern occurring inside the text —
           if the pattern (the whole file) is longer than the text (the
           snippet), it can never be "found inside" it. So we separately
           check the opposite: is this text a substring of some
           registered pattern?
        """
        results: list[MatchResult] = []
        seen_fragment_ids: set[str] = set()

        if self._automaton is not None:
            for _end_index, (fid, pattern) in self._automaton.iter(text):
                if fid not in seen_fragment_ids:
                    results.append(MatchResult(matched_fragment_id=fid, matched_pattern=pattern))
                    seen_fragment_ids.add(fid)
        else:
            # Pure-Python fallback: O(patterns * len(text)) substring
            # search. Fine for a prototype's pattern counts (dozens, not
            # millions); swap back to the C-extension path automatically
            # once it's installable in the user's environment.
            for fragment_id, pattern in self._fragments:
                if pattern and pattern in text and fragment_id not in seen_fragment_ids:
                    results.append(MatchResult(matched_fragment_id=fragment_id, matched_pattern=pattern))
                    seen_fragment_ids.add(fragment_id)

        if len(text) >= _MIN_REVERSE_MATCH_LEN:
            # Check the whole text first (handles "payload IS just the
            # snippet, nothing else"), then individual extracted tokens
            # (handles "snippet is embedded in a larger, noisier
            # payload" — e.g. a secret sitting inside a URL or JSON body).
            candidates = [text] + [
                tok for tok in _TOKEN_SPLIT_RE.split(text) if len(tok) >= _MIN_REVERSE_MATCH_LEN
            ]
            for fragment_id, pattern in self._fragments:
                if fragment_id in seen_fragment_ids:
                    continue
                for candidate in candidates:
                    if not candidate or candidate not in pattern:
                        continue
                    source_coverage = len(candidate) / len(pattern) if pattern else 0.0
                    if source_coverage < _MIN_REVERSE_SOURCE_COVERAGE:
                        continue
                    results.append(MatchResult(matched_fragment_id=fragment_id, matched_pattern=candidate))
                    seen_fragment_ids.add(fragment_id)
                    break

        return results

    @staticmethod
    def empty() -> "MatcherSnapshot":
        return MatcherSnapshot([])


class SessionMatcher:
    """Per-session matcher state. Owns the current snapshot and the raw
    fragment list needed to rebuild it when a new sensitive source is
    registered."""

    def __init__(self, ttl_seconds: float):
        self._snapshot = MatcherSnapshot.empty()
        self._fragments: list[tuple[str, str]] = []
        self._last_activity = time.monotonic()
        self._ttl_seconds = ttl_seconds
        self._lock = threading.RLock()

    def register_fragment(self, fragment_id: str, raw_pattern: str) -> None:
        with self._lock:
            self._fragments.append((fragment_id, raw_pattern))
            self._snapshot = MatcherSnapshot(list(self._fragments))
            self._last_activity = time.monotonic()

    def current_snapshot(self) -> MatcherSnapshot:
        with self._lock:
            return self._snapshot

    def is_expired(self) -> bool:
        with self._lock:
            return (time.monotonic() - self._last_activity) > self._ttl_seconds

    def expire(self) -> None:
        """Replace-on-expiry: swap in a fresh, empty automaton and drop
        this session's raw fragment list. Any reference still held by an
        in-flight caller keeps working against the pre-expiry snapshot —
        Python doesn't garbage-collect it out from under them — but this
        call stops *new* scans from seeing the expired data."""
        with self._lock:
            self._fragments.clear()
            self._snapshot = MatcherSnapshot.empty()
