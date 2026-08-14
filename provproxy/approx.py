"""Approximate Matcher (T3 / V3) — catches split/partially-transformed
payloads that exact matching (even after decoding) misses, via N-gram
coverage against a known sensitive source.

Coverage(s, p) = |Ngrams_n(s) intersect Ngrams_n(p)| / |Ngrams_n(s)|

A candidate is flagged when Coverage >= threshold. Defaults: n=4,
threshold=0.6, both policy-configurable — the right operating point is a
DR/FPR trade-off the evaluation harness is built to characterize, not
something to hardcode ahead of that data.

## Evidence reconstruction (key=value extraction)

Splitting a secret into several `field=value`-style fragments (whether
within one request or across several calls) and interleaving them with
field-name/delimiter noise breaks n-gram CONTINUITY at every fragment
boundary — even though every character of the secret is still present
somewhere in the payload. `extract_reconstructable_value()` is a general,
format-agnostic heuristic (not tuned to any specific fixture or dataset):
it looks for the common `key=value` pattern, extracts just the value
parts, and concatenates them in their original order with the
intervening noise stripped out. This recovers the n-grams that only
exist across a fragment boundary in the ORIGINAL secret, which get lost
by naive whitespace-joined flattening. It's a strict *evidence
extraction* step — it never invents content, and payloads with no
`key=value` structure pass through unchanged, so it can't spuriously
inflate coverage for content that was never actually a value fragment.
"""
from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass

_KV_VALUE_RE = re.compile(r"\w+=(\S+)")


def ngrams(s: str, n: int) -> set[str]:
    if n <= 0 or len(s) < n:
        return set()
    return {s[i : i + n] for i in range(len(s) - n + 1)}


def _json_string_leaves(value) -> list[str]:
    """Return JSON string leaves in document order.

    Keys are deliberately excluded: provenance should be reconstructed
    from transmitted values, not from schema/field-name text.
    """
    out: list[str] = []
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, list):
        for item in value:
            out.extend(_json_string_leaves(item))
    elif isinstance(value, dict):
        for item in value.values():
            out.extend(_json_string_leaves(item))
    return out


def extract_reconstructable_value(text: str) -> str:
    """Return a bounded logical value stream for structured payloads.

    Two common structures are supported without inventing content:

    1. Valid JSON: concatenate string *values* in document order.
    2. ``key=value`` text: concatenate captured values in order.

    Free text falls back unchanged.  This lets V3/V4 recover provenance
    split across fields while avoiding arbitrary concatenation of
    unrelated field names and punctuation.
    """
    stripped = text.strip()
    if stripped and stripped[0] in "[{":
        try:
            parsed = json.loads(stripped)
        except (json.JSONDecodeError, TypeError):
            parsed = None
        if parsed is not None:
            leaves = _json_string_leaves(parsed)
            if leaves:
                return "".join(leaves)

    values = _KV_VALUE_RE.findall(text)
    return "".join(values) if values else text


def coverage(source: str, payload: str, n: int) -> float:
    """Coverage of `source` by `payload`. Intentionally asymmetric — a
    large payload containing all of a short secret's n-grams scores ~1.0
    even though the payload itself is much bigger than the secret."""
    source_grams = ngrams(source, n)
    if not source_grams:
        return 0.0
    payload_grams = ngrams(payload, n)
    hits = len(source_grams & payload_grams)
    return hits / len(source_grams)


def best_coverage(source: str, payload: str, n: int) -> float:
    """Coverage against the raw payload AND against its key=value-
    reconstructed form, whichever is higher. This is what `scan()` /
    `scan_sweep()` actually use — it never LOWERS coverage relative to
    the raw-only computation (reconstruction is additive evidence, not a
    replacement), and for payloads with no key=value structure the two
    values are identical (extract_reconstructable_value is a no-op)."""
    raw = coverage(source, payload, n)
    reconstructed_text = extract_reconstructable_value(payload)
    if reconstructed_text == payload:
        return raw
    return max(raw, coverage(source, reconstructed_text, n))


@dataclass
class ApproxMatch:
    fragment_id: str
    coverage: float


class ApproxMatcher:
    def __init__(self, ngram_size: int, threshold: float):
        self._sources: list[tuple[str, str]] = []  # (fragment_id, raw_text)
        self.ngram_size = ngram_size
        self.threshold = threshold
        self._lock = threading.RLock()

    def register_source(self, fragment_id: str, raw_text: str) -> None:
        with self._lock:
            self._sources.append((fragment_id, raw_text))

    def sources(self) -> list[tuple[str, str]]:
        """Public accessor for (fragment_id, raw_text) pairs — used by V4
        cross-call scoring, which needs the same registered sources this
        matcher already tracks."""
        with self._lock:
            return list(self._sources)

    def scan(self, payload: str) -> list[ApproxMatch]:
        with self._lock:
            sources = list(self._sources)
        matches = []
        for fragment_id, source in sources:
            cov = best_coverage(source, payload, self.ngram_size)
            if cov >= self.threshold:
                matches.append(ApproxMatch(fragment_id=fragment_id, coverage=cov))
        return matches

    def scan_sweep(self, payload: str, thresholds: list[float]) -> list[tuple[float, int]]:
        """Same scan, but sweeping a set of thresholds instead of the
        single enforced one — used by the Week 4/5 evaluation harness to
        build a precision/recall curve rather than a single point."""
        with self._lock:
            sources = list(self._sources)
        results = []
        for t in thresholds:
            count = sum(
                1 for _fid, source in sources
                if best_coverage(source, payload, self.ngram_size) >= t
            )
            results.append((t, count))
        return results
