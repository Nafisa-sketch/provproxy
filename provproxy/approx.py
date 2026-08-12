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

import re
from dataclasses import dataclass

_KV_VALUE_RE = re.compile(r"\w+=(\S+)")


def ngrams(s: str, n: int) -> set[str]:
    if n <= 0 or len(s) < n:
        return set()
    return {s[i : i + n] for i in range(len(s) - n + 1)}


def extract_reconstructable_value(text: str) -> str:
    """Extract `key=value`-shaped values from `text` and concatenate them
    in order, with delimiters/field-name noise stripped. Falls back to
    the text unchanged if no `key=value` pattern is present, so behavior
    for payloads without this structure (free text, already-clean
    content) is unaffected."""
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

    def register_source(self, fragment_id: str, raw_text: str) -> None:
        self._sources.append((fragment_id, raw_text))

    def sources(self) -> list[tuple[str, str]]:
        """Public accessor for (fragment_id, raw_text) pairs — used by V4
        cross-call scoring, which needs the same registered sources this
        matcher already tracks."""
        return list(self._sources)

    def scan(self, payload: str) -> list[ApproxMatch]:
        matches = []
        for fragment_id, source in self._sources:
            cov = best_coverage(source, payload, self.ngram_size)
            if cov >= self.threshold:
                matches.append(ApproxMatch(fragment_id=fragment_id, coverage=cov))
        return matches

    def scan_sweep(self, payload: str, thresholds: list[float]) -> list[tuple[float, int]]:
        """Same scan, but sweeping a set of thresholds instead of the
        single enforced one — used by the Week 4/5 evaluation harness to
        build a precision/recall curve rather than a single point."""
        results = []
        for t in thresholds:
            count = sum(
                1 for _fid, source in self._sources
                if best_coverage(source, payload, self.ngram_size) >= t
            )
            results.append((t, count))
        return results
