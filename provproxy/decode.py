"""Transformation Tier (T2 / V2) — extracts candidate substrings from a
payload and recursively decodes them (Base64, URL-safe Base64, Hex, JSON
escapes) so obfuscated copies of a sensitive fragment are still visible to
the exact/approximate matchers underneath.

Every limit here maps directly to Section 5G of the proposal — not soft
guidelines, but what keeps a maliciously-shaped payload (e.g. deeply
nested Base64) from turning "decode and match" into a denial-of-service
against the proxy itself.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from urllib.parse import unquote

from .config import DecodeLimits

_TOKEN_SPLIT_RE = re.compile(r'[\s"\'{},:]+')


@dataclass
class Candidate:
    text: str
    nesting_depth: int


class Decoder:
    def __init__(self, limits: DecodeLimits):
        self.limits = limits

    def expand(self, payload: str) -> list[Candidate]:
        out = [Candidate(text=_truncate(payload, self.limits.max_candidate_len_bytes), nesting_depth=0)]
        for candidate in self._extract_candidates(payload):
            self._decode_recursive(candidate, 0, out)
        return out

    def _extract_candidates(self, payload: str) -> list[str]:
        tokens = [t for t in _TOKEN_SPLIT_RE.split(payload) if len(t) >= 8]
        tokens = tokens[: self.limits.max_candidates_per_payload]
        return [_truncate(t, self.limits.max_candidate_len_bytes) for t in tokens]

    def _decode_recursive(self, candidate: str, depth: int, out: list[Candidate]) -> None:
        if depth >= self.limits.max_nesting_depth:
            return

        for decoded in self._try_all_decoders(candidate):
            expansion_ratio = len(decoded) / max(len(candidate), 1)
            if expansion_ratio > self.limits.max_expansion_ratio:
                cap = int(len(candidate) * self.limits.max_expansion_ratio)
                bounded = _truncate(decoded, min(cap, self.limits.max_candidate_len_bytes))
            else:
                bounded = _truncate(decoded, self.limits.max_candidate_len_bytes)

            out.append(Candidate(text=bounded, nesting_depth=depth + 1))
            self._decode_recursive(bounded, depth + 1, out)

    def _try_all_decoders(self, s: str) -> list[str]:
        results = []
        for fn in (_try_base64, _try_hex, _try_url, _try_json_escape):
            decoded = fn(s)
            if decoded is not None:
                results.append(decoded)
        return results


def _truncate(s: str, max_bytes: int) -> str:
    if len(s.encode("utf-8", errors="ignore")) <= max_bytes:
        return s
    return s[:max_bytes]


def _try_base64(s: str) -> str | None:
    # Try padded string as-is, and the stripped string with padding
    # re-added — a manually-trimmed string fed straight to a
    # padding-required decoder silently fails otherwise.
    stripped = s.rstrip("=")
    padded = stripped + "=" * (-len(stripped) % 4)
    for candidate, altchars in ((s, None), (padded, None), (padded, "-_")):
        try:
            raw = base64.b64decode(candidate, altchars=altchars, validate=False)
            text = raw.decode("utf-8")
            if text:
                return text
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
    return None


def _try_hex(s: str) -> str | None:
    cleaned = "".join(s.split())
    if len(cleaned) % 2 != 0 or not cleaned or not all(c in "0123456789abcdefABCDEF" for c in cleaned):
        return None
    try:
        raw = bytes.fromhex(cleaned)
        text = raw.decode("utf-8")
        return text if text else None
    except (ValueError, UnicodeDecodeError):
        return None


def _try_url(s: str) -> str | None:
    if "%" not in s:
        return None
    decoded = unquote(s)
    return decoded if decoded != s and decoded else None


def _try_json_escape(s: str) -> str | None:
    if "\\u" not in s and "\\n" not in s and '\\"' not in s:
        return None
    try:
        decoded = json.loads(f'"{s}"')
        return decoded if decoded != s and decoded else None
    except json.JSONDecodeError:
        return None
