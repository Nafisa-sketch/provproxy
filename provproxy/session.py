"""Per-session state: owns the exact matcher (matcher.py) and the
approximate matcher (approx.py) — and, once wired, the cross-call windows
(crosscall.py). One Session exists per MCP client connection."""
from __future__ import annotations

from .approx import ApproxMatcher
from .config import PolicyFile
from .crosscall import CrossCallRegistry
from .matcher import SessionMatcher


class Session:
    def __init__(self, session_id: str, policy: PolicyFile, ttl_seconds: float):
        self.session_id = session_id
        self.exact_matcher = SessionMatcher(ttl_seconds=ttl_seconds)
        self.approx_matcher = ApproxMatcher(
            ngram_size=policy.approx_matching.ngram_size,
            threshold=policy.approx_matching.coverage_threshold,
        )
        self.cross_call_registry = CrossCallRegistry(policy.cross_call_window)

    def register_sensitive_fragment(self, fragment_id: str, raw_text: str) -> None:
        """Register a fragment of sensitive data observed in a tool
        *result* (e.g. read_file contents from a sensitive path), so
        subsequent outbound calls can be checked against it."""
        self.exact_matcher.register_fragment(fragment_id, raw_text)
        self.approx_matcher.register_source(fragment_id, raw_text)

    def expire_if_stale(self) -> None:
        if self.exact_matcher.is_expired():
            self.exact_matcher.expire()
