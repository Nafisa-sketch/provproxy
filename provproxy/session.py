"""Per-session provenance state.

When P6 persistence is enabled, the Session restores BOTH registered
sensitive sources and V4 cross-call evidence for the same stable session_id.
"""
from __future__ import annotations

from .approx import ApproxMatcher
from .config import PolicyFile
from .crosscall import CrossCallRegistry
from .fanout import FanoutRegistry
from .matcher import SessionMatcher
from .persistence import get_shared_persistence


class Session:
    def __init__(self, session_id: str, policy: PolicyFile, ttl_seconds: float):
        self.session_id = session_id
        self.policy = policy
        self.exact_matcher = SessionMatcher(ttl_seconds=ttl_seconds)
        self.approx_matcher = ApproxMatcher(
            ngram_size=policy.approx_matching.ngram_size,
            threshold=policy.approx_matching.coverage_threshold,
        )

        self.persistent_state = None
        if policy.persistence.enabled:
            self.persistent_state = get_shared_persistence(
                policy.persistence,
                ttl_seconds=policy.cross_call_window.window_seconds,
            )

            # Restore the source corpus FIRST. Without this, restored
            # outbound evidence cannot be scored after restart.
            for fragment_id, source_text in self.persistent_state.get_sources(
                session_id
            ):
                self.exact_matcher.register_fragment(fragment_id, source_text)
                self.approx_matcher.register_source(fragment_id, source_text)

        self.cross_call_registry = CrossCallRegistry(
            policy.cross_call_window,
            persistent_state=self.persistent_state,
        )

        # Fan-out review remains an optional review-only layer. Its historical
        # in-memory semantics are preserved in this patch; strict V4 hard-match
        # persistence is the P6 guarantee being integrated here.
        self.fanout_registry = FanoutRegistry(policy.cross_call_window)

    def register_sensitive_fragment(self, fragment_id: str, raw_text: str) -> None:
        """Register sensitive source material observed in a tool result."""
        # Persist first. If this fails while persistence is enabled, the
        # exception propagates instead of silently claiming restart safety.
        if self.persistent_state is not None:
            self.persistent_state.register_source(
                self.session_id, fragment_id, raw_text
            )

        self.exact_matcher.register_fragment(fragment_id, raw_text)
        self.approx_matcher.register_source(fragment_id, raw_text)

    def expire_if_stale(self) -> None:
        if self.exact_matcher.is_expired():
            self.exact_matcher.expire()
