from __future__ import annotations

from dataclasses import dataclass

from benchmarks.p15.provproxy_adapter import make_b5_policy
from provproxy.destination import (
    is_destination_allowed,
    primary_domain,
)
from provproxy.pipeline import (
    evaluate,
    flatten_json_strings,
)
from provproxy.session import Session


@dataclass
class P16Decision:
    matched: bool
    review_required: bool
    signal: bool
    blocked: bool
    matched_via: str | None
    coverage: float | None


class P16EarlyReviewAdapter:
    """
    P16 candidate.

    Identical to frozen P15 B5 except for one added
    cross-call early-review threshold.

    The hard provenance threshold remains 0.60.
    """

    def __init__(
        self,
        *,
        session_id: str,
        source_id: str,
        source_text: str,
        review_threshold: float,
    ) -> None:

        if not (0.0 < review_threshold < 0.60):
            raise ValueError(
                "review_threshold must satisfy "
                "0 < review_threshold < 0.60"
            )

        self.policy = make_b5_policy()

        # P16 adds ONLY this early-review threshold.
        # Frozen hard threshold remains 0.60.
        self.policy.cross_call_window.review_threshold = (
            float(review_threshold)
        )

        self.session = Session(
            session_id=session_id,
            policy=self.policy,
            ttl_seconds=300.0,
        )

        self.session.register_sensitive_fragment(
            source_id,
            source_text,
        )

    def evaluate_call(
        self,
        tool_name: str,
        arguments: dict,
    ) -> P16Decision:

        adapted_tool = tool_name
        adapted_arguments = dict(arguments)

        # Preserve frozen P15 matching semantics:
        # matching sees original argument content.
        payload_text = flatten_json_strings(
            arguments
        )

        destination = primary_domain(
            adapted_tool,
            adapted_arguments,
        )

        allowed = is_destination_allowed(
            self.policy,
            "network-egress",
            adapted_tool,
            adapted_arguments,
        )

        result = evaluate(
            policy=self.policy,
            session=self.session,
            payload_text=payload_text,
            decode_limits=self.policy.decode_limits,
            destination_allowed=allowed,
            destination_domain=destination,
        )

        return P16Decision(
            matched=bool(result.matched),
            review_required=bool(
                result.review_required
            ),
            signal=bool(
                result.matched
                or result.review_required
            ),
            blocked=bool(
                result.enforcement_blocked
            ),
            matched_via=result.matched_via,
            coverage=result.approx_coverage,
        )
