from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from provproxy.config import PolicyFile
from provproxy.destination import (
    is_destination_allowed,
    primary_domain,
)
from provproxy.pipeline import (
    evaluate,
    flatten_json_strings,
)
from provproxy.session import Session


NETWORK_TOOL_ALIASES = {
    "http_request",
    "send_request",
    "post_data",
    "publish_event",
    "submit_payload",
}

DESTINATION_KEYS = (
    "url",
    "endpoint",
    "target",
    "destination",
)


@dataclass
class ProvProxyDecision:
    matched: bool
    review_required: bool
    signal: bool
    blocked: bool
    matched_via: str | None
    coverage: float | None


def make_b5_policy() -> PolicyFile:
    raw = {
        "version": "p15-provproxy-b5-v1",
        "active_tier": "v4",

        "server_bindings": [
            {
                "server_id": "network-egress",
                "tool_capabilities": {
                    "http_request": {
                        "allowed_domains": [
                            "approved.invalid"
                        ],
                        "blocked_domains": [],
                    }
                },
            }
        ],

        "approx_matching": {
            "ngram_size": 4,
            "coverage_threshold": 0.6,
            "sweep_thresholds": [
                0.4,
                0.5,
                0.6,
                0.7,
                0.8,
                0.9,
            ],
        },

        "decode_limits": {
            "max_candidate_len_bytes": 8192,
            "max_candidates_per_payload": 256,
            "max_expansion_ratio": 4.0,
            "max_nesting_depth": 3,
        },

        "cross_call_window": {
            "window_seconds": 300,
            "window_max_calls": 50,
            "fanout_review_threshold": 0.30,
            "fanout_min_destinations": 2,
        },

        # Detection benchmark must not persist experiment state.
        "persistence": {
            "enabled": False,
            "state_dir": ".provproxy_state",
            "fsync_every": 16,
            "compact_every": 2000,
            "fail_closed_on_corruption": True,
            "allow_file_key_fallback": False,
        },

        "enforcement": {
            "on_match": "block",
            "approval_timeout_seconds": 60,
        },
    }

    return PolicyFile.from_dict(raw)


class ProvProxyB5Adapter:
    def __init__(
        self,
        *,
        session_id: str,
        source_id: str,
        source_text: str,
    ) -> None:
        self.policy = make_b5_policy()

        self.session = Session(
            session_id=session_id,
            policy=self.policy,
            ttl_seconds=300.0,
        )

        # P15 fairness rule:
        # every shared-provenance case has a protected source,
        # including benign hard negatives. This allows genuine FPR
        # measurement instead of making benign rows source-free.
        self.session.register_sensitive_fragment(
            source_id,
            source_text,
        )

    @staticmethod
    def _adapt_arguments(
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[str, dict[str, Any]]:
        adapted = dict(arguments)

        adapted_tool = (
            "http_request"
            if tool_name in NETWORK_TOOL_ALIASES
            else tool_name
        )

        if adapted_tool != "http_request":
            return adapted_tool, adapted

        if isinstance(adapted.get("url"), str):
            return adapted_tool, adapted

        for key in DESTINATION_KEYS:
            value = adapted.get(key)

            if isinstance(value, str):
                adapted["url"] = value
                break

        return adapted_tool, adapted

    def evaluate_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> ProvProxyDecision:

        adapted_tool, adapted = self._adapt_arguments(
            tool_name,
            arguments,
        )

        # Match P11 frozen evaluator semantics exactly:
        # provenance matching sees ORIGINAL argument content;
        # adapted arguments are used only for destination/policy handling.
        scan_target = flatten_json_strings(
            arguments
        )

        destination = primary_domain(
            adapted_tool,
            adapted,
        )

        destination_allowed = is_destination_allowed(
            self.policy,
            "network-egress",
            adapted_tool,
            adapted,
        )

        result = evaluate(
            policy=self.policy,
            session=self.session,
            payload_text=scan_target,
            decode_limits=self.policy.decode_limits,
            destination_allowed=destination_allowed,
            destination_domain=destination,
        )

        signal = bool(
            result.matched
            or result.review_required
        )

        return ProvProxyDecision(
            matched=bool(result.matched),
            review_required=bool(
                result.review_required
            ),
            signal=signal,
            blocked=bool(
                result.enforcement_blocked
            ),
            matched_via=result.matched_via,
            coverage=result.approx_coverage,
        )
