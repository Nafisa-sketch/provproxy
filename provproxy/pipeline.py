"""Ablation Pipeline — given the `active_tier` in the policy file, runs a
`tools/call` payload through exactly the matchers that tier enables. This
is what makes the V0-V4 matrix a runtime switch rather than five different
programs."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from .config import AblationTier, DecodeLimits, PolicyFile
from .decode import Decoder
from .session import Session


@dataclass
class TierResult:
    tier: str
    matched: bool
    matched_via: Optional[str] = None  # "exact" | "exact-decoded" | "approximate"
    matched_fragment_id: Optional[str] = None
    approx_coverage: Optional[float] = None
    # V0 integration (fixes the B5 gap the evaluation harness surfaced):
    # `matched` is the pure detection signal — did the payload contain
    # provenance-linked content? — kept independent of destination so it
    # still measures what the research question is actually about.
    # `enforcement_blocked` is the downstream decision after consulting
    # the V0 destination allow-list: a match against an allow-listed
    # destination is still a match (detected), but is NOT enforcement-
    # blocked. Defaults mirror "no destination info available" as
    # fail-closed (blocked whenever matched).
    destination_allowed: Optional[bool] = None
    enforcement_blocked: bool = False


def evaluate(
    policy: PolicyFile,
    session: Session,
    payload_text: str,
    decode_limits: DecodeLimits,
    destination_allowed: Optional[bool] = None,
    destination_domain: Optional[str] = None,
) -> TierResult:
    result = _evaluate_detection(policy, session, payload_text, decode_limits, destination_domain)
    result.destination_allowed = destination_allowed

    if result.matched:
        # Fail-closed: if destination_allowed wasn't determined (None),
        # treat it the same as "not allowed" — a match blocks by default.
        result.enforcement_blocked = not bool(destination_allowed)
    else:
        result.enforcement_blocked = False

    return result


def _evaluate_detection(
    policy: PolicyFile,
    session: Session,
    payload_text: str,
    decode_limits: DecodeLimits,
    destination_domain: Optional[str] = None,
) -> TierResult:
    tier = policy.active_tier

    if tier == AblationTier.V0:
        return TierResult(tier="v0", matched=False)

    # V1: exact match against the raw payload.
    snapshot = session.exact_matcher.current_snapshot()
    exact_hits = snapshot.scan(payload_text)
    if exact_hits:
        hit = exact_hits[0]
        return TierResult(
            tier=tier.value, matched=True, matched_via="exact", matched_fragment_id=hit.matched_fragment_id
        )

    # V2+: also check decoded candidates against the exact matcher.
    if tier.at_least(AblationTier.V2):
        decoder = Decoder(decode_limits)
        for candidate in decoder.expand(payload_text):
            hits = snapshot.scan(candidate.text)
            if hits:
                return TierResult(
                    tier=tier.value,
                    matched=True,
                    matched_via="exact-decoded",
                    matched_fragment_id=hits[0].matched_fragment_id,
                )

    # V3+: approximate N-gram coverage against the raw payload.
    if tier.at_least(AblationTier.V3):
        approx_hits = session.approx_matcher.scan(payload_text)
        if approx_hits:
            m = approx_hits[0]
            return TierResult(
                tier=tier.value,
                matched=True,
                matched_via="approximate",
                matched_fragment_id=m.fragment_id,
                approx_coverage=m.coverage,
            )

    # V4: cross-call accumulation — did this call, combined with earlier
    # calls to the SAME destination in this session, add up to enough of
    # a registered secret to cross the threshold? Each call's n-grams are
    # recorded into a window scoped by (session, destination, source_id)
    # — one independent window PER tracked secret — regardless of
    # whether this single call alone matches, so a secret split thin
    # enough to evade V1-V3 on every individual call can still be caught
    # once enough slices land. Scoping by source_id (not just session +
    # destination) prevents two unrelated tracked secrets heading to the
    # same destination from contaminating each other's accumulated
    # evidence.
    if tier.at_least(AblationTier.V4) and destination_domain:
        n = policy.approx_matching.ngram_size

        for fragment_id, source_text in session.approx_matcher.sources():
            window = session.cross_call_registry.window_for(
                session.session_id, destination_domain, fragment_id
            )
            window.record(payload_text)

            coverage = window.accumulated_coverage(source_text, n)
            if coverage is not None and coverage >= policy.approx_matching.coverage_threshold:
                return TierResult(
                    tier=tier.value,
                    matched=True,
                    matched_via="cross-call",
                    matched_fragment_id=fragment_id,
                    approx_coverage=coverage,
                )

    return TierResult(tier=tier.value, matched=False)


def flatten_json_strings(value: Any) -> str:
    """Flatten a JSON value's string leaves into one scan target — cheap
    and sufficient for the exact/approximate matchers, which work over
    raw text."""
    parts: list[str] = []
    _flatten_recursive(value, parts)
    return " ".join(parts)


def _flatten_recursive(value: Any, out: list[str]) -> None:
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, list):
        for v in value:
            _flatten_recursive(v, out)
    elif isinstance(value, dict):
        for v in value.values():
            _flatten_recursive(v, out)
