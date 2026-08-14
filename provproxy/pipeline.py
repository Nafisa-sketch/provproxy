"""Ablation Pipeline — given the `active_tier` in the policy file, runs a
`tools/call` payload through exactly the matchers that tier enables. This
is what makes the V0-V4 matrix a runtime switch rather than five different
programs."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from .config import AblationTier, DecodeLimits, PolicyFile
from .approx import best_coverage, extract_reconstructable_value
from .decode import Decoder
from .session import Session


@dataclass
class TierResult:
    tier: str
    matched: bool
    matched_via: Optional[str] = None  # "exact" | "exact-decoded" | "approximate"
    matched_fragment_id: Optional[str] = None
    approx_coverage: Optional[float] = None
    # Optional V4 early-containment signal. This is NOT counted as a hard
    # provenance match; it means cumulative source-bound evidence crossed a
    # lower policy threshold and the request should be held for approval (or
    # fail closed if no approval path is available).
    review_required: bool = False
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


def _select_crosscall_evidence(
    source_text: str,
    payload_text: str,
    decode_limits: DecodeLimits,
    ngram_size: int,
) -> str:
    """Choose the most source-relevant representation of one outbound call.

    V4 operates on a source-specific window, so it can safely normalize
    the current call before accumulation.  We first strip structured
    key/value or JSON noise, then try the same bounded decoders used by
    V2.  Exact substrings of the registered source are preferred even
    when shorter than ``ngram_size``; otherwise the candidate with the
    greatest approximate source coverage is retained.

    This enables transformation+fragmentation chains (e.g. each secret
    chunk Base64/Hex/URL/JSON encoded independently) without lowering the
    global threshold or changing V1-V3 semantics.
    """
    cleaned = extract_reconstructable_value(payload_text)
    decoder = Decoder(decode_limits)

    candidates: list[str] = [cleaned]
    for candidate in decoder.expand(cleaned):
        if candidate.text not in candidates:
            candidates.append(candidate.text)

    exact_substrings = [c for c in candidates if c and c in source_text]
    if exact_substrings:
        return max(exact_substrings, key=len)

    return max(
        candidates,
        key=lambda c: best_coverage(source_text, c, ngram_size),
        default=cleaned,
    )


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

    if result.matched or result.review_required:
        # Fail-closed: if destination_allowed wasn't determined (None),
        # treat it the same as "not allowed". A hard match blocks; an early
        # review signal is held pending approval and therefore also does not
        # forward on an untrusted/unknown destination.
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
            # Score before and after the current call.  A cross-call
            # detection event is emitted only when THIS call causes the
            # source/destination window to cross the threshold.  Without
            # this transition check, once a destination crossed the
            # threshold every later benign call inherited matched=True
            # until the window expired ("sticky" false alerts).
            evidence_text = _select_crosscall_evidence(
                source_text, payload_text, decode_limits, n
            )
            coverage_before, coverage_after = window.record_and_measure(
                evidence_text, source_text, n
            )

            threshold = policy.approx_matching.coverage_threshold
            if coverage_before < threshold <= coverage_after:
                return TierResult(
                    tier=tier.value,
                    matched=True,
                    matched_via="cross-call",
                    matched_fragment_id=fragment_id,
                    approx_coverage=coverage_after,
                )

            review_threshold = policy.cross_call_window.review_threshold
            if (
                review_threshold is not None
                and 0.0 < review_threshold < threshold
                and coverage_before < review_threshold <= coverage_after
            ):
                return TierResult(
                    tier=tier.value,
                    matched=False,
                    matched_via="cross-call-review",
                    matched_fragment_id=fragment_id,
                    approx_coverage=coverage_after,
                    review_required=True,
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
