from provproxy.config import AblationTier, ApproxMatchingConfig, PolicyFile, DecodeLimits
from provproxy.session import Session
from provproxy import pipeline

# Secret + chunking matches fixtures.py's design: chunks stay under
# matcher.py's 8-char reverse-match floor (invisible to V1 alone).
SECRET = "AKIA2HAFCFGWPBBBW43JFLHA65PE"
CHUNKS = [SECRET[i : i + 7] for i in range(0, len(SECRET), 7)]


def _v4_policy():
    return PolicyFile(
        version="test",
        active_tier=AblationTier.V4,
        approx_matching=ApproxMatchingConfig(ngram_size=4, coverage_threshold=0.6),
        decode_limits=DecodeLimits(),
    )


def _kv_call(index: int, chunk: str) -> str:
    return f"part{index}={chunk}"


def test_v4_catches_secret_split_across_multiple_key_value_calls():
    """With the ordered-reconstruction fix, key=value-shaped chunks sent
    across separate calls to the same destination should reassemble in
    arrival order and cross the coverage threshold once enough of the
    secret has landed."""
    policy = _v4_policy()
    session = Session(session_id="s1", policy=policy, ttl_seconds=300)
    session.register_sensitive_fragment("frag-1", SECRET)

    results = [
        pipeline.evaluate(
            policy, session, _kv_call(i, chunk), policy.decode_limits, destination_domain="attacker.example"
        )
        for i, chunk in enumerate(CHUNKS)
    ]
    assert results[-1].matched is True
    assert results[-1].matched_via == "cross-call"
    assert results[-1].matched_fragment_id == "frag-1"


def test_v4_does_not_cross_correlate_different_destinations():
    policy = _v4_policy()
    session = Session(session_id="s1", policy=policy, ttl_seconds=300)
    session.register_sensitive_fragment("frag-1", SECRET)

    domains = ["site-a.example", "site-b.example", "site-c.example", "site-d.example"]
    results = [
        pipeline.evaluate(
            policy, session, _kv_call(i, chunk), policy.decode_limits, destination_domain=domain
        )
        for i, (chunk, domain) in enumerate(zip(CHUNKS, domains))
    ]
    assert not any(r.matched for r in results)


def test_v3_tier_never_reaches_v4_cross_call_logic():
    policy = PolicyFile(
        version="test",
        active_tier=AblationTier.V3,
        approx_matching=ApproxMatchingConfig(ngram_size=4, coverage_threshold=0.6),
        decode_limits=DecodeLimits(),
    )
    session = Session(session_id="s1", policy=policy, ttl_seconds=300)
    session.register_sensitive_fragment("frag-1", SECRET)

    results = [
        pipeline.evaluate(
            policy, session, _kv_call(i, chunk), policy.decode_limits, destination_domain="attacker.example"
        )
        for i, chunk in enumerate(CHUNKS)
    ]
    # V3 doesn't do CROSS-CALL accumulation — even after all chunks have
    # gone out across separate calls, each individual call is evaluated
    # independently at V3, so none should match (V3's own intra-request
    # reconstruction only helps when fragments arrive in the SAME call).
    assert not any(r.matched for r in results)
