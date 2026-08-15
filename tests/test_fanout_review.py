from provproxy.config import AblationTier, ApproxMatchingConfig, CrossCallWindowConfig, DecodeLimits, PolicyFile
from provproxy.session import Session
from provproxy import pipeline


def _policy(enabled: bool):
    return PolicyFile(
        version='fanout-test',
        active_tier=AblationTier.V4,
        approx_matching=ApproxMatchingConfig(),
        decode_limits=DecodeLimits(),
        cross_call_window=CrossCallWindowConfig(
            review_threshold=0.30,
            fanout_review_threshold=0.30 if enabled else None,
            fanout_min_destinations=2,
        ),
    )


def test_fanout_guard_is_disabled_by_default():
    secret='SYNTHETIC_FANOUT_SECRET_ABCDEF123456'
    p=_policy(False)
    s=Session('s',p,ttl_seconds=300)
    s.register_sensitive_fragment('src',secret)
    triggered=False
    for i in range(0,len(secret),3):
        r=pipeline.evaluate(p,s,secret[i:i+3],p.decode_limits,destination_allowed=False,destination_domain=f'https://d{i}.example')
        triggered |= r.review_required or r.matched
    assert not triggered


def test_fanout_guard_reviews_distributed_fragments():
    secret='SYNTHETIC_FANOUT_SECRET_ABCDEF123456'
    p=_policy(True)
    s=Session('s',p,ttl_seconds=300)
    s.register_sensitive_fragment('src',secret)
    result=None
    for i in range(0,len(secret),3):
        result=pipeline.evaluate(p,s,secret[i:i+3],p.decode_limits,destination_allowed=False,destination_domain=f'https://d{i}.example')
        if result.review_required:
            break
    assert result is not None
    assert result.review_required
    assert result.matched is False
    assert result.matched_via == 'cross-destination-review'
    assert result.enforcement_blocked is True


def test_duplicate_piece_across_destinations_does_not_inflate_coverage():
    secret='SYNTHETIC_FANOUT_SECRET_ABCDEF123456'
    p=_policy(True)
    s=Session('s',p,ttl_seconds=300)
    s.register_sensitive_fragment('src',secret)
    piece=secret[:3]
    for i in range(20):
        r=pipeline.evaluate(p,s,piece,p.decode_limits,destination_allowed=False,destination_domain=f'https://d{i}.example')
        assert not r.review_required
        assert not r.matched
