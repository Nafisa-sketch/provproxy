"""Explicit tests for each requirement of the evidence-accumulation fix:
  1-4. Cross-call accumulation succeeds at chunk sizes 4, 5, 6, and 7.
  5. Benign repeated fragments do not cause enforcement.
  6. Evidence from different destinations does not combine.
  7. Evidence from different sessions does not combine.

Threshold (0.6), ngram_size (4), and TTL/memory bounds are all left at
their existing defaults throughout — nothing here changes global config.
"""
from provproxy.config import AblationTier, ApproxMatchingConfig, DecodeLimits, PolicyFile
from provproxy.session import Session
from provproxy import pipeline

SECRET = "AKIA2HAFCFGWPBBBW43JFLHA65PE"  # 28 chars


def _policy(tier=AblationTier.V4):
    return PolicyFile(
        version="test",
        active_tier=tier,
        approx_matching=ApproxMatchingConfig(ngram_size=4, coverage_threshold=0.6),
        decode_limits=DecodeLimits(),
    )


def _split_and_send(secret: str, chunk_size: int, session_id: str, destination: str):
    policy = _policy()
    session = Session(session_id=session_id, policy=policy, ttl_seconds=300)
    session.register_sensitive_fragment("frag-1", secret)

    chunks = [secret[i : i + chunk_size] for i in range(0, len(secret), chunk_size)]
    results = []
    for i, chunk in enumerate(chunks):
        result = pipeline.evaluate(
            policy, session, f"part{i}={chunk}", policy.decode_limits, destination_domain=destination
        )
        results.append(result)
    return results


def test_1_chunk_size_4_accumulates_to_a_match():
    results = _split_and_send(SECRET, chunk_size=4, session_id="s1", destination="attacker.example")
    assert any(r.matched and r.matched_via == "cross-call" for r in results)


def test_2_chunk_size_5_accumulates_to_a_match():
    results = _split_and_send(SECRET, chunk_size=5, session_id="s2", destination="attacker.example")
    assert any(r.matched and r.matched_via == "cross-call" for r in results)


def test_3_chunk_size_6_accumulates_to_a_match():
    results = _split_and_send(SECRET, chunk_size=6, session_id="s3", destination="attacker.example")
    assert any(r.matched and r.matched_via == "cross-call" for r in results)


def test_4_chunk_size_7_accumulates_to_a_match():
    results = _split_and_send(SECRET, chunk_size=7, session_id="s4", destination="attacker.example")
    assert any(r.matched and r.matched_via == "cross-call" for r in results)


def test_5_benign_repeated_fragments_do_not_cause_enforcement():
    """Sending the SAME benign, non-sensitive text repeatedly to the same
    destination must never accumulate into a false match — there's no
    registered source for it to accumulate evidence against."""
    policy = _policy()
    session = Session(session_id="s5", policy=policy, ttl_seconds=300)
    session.register_sensitive_fragment("frag-1", SECRET)  # a real secret IS tracked...

    benign_text = "field0=timeout field1=retries field2=region"  # ...but this isn't it, ever
    results = [
        pipeline.evaluate(
            policy, session, benign_text, policy.decode_limits, destination_domain="api.github.com"
        )
        for _ in range(10)  # repeated many times — should never accumulate to a match
    ]
    assert not any(r.enforcement_blocked for r in results)


def test_6_evidence_from_different_destinations_does_not_combine():
    policy = _policy()
    session = Session(session_id="s6", policy=policy, ttl_seconds=300)
    session.register_sensitive_fragment("frag-1", SECRET)

    chunks = [SECRET[i : i + 4] for i in range(0, len(SECRET), 4)]
    domains = ["site-a.example", "site-b.example", "site-c.example", "site-d.example",
               "site-e.example", "site-f.example", "site-g.example"]
    results = [
        pipeline.evaluate(
            policy, session, f"part{i}={chunk}", policy.decode_limits,
            destination_domain=domains[i % len(domains)],
        )
        for i, chunk in enumerate(chunks)
    ]
    # Each chunk went to a DIFFERENT destination — no single destination's
    # window ever accumulated more than one chunk's worth of evidence.
    assert not any(r.matched for r in results)


def test_7_evidence_from_different_sessions_does_not_combine():
    policy = _policy()
    chunks = [SECRET[i : i + 4] for i in range(0, len(SECRET), 4)]

    results = []
    for i, chunk in enumerate(chunks):
        # A FRESH session for every single chunk — simulates N different
        # attackers/conversations each sending one small piece, none of
        # which should be able to combine with another's evidence.
        session = Session(session_id=f"isolated-session-{i}", policy=policy, ttl_seconds=300)
        session.register_sensitive_fragment("frag-1", SECRET)
        result = pipeline.evaluate(
            policy, session, f"part{i}={chunk}", policy.decode_limits, destination_domain="attacker.example"
        )
        results.append(result)

    assert not any(r.matched for r in results)
