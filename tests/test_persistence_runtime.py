from __future__ import annotations

import os
from pathlib import Path

import pytest

from provproxy.config import (
    AblationTier,
    ApproxMatchingConfig,
    CrossCallWindowConfig,
    PersistenceConfig,
    PolicyFile,
)
from provproxy.persistence import (
    PersistenceCorruptionError,
    reset_shared_persistence_for_tests,
)
from provproxy.pipeline import evaluate
from provproxy.session import Session


DEST = "https://evil.com:443/http_post"


def _policy(tmp_path: Path) -> PolicyFile:
    return PolicyFile(
        version="p6-test",
        active_tier=AblationTier.V4,
        approx_matching=ApproxMatchingConfig(
            ngram_size=4,
            coverage_threshold=0.6,
        ),
        cross_call_window=CrossCallWindowConfig(
            window_seconds=300,
            window_max_calls=50,
        ),
        persistence=PersistenceConfig(
            enabled=True,
            state_dir=str(tmp_path / "state"),
            fsync_every=1,
            compact_every=10000,
            fail_closed_on_corruption=True,
            allow_file_key_fallback=(os.name != "nt"),
        ),
    )


def test_sources_and_v4_evidence_survive_restart(tmp_path):
    policy = _policy(tmp_path)
    secret = "CONFIDENTIAL_EXFIL_DATA_999"

    # MatcherSnapshot's reverse-exact floor is 8 chars, so every test
    # fragment is intentionally <8 chars. No individual fragment can be
    # classified as the V1 reverse-exact case; V4 accumulation must do
    # the work.
    chunks = [
        "CONF",
        "IDEN",
        "TIAL",
        "_EXF",
        "IL_D",
        "ATA_",
        "999",
    ]
    assert "".join(chunks) == secret
    assert all(len(piece) < 8 for piece in chunks)

    s1 = Session("stable-session", policy, ttl_seconds=300)
    s1.register_sensitive_fragment("src-1", secret)

    # Two 4-char pieces remain below 60% coverage before restart.
    for piece in chunks[:2]:
        r = evaluate(
            policy,
            s1,
            piece,
            policy.decode_limits,
            destination_allowed=False,
            destination_domain=DEST,
        )
        assert r.matched is False, (
            f"pre-restart fragment {piece!r} unexpectedly matched "
            f"via {r.matched_via!r}"
        )

    # Fresh-process simulation.
    reset_shared_persistence_for_tests()

    s2 = Session("stable-session", policy, ttl_seconds=300)

    # Source corpus must be restored as well as outbound evidence.
    assert ("src-1", secret) in s2.approx_matcher.sources()

    matched_results = []
    for piece in chunks[2:]:
        r = evaluate(
            policy,
            s2,
            piece,
            policy.decode_limits,
            destination_allowed=False,
            destination_domain=DEST,
        )
        if r.matched:
            matched_results.append(r)
            break

    assert matched_results, "V4 did not detect after persisted evidence was restored"
    assert matched_results[0].matched_via == "cross-call"


def test_wrong_session_does_not_restore_sources(tmp_path):
    policy = _policy(tmp_path)
    s1 = Session("A", policy, ttl_seconds=300)
    s1.register_sensitive_fragment("src", "SECRET_A_LONG_VALUE")
    reset_shared_persistence_for_tests()

    s2 = Session("B", policy, ttl_seconds=300)
    assert s2.approx_matcher.sources() == []


def test_tampered_journal_fails_closed(tmp_path):
    policy = _policy(tmp_path)
    s1 = Session("A", policy, ttl_seconds=300)
    s1.register_sensitive_fragment("src", "SECRET_A_LONG_VALUE")
    reset_shared_persistence_for_tests()

    journal = Path(policy.persistence.state_dir) / "state.journal"
    raw = bytearray(journal.read_bytes())
    assert raw

    idx = len(raw) // 2
    raw[idx] = ord("A") if raw[idx] != ord("A") else ord("B")
    journal.write_bytes(raw)

    with pytest.raises(PersistenceCorruptionError):
        Session("A", policy, ttl_seconds=300)
