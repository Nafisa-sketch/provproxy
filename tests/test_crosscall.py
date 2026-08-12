from provproxy.config import CrossCallWindowConfig
from provproxy.crosscall import CrossCallRegistry, CrossCallWindow, DestinationId


def _dest():
    return DestinationId(scheme="https", host="attacker.example", port=443, server_id="network-egress")


def test_window_respects_count_bound():
    cfg = CrossCallWindowConfig(window_seconds=300, window_max_calls=3)
    w = CrossCallWindow(cfg)
    for i in range(5):
        w.record(f"chunk{i}=data{i}")
    assert len(w) == 3


def test_registry_scopes_per_session_destination_and_source():
    cfg = CrossCallWindowConfig()
    registry = CrossCallRegistry(cfg)
    registry.window_for("session-a", "attacker.example", "frag-1").record("x=1")
    registry.window_for("session-b", "attacker.example", "frag-1").record("y=2")
    assert len(registry) == 2


def test_registry_isolates_different_sources_to_the_same_destination():
    """The gap this fix closes: two DIFFERENT tracked secrets heading to
    the same destination in the same session must not share accumulated
    evidence — each source_id gets its own window."""
    cfg = CrossCallWindowConfig()
    registry = CrossCallRegistry(cfg)
    w1 = registry.window_for("session-a", "attacker.example", "frag-1")
    w2 = registry.window_for("session-a", "attacker.example", "frag-2")
    assert w1 is not w2
    w1.record("ab=cd")
    assert len(w1) == 1
    assert len(w2) == 0  # frag-2's window is untouched by frag-1's call


def test_scoring_returns_zero_when_nothing_recorded_yet():
    w = CrossCallWindow(CrossCallWindowConfig())
    assert w.accumulated_coverage("AKIASECRETSOURCE", 4) == 0.0


def test_ordered_concatenation_recovers_cross_call_boundary_ngrams():
    """The core fix: splitting a secret's chunks across separate calls
    and recording them in key=value form should recover full coverage
    once reassembled in arrival order — not just a union of independent
    per-call n-grams, which loses boundary continuity."""
    w = CrossCallWindow(CrossCallWindowConfig())
    secret = "AKIA1234ABCD5678EFGH"
    # Split into 4-char chunks (the size that used to fail entirely),
    # sent as separate key=value-shaped calls.
    chunks = [secret[i : i + 4] for i in range(0, len(secret), 4)]
    for i, c in enumerate(chunks):
        w.record(f"part{i}={c}")
    coverage = w.accumulated_coverage(secret, 4)
    assert coverage == 1.0, f"expected full reconstruction, got {coverage}"


def test_out_of_order_calls_still_get_union_fallback_coverage():
    """Calls arriving out of the secret's original order shouldn't
    reconstruct perfectly via ordered concatenation, but the per-entry
    union fallback should still give partial credit for whichever
    n-grams each individual chunk does contain."""
    w = CrossCallWindow(CrossCallWindowConfig())
    secret = "AKIA1234ABCD5678EFGH"
    chunks = [secret[i : i + 4] for i in range(0, len(secret), 4)]
    for c in reversed(chunks):  # deliberately out of order
        w.record(f"x={c}")
    coverage = w.accumulated_coverage(secret, 4)
    assert coverage > 0.0  # union fallback still finds each chunk's own n-grams
