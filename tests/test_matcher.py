from provproxy.matcher import SessionMatcher


def test_exact_match_is_found():
    sm = SessionMatcher(ttl_seconds=300)
    sm.register_fragment("frag-1", "AKIAABCDEFGHIJKLMNOP")
    snap = sm.current_snapshot()
    hits = snap.scan("leaking: AKIAABCDEFGHIJKLMNOP here")
    assert len(hits) == 1
    assert hits[0].matched_fragment_id == "frag-1"


def test_expire_replaces_snapshot_but_old_reference_still_readable():
    sm = SessionMatcher(ttl_seconds=300)
    sm.register_fragment("frag-1", "secretvalue")
    old_snap = sm.current_snapshot()  # simulate an in-flight reader

    sm.expire()
    new_snap = sm.current_snapshot()

    # In-flight reader's held reference still finds the old pattern.
    assert len(old_snap.scan("secretvalue")) == 1
    # New scans against the fresh snapshot see nothing.
    assert len(new_snap.scan("secretvalue")) == 0


def test_no_fragments_means_no_matches():
    sm = SessionMatcher(ttl_seconds=300)
    snap = sm.current_snapshot()
    assert snap.scan("anything at all") == []


def test_reverse_match_catches_snippet_cut_from_larger_registered_secret():
    """A whole file's contents get registered (e.g. after reading an SSH
    key), but the attacker's outbound payload is just a short snippet cut
    out of it — the forward-only check would miss this, since the pattern
    (the whole file) is longer than the payload (the snippet), so it can
    never be "found inside" it. The reverse check handles this: is the
    payload itself a substring of some registered source?"""
    sm = SessionMatcher(ttl_seconds=300)
    whole_file = "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEKEYCONTENT1234567890\n-----END-----"
    sm.register_fragment("frag-1", whole_file)
    snap = sm.current_snapshot()

    hits = snap.scan("FAKEKEYCONTENT1234567890")
    assert len(hits) == 1
    assert hits[0].matched_fragment_id == "frag-1"


def test_reverse_match_has_a_minimum_length_floor():
    sm = SessionMatcher(ttl_seconds=300)
    sm.register_fragment("frag-1", "a very long sensitive document full of text")
    snap = sm.current_snapshot()
    # A short, common substring like "a" trivially appears inside the
    # registered source — the length floor exists specifically to stop
    # this from counting as a match.
    assert snap.scan("a") == []
