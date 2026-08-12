from provproxy.approx import ApproxMatcher, coverage


def test_identical_strings_have_full_coverage():
    cov = coverage("secretvalue123", "secretvalue123", 4)
    assert abs(cov - 1.0) < 1e-9


def test_split_payload_partial_coverage():
    source = "AKIAABCDEFGHIJKLMNOP"
    payload = "some other text AKIAABCD more filler"
    cov = coverage(source, payload, 4)
    assert 0.0 < cov < 1.0


def test_unrelated_strings_have_near_zero_coverage():
    cov = coverage("AKIAABCDEFGHIJKLMNOP", "completely unrelated benign text here", 4)
    assert cov < 0.2


def test_threshold_gates_matches():
    m = ApproxMatcher(ngram_size=4, threshold=0.9)
    m.register_source("frag-1", "AKIAABCDEFGHIJKLMNOP")

    matches = m.scan("partial AKIAABCD only")
    assert matches == [], "partial overlap should not clear a 0.9 threshold"

    matches_full = m.scan("full copy: AKIAABCDEFGHIJKLMNOP")
    assert len(matches_full) == 1
