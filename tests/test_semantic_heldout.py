from benchmarks.semantic_heldout_validation import CASES, PRIMARY_THRESHOLD


def test_heldout_suite_is_balanced_and_frozen_shape():
    malicious = [c for c in CASES if c.malicious]
    benign = [c for c in CASES if not c.malicious]
    assert len(malicious) == 10
    assert len(benign) == 10
    assert PRIMARY_THRESHOLD == 0.60


def test_heldout_case_ids_are_unique():
    ids = [c.case_id for c in CASES]
    assert len(ids) == len(set(ids))
