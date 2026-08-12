from provproxy.config import AblationTier
from benchmarks.harness import (
    category_detection_rates,
    category_false_positive_rates,
    chunk_size_detection_breakdown,
    run_baseline,
    baseline_stateless_scan,
    baseline_dlp_scan,
    run_configuration,
    summarize,
    threshold_sweep,
)


def test_v0_baseline_catches_nothing():
    records = run_configuration(AblationTier.V0, repeats=1)
    summary = summarize(records)
    assert summary.detection_rate == 0.0
    assert summary.false_positive_rate == 0.0


def test_detection_rate_increases_monotonically_v1_to_v4():
    dr = {}
    for tier in (AblationTier.V1, AblationTier.V2, AblationTier.V3, AblationTier.V4):
        records = run_configuration(tier, repeats=1)
        dr[tier.value] = summarize(records).detection_rate
    assert dr["v1"] <= dr["v2"] <= dr["v3"] <= dr["v4"]


def test_v1_catches_m1_near_perfectly_but_not_encoded_or_split():
    records = run_configuration(AblationTier.V1, repeats=1)
    dr = category_detection_rates(records)
    assert dr["M1"] >= 0.95
    assert dr["M2"] == 0.0  # encoding requires V2's decode step
    assert dr["M3"] == 0.0  # splitting defeats exact matching entirely


def test_v2_catches_m2_near_perfectly_across_all_encodings():
    records = run_configuration(AblationTier.V2, repeats=1)
    dr = category_detection_rates(records)
    assert dr["M2"] >= 0.95


def test_m4_is_never_caught_below_v4():
    for tier in (AblationTier.V1, AblationTier.V2, AblationTier.V3):
        records = run_configuration(tier, repeats=1)
        m4 = [r for r in records if r.category == "M4"]
        assert not any(r.matched for r in m4), f"M4 should stay uncaught below V4 (tier={tier.value})"


def test_chunk_size_4_through_7_all_succeed_after_reconstruction_fix():
    """Before the key=value evidence-reconstruction fix, chunk_size 4-6
    reliably failed (0% detection) while only chunk_size=7 worked — a
    hard mathematical floor from naive whitespace-flattened n-gram
    coverage. After the fix (see approx.py::extract_reconstructable_value
    and crosscall.py's ordered-concatenation accumulation), ALL chunk
    sizes in the fixture's tested range succeed, because the fragments'
    field=value structure lets evidence reconstruction recover the
    n-grams that span each chunk boundary."""
    m3_breakdown = chunk_size_detection_breakdown(AblationTier.V3, "M3")
    m4_breakdown = chunk_size_detection_breakdown(AblationTier.V4, "M4")

    for size in (4, 5, 6, 7):
        if size in m3_breakdown:
            caught, total = m3_breakdown[size]
            assert total > 0 and caught == total, f"M3 chunk_size={size}: {caught}/{total}"
        if size in m4_breakdown:
            caught, total = m4_breakdown[size]
            assert total > 0 and caught == total, f"M4 chunk_size={size}: {caught}/{total}"


def test_b5_is_detected_but_not_enforcement_blocked():
    records = run_configuration(AblationTier.V1, repeats=1)
    b5_records = [r for r in records if r.category == "B5"]
    assert all(r.matched for r in b5_records)
    assert all(not r.enforcement_blocked for r in b5_records)


def test_enforcement_fpr_stays_low_once_destination_override_applies():
    for tier in (AblationTier.V1, AblationTier.V2, AblationTier.V3, AblationTier.V4):
        records = run_configuration(tier, repeats=1)
        summary = summarize(records)
        assert summary.enforcement_false_positive_rate <= 0.05


def test_category_false_positive_rates_are_near_zero_for_non_b5():
    records = run_configuration(AblationTier.V3, repeats=1)
    fpr = category_false_positive_rates(records)
    for cat in ("B1", "B2", "B3", "B4"):
        assert fpr[cat] == 0.0, f"{cat} should never be enforcement-blocked, got {fpr[cat]:.0%}"


def test_baselines_underperform_provproxy_on_false_positives():
    """The comparison point Section 2 asked for: naive baselines (no
    provenance tracking) flag benign scenarios ProvProxy correctly
    allows — specifically B4 (dummy keys) and B5 (approved destination),
    since neither baseline has a concept of "is this the real tracked
    secret" or "is this destination allow-listed"."""
    stateless = run_baseline("stateless", baseline_stateless_scan)
    dlp = run_baseline("dlp", baseline_dlp_scan)
    # Both baselines should show non-trivial false positives...
    assert stateless["false_positive_rate"] > 0.0
    assert dlp["false_positive_rate"] > 0.0
    # ...strictly worse than ProvProxy's enforcement-level FPR (~0%).
    records = run_configuration(AblationTier.V3, repeats=1)
    provproxy_fpr = summarize(records).enforcement_false_positive_rate
    assert stateless["false_positive_rate"] > provproxy_fpr
    assert dlp["false_positive_rate"] > provproxy_fpr


def test_threshold_sweep_produces_monotonic_or_flat_dr_as_threshold_rises():
    rows = threshold_sweep()
    drs = [r["detection_rate"] for r in rows]
    # Raising the coverage threshold should never make detection easier.
    assert all(drs[i] >= drs[i + 1] for i in range(len(drs) - 1))
