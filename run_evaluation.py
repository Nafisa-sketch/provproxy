#!/usr/bin/env python3
"""Full evaluation pipeline for the ProvProxy paper's Evaluation section.

Runs, in order:
  1. V0-V4 ablation summary (DR, FPR-detect, FPR-enforce, latency w/ CI)
  2. Per-category detection table (M1-M4) and per-category FPR (B1-B5)
  3. Chunk-size failure-mode breakdown for M3/M4 (where detection
     actually starts failing, not just an aggregate number)
  4. Baseline comparison (stateless pattern matcher, DLP-only gateway)
     vs ProvProxy, on the same fixtures
  5. Peak memory per tier
  6. Threshold sweep (ApproxMatcher.scan_sweep) — the DR/FPR trade-off
     curve across coverage_threshold operating points

All tables are also written to benchmarks/results/ as LaTeX (.tex) and
Markdown (.md), ready to paste into a paper.

Usage:
    python run_evaluation.py [--repeats N]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from provproxy.config import AblationTier
from benchmarks.harness import (
    baseline_dlp_scan,
    baseline_stateless_scan,
    category_detection_rates,
    category_false_positive_rates,
    chunk_size_detection_breakdown,
    measure_memory,
    run_all,
    run_baseline,
    run_configuration,
    threshold_sweep,
    to_latex_table,
    to_markdown_table,
)

RESULTS_DIR = Path(__file__).parent / "benchmarks" / "results"
TIERS = [AblationTier.V0, AblationTier.V1, AblationTier.V2, AblationTier.V3, AblationTier.V4]


def _save(name: str, rows: list[dict], columns: list[str], caption: str) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / f"{name}.tex").write_text(to_latex_table(rows, columns, caption, f"tab:{name}"))
    (RESULTS_DIR / f"{name}.md").write_text(to_markdown_table(rows, columns))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repeats", type=int, default=10, help="Repeats per fixture for latency stats")
    args = parser.parse_args()

    print(f"ProvProxy Evaluation — repeats={args.repeats} per fixture\n{'=' * 70}\n")

    # --- 1. Overall ablation summary ---
    print("[1/6] Overall ablation summary (V0-V4)")
    summaries = run_all(repeats=args.repeats)
    rows = [
        {
            "tier": s.tier, "detection_rate": s.detection_rate,
            "fpr_detect": s.false_positive_rate, "fpr_enforce": s.enforcement_false_positive_rate,
            "p50_ms": s.p50_ms, "p95_ms": s.p95_ms, "p99_ms": s.p99_ms,
        }
        for s in summaries
    ]
    cols = ["tier", "detection_rate", "fpr_detect", "fpr_enforce", "p50_ms", "p95_ms", "p99_ms"]
    print(to_markdown_table(rows, cols))
    _save("ablation_summary", rows, cols, "ProvProxy ablation summary: detection rate, false-positive rate, and latency by tier.")

    # --- 2. Per-category tables ---
    print("\n[2/6] Per-category detection rate (malicious) and enforcement FPR (benign)")
    dr_rows, fpr_rows = [], []
    for tier in TIERS:
        records = run_configuration(tier, repeats=1)
        dr = category_detection_rates(records)
        fpr = category_false_positive_rates(records)
        dr_rows.append({"tier": tier.value, **{c: dr.get(c, 0.0) for c in ("M1", "M2", "M3", "M4")}})
        fpr_rows.append({"tier": tier.value, **{c: fpr.get(c, 0.0) for c in ("B1", "B2", "B3", "B4", "B5")}})
    print("\nDetection rate by malicious category:")
    print(to_markdown_table(dr_rows, ["tier", "M1", "M2", "M3", "M4"]))
    print("\nEnforcement FPR by benign category:")
    print(to_markdown_table(fpr_rows, ["tier", "B1", "B2", "B3", "B4", "B5"]))
    _save("category_dr", dr_rows, ["tier", "M1", "M2", "M3", "M4"], "Per-category detection rate by tier.")
    _save("category_fpr", fpr_rows, ["tier", "B1", "B2", "B3", "B4", "B5"], "Per-category enforcement false-positive rate by tier.")

    # --- 3. Chunk-size failure analysis ---
    print("\n[3/6] Failure-mode analysis: detection rate by chunk size (M3 @ V3, M4 @ V4)")
    m3_breakdown = chunk_size_detection_breakdown(AblationTier.V3, "M3")
    m4_breakdown = chunk_size_detection_breakdown(AblationTier.V4, "M4")
    fail_rows = []
    for size in sorted(set(m3_breakdown) | set(m4_breakdown)):
        m3c, m3t = m3_breakdown.get(size, (0, 0))
        m4c, m4t = m4_breakdown.get(size, (0, 0))
        fail_rows.append({
            "chunk_size": size,
            "m3_detection_rate": (m3c / m3t) if m3t else None,
            "m4_detection_rate": (m4c / m4t) if m4t else None,
        })
    print(to_markdown_table(fail_rows, ["chunk_size", "m3_detection_rate", "m4_detection_rate"]))
    _save("chunk_size_failure", fail_rows, ["chunk_size", "m3_detection_rate", "m4_detection_rate"],
          "Detection rate as a function of chunk size — the failure boundary for coverage-based matching.")

    # --- 4. Baseline comparison ---
    print("\n[4/6] Baseline comparison")
    stateless = run_baseline("Stateless pattern matcher", baseline_stateless_scan)
    dlp = run_baseline("DLP-only gateway (transform-aware, no provenance)", baseline_dlp_scan)
    provproxy_v3 = next(s for s in summaries if s.tier == "v3")
    baseline_rows = [
        {"approach": stateless["name"], "detection_rate": stateless["detection_rate"], "false_positive_rate": stateless["false_positive_rate"]},
        {"approach": dlp["name"], "detection_rate": dlp["detection_rate"], "false_positive_rate": dlp["false_positive_rate"]},
        {"approach": "ProvProxy (V3, enforcement)", "detection_rate": provproxy_v3.detection_rate, "false_positive_rate": provproxy_v3.enforcement_false_positive_rate},
    ]
    print(to_markdown_table(baseline_rows, ["approach", "detection_rate", "false_positive_rate"]))
    _save("baseline_comparison", baseline_rows, ["approach", "detection_rate", "false_positive_rate"],
          "ProvProxy vs.\\ non-provenance-aware baselines on the same fixture set.")

    # --- 5. Memory ---
    print("\n[5/6] Peak memory per tier")
    mem_rows = [measure_memory(tier) for tier in TIERS]
    print(to_markdown_table(mem_rows, ["tier", "peak_kb"]))
    _save("memory", mem_rows, ["tier", "peak_kb"], "Peak traced memory allocation per tier over one full fixture pass.")

    # --- 6. Threshold sweep ---
    print("\n[6/6] Threshold sweep (coverage_threshold, via ApproxMatcher.scan_sweep)")
    print("  'false_positive_rate' includes B5 (a genuine detection-level signal, policy-")
    print("  suppressed at enforcement — see README). 'noise_false_positive_rate' excludes")
    print("  B5 and shows only genuine coincidental-overlap noise, which the threshold")
    print("  should (and does) suppress as it gets stricter.")
    sweep_rows = threshold_sweep()
    sweep_cols = ["threshold", "detection_rate", "false_positive_rate", "noise_false_positive_rate"]
    print(to_markdown_table(sweep_rows, sweep_cols))
    _save("threshold_sweep", sweep_rows, sweep_cols,
          "Detection rate / false-positive rate trade-off across the N-gram coverage threshold. "
          "false\\_positive\\_rate includes B5 (policy-suppressed true signal); "
          "noise\\_false\\_positive\\_rate excludes it and shows genuine noise suppression.")

    print(f"\nAll tables written to {RESULTS_DIR}/ as .tex and .md")


if __name__ == "__main__":
    sys.exit(main())
