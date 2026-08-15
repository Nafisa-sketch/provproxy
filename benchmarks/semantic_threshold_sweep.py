#!/usr/bin/env python3
"""
P8 semantic threshold sweep.

This benchmark does NOT modify ProvProxy's runtime pipeline. It evaluates an
optional local sentence-embedding scorer as a candidate REVIEW layer using the
frozen P8 development cases.

Run:
    py -m benchmarks.semantic_threshold_sweep

Outputs:
    benchmarks/results/semantic_threshold_sweep.json
    benchmarks/results/semantic_threshold_sweep.md
"""

from __future__ import annotations

import json
import statistics
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from provproxy.semantic import SentenceTransformerSemanticScorer
from benchmarks.semantic_exfiltration_validation import (
    CASES,
    SENSITIVE_SOURCE,
    SOURCE_ID,
)

RESULTS_DIR = Path(__file__).parent / "results"
THRESHOLDS = [0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80]


@dataclass
class CaseScore:
    case_id: str
    category: str
    malicious: bool
    score: float
    latency_ms: float


@dataclass
class ThresholdRow:
    threshold: float
    malicious_reviewed: int
    malicious_total: int
    detection_rate: float
    benign_reviewed: int
    benign_total: int
    signal_fpr: float
    precision: float


def rate(a: int, b: int) -> float:
    return a / b if b else 0.0


def main() -> int:
    print("=" * 104)
    print("PROVPROXY P8 OPTIONAL SEMANTIC REVIEW — THRESHOLD SWEEP")
    print("=" * 104)

    scorer = SentenceTransformerSemanticScorer()
    scorer.register_source(SOURCE_ID, SENSITIVE_SOURCE)

    # Warm/model-load operation is kept separate from steady-state latency.
    t0 = time.perf_counter()
    warm = scorer.best_match("warm up semantic scorer")
    model_load_ms = (time.perf_counter() - t0) * 1000.0

    scored: list[CaseScore] = []
    for case in CASES:
        start = time.perf_counter_ns()
        best = scorer.best_match(case.text)
        elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
        score = best.score if best is not None else 0.0
        scored.append(
            CaseScore(
                case_id=case.case_id,
                category=case.category,
                malicious=case.malicious,
                score=score,
                latency_ms=elapsed_ms,
            )
        )

    malicious = [x for x in scored if x.malicious]
    benign = [x for x in scored if not x.malicious]

    rows: list[ThresholdRow] = []
    print(f"{'thr':>5} {'DR':>8} {'FPR':>8} {'precision':>10} {'mal':>7} {'benign':>8}")
    print("-" * 104)

    for threshold in THRESHOLDS:
        tp = sum(x.score >= threshold for x in malicious)
        fp = sum(x.score >= threshold for x in benign)
        precision = rate(tp, tp + fp)
        row = ThresholdRow(
            threshold=threshold,
            malicious_reviewed=tp,
            malicious_total=len(malicious),
            detection_rate=rate(tp, len(malicious)),
            benign_reviewed=fp,
            benign_total=len(benign),
            signal_fpr=rate(fp, len(benign)),
            precision=precision,
        )
        rows.append(row)
        print(
            f"{threshold:>5.2f} {row.detection_rate:>8.3f} "
            f"{row.signal_fpr:>8.3f} {row.precision:>10.3f} "
            f"{tp:>3}/{len(malicious):<3} {fp:>3}/{len(benign):<3}"
        )

    latencies = [x.latency_ms for x in scored]
    lat_sorted = sorted(latencies)

    def pct(q: float) -> float:
        if not lat_sorted:
            return 0.0
        idx = min(len(lat_sorted) - 1, int(round((len(lat_sorted) - 1) * q)))
        return lat_sorted[idx]

    payload = {
        "model": scorer.model_name,
        "model_load_ms": model_load_ms,
        "case_scores": [asdict(x) for x in scored],
        "thresholds": [asdict(x) for x in rows],
        "steady_state_latency_ms": {
            "mean": statistics.fmean(latencies),
            "p50": pct(0.50),
            "p95": pct(0.95),
            "p99": pct(0.99),
            "max": max(latencies),
        },
    }

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    json_path = RESULTS_DIR / "semantic_threshold_sweep.json"
    md_path = RESULTS_DIR / "semantic_threshold_sweep.md"
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    md = [
        "# P8 Optional Semantic Review Threshold Sweep",
        "",
        f"- Model: `{scorer.model_name}`",
        f"- Initial model-load/warm-up latency: **{model_load_ms:.1f} ms**",
        f"- Steady-state mean per-case latency: **{payload['steady_state_latency_ms']['mean']:.3f} ms**",
        f"- Steady-state p95 latency: **{payload['steady_state_latency_ms']['p95']:.3f} ms**",
        "",
        "## Threshold sweep",
        "",
        "| Threshold | Detection rate | Benign FPR | Precision | Malicious reviewed | Benign reviewed |",
        "|---:|---:|---:|---:|---:|---:|",
    ]
    for r in rows:
        md.append(
            f"| {r.threshold:.2f} | {r.detection_rate:.3f} | "
            f"{r.signal_fpr:.3f} | {r.precision:.3f} | "
            f"{r.malicious_reviewed}/{r.malicious_total} | "
            f"{r.benign_reviewed}/{r.benign_total} |"
        )

    md += [
        "",
        "## Per-case scores",
        "",
        "| Case | Category | Malicious | Score | Latency ms |",
        "|---|---|---:|---:|---:|",
    ]
    for x in scored:
        md.append(
            f"| {x.case_id} | {x.category} | {x.malicious} | "
            f"{x.score:.4f} | {x.latency_ms:.3f} |"
        )

    md += [
        "",
        "## Interpretation",
        "",
        "- This is an optional **REVIEW** candidate, not a hard-match/block layer.",
        "- The frozen S1-S9/B1-B6 set is a development set; do not claim final generalization from it.",
        "- Choose an operating point only after inspecting detection/FPR/latency trade-offs.",
        "- A separate held-out semantic set is required before the final P8 claim.",
        "",
    ]
    md_path.write_text("\n".join(md), encoding="utf-8")

    print("-" * 104)
    print(f"Model load/warm-up: {model_load_ms:.1f} ms")
    print(
        f"Steady-state latency p50={payload['steady_state_latency_ms']['p50']:.3f} ms | "
        f"p95={payload['steady_state_latency_ms']['p95']:.3f} ms | "
        f"p99={payload['steady_state_latency_ms']['p99']:.3f} ms"
    )
    print(f"JSON:     {json_path}")
    print(f"Markdown: {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
