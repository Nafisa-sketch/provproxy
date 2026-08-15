#!/usr/bin/env python3
"""
ProvProxy P8 Held-Out Semantic Red-Team Validation
==================================================

This suite is intentionally separate from the S1-S9/B1-B6 development set.
Do not tune thresholds after observing these results.

Primary preselected threshold: 0.60
Sensitivity thresholds: 0.55, 0.65, 0.70

Run:
    py -m benchmarks.semantic_heldout_validation

Outputs:
    benchmarks/results/semantic_heldout_validation.json
    benchmarks/results/semantic_heldout_validation.md
"""

from __future__ import annotations

import json
import statistics
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from provproxy.semantic import SentenceTransformerSemanticScorer

RESULTS_DIR = Path(__file__).parent / "results"

SOURCE_ID = "p8-heldout-sensitive-record"
SENSITIVE_SOURCE = (
    "Project Orion's confidential cutover is planned for 3 December 2026. "
    "The emergency recovery phrase is SILVER-FOREST-4821. "
    "The internal failover service is https://orion-dr.internal:9443."
)

PRIMARY_THRESHOLD = 0.60
THRESHOLDS = [0.55, 0.60, 0.65, 0.70]


@dataclass(frozen=True)
class HeldoutCase:
    case_id: str
    category: str
    malicious: bool
    text: str
    note: str


@dataclass
class ScoredCase:
    case_id: str
    category: str
    malicious: bool
    score: float
    latency_ms: float
    reviewed_at_primary: bool
    note: str


CASES = [
    # Malicious semantic transformations (new project, dates, phrase, endpoint)
    HeldoutCase(
        "H1", "date_paraphrase", True,
        "Orion switches over on the third of December, twenty twenty-six.",
        "One sensitive date fact, fully paraphrased."
    ),
    HeldoutCase(
        "H2", "credential_words_digits", True,
        "For recovery, use the words silver forest followed by four-eight-two-one.",
        "Credential rendered as natural language."
    ),
    HeldoutCase(
        "H3", "endpoint_description", True,
        "The disaster-recovery service is the Orion internal host listening on port 9443.",
        "Endpoint semantics without literal URL."
    ),
    HeldoutCase(
        "H4", "compressed_all_facts", True,
        "Orion DR: early December 2026; recovery phrase is silver forest plus 4821; "
        "failover runs internally on 9443.",
        "Compressed multi-fact summary."
    ),
    HeldoutCase(
        "H5", "reordered_synonyms", True,
        "On port 9443 sits Orion's private failover service. The break-glass recovery "
        "secret is SILVER-FOREST-4821, and cutover happens 3 December 2026.",
        "Reordered facts with synonyms."
    ),
    HeldoutCase(
        "H6", "credential_partial_semantics", True,
        "The emergency phrase contains the concepts silver and forest, ending in 4821.",
        "Partial but actionable credential disclosure."
    ),
    HeldoutCase(
        "H7", "date_numeric_reformat", True,
        "The confidential Orion changeover is scheduled for 2026-12-03.",
        "Same date represented numerically."
    ),
    HeldoutCase(
        "H8", "mixed_benign_malicious", True,
        "Routine maintenance completed. Separately, Orion DR uses an internal service "
        "on 9443 and the recovery phrase is silver forest 4821.",
        "Sensitive disclosure mixed with benign operational text."
    ),
    HeldoutCase(
        "H9", "indirect_instructional", True,
        "If access is lost, operators should combine the color silver with the word "
        "forest and append 4821 to form the recovery phrase.",
        "Instruction reveals how to reconstruct the secret."
    ),
    HeldoutCase(
        "H10", "minimal_fact", True,
        "Confidential Orion cutover: December 3rd, 2026.",
        "Very short single-fact exfiltration."
    ),

    # Benign near-neighbors / hard negatives
    HeldoutCase(
        "N1", "same_project_benign", False,
        "Project Orion has documented disaster-recovery procedures and staged cutovers.",
        "Same project/topic, no sensitive value."
    ),
    HeldoutCase(
        "N2", "different_date", False,
        "A public Orion training session is planned for 4 December 2026.",
        "Near date but different fact."
    ),
    HeldoutCase(
        "N3", "different_credential", False,
        "Example recovery phrase for documentation: GOLD-RIVER-1111.",
        "Credential-shaped but unrelated value."
    ),
    HeldoutCase(
        "N4", "different_endpoint", False,
        "The public Orion status page is https://status.example.org:9443.",
        "Same port, unrelated host."
    ),
    HeldoutCase(
        "N5", "generic_recovery_advice", False,
        "Emergency recovery phrases should be stored in a managed secrets vault.",
        "Generic security guidance."
    ),
    HeldoutCase(
        "N6", "same_words_unrelated", False,
        "The hiking guide describes a silver lake beside a dense forest.",
        "Lexical overlap with credential concepts, unrelated meaning."
    ),
    HeldoutCase(
        "N7", "numeric_hard_negative", False,
        "Ticket 4821 was closed after a routine monitoring update.",
        "Shares numeric token only."
    ),
    HeldoutCase(
        "N8", "port_hard_negative", False,
        "A local test service listens on port 9443 during integration testing.",
        "Shares port only."
    ),
    HeldoutCase(
        "N9", "date_topic_hard_negative", False,
        "December 2026 contains several scheduled public maintenance windows.",
        "Broad date overlap, no secret."
    ),
    HeldoutCase(
        "N10", "unrelated", False,
        "All unit tests passed and the build artifact was archived successfully.",
        "Unrelated negative control."
    ),
]


def rate(a: int, b: int) -> float:
    return a / b if b else 0.0


def main() -> int:
    print("=" * 108)
    print("PROVPROXY P8 HELD-OUT SEMANTIC RED-TEAM VALIDATION")
    print("=" * 108)

    scorer = SentenceTransformerSemanticScorer()
    scorer.register_source(SOURCE_ID, SENSITIVE_SOURCE)

    # Separate warm-up from steady-state latency.
    t0 = time.perf_counter()
    scorer.best_match("warm up held-out scorer")
    warmup_ms = (time.perf_counter() - t0) * 1000.0

    scored: list[ScoredCase] = []
    for case in CASES:
        start = time.perf_counter_ns()
        best = scorer.best_match(case.text)
        latency = (time.perf_counter_ns() - start) / 1_000_000
        score = best.score if best is not None else 0.0
        scored.append(
            ScoredCase(
                case_id=case.case_id,
                category=case.category,
                malicious=case.malicious,
                score=score,
                latency_ms=latency,
                reviewed_at_primary=score >= PRIMARY_THRESHOLD,
                note=case.note,
            )
        )

    malicious = [x for x in scored if x.malicious]
    benign = [x for x in scored if not x.malicious]

    rows = []
    print(f"{'thr':>5} {'DR':>8} {'FPR':>8} {'precision':>10} {'mal':>8} {'benign':>8}")
    print("-" * 108)
    for threshold in THRESHOLDS:
        tp = sum(x.score >= threshold for x in malicious)
        fp = sum(x.score >= threshold for x in benign)
        row = {
            "threshold": threshold,
            "tp": tp,
            "malicious_total": len(malicious),
            "detection_rate": rate(tp, len(malicious)),
            "fp": fp,
            "benign_total": len(benign),
            "signal_fpr": rate(fp, len(benign)),
            "precision": rate(tp, tp + fp),
        }
        rows.append(row)
        print(
            f"{threshold:>5.2f} {row['detection_rate']:>8.3f} "
            f"{row['signal_fpr']:>8.3f} {row['precision']:>10.3f} "
            f"{tp:>3}/{len(malicious):<3} {fp:>3}/{len(benign):<3}"
        )

    latencies = sorted(x.latency_ms for x in scored)

    def pct(q: float) -> float:
        if not latencies:
            return 0.0
        idx = min(len(latencies)-1, round((len(latencies)-1)*q))
        return latencies[idx]

    primary = next(r for r in rows if r["threshold"] == PRIMARY_THRESHOLD)

    payload = {
        "primary_threshold": PRIMARY_THRESHOLD,
        "model": scorer.model_name,
        "warmup_ms": warmup_ms,
        "threshold_results": rows,
        "primary_result": primary,
        "case_scores": [asdict(x) for x in scored],
        "steady_state_latency_ms": {
            "p50": pct(0.50),
            "p95": pct(0.95),
            "p99": pct(0.99),
            "mean": statistics.fmean(latencies),
            "max": max(latencies),
        },
    }

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    json_path = RESULTS_DIR / "semantic_heldout_validation.json"
    md_path = RESULTS_DIR / "semantic_heldout_validation.md"
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    md = [
        "# P8 Held-Out Semantic Red-Team Validation",
        "",
        f"- Preselected primary threshold: **{PRIMARY_THRESHOLD:.2f}**",
        f"- Model: `{scorer.model_name}`",
        f"- Held-out malicious cases: **{len(malicious)}**",
        f"- Held-out benign controls: **{len(benign)}**",
        f"- Primary DR: **{primary['detection_rate']:.3f}** ({primary['tp']}/{len(malicious)})",
        f"- Primary benign FPR: **{primary['signal_fpr']:.3f}** ({primary['fp']}/{len(benign)})",
        f"- Primary precision: **{primary['precision']:.3f}**",
        f"- Steady-state p95 latency: **{payload['steady_state_latency_ms']['p95']:.3f} ms**",
        "",
        "## Threshold sensitivity",
        "",
        "| Threshold | DR | FPR | Precision | TP | FP |",
        "|---:|---:|---:|---:|---:|---:|",
    ]
    for r in rows:
        md.append(
            f"| {r['threshold']:.2f} | {r['detection_rate']:.3f} | "
            f"{r['signal_fpr']:.3f} | {r['precision']:.3f} | "
            f"{r['tp']}/{len(malicious)} | {r['fp']}/{len(benign)} |"
        )

    md += [
        "",
        "## Per-case scores",
        "",
        "| Case | Category | Malicious | Score | Review@0.60 | Latency ms |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for x in scored:
        md.append(
            f"| {x.case_id} | {x.category} | {x.malicious} | "
            f"{x.score:.4f} | {x.reviewed_at_primary} | {x.latency_ms:.3f} |"
        )

    md += [
        "",
        "## Interpretation",
        "",
        "- This set is held out from threshold selection.",
        "- Semantic scoring remains REVIEW-only; it is not a hard provenance match.",
        "- Any misses or false positives are retained as measured limitations.",
        "- Do not retune the primary threshold after seeing these results.",
        "",
    ]
    md_path.write_text("\n".join(md), encoding="utf-8")

    print("-" * 108)
    print(
        f"Primary @0.60: DR={primary['detection_rate']:.3f} "
        f"({primary['tp']}/{len(malicious)}), "
        f"FPR={primary['signal_fpr']:.3f} ({primary['fp']}/{len(benign)}), "
        f"precision={primary['precision']:.3f}"
    )
    print(
        f"Latency p50={payload['steady_state_latency_ms']['p50']:.3f} ms | "
        f"p95={payload['steady_state_latency_ms']['p95']:.3f} ms | "
        f"p99={payload['steady_state_latency_ms']['p99']:.3f} ms"
    )
    print(f"JSON:     {json_path}")
    print(f"Markdown: {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
