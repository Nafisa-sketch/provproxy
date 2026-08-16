from __future__ import annotations

import hashlib
import json
import math
import statistics
import time
from collections import Counter, defaultdict
from pathlib import Path

from sentence_transformers import SentenceTransformer

from benchmarks.p13.dev.attribute_verifier import (
    analyze_attributes,
    review_decision,
)


ROOT = Path(__file__).resolve().parents[3]

CORPUS = (
    ROOT
    / "benchmarks"
    / "p13"
    / "final"
    / "fixtures"
    / "p13_final_corpus.jsonl"
)

OUTDIR = (
    ROOT
    / "benchmarks"
    / "results"
    / "p13"
    / "final"
)

EXPECTED_CORPUS_SHA256 = (
    "C2EF14D344B0B34AD87D8736616AC4F3586FF61BFABAE0F37FED79289E5CAB31"
)

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
A1_THRESHOLD = 0.60

A2_SCORE_THRESHOLD = 4.5
A2_MIN_SENSITIVE = 1


def sha256_file(path: Path) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest().upper()


def read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(
            encoding="utf-8-sig"
        ).splitlines()
        if line.strip()
    ]


def flatten_strings(value) -> list[str]:
    out = []

    if isinstance(value, str):
        out.append(value)

    elif isinstance(value, list):
        for item in value:
            out.extend(
                flatten_strings(item)
            )

    elif isinstance(value, dict):
        for item in value.values():
            out.extend(
                flatten_strings(item)
            )

    return out


def candidate_text(row: dict) -> str:
    return " ".join(
        flatten_strings(
            row["calls"]
        )
    )


def percentile(
    values: list[float],
    q: float,
) -> float:
    xs = sorted(values)

    if not xs:
        return 0.0

    if len(xs) == 1:
        return xs[0]

    pos = (len(xs) - 1) * q
    lo = math.floor(pos)
    hi = math.ceil(pos)

    if lo == hi:
        return xs[lo]

    frac = pos - lo

    return (
        xs[lo] * (1.0 - frac)
        + xs[hi] * frac
    )


def wilson_interval(
    successes: int,
    n: int,
    z: float = 1.959963984540054,
) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)

    p = successes / n
    denom = 1.0 + (z * z / n)

    center = (
        p + (z * z / (2.0 * n))
    ) / denom

    margin = (
        z
        * math.sqrt(
            (
                p * (1.0 - p) / n
                + z * z / (4.0 * n * n)
            )
        )
        / denom
    )

    return (
        max(0.0, center - margin),
        min(1.0, center + margin),
    )


def exact_mcnemar(
    b: int,
    c: int,
) -> float:
    n = b + c

    if n == 0:
        return 1.0

    k = min(b, c)

    cumulative = sum(
        math.comb(n, i)
        * (0.5 ** n)
        for i in range(k + 1)
    )

    return min(
        1.0,
        2.0 * cumulative,
    )


def metrics(
    rows: list[dict],
    key: str,
) -> dict:
    malicious = [
        row
        for row in rows
        if row["label"] == "malicious"
    ]

    benign = [
        row
        for row in rows
        if row["label"] == "benign"
    ]

    tp = sum(
        bool(row[key])
        for row in malicious
    )

    fp = sum(
        bool(row[key])
        for row in benign
    )

    fn = len(malicious) - tp
    tn = len(benign) - fp

    dr = (
        tp / len(malicious)
        if malicious
        else 0.0
    )

    fpr = (
        fp / len(benign)
        if benign
        else 0.0
    )

    precision = (
        tp / (tp + fp)
        if (tp + fp)
        else 1.0
    )

    specificity = (
        tn / len(benign)
        if benign
        else 0.0
    )

    ba = (
        dr + specificity
    ) / 2.0

    f1 = (
        2.0 * precision * dr
        / (precision + dr)
        if (precision + dr)
        else 0.0
    )

    dr_ci = wilson_interval(
        tp,
        len(malicious),
    )

    fpr_ci = wilson_interval(
        fp,
        len(benign),
    )

    return {
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "malicious_review_rate": dr,
        "malicious_review_ci95": list(dr_ci),
        "benign_review_fpr": fpr,
        "benign_review_fpr_ci95": list(fpr_ci),
        "precision": precision,
        "specificity": specificity,
        "balanced_accuracy": ba,
        "f1": f1,
    }


def main() -> None:
    corpus_hash_before = sha256_file(
        CORPUS
    )

    if corpus_hash_before != EXPECTED_CORPUS_SHA256:
        raise RuntimeError(
            "Frozen P13 final corpus hash mismatch before evaluation."
        )

    rows = read_jsonl(
        CORPUS
    )

    if len(rows) != 1200:
        raise RuntimeError(
            f"Expected 1200 final cases, found {len(rows)}."
        )

    labels = Counter(
        row["label"]
        for row in rows
    )

    if labels != Counter(
        {
            "malicious": 600,
            "benign": 600,
        }
    ):
        raise RuntimeError(
            f"Unexpected final label distribution: {labels}"
        )

    print("=" * 112)
    print("P13 FROZEN FINAL ATTRIBUTE-PROVENANCE EVALUATION")
    print("=" * 112)
    print(f"Corpus SHA-256 : {corpus_hash_before}")
    print(f"Cases           : {len(rows)}")
    print(f"Malicious       : {labels['malicious']}")
    print(f"Benign          : {labels['benign']}")
    print(f"A1 model        : {MODEL_NAME}")
    print(f"A1 threshold    : {A1_THRESHOLD:.2f}")
    print(f"A2 score rule   : >= {A2_SCORE_THRESHOLD}")
    print(f"A2 sensitive    : >= {A2_MIN_SENSITIVE}")
    print("Semantic action : REVIEW ONLY")
    print()

    # ----------------------------------------------------------
    # Frozen A2 attribute verification
    # ----------------------------------------------------------

    a2_latencies = []

    for index, row in enumerate(
        rows,
        start=1,
    ):
        text = candidate_text(
            row
        )

        t0 = time.perf_counter_ns()

        evidence = analyze_attributes(
            row["synthetic_source"],
            text,
        )

        decision = review_decision(
            evidence,
            score_threshold=A2_SCORE_THRESHOLD,
            min_sensitive_matches=A2_MIN_SENSITIVE,
        )

        latency_ms = (
            time.perf_counter_ns()
            - t0
        ) / 1_000_000.0

        a2_latencies.append(
            latency_ms
        )

        row["_a2_review"] = decision
        row["_a2_weighted_score"] = evidence.weighted_score
        row["_a2_sensitive_matches"] = evidence.sensitive_matches
        row["_a2_contextual_matches"] = evidence.contextual_matches
        row["_a2_matched_attributes"] = list(
            evidence.matched_attributes
        )
        row["_a2_latency_ms"] = latency_ms

        if index % 200 == 0:
            print(
                f"A2 evaluated "
                f"{index:4d}/1200"
            )

    a2_metrics = metrics(
        rows,
        "_a2_review",
    )

    print()
    print("-" * 112)
    print("A2 FROZEN ATTRIBUTE VERIFIER")
    print("-" * 112)
    print(
        f"DR        : "
        f"{a2_metrics['malicious_review_rate']:.3f}"
    )
    print(
        f"FPR       : "
        f"{a2_metrics['benign_review_fpr']:.3f}"
    )
    print(
        f"Precision : "
        f"{a2_metrics['precision']:.3f}"
    )
    print(
        f"BA        : "
        f"{a2_metrics['balanced_accuracy']:.3f}"
    )

    # ----------------------------------------------------------
    # A1 frozen generic semantic baseline
    # ----------------------------------------------------------

    print()
    print("-" * 112)
    print("A1 GENERIC MiniLM BASELINE @ 0.60")
    print("-" * 112)

    load_start = (
        time.perf_counter_ns()
    )

    model = SentenceTransformer(
        MODEL_NAME
    )

    model_load_ms = (
        time.perf_counter_ns()
        - load_start
    ) / 1_000_000.0

    a1_latencies = []

    for index, row in enumerate(
        rows,
        start=1,
    ):
        source = row[
            "synthetic_source"
        ]

        text = candidate_text(
            row
        )

        t0 = time.perf_counter_ns()

        embeddings = model.encode(
            [
                source,
                text,
            ],
            normalize_embeddings=True,
            convert_to_numpy=True,
            show_progress_bar=False,
        )

        score = float(
            embeddings[0]
            @ embeddings[1]
        )

        latency_ms = (
            time.perf_counter_ns()
            - t0
        ) / 1_000_000.0

        a1_latencies.append(
            latency_ms
        )

        row["_a1_score"] = score
        row["_a1_review"] = (
            score >= A1_THRESHOLD
        )
        row["_a1_latency_ms"] = latency_ms

        if index % 100 == 0:
            print(
                f"A1 evaluated "
                f"{index:4d}/1200"
            )

    a1_metrics = metrics(
        rows,
        "_a1_review",
    )

    print()
    print(
        f"A1 DR        : "
        f"{a1_metrics['malicious_review_rate']:.3f}"
    )
    print(
        f"A1 FPR       : "
        f"{a1_metrics['benign_review_fpr']:.3f}"
    )
    print(
        f"A1 Precision : "
        f"{a1_metrics['precision']:.3f}"
    )
    print(
        f"A1 BA        : "
        f"{a1_metrics['balanced_accuracy']:.3f}"
    )

    # ----------------------------------------------------------
    # A3 combined review signal
    # ----------------------------------------------------------

    for row in rows:
        row["_a3_review"] = (
            row["_a1_review"]
            or row["_a2_review"]
        )

    a3_metrics = metrics(
        rows,
        "_a3_review",
    )

    print()
    print("-" * 112)
    print("A3 COMBINED REVIEW SIGNAL")
    print("-" * 112)
    print(
        f"A3 DR        : "
        f"{a3_metrics['malicious_review_rate']:.3f}"
    )
    print(
        f"A3 FPR       : "
        f"{a3_metrics['benign_review_fpr']:.3f}"
    )
    print(
        f"A3 Precision : "
        f"{a3_metrics['precision']:.3f}"
    )
    print(
        f"A3 BA        : "
        f"{a3_metrics['balanced_accuracy']:.3f}"
    )

    # ----------------------------------------------------------
    # Paired A1 vs A2 comparison
    # ----------------------------------------------------------

    malicious = [
        row
        for row in rows
        if row["label"] == "malicious"
    ]

    benign = [
        row
        for row in rows
        if row["label"] == "benign"
    ]

    mal_a1_miss_a2_hit = sum(
        (
            not row["_a1_review"]
        )
        and row["_a2_review"]
        for row in malicious
    )

    mal_a1_hit_a2_miss = sum(
        row["_a1_review"]
        and (
            not row["_a2_review"]
        )
        for row in malicious
    )

    benign_a1_false_a2_clean = sum(
        row["_a1_review"]
        and (
            not row["_a2_review"]
        )
        for row in benign
    )

    benign_a1_clean_a2_false = sum(
        (
            not row["_a1_review"]
        )
        and row["_a2_review"]
        for row in benign
    )

    malicious_p = exact_mcnemar(
        mal_a1_miss_a2_hit,
        mal_a1_hit_a2_miss,
    )

    benign_p = exact_mcnemar(
        benign_a1_false_a2_clean,
        benign_a1_clean_a2_false,
    )

    print()
    print("-" * 112)
    print("PAIRED A1 VS A2")
    print("-" * 112)
    print(
        "Malicious A1 miss -> A2 hit : "
        f"{mal_a1_miss_a2_hit}"
    )
    print(
        "Malicious A1 hit -> A2 miss : "
        f"{mal_a1_hit_a2_miss}"
    )
    print(
        "Malicious McNemar p         : "
        f"{malicious_p:.12g}"
    )
    print(
        "Benign A1 false -> A2 clean : "
        f"{benign_a1_false_a2_clean}"
    )
    print(
        "Benign A1 clean -> A2 false : "
        f"{benign_a1_clean_a2_false}"
    )
    print(
        "Benign McNemar p            : "
        f"{benign_p:.12g}"
    )

    # ----------------------------------------------------------
    # Per-category analysis
    # ----------------------------------------------------------

    category_rows = []

    for (
        label,
        category,
    ) in sorted(
        {
            (
                row["label"],
                row["category"],
            )
            for row in rows
        }
    ):
        subset = [
            row
            for row in rows
            if row["label"] == label
            and row["category"] == category
        ]

        category_rows.append(
            {
                "label": label,
                "category": category,
                "n": len(subset),
                "a1_review_rate": (
                    sum(
                        bool(row["_a1_review"])
                        for row in subset
                    )
                    / len(subset)
                ),
                "a2_review_rate": (
                    sum(
                        bool(row["_a2_review"])
                        for row in subset
                    )
                    / len(subset)
                ),
                "a3_review_rate": (
                    sum(
                        bool(row["_a3_review"])
                        for row in subset
                    )
                    / len(subset)
                ),
            }
        )

    # ----------------------------------------------------------
    # Latency
    # ----------------------------------------------------------

    a1_latency = {
        "p50": percentile(
            a1_latencies,
            0.50,
        ),
        "p95": percentile(
            a1_latencies,
            0.95,
        ),
        "p99": percentile(
            a1_latencies,
            0.99,
        ),
        "mean": statistics.fmean(
            a1_latencies
        ),
        "max": max(
            a1_latencies
        ),
    }

    a2_latency = {
        "p50": percentile(
            a2_latencies,
            0.50,
        ),
        "p95": percentile(
            a2_latencies,
            0.95,
        ),
        "p99": percentile(
            a2_latencies,
            0.99,
        ),
        "mean": statistics.fmean(
            a2_latencies
        ),
        "max": max(
            a2_latencies
        ),
    }

    # ----------------------------------------------------------
    # Integrity after evaluation
    # ----------------------------------------------------------

    corpus_hash_after = sha256_file(
        CORPUS
    )

    if corpus_hash_after != corpus_hash_before:
        raise RuntimeError(
            "Frozen P13 corpus changed during evaluation."
        )

    # ----------------------------------------------------------
    # Write results
    # ----------------------------------------------------------

    OUTDIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    summary = {
        "experiment": (
            "P13 frozen independent "
            "provenance-specific semantic evaluation"
        ),
        "status": "FINAL_ONE_SHOT_EVALUATION",
        "corpus_sha256_before": corpus_hash_before,
        "corpus_sha256_after": corpus_hash_after,
        "corpus_hash_unchanged": (
            corpus_hash_before
            == corpus_hash_after
        ),
        "cases": {
            "total": len(rows),
            "malicious": len(malicious),
            "benign": len(benign),
        },
        "A1_generic_semantic": {
            "model": MODEL_NAME,
            "threshold": A1_THRESHOLD,
            "metrics": a1_metrics,
            "model_load_ms": model_load_ms,
            "latency_ms": a1_latency,
        },
        "A2_attribute_verifier": {
            "score_threshold": A2_SCORE_THRESHOLD,
            "min_sensitive_matches": A2_MIN_SENSITIVE,
            "metrics": a2_metrics,
            "latency_ms": a2_latency,
        },
        "A3_combined_review": {
            "rule": "A1 OR A2",
            "metrics": a3_metrics,
        },
        "paired_A1_vs_A2": {
            "malicious": {
                "A1_miss_A2_hit": mal_a1_miss_a2_hit,
                "A1_hit_A2_miss": mal_a1_hit_a2_miss,
                "mcnemar_p": malicious_p,
            },
            "benign": {
                "A1_false_A2_clean": benign_a1_false_a2_clean,
                "A1_clean_A2_false": benign_a1_clean_a2_false,
                "mcnemar_p": benign_p,
            },
        },
        "category_results": category_rows,
        "reporting_constraint": (
            "A1/A2/A3 are review signals. "
            "They must not be merged into P11 hard-detection results."
        ),
    }

    summary_path = (
        OUTDIR
        / "p13_final_summary.json"
    )

    summary_path.write_text(
        json.dumps(
            summary,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    results_path = (
        OUTDIR
        / "p13_final_results.jsonl"
    )

    with results_path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as handle:
        for row in rows:
            record = {
                "case_id": row["case_id"],
                "label": row["label"],
                "category": row["category"],
                "structural_family": row["structural_family"],
                "source_id": row["source_id"],
                "a1_score": row["_a1_score"],
                "a1_review": row["_a1_review"],
                "a1_latency_ms": row["_a1_latency_ms"],
                "a2_weighted_score": row["_a2_weighted_score"],
                "a2_sensitive_matches": row["_a2_sensitive_matches"],
                "a2_contextual_matches": row["_a2_contextual_matches"],
                "a2_matched_attributes": row["_a2_matched_attributes"],
                "a2_review": row["_a2_review"],
                "a2_latency_ms": row["_a2_latency_ms"],
                "a3_review": row["_a3_review"],
            }

            handle.write(
                json.dumps(
                    record,
                    sort_keys=True,
                )
                + "\n"
            )

    category_path = (
        OUTDIR
        / "p13_final_category_summary.json"
    )

    category_path.write_text(
        json.dumps(
            category_rows,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    print()
    print("=" * 112)
    print("P13 FINAL RESULTS")
    print("=" * 112)

    print(
        f"A1 DR/FPR       : "
        f"{a1_metrics['malicious_review_rate']:.3f} / "
        f"{a1_metrics['benign_review_fpr']:.3f}"
    )

    print(
        f"A2 DR/FPR       : "
        f"{a2_metrics['malicious_review_rate']:.3f} / "
        f"{a2_metrics['benign_review_fpr']:.3f}"
    )

    print(
        f"A3 DR/FPR       : "
        f"{a3_metrics['malicious_review_rate']:.3f} / "
        f"{a3_metrics['benign_review_fpr']:.3f}"
    )

    print(
        f"A2 precision    : "
        f"{a2_metrics['precision']:.3f}"
    )

    print(
        f"A2 BA           : "
        f"{a2_metrics['balanced_accuracy']:.3f}"
    )

    print(
        f"A1 p50/p95 ms   : "
        f"{a1_latency['p50']:.3f} / "
        f"{a1_latency['p95']:.3f}"
    )

    print(
        f"A2 p50/p95 ms   : "
        f"{a2_latency['p50']:.3f} / "
        f"{a2_latency['p95']:.3f}"
    )

    print(
        f"Corpus unchanged: "
        f"{corpus_hash_after == corpus_hash_before}"
    )

    print()
    print(f"[WRITE] {summary_path}")
    print(f"[WRITE] {results_path}")
    print(f"[WRITE] {category_path}")
    print()
    print("[PASS] Frozen final corpus evaluated once.")
    print("[PASS] Frozen A1/A2 rules used without retuning.")
    print("[PASS] No P11/P12 artifact modified.")
    print("=" * 112)


if __name__ == "__main__":
    main()
