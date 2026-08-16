from __future__ import annotations

import json
import math
import statistics
import time
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
    / "dev"
    / "fixtures"
    / "p13_dev_corpus.jsonl"
)

OUTDIR = (
    ROOT
    / "benchmarks"
    / "results"
    / "p13"
    / "dev"
)

MODEL_NAME = (
    "sentence-transformers/all-MiniLM-L6-v2"
)

GENERIC_THRESHOLD = 0.60


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

    pos = (
        len(xs) - 1
    ) * q

    lo = math.floor(pos)
    hi = math.ceil(pos)

    if lo == hi:
        return xs[lo]

    frac = pos - lo

    return (
        xs[lo] * (1.0 - frac)
        + xs[hi] * frac
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

    tpr = tp / len(malicious)
    fpr = fp / len(benign)

    precision = (
        tp / (tp + fp)
        if tp + fp
        else 1.0
    )

    specificity = (
        tn / len(benign)
    )

    balanced_accuracy = (
        tpr + specificity
    ) / 2.0

    return {
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "malicious_review_rate": tpr,
        "benign_review_fpr": fpr,
        "precision": precision,
        "balanced_accuracy": balanced_accuracy,
    }


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


def main() -> None:
    rows = [
        json.loads(line)
        for line in CORPUS.read_text(
            encoding="utf-8-sig"
        ).splitlines()
        if line.strip()
    ]

    if len(rows) != 360:
        raise RuntimeError(
            f"Expected 360 development cases; found {len(rows)}"
        )

    print("=" * 104)
    print("P13-D2 ATTRIBUTE VERIFIER DEVELOPMENT")
    print("=" * 104)

    print(
        f"Cases     : {len(rows)}"
    )

    print(
        f"Malicious : "
        f"{sum(r['label'] == 'malicious' for r in rows)}"
    )

    print(
        f"Benign    : "
        f"{sum(r['label'] == 'benign' for r in rows)}"
    )

    # ----------------------------------------------------------
    # Attribute evidence
    # ----------------------------------------------------------

    attr_latencies = []

    for row in rows:
        text = candidate_text(row)

        t0 = time.perf_counter_ns()

        evidence = analyze_attributes(
            row["synthetic_source"],
            text,
        )

        attr_latencies.append(
            (
                time.perf_counter_ns()
                - t0
            )
            / 1_000_000.0
        )

        row["_attribute_evidence"] = {
            "weighted_score": (
                evidence.weighted_score
            ),
            "sensitive_matches": (
                evidence.sensitive_matches
            ),
            "contextual_matches": (
                evidence.contextual_matches
            ),
            "matched_attributes": list(
                evidence.matched_attributes
            ),
        }

    # ----------------------------------------------------------
    # A2 DEVELOPMENT SWEEP
    # ----------------------------------------------------------

    thresholds = [
        2.0,
        2.5,
        3.0,
        3.5,
        4.0,
        4.5,
        5.0,
        5.5,
        6.0,
    ]

    sensitive_requirements = [
        1,
        2,
    ]

    sweep = []

    for threshold in thresholds:
        for min_sensitive in sensitive_requirements:

            key = (
                f"_a2_{threshold}_"
                f"{min_sensitive}"
            )

            for row in rows:
                ev = row[
                    "_attribute_evidence"
                ]

                # Reconstruct only fields needed by rule.
                class Obj:
                    pass

                obj = Obj()

                obj.weighted_score = ev[
                    "weighted_score"
                ]

                obj.sensitive_matches = ev[
                    "sensitive_matches"
                ]

                row[key] = (
                    obj.sensitive_matches
                    >= min_sensitive
                    and obj.weighted_score
                    >= threshold
                )

            m = metrics(
                rows,
                key,
            )

            sweep.append(
                {
                    "score_threshold": threshold,
                    "min_sensitive_matches": min_sensitive,
                    **m,
                }
            )

    sweep.sort(
        key=lambda x: (
            x[
                "balanced_accuracy"
            ],
            x["precision"],
            -x[
                "benign_review_fpr"
            ],
        ),
        reverse=True,
    )

    print()
    print("-" * 104)
    print("A2 DEVELOPMENT SWEEP — TOP 12")
    print("-" * 104)

    for item in sweep[:12]:
        print(
            f"score>={item['score_threshold']:<4} "
            f"sensitive>={item['min_sensitive_matches']} | "
            f"DR={item['malicious_review_rate']:.3f} "
            f"FPR={item['benign_review_fpr']:.3f} "
            f"P={item['precision']:.3f} "
            f"BA={item['balanced_accuracy']:.3f}"
        )

    best = sweep[0]

    # ----------------------------------------------------------
    # A1 GENERIC SEMANTIC BASELINE
    # ----------------------------------------------------------

    print()
    print("-" * 104)
    print("A1 GENERIC MiniLM BASELINE @ 0.60")
    print("-" * 104)

    load_start = (
        time.perf_counter_ns()
    )

    model = SentenceTransformer(
        MODEL_NAME
    )

    load_ms = (
        time.perf_counter_ns()
        - load_start
    ) / 1_000_000.0

    semantic_latencies = []

    for index, row in enumerate(
        rows,
        start=1,
    ):
        source = row[
            "synthetic_source"
        ]

        text = candidate_text(row)

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

        semantic_latencies.append(
            (
                time.perf_counter_ns()
                - t0
            )
            / 1_000_000.0
        )

        row["_a1_score"] = score

        row["_a1_review"] = (
            score
            >= GENERIC_THRESHOLD
        )

        if index % 60 == 0:
            print(
                f"Semantic baseline "
                f"{index:3d}/360"
            )

    a1 = metrics(
        rows,
        "_a1_review",
    )

    print()
    print(
        f"A1 DR        : "
        f"{a1['malicious_review_rate']:.3f}"
    )

    print(
        f"A1 FPR       : "
        f"{a1['benign_review_fpr']:.3f}"
    )

    print(
        f"A1 Precision : "
        f"{a1['precision']:.3f}"
    )

    print(
        f"A1 BA        : "
        f"{a1['balanced_accuracy']:.3f}"
    )

    # ----------------------------------------------------------
    # BEST DEVELOPMENT A2
    # ----------------------------------------------------------

    best_key = (
        f"_a2_"
        f"{best['score_threshold']}_"
        f"{best['min_sensitive_matches']}"
    )

    a2 = metrics(
        rows,
        best_key,
    )

    print()
    print("-" * 104)
    print("BEST DEVELOPMENT A2")
    print("-" * 104)

    print(
        f"Score threshold      : "
        f"{best['score_threshold']}"
    )

    print(
        f"Min sensitive attrs  : "
        f"{best['min_sensitive_matches']}"
    )

    print(
        f"A2 DR                : "
        f"{a2['malicious_review_rate']:.3f}"
    )

    print(
        f"A2 FPR               : "
        f"{a2['benign_review_fpr']:.3f}"
    )

    print(
        f"A2 Precision         : "
        f"{a2['precision']:.3f}"
    )

    print(
        f"A2 Balanced accuracy : "
        f"{a2['balanced_accuracy']:.3f}"
    )

    # ----------------------------------------------------------
    # Paired A1 vs A2
    # ----------------------------------------------------------

    malicious = [
        row
        for row in rows
        if row["label"]
        == "malicious"
    ]

    benign = [
        row
        for row in rows
        if row["label"]
        == "benign"
    ]

    malicious_a1_miss_a2_hit = sum(
        (
            not row["_a1_review"]
        )
        and row[best_key]
        for row in malicious
    )

    malicious_a1_hit_a2_miss = sum(
        row["_a1_review"]
        and (
            not row[best_key]
        )
        for row in malicious
    )

    benign_a1_false_a2_clean = sum(
        row["_a1_review"]
        and (
            not row[best_key]
        )
        for row in benign
    )

    benign_a1_clean_a2_false = sum(
        (
            not row["_a1_review"]
        )
        and row[best_key]
        for row in benign
    )

    malicious_p = exact_mcnemar(
        malicious_a1_miss_a2_hit,
        malicious_a1_hit_a2_miss,
    )

    benign_p = exact_mcnemar(
        benign_a1_false_a2_clean,
        benign_a1_clean_a2_false,
    )

    print()
    print("-" * 104)
    print("PAIRED DEVELOPMENT COMPARISON")
    print("-" * 104)

    print(
        "Malicious A1 miss -> A2 hit : "
        f"{malicious_a1_miss_a2_hit}"
    )

    print(
        "Malicious A1 hit -> A2 miss : "
        f"{malicious_a1_hit_a2_miss}"
    )

    print(
        f"Malicious McNemar p         : "
        f"{malicious_p:.8g}"
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
        f"Benign McNemar p            : "
        f"{benign_p:.8g}"
    )

    # ----------------------------------------------------------
    # Per-category
    # ----------------------------------------------------------

    categories = sorted(
        {
            (
                row["label"],
                row["category"],
            )
            for row in rows
        }
    )

    category_rows = []

    for label, category in categories:
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
                        r["_a1_review"]
                        for r in subset
                    )
                    / len(subset)
                ),
                "a2_review_rate": (
                    sum(
                        r[best_key]
                        for r in subset
                    )
                    / len(subset)
                ),
            }
        )

    # ----------------------------------------------------------
    # Save development output
    # ----------------------------------------------------------

    OUTDIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    result = {
        "experiment": (
            "P13-D2 development-only "
            "attribute verifier calibration"
        ),
        "status": (
            "DEVELOPMENT_ONLY_NOT_FINAL"
        ),
        "development_corpus_sha256": (
            "00F0FB3B957D3C743C5CFA67467C0ABCEA6DCF7D3AB2D1D9E4712B6A4E32C789"
        ),
        "generic_semantic_baseline": {
            "model": MODEL_NAME,
            "threshold": GENERIC_THRESHOLD,
            "metrics": a1,
            "model_load_ms": load_ms,
            "latency_ms": {
                "p50": percentile(
                    semantic_latencies,
                    0.50,
                ),
                "p95": percentile(
                    semantic_latencies,
                    0.95,
                ),
                "mean": statistics.fmean(
                    semantic_latencies
                ),
            },
        },
        "attribute_verifier_best_development": {
            "score_threshold": (
                best[
                    "score_threshold"
                ]
            ),
            "min_sensitive_matches": (
                best[
                    "min_sensitive_matches"
                ]
            ),
            "metrics": a2,
            "latency_ms": {
                "p50": percentile(
                    attr_latencies,
                    0.50,
                ),
                "p95": percentile(
                    attr_latencies,
                    0.95,
                ),
                "mean": statistics.fmean(
                    attr_latencies
                ),
            },
        },
        "paired_comparison": {
            "malicious": {
                "A1_miss_A2_hit": (
                    malicious_a1_miss_a2_hit
                ),
                "A1_hit_A2_miss": (
                    malicious_a1_hit_a2_miss
                ),
                "mcnemar_p": (
                    malicious_p
                ),
            },
            "benign": {
                "A1_false_A2_clean": (
                    benign_a1_false_a2_clean
                ),
                "A1_clean_A2_false": (
                    benign_a1_clean_a2_false
                ),
                "mcnemar_p": (
                    benign_p
                ),
            },
        },
        "category_results": (
            category_rows
        ),
        "development_sweep": sweep,
        "warning": (
            "All results in this file are DEVELOPMENT ONLY. "
            "They may be used to freeze the P13 verifier rule, "
            "but must not be reported as final P13 evidence."
        ),
    }

    out = (
        OUTDIR
        / "p13_dev_attribute_calibration.json"
    )

    out.write_text(
        json.dumps(
            result,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    print()
    print(
        f"[WRITE] {out}"
    )

    print()
    print("[PASS] Development corpus only.")
    print("[PASS] Final P13 corpus does not exist yet.")
    print("[PASS] No P11/P12 artifact modified.")
    print("=" * 104)


if __name__ == "__main__":
    main()
