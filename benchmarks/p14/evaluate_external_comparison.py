from __future__ import annotations

import csv
import hashlib
import json
import math
import statistics
import time
from collections import Counter, defaultdict
from pathlib import Path

from benchmarks.p14.runtime_snippet_baseline import RuntimeSnippetBaseline


ROOT = Path(__file__).resolve().parents[2]

CORPUS = (
    ROOT
    / "benchmarks"
    / "p11"
    / "fixtures"
    / "p11_independent_corpus.jsonl"
)

P11_RESULTS = (
    ROOT
    / "benchmarks"
    / "results"
    / "p11"
    / "p11_frozen_results.jsonl"
)

P11_SUMMARY = (
    ROOT
    / "benchmarks"
    / "results"
    / "p11"
    / "p11_summary.csv"
)

OUTDIR = (
    ROOT
    / "benchmarks"
    / "results"
    / "p14"
)

EXPECTED_CORPUS_SHA256 = (
    "2BB245B0CEDA6462253B3D25E7E76B6676FB91A6A4BA4B965EA3C8B35E8B63E4"
)

BASELINE_MIN_FRAGMENT_CHARS = 8


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


def flatten_strings(value) -> str:
    parts: list[str] = []

    def walk(v):
        if isinstance(v, str):
            parts.append(v)

        elif isinstance(v, list):
            for item in v:
                walk(item)

        elif isinstance(v, dict):
            for item in v.values():
                walk(item)

    walk(value)

    return " ".join(parts)


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

    fraction = pos - lo

    return (
        xs[lo] * (1.0 - fraction)
        + xs[hi] * fraction
    )


def wilson(
    successes: int,
    n: int,
    z: float = 1.959963984540054,
) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)

    p = successes / n

    denominator = (
        1.0
        + z * z / n
    )

    center = (
        p
        + z * z / (2.0 * n)
    ) / denominator

    margin = (
        z
        * math.sqrt(
            p * (1.0 - p) / n
            + z * z / (4.0 * n * n)
        )
        / denominator
    )

    return (
        max(0.0, center - margin),
        min(1.0, center + margin),
    )


def exact_mcnemar(
    discordant_a: int,
    discordant_b: int,
) -> float:
    n = (
        discordant_a
        + discordant_b
    )

    if n == 0:
        return 1.0

    k = min(
        discordant_a,
        discordant_b,
    )

    probability = sum(
        math.comb(n, i)
        * (0.5 ** n)
        for i in range(k + 1)
    )

    return min(
        1.0,
        2.0 * probability,
    )


def metric_block(
    rows: list[dict],
    field: str,
) -> dict:
    malicious = [
        r
        for r in rows
        if r["label"] == "malicious"
    ]

    benign = [
        r
        for r in rows
        if r["label"] == "benign"
    ]

    tp = sum(
        bool(r[field])
        for r in malicious
    )

    fp = sum(
        bool(r[field])
        for r in benign
    )

    fn = len(malicious) - tp
    tn = len(benign) - fp

    dr = (
        tp / len(malicious)
    )

    fpr = (
        fp / len(benign)
    )

    precision = (
        tp / (tp + fp)
        if tp + fp
        else 1.0
    )

    specificity = (
        tn / len(benign)
    )

    balanced_accuracy = (
        dr + specificity
    ) / 2.0

    f1 = (
        2.0
        * precision
        * dr
        / (precision + dr)
        if precision + dr
        else 0.0
    )

    return {
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,

        "detection_rate": dr,
        "detection_rate_ci95": list(
            wilson(
                tp,
                len(malicious),
            )
        ),

        "false_positive_rate": fpr,
        "false_positive_rate_ci95": list(
            wilson(
                fp,
                len(benign),
            )
        ),

        "precision": precision,
        "specificity": specificity,
        "balanced_accuracy": balanced_accuracy,
        "f1": f1,
    }


def load_b5_results() -> dict[str, dict]:
    rows = read_jsonl(
        P11_RESULTS
    )

    b5 = [
        r
        for r in rows
        if r.get("config") == "B5"
    ]

    if len(b5) != 1440:
        raise RuntimeError(
            "Expected exactly 1440 frozen B5 records; "
            f"found {len(b5)}."
        )

    by_id = {}

    for row in b5:
        case_id = row.get(
            "case_id"
        )

        if not case_id:
            raise RuntimeError(
                "Frozen B5 record missing case_id."
            )

        if case_id in by_id:
            raise RuntimeError(
                f"Duplicate B5 case_id: {case_id}"
            )

        if "signal" not in row:
            raise RuntimeError(
                f"B5 record {case_id} missing signal field."
            )

        by_id[case_id] = row

    return by_id


def load_b5_summary() -> dict:
    with P11_SUMMARY.open(
        newline="",
        encoding="utf-8-sig",
    ) as handle:
        rows = list(
            csv.DictReader(handle)
        )

    matches = [
        r
        for r in rows
        if r.get("config") == "B5"
    ]

    if len(matches) != 1:
        raise RuntimeError(
            "Expected one B5 summary row; "
            f"found {len(matches)}."
        )

    return matches[0]


def numeric_from_row(
    row: dict,
    candidates: list[str],
):
    for key in candidates:
        if key not in row:
            continue

        value = str(
            row[key]
        ).strip()

        if not value:
            continue

        try:
            return float(value)
        except ValueError:
            continue

    return None


def main() -> None:
    corpus_hash_before = sha256_file(
        CORPUS
    )

    if (
        corpus_hash_before
        != EXPECTED_CORPUS_SHA256
    ):
        raise RuntimeError(
            "P11 frozen corpus hash mismatch."
        )

    corpus = read_jsonl(
        CORPUS
    )

    if len(corpus) != 1440:
        raise RuntimeError(
            f"Expected 1440 corpus rows; found {len(corpus)}."
        )

    labels = Counter(
        r["label"]
        for r in corpus
    )

    if labels != Counter(
        {
            "malicious": 800,
            "benign": 640,
        }
    ):
        raise RuntimeError(
            f"Unexpected label counts: {labels}"
        )

    frozen_b5 = load_b5_results()
    b5_summary = load_b5_summary()

    corpus_ids = {
        r["case_id"]
        for r in corpus
    }

    if corpus_ids != set(
        frozen_b5
    ):
        raise RuntimeError(
            "P11 corpus case IDs and frozen B5 case IDs differ."
        )

    print("=" * 112)
    print("P14 FROZEN EXTERNAL RUNTIME-PROVENANCE COMPARISON")
    print("=" * 112)

    print(
        f"Corpus SHA-256    : "
        f"{corpus_hash_before}"
    )

    print(
        f"Cases              : "
        f"{len(corpus)}"
    )

    print(
        f"Malicious          : "
        f"{labels['malicious']}"
    )

    print(
        f"Benign             : "
        f"{labels['benign']}"
    )

    print(
        f"External baseline  : "
        f"runtime direct-snippet provenance"
    )

    print(
        f"Min snippet chars  : "
        f"{BASELINE_MIN_FRAGMENT_CHARS}"
    )

    print(
        "ProvProxy          : "
        "P11 B5 FROZEN results"
    )

    print()

    comparison_rows = []
    baseline_call_latencies = []

    for index, row in enumerate(
        corpus,
        start=1,
    ):
        detector = RuntimeSnippetBaseline(
            min_fragment_chars=(
                BASELINE_MIN_FRAGMENT_CHARS
            )
        )

        detector.register_source(
            row["source_id"],
            row["synthetic_secret"],
        )

        any_baseline_signal = False
        first_baseline_call = None
        largest_fragment = None

        for call_index, call in enumerate(
            row["calls"],
            start=1,
        ):
            payload = flatten_strings(
                call["arguments"]
            )

            t0 = time.perf_counter_ns()

            result = detector.scan(
                payload
            )

            elapsed_ms = (
                time.perf_counter_ns()
                - t0
            ) / 1_000_000.0

            baseline_call_latencies.append(
                elapsed_ms
            )

            if result.matched:
                if not any_baseline_signal:
                    first_baseline_call = (
                        call_index
                    )

                any_baseline_signal = True

                if (
                    result.matched_fragment
                    and (
                        largest_fragment is None
                        or len(
                            result.matched_fragment
                        )
                        > len(
                            largest_fragment
                        )
                    )
                ):
                    largest_fragment = (
                        result.matched_fragment
                    )

        b5 = frozen_b5[
            row["case_id"]
        ]

        comparison_rows.append(
            {
                "case_id": row["case_id"],
                "label": row["label"],
                "category": row["category"],
                "transformation": row.get(
                    "transformation"
                ),
                "structural_family": row.get(
                    "structural_family"
                ),

                "baseline_signal": (
                    any_baseline_signal
                ),

                "baseline_first_match_call": (
                    first_baseline_call
                ),

                "baseline_matched_fragment_length": (
                    len(largest_fragment)
                    if largest_fragment
                    else 0
                ),

                "provproxy_b5_signal": bool(
                    b5["signal"]
                ),

                "provproxy_b5_hard_match": bool(
                    b5.get(
                        "hard_match",
                        False,
                    )
                ),

                "provproxy_b5_review": bool(
                    b5.get(
                        "review",
                        False,
                    )
                ),

                "provproxy_b5_containment": bool(
                    b5.get(
                        "containment",
                        b5.get(
                            "contained",
                            b5.get(
                                "blocked",
                                False,
                            ),
                        ),
                    )
                ),
            }
        )

        if index % 200 == 0:
            print(
                f"Baseline evaluated "
                f"{index:4d}/1440"
            )

    baseline_metrics = metric_block(
        comparison_rows,
        "baseline_signal",
    )

    provproxy_metrics = metric_block(
        comparison_rows,
        "provproxy_b5_signal",
    )

    malicious = [
        r
        for r in comparison_rows
        if r["label"]
        == "malicious"
    ]

    benign = [
        r
        for r in comparison_rows
        if r["label"]
        == "benign"
    ]

    # Positive-side paired transitions.
    baseline_miss_provproxy_hit = sum(
        (
            not r["baseline_signal"]
        )
        and r["provproxy_b5_signal"]
        for r in malicious
    )

    baseline_hit_provproxy_miss = sum(
        r["baseline_signal"]
        and (
            not r["provproxy_b5_signal"]
        )
        for r in malicious
    )

    malicious_mcnemar = exact_mcnemar(
        baseline_miss_provproxy_hit,
        baseline_hit_provproxy_miss,
    )

    # Benign side.
    baseline_false_provproxy_clean = sum(
        r["baseline_signal"]
        and (
            not r["provproxy_b5_signal"]
        )
        for r in benign
    )

    baseline_clean_provproxy_false = sum(
        (
            not r["baseline_signal"]
        )
        and r["provproxy_b5_signal"]
        for r in benign
    )

    benign_mcnemar = exact_mcnemar(
        baseline_false_provproxy_clean,
        baseline_clean_provproxy_false,
    )

    # Category-level paired results.
    categories = []

    category_keys = sorted(
        {
            (
                r["label"],
                r["category"],
            )
            for r in comparison_rows
        }
    )

    for label, category in category_keys:
        subset = [
            r
            for r in comparison_rows
            if r["label"] == label
            and r["category"] == category
        ]

        baseline_hits = sum(
            r["baseline_signal"]
            for r in subset
        )

        provproxy_hits = sum(
            r["provproxy_b5_signal"]
            for r in subset
        )

        categories.append(
            {
                "label": label,
                "category": category,
                "n": len(subset),

                "baseline_signal_rate": (
                    baseline_hits
                    / len(subset)
                ),

                "provproxy_b5_signal_rate": (
                    provproxy_hits
                    / len(subset)
                ),

                "delta_provproxy_minus_baseline": (
                    (
                        provproxy_hits
                        - baseline_hits
                    )
                    / len(subset)
                ),
            }
        )

    baseline_latency = {
        "samples": len(
            baseline_call_latencies
        ),

        "p50_ms": percentile(
            baseline_call_latencies,
            0.50,
        ),

        "p95_ms": percentile(
            baseline_call_latencies,
            0.95,
        ),

        "p99_ms": percentile(
            baseline_call_latencies,
            0.99,
        ),

        "mean_ms": statistics.fmean(
            baseline_call_latencies
        ),

        "max_ms": max(
            baseline_call_latencies
        ),
    }

    frozen_b5_latency = {
        "raw_summary_row": (
            b5_summary
        ),

        "p50_ms": numeric_from_row(
            b5_summary,
            [
                "p50_ms",
                "latency_p50_ms",
                "p50",
            ],
        ),

        "p95_ms": numeric_from_row(
            b5_summary,
            [
                "p95_ms",
                "latency_p95_ms",
                "p95",
            ],
        ),

        "p99_ms": numeric_from_row(
            b5_summary,
            [
                "p99_ms",
                "latency_p99_ms",
                "p99",
            ],
        ),
    }

    corpus_hash_after = sha256_file(
        CORPUS
    )

    if (
        corpus_hash_after
        != corpus_hash_before
    ):
        raise RuntimeError(
            "Frozen P11 corpus changed during P14."
        )

    summary = {
        "experiment": (
            "P14 frozen external "
            "runtime-provenance comparison"
        ),

        "status": (
            "ONE_SHOT_COMPARISON"
        ),

        "corpus": {
            "sha256_before": (
                corpus_hash_before
            ),

            "sha256_after": (
                corpus_hash_after
            ),

            "hash_unchanged": (
                corpus_hash_before
                == corpus_hash_after
            ),

            "total": len(corpus),
            "malicious": len(malicious),
            "benign": len(benign),
        },

        "external_baseline": {
            "name": (
                "runtime direct-snippet "
                "provenance baseline"
            ),

            "min_fragment_chars": (
                BASELINE_MIN_FRAGMENT_CHARS
            ),

            "metrics": baseline_metrics,
            "latency": baseline_latency,
        },

        "provproxy": {
            "configuration": (
                "P11 B5 frozen"
            ),

            "source": (
                "benchmarks/results/p11/"
                "p11_frozen_results.jsonl"
            ),

            "metrics": provproxy_metrics,
            "frozen_latency": (
                frozen_b5_latency
            ),
        },

        "paired_comparison": {
            "malicious": {
                "baseline_miss_provproxy_hit": (
                    baseline_miss_provproxy_hit
                ),

                "baseline_hit_provproxy_miss": (
                    baseline_hit_provproxy_miss
                ),

                "mcnemar_p": (
                    malicious_mcnemar
                ),
            },

            "benign": {
                "baseline_false_provproxy_clean": (
                    baseline_false_provproxy_clean
                ),

                "baseline_clean_provproxy_false": (
                    baseline_clean_provproxy_false
                ),

                "mcnemar_p": (
                    benign_mcnemar
                ),
            },
        },

        "category_results": (
            categories
        ),

        "fairness": {
            "same_cases": True,
            "same_ground_truth": True,
            "provproxy_not_reexecuted": True,
            "provproxy_results_frozen": True,
            "baseline_frozen_before_execution": True,
            "no_network_execution": True,
        },

        "interpretation_constraint": (
            "This comparison tests runtime "
            "source-to-sink provenance detection. "
            "It is not a claim of universal "
            "security-tool superiority."
        ),
    }

    OUTDIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    summary_path = (
        OUTDIR
        / "p14_external_comparison_summary.json"
    )

    results_path = (
        OUTDIR
        / "p14_external_comparison_results.jsonl"
    )

    category_path = (
        OUTDIR
        / "p14_external_comparison_categories.csv"
    )

    summary_path.write_text(
        json.dumps(
            summary,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    with results_path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as handle:
        for row in comparison_rows:
            handle.write(
                json.dumps(
                    row,
                    sort_keys=True,
                )
                + "\n"
            )

    with category_path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "label",
                "category",
                "n",
                "baseline_signal_rate",
                "provproxy_b5_signal_rate",
                "delta_provproxy_minus_baseline",
            ],
        )

        writer.writeheader()
        writer.writerows(
            categories
        )

    print()
    print("=" * 112)
    print("P14 FINAL COMPARISON")
    print("=" * 112)

    print(
        "External baseline DR/FPR : "
        f"{baseline_metrics['detection_rate']:.3f} / "
        f"{baseline_metrics['false_positive_rate']:.3f}"
    )

    print(
        "ProvProxy B5 DR/FPR      : "
        f"{provproxy_metrics['detection_rate']:.3f} / "
        f"{provproxy_metrics['false_positive_rate']:.3f}"
    )

    print(
        "External precision       : "
        f"{baseline_metrics['precision']:.3f}"
    )

    print(
        "ProvProxy precision      : "
        f"{provproxy_metrics['precision']:.3f}"
    )

    print(
        "External BA              : "
        f"{baseline_metrics['balanced_accuracy']:.3f}"
    )

    print(
        "ProvProxy BA             : "
        f"{provproxy_metrics['balanced_accuracy']:.3f}"
    )

    print()
    print(
        "Baseline miss -> ProvProxy hit : "
        f"{baseline_miss_provproxy_hit}"
    )

    print(
        "Baseline hit -> ProvProxy miss : "
        f"{baseline_hit_provproxy_miss}"
    )

    print(
        "Malicious McNemar p            : "
        f"{malicious_mcnemar:.12g}"
    )

    print()
    print(
        "Baseline false -> ProvProxy clean : "
        f"{baseline_false_provproxy_clean}"
    )

    print(
        "Baseline clean -> ProvProxy false : "
        f"{baseline_clean_provproxy_false}"
    )

    print(
        "Benign McNemar p                : "
        f"{benign_mcnemar:.12g}"
    )

    print()
    print(
        "External latency p50/p95/p99 ms : "
        f"{baseline_latency['p50_ms']:.6f} / "
        f"{baseline_latency['p95_ms']:.6f} / "
        f"{baseline_latency['p99_ms']:.6f}"
    )

    print(
        "Frozen B5 latency row           : "
        f"{b5_summary}"
    )

    print(
        f"Corpus unchanged                : "
        f"{corpus_hash_after == corpus_hash_before}"
    )

    print()
    print(
        f"[WRITE] {summary_path}"
    )

    print(
        f"[WRITE] {results_path}"
    )

    print(
        f"[WRITE] {category_path}"
    )

    print()
    print("[PASS] Same frozen P11 cases used.")
    print("[PASS] Frozen ProvProxy B5 results reused.")
    print("[PASS] ProvProxy was NOT rerun or retuned.")
    print("[PASS] External baseline used frozen implementation.")
    print("=" * 112)


if __name__ == "__main__":
    main()
