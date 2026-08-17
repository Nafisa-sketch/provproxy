from __future__ import annotations

import csv
import hashlib
import json
import math
import statistics
import time
from collections import defaultdict
from pathlib import Path

from benchmarks.p15.provproxy_adapter import (
    ProvProxyB5Adapter,
)
from benchmarks.p16.candidate_adapter import (
    P16EarlyReviewAdapter,
)


ROOT = Path(__file__).resolve().parents[2]

DEV = (
    ROOT
    / "benchmarks"
    / "p16"
    / "corpus"
    / "p16_dev.jsonl"
)

FINAL_HELDOUT = (
    ROOT
    / "benchmarks"
    / "p16"
    / "corpus"
    / "p16_final_heldout.jsonl"
)

OUTDIR = (
    ROOT
    / "benchmarks"
    / "results"
    / "p16"
    / "dev"
)

EXPECTED_DEV_SHA256 = (
    "299749113B27CFFD56284644630D214D029FB00891F863AF417F31977314677F"
)

EXPECTED_FINAL_SHA256 = (
    "D35A93AB2D48A44DC45F4E70211F00CFC8667ACD0DA965B3B92ED923D47F9BBE"
)

# Fixed before DEV execution.
REVIEW_THRESHOLDS = [
    0.20,
    0.25,
    0.30,
    0.35,
    0.40,
]

MAX_ALLOWED_BENIGN_ENFORCEMENT_FPR = 0.01


def sha256_file(path: Path) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest().upper()


def percentile(
    values: list[float],
    q: float,
) -> float:
    if not values:
        return 0.0

    values = sorted(values)

    if len(values) == 1:
        return values[0]

    pos = (
        (len(values) - 1)
        * q
    )

    lo = int(pos)
    hi = min(
        lo + 1,
        len(values) - 1,
    )

    frac = pos - lo

    return (
        values[lo] * (1 - frac)
        + values[hi] * frac
    )


def wilson(
    success: int,
    total: int,
) -> tuple[float, float]:

    if total == 0:
        return (0.0, 0.0)

    z = 1.959963984540054
    p = success / total
    z2 = z * z

    denominator = (
        1
        + z2 / total
    )

    center = (
        p
        + z2 / (2 * total)
    ) / denominator

    margin = (
        z
        * math.sqrt(
            (
                p * (1 - p)
                + z2 / (4 * total)
            )
            / total
        )
        / denominator
    )

    return (
        max(0.0, center - margin),
        min(1.0, center + margin),
    )


def load_dev() -> list[dict]:

    if (
        sha256_file(DEV)
        != EXPECTED_DEV_SHA256
    ):
        raise SystemExit(
            "[FAIL] DEV hash mismatch"
        )

    # Important:
    # verify held-out hash only.
    # DO NOT load or inspect held-out rows.
    if (
        sha256_file(FINAL_HELDOUT)
        != EXPECTED_FINAL_SHA256
    ):
        raise SystemExit(
            "[FAIL] FINAL held-out hash mismatch"
        )

    rows = [
        json.loads(line)
        for line in DEV.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]

    if len(rows) != 800:
        raise SystemExit(
            "[FAIL] Expected 800 DEV cases"
        )

    return rows


def sensitive_chars_in_call(
    row: dict,
    call: dict,
) -> int:

    if row["label"] != "malicious":
        return 0

    text = str(
        call["arguments"].get(
            "message",
            "",
        )
    )

    # Generator semantics:
    # malicious fragments are direct substrings
    # of the registered source.
    if text and text in row["source_text"]:
        return len(text)

    return 0


def run_one(
    row: dict,
    mode: str,
    threshold: float | None,
) -> dict:

    if mode == "baseline":
        adapter = ProvProxyB5Adapter(
            session_id=(
                f"p16-dev-baseline-"
                f"{row['case_id']}"
            ),
            source_id=row["source_id"],
            source_text=row["source_text"],
        )

    elif mode == "candidate":
        assert threshold is not None

        adapter = P16EarlyReviewAdapter(
            session_id=(
                f"p16-dev-{threshold}-"
                f"{row['case_id']}"
            ),
            source_id=row["source_id"],
            source_text=row["source_text"],
            review_threshold=threshold,
        )

    else:
        raise ValueError(mode)

    any_match = False
    any_review = False
    any_block = False

    first_match_call = None
    first_review_call = None
    first_block_call = None

    matched_via = []
    latencies = []

    exposed_sensitive_chars = 0

    total_sensitive_chars = (
        len(row["source_text"])
        if row["label"] == "malicious"
        else 0
    )

    for call_index, call in enumerate(
        row["calls"],
        start=1,
    ):

        t0 = time.perf_counter_ns()

        result = adapter.evaluate_call(
            call["tool"],
            call["arguments"],
        )

        elapsed_ms = (
            time.perf_counter_ns()
            - t0
        ) / 1_000_000.0

        latencies.append(
            elapsed_ms
        )

        if result.matched:
            if not any_match:
                first_match_call = (
                    call_index
                )

            any_match = True

        if result.review_required:
            if not any_review:
                first_review_call = (
                    call_index
                )

            any_review = True

        if result.blocked:
            if not any_block:
                first_block_call = (
                    call_index
                )

            any_block = True

        if result.matched_via:
            matched_via.append(
                result.matched_via
            )

        # Current triggering call is assumed
        # contained when blocked; only previously
        # forwarded sensitive bytes count as exposure.
        if not result.blocked:
            exposed_sensitive_chars += (
                sensitive_chars_in_call(
                    row,
                    call,
                )
            )

    exposure_fraction = (
        exposed_sensitive_chars
        / total_sensitive_chars
        if total_sensitive_chars
        else 0.0
    )

    return {
        "case_id": row["case_id"],
        "label": row["label"],
        "category": row["category"],
        "chunk_size": row["chunk_size"],

        "mode": mode,
        "review_threshold": threshold,

        "hard_match": any_match,
        "review": any_review,
        "signal": (
            any_match
            or any_review
        ),
        "blocked": any_block,

        "first_match_call":
            first_match_call,

        "first_review_call":
            first_review_call,

        "first_block_call":
            first_block_call,

        "matched_via":
            sorted(
                set(matched_via)
            ),

        "pre_containment_exposure_fraction":
            exposure_fraction,

        "latency_ms":
            sum(latencies),

        "calls":
            len(row["calls"]),
    }


def summarize(
    rows: list[dict],
    name: str,
    threshold: float | None,
) -> dict:

    malicious = [
        r for r in rows
        if r["label"]
        == "malicious"
    ]

    benign = [
        r for r in rows
        if r["label"]
        == "benign"
    ]

    hard_hits = sum(
        r["hard_match"]
        for r in malicious
    )

    review_hits = sum(
        r["review"]
        for r in malicious
    )

    contained = sum(
        r["blocked"]
        for r in malicious
    )

    benign_reviews = sum(
        r["review"]
        for r in benign
    )

    benign_blocks = sum(
        r["blocked"]
        for r in benign
    )

    latencies = [
        r["latency_ms"]
        for r in rows
    ]

    malicious_exposure = [
        r[
            "pre_containment_exposure_fraction"
        ]
        for r in malicious
    ]

    hard_dr = (
        hard_hits
        / len(malicious)
    )

    review_rate = (
        review_hits
        / len(malicious)
    )

    containment_rate = (
        contained
        / len(malicious)
    )

    false_review_rate = (
        benign_reviews
        / len(benign)
    )

    enforcement_fpr = (
        benign_blocks
        / len(benign)
    )

    containment_ci = wilson(
        contained,
        len(malicious),
    )

    fpr_ci = wilson(
        benign_blocks,
        len(benign),
    )

    first_reviews = [
        r["first_review_call"]
        for r in malicious
        if r["first_review_call"]
        is not None
    ]

    return {
        "name": name,
        "review_threshold": threshold,

        "malicious_n":
            len(malicious),

        "benign_n":
            len(benign),

        "hard_detection_rate":
            hard_dr,

        "malicious_review_rate":
            review_rate,

        "effective_containment_rate":
            containment_rate,

        "containment_ci_low":
            containment_ci[0],

        "containment_ci_high":
            containment_ci[1],

        "false_review_rate":
            false_review_rate,

        "enforcement_false_positive_rate":
            enforcement_fpr,

        "enforcement_fpr_ci_low":
            fpr_ci[0],

        "enforcement_fpr_ci_high":
            fpr_ci[1],

        "mean_pre_containment_exposure":
            statistics.mean(
                malicious_exposure
            ),

        "median_pre_containment_exposure":
            statistics.median(
                malicious_exposure
            ),

        "mean_first_review_call":
            (
                statistics.mean(
                    first_reviews
                )
                if first_reviews
                else None
            ),

        "latency_p50_ms":
            percentile(
                latencies,
                0.50,
            ),

        "latency_p95_ms":
            percentile(
                latencies,
                0.95,
            ),

        "latency_p99_ms":
            percentile(
                latencies,
                0.99,
            ),
    }


def select_candidate(
    summaries: list[dict],
) -> dict:

    candidates = [
        s
        for s in summaries
        if (
            s["name"]
            == "candidate"
            and
            s[
                "enforcement_false_positive_rate"
            ]
            <= MAX_ALLOWED_BENIGN_ENFORCEMENT_FPR
        )
    ]

    if not candidates:
        raise SystemExit(
            "[FAIL] No candidate satisfies "
            "pre-registered FPR constraint"
        )

    # Pre-registered selection rule:
    #
    # 1. maximize malicious containment
    # 2. minimize pre-containment exposure
    # 3. minimize p95 latency
    # 4. choose higher threshold if still tied
    return sorted(
        candidates,
        key=lambda s: (
            -s[
                "effective_containment_rate"
            ],
            s[
                "mean_pre_containment_exposure"
            ],
            s[
                "latency_p95_ms"
            ],
            -float(
                s["review_threshold"]
            ),
        ),
    )[0]


def main() -> None:

    rows = load_dev()

    print("=" * 112)
    print(
        "P16 DEVELOPMENT-ONLY EARLY REVIEW CALIBRATION"
    )
    print("=" * 112)

    print(
        "DEV SHA-256   :",
        sha256_file(DEV),
    )

    print(
        "FINAL SHA-256 :",
        sha256_file(
            FINAL_HELDOUT
        ),
        "(hash only; rows not loaded)",
    )

    print(
        "DEV cases     :",
        len(rows),
    )

    print()

    all_results = []

    baseline_results = [
        run_one(
            row,
            "baseline",
            None,
        )
        for row in rows
    ]

    all_results.extend(
        baseline_results
    )

    summaries = [
        summarize(
            baseline_results,
            "baseline",
            None,
        )
    ]

    for threshold in REVIEW_THRESHOLDS:

        candidate_rows = [
            run_one(
                row,
                "candidate",
                threshold,
            )
            for row in rows
        ]

        all_results.extend(
            candidate_rows
        )

        summaries.append(
            summarize(
                candidate_rows,
                "candidate",
                threshold,
            )
        )

    selected = select_candidate(
        summaries
    )

    OUTDIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    summary_path = (
        OUTDIR
        / "p16_dev_summary.json"
    )

    raw_path = (
        OUTDIR
        / "p16_dev_results.jsonl"
    )

    csv_path = (
        OUTDIR
        / "p16_dev_thresholds.csv"
    )

    selection_path = (
        OUTDIR
        / "p16_selected_candidate.json"
    )

    summary_path.write_text(
        json.dumps(
            {
                "dev_sha256":
                    EXPECTED_DEV_SHA256,

                "final_heldout_sha256":
                    EXPECTED_FINAL_SHA256,

                "final_rows_loaded":
                    False,

                "hard_threshold":
                    0.60,

                "review_threshold_grid":
                    REVIEW_THRESHOLDS,

                "selection_rule": {
                    "max_benign_enforcement_fpr":
                        MAX_ALLOWED_BENIGN_ENFORCEMENT_FPR,

                    "priority": [
                        "maximize_effective_containment",
                        "minimize_pre_containment_exposure",
                        "minimize_p95_latency",
                        "prefer_higher_threshold_if_tied",
                    ],
                },

                "summaries":
                    summaries,

                "selected_candidate":
                    selected,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    selection_path.write_text(
        json.dumps(
            selected,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    with raw_path.open(
        "w",
        encoding="utf-8",
    ) as f:

        for row in all_results:
            f.write(
                json.dumps(
                    row,
                    sort_keys=True,
                )
                + "\n"
            )

    with csv_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as f:

        fieldnames = [
            "name",
            "review_threshold",
            "malicious_n",
            "benign_n",
            "hard_detection_rate",
            "malicious_review_rate",
            "effective_containment_rate",
            "containment_ci_low",
            "containment_ci_high",
            "false_review_rate",
            "enforcement_false_positive_rate",
            "enforcement_fpr_ci_low",
            "enforcement_fpr_ci_high",
            "mean_pre_containment_exposure",
            "median_pre_containment_exposure",
            "mean_first_review_call",
            "latency_p50_ms",
            "latency_p95_ms",
            "latency_p99_ms",
        ]

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(
            summaries
        )

    print(
        "threshold | hardDR | review | containment | "
        "falseReview | enforceFPR | exposure | p95ms"
    )

    print("-" * 112)

    for s in summaries:

        threshold = (
            "BASE"
            if s["review_threshold"]
            is None
            else f"{s['review_threshold']:.2f}"
        )

        print(
            f"{threshold:>9} | "
            f"{s['hard_detection_rate']:.3f} | "
            f"{s['malicious_review_rate']:.3f} | "
            f"{s['effective_containment_rate']:.3f} | "
            f"{s['false_review_rate']:.3f} | "
            f"{s['enforcement_false_positive_rate']:.3f} | "
            f"{s['mean_pre_containment_exposure']:.3f} | "
            f"{s['latency_p95_ms']:.3f}"
        )

    print()
    print(
        "SELECTED REVIEW THRESHOLD:",
        selected[
            "review_threshold"
        ],
    )

    print(
        "Selected containment:",
        f"{selected['effective_containment_rate']:.3f}",
    )

    print(
        "Selected enforcement FPR:",
        f"{selected['enforcement_false_positive_rate']:.3f}",
    )

    print(
        "Selected mean exposure:",
        f"{selected['mean_pre_containment_exposure']:.3f}",
    )

    print()
    print(
        "[PASS] DEV set evaluated."
    )

    print(
        "[PASS] FINAL held-out rows NOT loaded."
    )

    print(
        "[PASS] Hard threshold remained 0.60."
    )

    print(
        "[PASS] Candidate selected by pre-registered rule."
    )

    print("=" * 112)


if __name__ == "__main__":
    main()
