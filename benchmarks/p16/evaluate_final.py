from __future__ import annotations

import csv
import hashlib
import json
import math
import statistics
import time
from pathlib import Path

from benchmarks.p15.provproxy_adapter import ProvProxyB5Adapter
from benchmarks.p16.candidate_adapter import P16EarlyReviewAdapter


ROOT = Path(__file__).resolve().parents[2]

FINAL = (
    ROOT
    / "benchmarks"
    / "p16"
    / "corpus"
    / "p16_final_heldout.jsonl"
)

LOCK = (
    ROOT
    / "benchmarks"
    / "p16"
    / "FINAL_CANDIDATE_LOCK.json"
)

OUTDIR = (
    ROOT
    / "benchmarks"
    / "results"
    / "p16"
    / "final"
)

EXPECTED_FINAL_SHA256 = (
    "D35A93AB2D48A44DC45F4E70211F00CFC8667ACD0DA965B3B92ED923D47F9BBE"
)

EXPECTED_LOCK_SHA256 = (
    "111C25B82793B35EA118F902D8845D6B4E7D78A9AE6DB1ADF6046893303A75CC"
)

LOCKED_REVIEW_THRESHOLD = 0.25
LOCKED_HARD_THRESHOLD = 0.60


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

    pos = (len(values) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(values) - 1)
    frac = pos - lo

    return (
        values[lo] * (1.0 - frac)
        + values[hi] * frac
    )


def wilson(
    successes: int,
    total: int,
) -> tuple[float, float]:
    if total == 0:
        return (0.0, 0.0)

    z = 1.959963984540054
    p = successes / total
    z2 = z * z

    denom = 1.0 + z2 / total

    center = (
        p + z2 / (2.0 * total)
    ) / denom

    margin = (
        z
        * math.sqrt(
            (
                p * (1.0 - p)
                + z2 / (4.0 * total)
            )
            / total
        )
        / denom
    )

    return (
        max(0.0, center - margin),
        min(1.0, center + margin),
    )


def exact_mcnemar_p(
    b: int,
    c: int,
) -> float:
    n = b + c

    if n == 0:
        return 1.0

    k = min(b, c)

    tail = sum(
        math.comb(n, i)
        for i in range(k + 1)
    ) / (2 ** n)

    return min(
        1.0,
        2.0 * tail,
    )


def load_final() -> list[dict]:
    if (
        sha256_file(FINAL)
        != EXPECTED_FINAL_SHA256
    ):
        raise SystemExit(
            "[FAIL] Final held-out hash mismatch"
        )

    if (
        sha256_file(LOCK)
        != EXPECTED_LOCK_SHA256
    ):
        raise SystemExit(
            "[FAIL] Candidate lock hash mismatch"
        )

    lock = json.loads(
        LOCK.read_text(
            encoding="utf-8"
        )
    )

    selected = lock[
        "selected_candidate"
    ]

    if (
        float(selected["review_threshold"])
        != LOCKED_REVIEW_THRESHOLD
    ):
        raise SystemExit(
            "[FAIL] Locked review threshold mismatch"
        )

    if (
        float(selected["hard_match_threshold"])
        != LOCKED_HARD_THRESHOLD
    ):
        raise SystemExit(
            "[FAIL] Locked hard threshold mismatch"
        )

    rows = [
        json.loads(line)
        for line in FINAL.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]

    if len(rows) != 800:
        raise SystemExit(
            f"[FAIL] Expected 800 held-out rows, got {len(rows)}"
        )

    return rows


def sensitive_chars_in_call(
    row: dict,
    call: dict,
) -> int:
    if row["label"] != "malicious":
        return 0

    message = str(
        call["arguments"].get(
            "message",
            "",
        )
    )

    if (
        message
        and message in row["source_text"]
    ):
        return len(message)

    return 0


def run_case(
    row: dict,
    mode: str,
) -> dict:

    if mode == "baseline":
        adapter = ProvProxyB5Adapter(
            session_id=(
                "p16-final-baseline-"
                + row["case_id"]
            ),
            source_id=row["source_id"],
            source_text=row["source_text"],
        )

    elif mode == "candidate":
        adapter = P16EarlyReviewAdapter(
            session_id=(
                "p16-final-candidate-"
                + row["case_id"]
            ),
            source_id=row["source_id"],
            source_text=row["source_text"],
            review_threshold=(
                LOCKED_REVIEW_THRESHOLD
            ),
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

        latencies.append(
            (
                time.perf_counter_ns()
                - t0
            )
            / 1_000_000.0
        )

        if result.matched:
            if not any_match:
                first_match_call = call_index

            any_match = True

        if result.review_required:
            if not any_review:
                first_review_call = call_index

            any_review = True

        if result.blocked:
            if not any_block:
                first_block_call = call_index

            any_block = True

        if result.matched_via:
            matched_via.append(
                result.matched_via
            )

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
        "interleaved": row["interleaved"],

        "mode": mode,

        "hard_match": bool(any_match),
        "review": bool(any_review),
        "signal": bool(
            any_match
            or any_review
        ),
        "blocked": bool(any_block),

        "first_match_call":
            first_match_call,

        "first_review_call":
            first_review_call,

        "first_block_call":
            first_block_call,

        "matched_via":
            sorted(set(matched_via)),

        "pre_containment_exposure_fraction":
            exposure_fraction,

        "latency_ms":
            float(sum(latencies)),

        "calls":
            len(row["calls"]),
    }


def summarize(
    rows: list[dict],
    name: str,
) -> dict:

    malicious = [
        r for r in rows
        if r["label"] == "malicious"
    ]

    benign = [
        r for r in rows
        if r["label"] == "benign"
    ]

    hard_hits = sum(
        bool(r["hard_match"])
        for r in malicious
    )

    review_hits = sum(
        bool(r["review"])
        for r in malicious
    )

    contained = sum(
        bool(r["blocked"])
        for r in malicious
    )

    benign_reviews = sum(
        bool(r["review"])
        for r in benign
    )

    benign_blocks = sum(
        bool(r["blocked"])
        for r in benign
    )

    latencies = [
        float(r["latency_ms"])
        for r in rows
    ]

    exposures = [
        float(
            r[
                "pre_containment_exposure_fraction"
            ]
        )
        for r in malicious
    ]

    first_reviews = [
        r["first_review_call"]
        for r in malicious
        if r["first_review_call"]
        is not None
    ]

    containment_ci = wilson(
        contained,
        len(malicious),
    )

    fpr_ci = wilson(
        benign_blocks,
        len(benign),
    )

    return {
        "name": name,

        "malicious_n":
            len(malicious),

        "benign_n":
            len(benign),

        "hard_detection_rate":
            hard_hits / len(malicious),

        "malicious_review_rate":
            review_hits / len(malicious),

        "effective_containment_rate":
            contained / len(malicious),

        "containment_ci_low":
            containment_ci[0],

        "containment_ci_high":
            containment_ci[1],

        "false_review_rate":
            benign_reviews / len(benign),

        "enforcement_false_positive_rate":
            benign_blocks / len(benign),

        "enforcement_fpr_ci_low":
            fpr_ci[0],

        "enforcement_fpr_ci_high":
            fpr_ci[1],

        "mean_pre_containment_exposure":
            statistics.mean(exposures),

        "median_pre_containment_exposure":
            statistics.median(exposures),

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


def category_summary(
    rows: list[dict],
) -> list[dict]:
    result = []

    keys = sorted({
        (
            r["mode"],
            r["label"],
            r["category"],
        )
        for r in rows
    })

    for mode, label, category in keys:
        subset = [
            r for r in rows
            if (
                r["mode"] == mode
                and r["label"] == label
                and r["category"] == category
            )
        ]

        signal_n = sum(
            bool(r["signal"])
            for r in subset
        )

        blocked_n = sum(
            bool(r["blocked"])
            for r in subset
        )

        review_n = sum(
            bool(r["review"])
            for r in subset
        )

        result.append({
            "mode": mode,
            "label": label,
            "category": category,
            "n": len(subset),

            "signal_rate":
                signal_n / len(subset),

            "review_rate":
                review_n / len(subset),

            "containment_rate":
                blocked_n / len(subset),
        })

    return result


def main() -> None:
    print("=" * 116)
    print(
        "P16 FINAL HELD-OUT CROSS-CALL "
        "LIMITATION FOLLOW-UP"
    )
    print("=" * 116)

    before_hash = sha256_file(FINAL)

    rows = load_final()

    print(
        "Final SHA-256 :",
        before_hash,
    )

    print(
        "Cases         :",
        len(rows),
    )

    print(
        "Locked review :",
        LOCKED_REVIEW_THRESHOLD,
    )

    print(
        "Hard threshold:",
        LOCKED_HARD_THRESHOLD,
    )

    print()

    print(
        "[1/2] Running frozen P15 baseline..."
    )

    baseline = [
        run_case(
            row,
            "baseline",
        )
        for row in rows
    ]

    print(
        "[2/2] Running locked P16 candidate..."
    )

    candidate = [
        run_case(
            row,
            "candidate",
        )
        for row in rows
    ]

    baseline_summary = summarize(
        baseline,
        "baseline",
    )

    candidate_summary = summarize(
        candidate,
        "candidate",
    )

    baseline_by_id = {
        r["case_id"]: r
        for r in baseline
    }

    candidate_by_id = {
        r["case_id"]: r
        for r in candidate
    }

    malicious_rows = [
        row
        for row in rows
        if row["label"] == "malicious"
    ]

    candidate_hit_baseline_miss = 0
    baseline_hit_candidate_miss = 0

    for row in malicious_rows:
        cid = row["case_id"]

        b = bool(
            baseline_by_id[cid]["blocked"]
        )

        c = bool(
            candidate_by_id[cid]["blocked"]
        )

        if c and not b:
            candidate_hit_baseline_miss += 1

        elif b and not c:
            baseline_hit_candidate_miss += 1

    mcnemar_p = exact_mcnemar_p(
        candidate_hit_baseline_miss,
        baseline_hit_candidate_miss,
    )

    combined = (
        baseline
        + candidate
    )

    categories = category_summary(
        combined
    )

    after_hash = sha256_file(FINAL)

    if after_hash != before_hash:
        raise SystemExit(
            "[FAIL] Final held-out corpus changed during execution"
        )

    OUTDIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    summary_path = (
        OUTDIR
        / "p16_final_summary.json"
    )

    raw_path = (
        OUTDIR
        / "p16_final_results.jsonl"
    )

    category_path = (
        OUTDIR
        / "p16_final_categories.csv"
    )

    summary = {
        "experiment": "P16",

        "final_sha256":
            EXPECTED_FINAL_SHA256,

        "candidate_lock_sha256":
            EXPECTED_LOCK_SHA256,

        "final_corpus_unchanged":
            True,

        "locked_review_threshold":
            LOCKED_REVIEW_THRESHOLD,

        "hard_match_threshold":
            LOCKED_HARD_THRESHOLD,

        "baseline":
            baseline_summary,

        "candidate":
            candidate_summary,

        "paired_malicious_containment": {
            "candidate_hit_baseline_miss":
                candidate_hit_baseline_miss,

            "baseline_hit_candidate_miss":
                baseline_hit_candidate_miss,

            "exact_mcnemar_p":
                mcnemar_p,
        },

        "interpretation_constraint": (
            "P16 evaluates a separately labeled "
            "early-review containment mechanism. "
            "Review events are not reclassified as "
            "hard provenance matches."
        ),
    }

    summary_path.write_text(
        json.dumps(
            summary,
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
        for row in combined:
            f.write(
                json.dumps(
                    row,
                    sort_keys=True,
                )
                + "\n"
            )

    with category_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as f:
        fieldnames = [
            "mode",
            "label",
            "category",
            "n",
            "signal_rate",
            "review_rate",
            "containment_rate",
        ]

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(categories)

    print("=" * 116)
    print("P16 FINAL RESULTS")
    print("=" * 116)

    print(
        "Baseline hardDR / containment / FPR : "
        f"{baseline_summary['hard_detection_rate']:.3f} / "
        f"{baseline_summary['effective_containment_rate']:.3f} / "
        f"{baseline_summary['enforcement_false_positive_rate']:.3f}"
    )

    print(
        "Candidate hardDR / containment / FPR: "
        f"{candidate_summary['hard_detection_rate']:.3f} / "
        f"{candidate_summary['effective_containment_rate']:.3f} / "
        f"{candidate_summary['enforcement_false_positive_rate']:.3f}"
    )

    print(
        "Candidate malicious review rate       : "
        f"{candidate_summary['malicious_review_rate']:.3f}"
    )

    print(
        "Baseline mean exposure                : "
        f"{baseline_summary['mean_pre_containment_exposure']:.3f}"
    )

    print(
        "Candidate mean exposure               : "
        f"{candidate_summary['mean_pre_containment_exposure']:.3f}"
    )

    print(
        "Candidate hit / Baseline miss         :",
        candidate_hit_baseline_miss,
    )

    print(
        "Baseline hit / Candidate miss         :",
        baseline_hit_candidate_miss,
    )

    print(
        "Exact McNemar p                       : "
        f"{mcnemar_p:.12g}"
    )

    print()
    print(
        "Baseline p95 ms : "
        f"{baseline_summary['latency_p95_ms']:.3f}"
    )

    print(
        "Candidate p95 ms: "
        f"{candidate_summary['latency_p95_ms']:.3f}"
    )

    print()
    print(
        "Corpus unchanged:",
        after_hash == before_hash,
    )

    print()
    print(
        "[WRITE]",
        summary_path,
    )

    print(
        "[WRITE]",
        raw_path,
    )

    print(
        "[WRITE]",
        category_path,
    )

    print()
    print(
        "[PASS] Locked candidate used."
    )

    print(
        "[PASS] Final held-out hash verified before and after."
    )

    print(
        "[PASS] Hard threshold remained 0.60."
    )

    print("=" * 116)


if __name__ == "__main__":
    main()
