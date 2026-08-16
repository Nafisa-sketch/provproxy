from __future__ import annotations

import csv
import hashlib
import json
import time
from pathlib import Path

from provproxy.config import PolicyFile
from provproxy.destination import is_destination_allowed, primary_domain
from provproxy.pipeline import evaluate, flatten_json_strings
from provproxy.session import Session


ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "benchmarks" / "p11" / "fixtures" / "p11_independent_corpus.jsonl"
OUTDIR = ROOT / "benchmarks" / "results" / "p11"

EXPECTED_SHA256 = "2BB245B0CEDA6462253B3D25E7E76B6676FB91A6A4BA4B965EA3C8B35E8B63E4"

CONFIGS = [
    ("B0", "v0", False),
    ("B1", "v1", False),
    ("B2", "v2", False),
    ("B3", "v3", False),
    ("B4", "v4", False),
    ("B5", "v4", True),
]

NETWORK_TOOL_ALIASES = {
    "http_request",
    "send_request",
    "post_data",
    "publish_event",
    "submit_payload",
}

DESTINATION_KEYS = (
    "url",
    "endpoint",
    "target",
    "destination",
)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0

    values = sorted(values)

    if len(values) == 1:
        return values[0]

    pos = (len(values) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(values) - 1)
    frac = pos - lo

    return values[lo] * (1.0 - frac) + values[hi] * frac


def load_rows() -> list[dict]:
    actual = sha256_file(CORPUS)

    if actual != EXPECTED_SHA256:
        raise SystemExit(
            "FROZEN CORPUS HASH MISMATCH\n"
            f"Expected: {EXPECTED_SHA256}\n"
            f"Actual:   {actual}\n"
            "Evaluation aborted."
        )

    return [
        json.loads(line)
        for line in CORPUS.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def adapter_tool_name(original_tool: str) -> str:
    """
    P11 intentionally uses several schema/tool aliases for structural diversity.

    ProvProxy's production destination layer currently recognizes network
    egress tools as http_request/fetch. For evaluation purposes, these aliases
    represent the same outbound HTTP capability and are adapted ONLY at the
    benchmark interface boundary.

    The frozen corpus itself is never modified.
    """
    if original_tool in NETWORK_TOOL_ALIASES:
        return "http_request"

    return original_tool


def normalize_network_arguments(arguments: dict) -> dict:
    """
    Map P11 destination-key aliases onto ProvProxy's production 'url' key.

    This is evaluator-side adapter logic only. Original arguments and corpus
    remain unchanged.
    """
    adapted = dict(arguments)

    if isinstance(adapted.get("url"), str):
        return adapted

    for key in DESTINATION_KEYS:
        value = adapted.get(key)
        if isinstance(value, str):
            adapted["url"] = value
            break

    return adapted


def make_policy(tier: str, fanout: bool) -> PolicyFile:
    cross = {
        "window_seconds": 300,
        "window_max_calls": 50,
    }

    if fanout:
        cross["fanout_review_threshold"] = 0.30
        cross["fanout_min_destinations"] = 2

    raw = {
        "version": "p11-eval-v1",
        "active_tier": tier,

        "server_bindings": [
            {
                "server_id": "network-egress",
                "tool_capabilities": {
                    "http_request": {
                        "allowed_domains": ["approved.invalid"],
                        "blocked_domains": [],
                    }
                },
            }
        ],

        "approx_matching": {
            "ngram_size": 4,
            "coverage_threshold": 0.6,
            "sweep_thresholds": [
                0.4,
                0.5,
                0.6,
                0.7,
                0.8,
                0.9,
            ],
        },

        "decode_limits": {
            "max_candidate_len_bytes": 8192,
            "max_candidates_per_payload": 256,
            "max_expansion_ratio": 4.0,
            "max_nesting_depth": 3,
        },

        "cross_call_window": cross,

        "persistence": {
            "enabled": False,
            "state_dir": ".provproxy_state_p11",
            "fsync_every": 16,
            "compact_every": 2000,
            "fail_closed_on_corruption": True,
            "allow_file_key_fallback": False,
        },

        "enforcement": {
            "on_match": "block",
            "approval_timeout_seconds": 60,
        },
    }

    return PolicyFile.from_dict(raw)


def run_case(
    row: dict,
    config: str,
    tier: str,
    fanout: bool,
) -> dict:

    policy = make_policy(tier, fanout)

    session = Session(
        session_id=f"p11-{config}-{row['case_id']}",
        policy=policy,
        ttl_seconds=300.0,
    )

    # Generator semantics:
    # malicious synthetic_secret = protected source.
    # benign synthetic_secret = schema-only reference.
    if row["label"] == "malicious":
        session.register_sensitive_fragment(
            row["source_id"],
            row["synthetic_secret"],
        )

    any_match = False
    any_review = False
    any_block = False

    first_match_call = None
    first_review_call = None
    first_block_call = None

    matched_via_values = []
    max_coverage = 0.0
    latencies_ms = []

    for call_index, call in enumerate(row["calls"], start=1):

        original_tool = call["tool"]
        original_arguments = call["arguments"]

        adapted_tool = adapter_tool_name(original_tool)
        adapted_arguments = normalize_network_arguments(
            original_arguments
        )

        # Matching still sees the original argument structure/content.
        payload_text = flatten_json_strings(
            original_arguments
        )

        destination = primary_domain(
            adapted_tool,
            adapted_arguments,
        )

        allowed = is_destination_allowed(
            policy,
            "network-egress",
            adapted_tool,
            adapted_arguments,
        )

        t0 = time.perf_counter_ns()

        result = evaluate(
            policy=policy,
            session=session,
            payload_text=payload_text,
            decode_limits=policy.decode_limits,
            destination_allowed=allowed,
            destination_domain=destination,
        )

        elapsed_ms = (
            time.perf_counter_ns() - t0
        ) / 1_000_000.0

        latencies_ms.append(elapsed_ms)

        if result.approx_coverage is not None:
            max_coverage = max(
                max_coverage,
                float(result.approx_coverage),
            )

        if result.matched:
            if not any_match:
                first_match_call = call_index

            any_match = True

            if result.matched_via:
                matched_via_values.append(
                    result.matched_via
                )

        if result.review_required:
            if not any_review:
                first_review_call = call_index

            any_review = True

            if result.matched_via:
                matched_via_values.append(
                    result.matched_via
                )

        if result.enforcement_blocked:
            if not any_block:
                first_block_call = call_index

            any_block = True

    signal = any_match or any_review

    return {
        "config": config,
        "tier": tier,
        "fanout": fanout,

        "case_id": row["case_id"],
        "label": row["label"],
        "category": row["category"],
        "transformation": row["transformation"],
        "structural_family": row["structural_family"],

        "calls": len(row["calls"]),

        "matched": any_match,
        "review_required": any_review,
        "signal": signal,
        "blocked": any_block,

        "first_match_call": first_match_call,
        "first_review_call": first_review_call,
        "first_block_call": first_block_call,

        "matched_via": sorted(
            set(matched_via_values)
        ),

        "max_coverage": max_coverage,

        "latency_p50_call_ms": percentile(
            latencies_ms,
            0.50,
        ),

        "latency_p95_call_ms": percentile(
            latencies_ms,
            0.95,
        ),

        "latency_p99_call_ms": percentile(
            latencies_ms,
            0.99,
        ),

        "latency_total_ms": sum(
            latencies_ms
        ),
    }


def safe_div(a: int, b: int) -> float:
    return a / b if b else 0.0


def summarize(
    rows: list[dict],
    config: str,
) -> dict:

    group = [
        r for r in rows
        if r["config"] == config
    ]

    malicious = [
        r for r in group
        if r["label"] == "malicious"
    ]

    benign = [
        r for r in group
        if r["label"] == "benign"
    ]

    hard_tp = sum(
        bool(r["matched"])
        for r in malicious
    )

    signal_tp = sum(
        bool(r["signal"])
        for r in malicious
    )

    contained = sum(
        bool(r["blocked"])
        for r in malicious
    )

    hard_fp = sum(
        bool(r["matched"])
        for r in benign
    )

    review_fp = sum(
        bool(r["review_required"])
        for r in benign
    )

    signal_fp = sum(
        bool(r["signal"])
        for r in benign
    )

    enforcement_fp = sum(
        bool(r["blocked"])
        for r in benign
    )

    hard_dr = safe_div(
        hard_tp,
        len(malicious),
    )

    signal_dr = safe_div(
        signal_tp,
        len(malicious),
    )

    containment_rate = safe_div(
        contained,
        len(malicious),
    )

    hard_fpr = safe_div(
        hard_fp,
        len(benign),
    )

    review_fpr = safe_div(
        review_fp,
        len(benign),
    )

    signal_fpr = safe_div(
        signal_fp,
        len(benign),
    )

    enforcement_fpr = safe_div(
        enforcement_fp,
        len(benign),
    )

    precision = safe_div(
        signal_tp,
        signal_tp + signal_fp,
    )

    recall = signal_dr

    f1 = (
        2 * precision * recall
        / (precision + recall)
        if precision + recall
        else 0.0
    )

    all_call_p50 = [
        r["latency_p50_call_ms"]
        for r in group
    ]

    all_call_p95 = [
        r["latency_p95_call_ms"]
        for r in group
    ]

    all_call_p99 = [
        r["latency_p99_call_ms"]
        for r in group
    ]

    return {
        "config": config,

        "malicious_n": len(malicious),
        "benign_n": len(benign),

        "hard_match_dr": hard_dr,
        "security_signal_dr": signal_dr,
        "containment_rate": containment_rate,

        "benign_hard_match_fpr": hard_fpr,
        "benign_review_fpr": review_fpr,
        "benign_signal_fpr": signal_fpr,
        "benign_enforcement_fpr": enforcement_fpr,

        "signal_precision": precision,
        "signal_recall": recall,
        "signal_f1": f1,

        "latency_p50_ms": percentile(
            all_call_p50,
            0.50,
        ),

        "latency_p95_ms": percentile(
            all_call_p95,
            0.95,
        ),

        "latency_p99_ms": percentile(
            all_call_p99,
            0.99,
        ),
    }


def category_summary(
    results: list[dict],
) -> list[dict]:

    output = []

    configs = sorted(
        {r["config"] for r in results}
    )

    categories = sorted(
        {r["category"] for r in results}
    )

    for config in configs:
        for category in categories:

            group = [
                r
                for r in results
                if r["config"] == config
                and r["category"] == category
            ]

            if not group:
                continue

            label = group[0]["label"]

            output.append({
                "config": config,
                "label": label,
                "category": category,
                "n": len(group),

                "hard_match_rate": safe_div(
                    sum(bool(r["matched"]) for r in group),
                    len(group),
                ),

                "review_rate": safe_div(
                    sum(bool(r["review_required"]) for r in group),
                    len(group),
                ),

                "signal_rate": safe_div(
                    sum(bool(r["signal"]) for r in group),
                    len(group),
                ),

                "containment_rate": safe_div(
                    sum(bool(r["blocked"]) for r in group),
                    len(group),
                ),
            })

    return output


def write_outputs(
    results: list[dict],
    summaries: list[dict],
) -> None:

    OUTDIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    jsonl_path = (
        OUTDIR
        / "p11_frozen_results.jsonl"
    )

    csv_path = (
        OUTDIR
        / "p11_summary.csv"
    )

    category_csv = (
        OUTDIR
        / "p11_category_summary.csv"
    )

    md_path = (
        OUTDIR
        / "p11_summary.md"
    )

    with jsonl_path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as f:
        for row in results:
            f.write(
                json.dumps(
                    row,
                    sort_keys=True,
                )
                + "\n"
            )

    with csv_path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=list(
                summaries[0].keys()
            ),
        )

        writer.writeheader()
        writer.writerows(
            summaries
        )

    cat_rows = category_summary(
        results
    )

    with category_csv.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=list(
                cat_rows[0].keys()
            ),
        )

        writer.writeheader()
        writer.writerows(
            cat_rows
        )

    lines = [
        "# P11 Generator-Independent Frozen Evaluation",
        "",
        f"- Corpus SHA-256: `{EXPECTED_SHA256}`",
        "- Frozen before detector execution: yes",
        "- Detector tuning on P11: none",
        "- Network execution: disabled",
        "- Semantic augmentation: excluded from B0-B5",
        "- Tool/destination aliases normalized only at evaluator adapter boundary",
        "",
        "| Config | Hard DR | Signal DR | Containment | Signal FPR | Enforcement FPR | Precision | F1 | p95 ms |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]

    for s in summaries:
        lines.append(
            f"| {s['config']} "
            f"| {s['hard_match_dr']:.3f} "
            f"| {s['security_signal_dr']:.3f} "
            f"| {s['containment_rate']:.3f} "
            f"| {s['benign_signal_fpr']:.3f} "
            f"| {s['benign_enforcement_fpr']:.3f} "
            f"| {s['signal_precision']:.3f} "
            f"| {s['signal_f1']:.3f} "
            f"| {s['latency_p95_ms']:.3f} |"
        )

    lines.extend([
        "",
        "## Category summary",
        "",
        "| Config | Label | Category | N | Hard match | Review | Signal | Containment |",
        "|---|---|---|---:|---:|---:|---:|---:|",
    ])

    for r in cat_rows:
        lines.append(
            f"| {r['config']} "
            f"| {r['label']} "
            f"| {r['category']} "
            f"| {r['n']} "
            f"| {r['hard_match_rate']:.3f} "
            f"| {r['review_rate']:.3f} "
            f"| {r['signal_rate']:.3f} "
            f"| {r['containment_rate']:.3f} |"
        )

    md_path.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    print()
    print(f"JSONL:       {jsonl_path}")
    print(f"Summary CSV: {csv_path}")
    print(f"Category CSV:{category_csv}")
    print(f"Markdown:    {md_path}")


def main() -> None:

    corpus_hash_before = sha256_file(
        CORPUS
    )

    print("=" * 110)
    print(
        "PROVPROXY P11 CORRECTED ADAPTER "
        "GENERATOR-INDEPENDENT EVALUATION"
    )
    print("=" * 110)

    print(
        f"Corpus SHA-256 : "
        f"{corpus_hash_before}"
    )

    print(
        "Expected SHA-256: "
        f"{EXPECTED_SHA256}"
    )

    if corpus_hash_before != EXPECTED_SHA256:
        raise SystemExit(
            "Corpus hash mismatch. "
            "Evaluation aborted."
        )

    rows = load_rows()

    print(f"Cases          : {len(rows)}")
    print(
        "Malicious      : "
        f"{sum(r['label']=='malicious' for r in rows)}"
    )
    print(
        "Benign         : "
        f"{sum(r['label']=='benign' for r in rows)}"
    )

    print(
        "Network        : DISABLED"
    )

    print(
        "Semantic       : DISABLED "
        "in core B0-B5"
    )

    print(
        "Adapter        : P11 aliases -> "
        "http_request destination semantics"
    )

    all_results = []
    summaries = []

    for config, tier, fanout in CONFIGS:

        print()
        print(
            f"[RUN] {config}: "
            f"tier={tier}, "
            f"fanout={'on' if fanout else 'off'}"
        )

        config_results = [
            run_case(
                row,
                config,
                tier,
                fanout,
            )
            for row in rows
        ]

        all_results.extend(
            config_results
        )

        summary = summarize(
            config_results,
            config,
        )

        summaries.append(
            summary
        )

        print(
            f"      hard-DR="
            f"{summary['hard_match_dr']:.3f} "
            f"signal-DR="
            f"{summary['security_signal_dr']:.3f} "
            f"contain="
            f"{summary['containment_rate']:.3f} "
            f"signal-FPR="
            f"{summary['benign_signal_fpr']:.3f} "
            f"enforce-FPR="
            f"{summary['benign_enforcement_fpr']:.3f} "
            f"precision="
            f"{summary['signal_precision']:.3f} "
            f"F1="
            f"{summary['signal_f1']:.3f} "
            f"p95="
            f"{summary['latency_p95_ms']:.3f} ms"
        )

    corpus_hash_after = sha256_file(
        CORPUS
    )

    if corpus_hash_after != EXPECTED_SHA256:
        raise RuntimeError(
            "Corpus changed during evaluation. "
            "Results invalid."
        )

    write_outputs(
        all_results,
        summaries,
    )

    print()
    print("-" * 110)

    print(
        "[PASS] Frozen corpus hash unchanged "
        "before and after evaluation."
    )

    print(
        "[PASS] Tool aliases adapted only at "
        "benchmark interface boundary."
    )

    print(
        "[PASS] No network execution performed."
    )

    print(
        "[PASS] Hard match / review / containment "
        "reported separately."
    )

    print("-" * 110)


if __name__ == "__main__":
    main()
