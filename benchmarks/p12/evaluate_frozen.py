from __future__ import annotations

import csv
import hashlib
import json
import math
import statistics
import time
from collections import Counter, defaultdict
from pathlib import Path

from provproxy.config import PolicyFile
from provproxy.destination import is_destination_allowed, primary_domain
from provproxy.pipeline import evaluate, flatten_json_strings
from provproxy.semantic import SentenceTransformerSemanticScorer
from provproxy.session import Session


ROOT = Path(__file__).resolve().parents[2]

CORPUS = ROOT / "benchmarks" / "p12" / "fixtures" / "p12_semantic_corpus.jsonl"
PROTOCOL = ROOT / "benchmarks" / "p12" / "P12_PROTOCOL_LOCK.json"
FREEZE = ROOT / "benchmarks" / "p12" / "P12_CORPUS_FREEZE.json"
CONTRACT = ROOT / "benchmarks" / "p12" / "P12_EVALUATION_CONTRACT.json"

OUTDIR = ROOT / "benchmarks" / "results" / "p12"

EXPECTED_SHA256 = (
    "4151C19567D24A52DCF8CB30B3575872680E1CE506C658FD6480F3C3A2334020"
)

NETWORK_TOOL_ALIASES = {
    "http_request",
    "post_data",
    "publish_event",
    "send_request",
    "submit_payload",
}

Z95 = 1.959963984540054


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def load_corpus() -> list[dict]:
    return [
        json.loads(line)
        for line in CORPUS.read_text(encoding="utf-8-sig").splitlines()
        if line.strip()
    ]


def percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0

    xs = sorted(values)

    if len(xs) == 1:
        return xs[0]

    pos = (len(xs) - 1) * q
    lo = math.floor(pos)
    hi = math.ceil(pos)

    if lo == hi:
        return xs[lo]

    frac = pos - lo
    return xs[lo] * (1.0 - frac) + xs[hi] * frac


def wilson_interval(successes: int, total: int) -> tuple[float, float]:
    if total <= 0:
        return 0.0, 0.0

    p = successes / total
    z2 = Z95 * Z95

    denominator = 1.0 + z2 / total
    center = (p + z2 / (2.0 * total)) / denominator

    margin = (
        Z95
        * math.sqrt(
            (p * (1.0 - p) / total)
            + (z2 / (4.0 * total * total))
        )
        / denominator
    )

    return max(0.0, center - margin), min(1.0, center + margin)


def exact_mcnemar_two_sided(b: int, c: int) -> float:
    """
    Exact two-sided McNemar/binomial test.

    b = baseline negative -> extension positive
    c = baseline positive -> extension negative
    """

    n = b + c

    if n == 0:
        return 1.0

    k = min(b, c)

    cumulative = sum(
        math.comb(n, i) * (0.5 ** n)
        for i in range(k + 1)
    )

    return min(1.0, 2.0 * cumulative)


def adapter_tool_name(original_tool: str) -> str:
    if original_tool in NETWORK_TOOL_ALIASES:
        return "http_request"

    return original_tool


def _find_destination_value(value):
    """
    Recursively locate an HTTP(S) destination in the frozen P12 argument tree.

    This is benchmark-interface adaptation only. It does not modify the
    frozen corpus or the payload inspected by provenance matching.
    """
    destination_keys = (
        "url",
        "endpoint",
        "uri",
        "target",
        "destination",
        "webhook",
        "address",
    )

    if isinstance(value, dict):
        for key in destination_keys:
            candidate = value.get(key)

            if (
                isinstance(candidate, str)
                and candidate.startswith(("http://", "https://"))
            ):
                return candidate

        for child in value.values():
            found = _find_destination_value(child)

            if found is not None:
                return found

    elif isinstance(value, list):
        for child in value:
            found = _find_destination_value(child)

            if found is not None:
                return found

    return None


def normalize_network_arguments(arguments: dict) -> dict:
    """
    Expose the already-present frozen P12 destination using the minimal
    argument shape understood by ProvProxy's production http_request
    destination helpers.

    Matching still uses ORIGINAL frozen arguments.
    """
    destination = _find_destination_value(arguments)

    if destination is None:
        return {}

    return {"url": destination}


def make_b5_policy() -> PolicyFile:
    raw = {
        "version": "p12-eval-v1",
        "active_tier": "v4",

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

        "cross_call_window": {
            "window_seconds": 300,
            "window_max_calls": 50,
            "fanout_review_threshold": 0.30,
            "fanout_min_destinations": 2,
        },

        "persistence": {
            "enabled": False,
            "state_dir": ".provproxy_state_p12",
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


def validate_locked_inputs() -> tuple[dict, dict, dict]:
    protocol = load_json(PROTOCOL)
    freeze = load_json(FREEZE)
    contract = load_json(CONTRACT)

    current_hash = sha256_file(CORPUS)

    if current_hash != EXPECTED_SHA256:
        raise RuntimeError(
            f"P12 corpus hash mismatch: {current_hash} != {EXPECTED_SHA256}"
        )

    frozen_hash = str(
        freeze["corpus"]["sha256"]
    ).upper()

    if frozen_hash != EXPECTED_SHA256:
        raise RuntimeError("Freeze manifest corpus hash does not match locked hash.")

    semantic = protocol["semantic_extension"]

    if semantic["model"] != "sentence-transformers/all-MiniLM-L6-v2":
        raise RuntimeError("Unexpected semantic model in protocol.")

    if float(semantic["threshold"]) != 0.60:
        raise RuntimeError("P12 threshold is not frozen at 0.60.")

    if semantic["action"] != "review_only":
        raise RuntimeError("P12 semantic action must remain review_only.")

    frozen_cfg = contract["frozen_configuration"]

    if float(frozen_cfg["semantic_threshold"]) != 0.60:
        raise RuntimeError("Evaluation contract threshold mismatch.")

    if frozen_cfg["semantic_action"] != "review_only":
        raise RuntimeError("Evaluation contract changed semantic action.")

    return protocol, freeze, contract


def run_core_case(row: dict) -> dict:
    policy = make_b5_policy()

    session = Session(
        session_id=f"p12-b5-{row['case_id']}",
        policy=policy,
        ttl_seconds=300.0,
    )

    # Preserve frozen P11 baseline semantics:
    # only malicious cases register a protected provenance source.
    if row["label"] == "malicious":
        session.register_sensitive_fragment(
            row["source_id"],
            row["synthetic_secret"],
        )

    any_match = False
    any_review = False
    any_block = False
    matched_via = []
    latencies = []

    for call in row["calls"]:
        original_tool = call["tool"]
        original_arguments = call["arguments"]

        adapted_tool = adapter_tool_name(original_tool)
        adapted_arguments = normalize_network_arguments(original_arguments)

        payload_text = flatten_json_strings(original_arguments)

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

        latencies.append(
            (time.perf_counter_ns() - t0) / 1_000_000.0
        )

        any_match = any_match or result.matched
        any_review = any_review or result.review_required
        any_block = any_block or result.enforcement_blocked

        if result.matched_via:
            matched_via.append(result.matched_via)

    return {
        "core_hard_match": any_match,
        "core_review": any_review,
        "core_signal": any_match or any_review,
        "core_blocked": any_block,
        "core_matched_via": sorted(set(matched_via)),
        "core_latency_total_ms": sum(latencies),
    }


def semantic_candidate_text(row: dict) -> str:
    return " ".join(
        flatten_json_strings(call["arguments"])
        for call in row["calls"]
    )


def run_semantic_case(
    row: dict,
    scorer: SentenceTransformerSemanticScorer,
    threshold: float,
) -> dict:
    """
    P12 semantic evaluation is deliberately case-local.

    Every case has its own synthetic reference source. This includes benign
    controls because benign semantic FPR asks whether a non-sensitive outbound
    statement is spuriously judged semantically similar to its paired
    synthetic reference.

    This does NOT alter frozen core source-registration semantics.
    """

    source_id = row["source_id"]
    source_text = row["synthetic_secret"]
    candidate = semantic_candidate_text(row)

    scorer.register_source(
        source_id,
        source_text,
    )

    t0 = time.perf_counter_ns()
    match = scorer.best_match(candidate)
    latency_ms = (
        time.perf_counter_ns() - t0
    ) / 1_000_000.0

    if match is None:
        score = float("-inf")
        semantic_source_id = None
    else:
        score = float(match.score)
        semantic_source_id = match.source_id

    review = bool(score >= threshold)

    return {
        "semantic_score": score,
        "semantic_source_id": semantic_source_id,
        "semantic_review": review,
        "semantic_latency_ms": latency_ms,
    }


def category_summary(results: list[dict]) -> list[dict]:
    groups = defaultdict(list)

    for row in results:
        groups[
            (row["label"], row["category"])
        ].append(row)

    output = []

    for (label, category), rows in sorted(groups.items()):
        n = len(rows)

        core = sum(r["core_hard_match"] for r in rows)
        sem = sum(r["semantic_review"] for r in rows)
        combined = sum(r["combined_signal"] for r in rows)
        incremental = sum(r["semantic_incremental"] for r in rows)

        output.append(
            {
                "label": label,
                "category": category,
                "n": n,
                "core_hard_rate": core / n,
                "semantic_review_rate": sem / n,
                "semantic_incremental_rate": incremental / n,
                "combined_signal_rate": combined / n,
            }
        )

    return output


def write_category_csv(rows: list[dict]) -> None:
    path = OUTDIR / "p12_category_summary.csv"

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "label",
                "category",
                "n",
                "core_hard_rate",
                "semantic_review_rate",
                "semantic_incremental_rate",
                "combined_signal_rate",
            ],
        )

        writer.writeheader()
        writer.writerows(rows)


def write_failures(results: list[dict]) -> None:
    malicious = [
        r for r in results
        if r["label"] == "malicious"
    ]

    combined_misses = [
        r for r in malicious
        if not r["combined_signal"]
    ]

    semantic_misses = [
        r for r in malicious
        if not r["semantic_review"]
    ]

    benign_reviews = [
        r for r in results
        if r["label"] == "benign"
        and r["semantic_review"]
    ]

    lines = [
        "# P12 Failure Analysis",
        "",
        "Frozen corpus; no failures removed or modified.",
        "",
        f"- Malicious combined misses: **{len(combined_misses)}/{len(malicious)}**",
        f"- Malicious semantic-review misses: **{len(semantic_misses)}/{len(malicious)}**",
        f"- Benign semantic reviews: **{len(benign_reviews)}/{sum(r['label'] == 'benign' for r in results)}**",
        "",
        "## Combined-signal malicious misses",
        "",
    ]

    for r in combined_misses:
        lines.append(
            f"- `{r['case_id']}` — {r['category']} — "
            f"semantic score={r['semantic_score']:.6f}"
        )

    lines.extend(
        [
            "",
            "## Benign semantic reviews",
            "",
        ]
    )

    for r in benign_reviews:
        lines.append(
            f"- `{r['case_id']}` — {r['category']} — "
            f"semantic score={r['semantic_score']:.6f}"
        )

    (OUTDIR / "p12_failures.md").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )


def write_summary_md(summary: dict) -> None:
    m = summary["malicious"]
    b = summary["benign"]
    s = summary["semantic_latency_ms"]
    mc = summary["paired_mcnemar_malicious"]

    lines = [
        "# P12 Frozen Semantic-Review Evaluation",
        "",
        "P12 is a post-P11 review-only semantic extension. "
        "Semantic review is not counted as a hard provenance match.",
        "",
        "## Malicious cases",
        "",
        f"- Cases: **{m['n']}**",
        f"- Frozen B5 core hard detection: **{m['core_hard_detected']}/{m['n']} "
        f"({m['core_hard_detection_rate']:.3f})**",
        f"- Semantic review: **{m['semantic_reviewed']}/{m['n']} "
        f"({m['semantic_review_rate']:.3f})**",
        f"- Incremental semantic recovery beyond core: "
        f"**{m['semantic_incremental']}/{m['n']} "
        f"({m['semantic_incremental_rate']:.3f})**",
        f"- Combined signal: **{m['combined_detected']}/{m['n']} "
        f"({m['combined_signal_detection_rate']:.3f})**",
        "",
        "## Benign cases",
        "",
        f"- Cases: **{b['n']}**",
        f"- Semantic reviews: **{b['semantic_reviewed']}/{b['n']} "
        f"({b['semantic_review_fpr']:.3f})**",
        f"- Semantic-review Wilson 95% CI: "
        f"**[{b['semantic_review_fpr_ci95'][0]:.4f}, "
        f"{b['semantic_review_fpr_ci95'][1]:.4f}]**",
        "",
        "## Semantic precision",
        "",
        f"- Precision: **{summary['semantic_precision']:.3f}**",
        "",
        "## Paired malicious comparison",
        "",
        f"- Core miss -> combined hit: **{mc['core_miss_combined_hit']}**",
        f"- Core hit -> combined miss: **{mc['core_hit_combined_miss']}**",
        f"- Exact two-sided McNemar p-value: **{mc['p_value']:.8g}**",
        "",
        "## Semantic latency",
        "",
        f"- Model load/warmup: **{summary['semantic_model_load_ms']:.3f} ms**",
        f"- p50: **{s['p50']:.3f} ms**",
        f"- p95: **{s['p95']:.3f} ms**",
        f"- p99: **{s['p99']:.3f} ms**",
        f"- mean: **{s['mean']:.3f} ms**",
        "",
        "## Integrity",
        "",
        f"- Corpus SHA-256 before: `{summary['corpus_sha256_before']}`",
        f"- Corpus SHA-256 after: `{summary['corpus_sha256_after']}`",
        f"- Hash unchanged: **{summary['corpus_hash_unchanged']}**",
        "- Semantic threshold remained frozen at **0.60**.",
        "- No P11 result or core detector was modified by this evaluation.",
    ]

    (OUTDIR / "p12_summary.md").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    protocol, freeze, contract = validate_locked_inputs()

    corpus_hash_before = sha256_file(CORPUS)
    rows = load_corpus()

    if len(rows) != 1200:
        raise RuntimeError(
            f"Expected 1200 frozen P12 cases, found {len(rows)}."
        )

    counts = Counter(row["label"] for row in rows)

    if counts != Counter({"malicious": 600, "benign": 600}):
        raise RuntimeError(
            f"Unexpected P12 label distribution: {counts}"
        )

    threshold = float(
        protocol["semantic_extension"]["threshold"]
    )

    model_name = protocol["semantic_extension"]["model"]

    print("=" * 108)
    print("P12 FROZEN SEMANTIC-REVIEW EVALUATION")
    print("=" * 108)
    print(f"Corpus SHA-256 : {corpus_hash_before}")
    print(f"Cases           : {len(rows)}")
    print(f"Model           : {model_name}")
    print(f"Threshold       : {threshold:.2f}")
    print("Semantic action : REVIEW ONLY")
    print()

    scorer = SentenceTransformerSemanticScorer(
        model_name=model_name
    )

    # Explicit model-load/warmup measurement, kept separate from case latency.
    warmup_start = time.perf_counter_ns()
    scorer._ensure_model()
    model_load_ms = (
        time.perf_counter_ns() - warmup_start
    ) / 1_000_000.0

    print(
        f"Semantic model loaded in "
        f"{model_load_ms:.3f} ms"
    )

    results = []
    semantic_latencies = []

    for index, row in enumerate(rows, start=1):
        core = run_core_case(row)

        # A fresh semantic scorer per case would repeatedly load the model.
        # Instead we reuse the loaded model but clear case-local reference
        # state so no source from one frozen case can affect another.
        scorer._sources.clear()
        scorer._source_embeddings.clear()

        semantic = run_semantic_case(
            row,
            scorer,
            threshold,
        )

        semantic_latencies.append(
            semantic["semantic_latency_ms"]
        )

        combined_signal = (
            core["core_hard_match"]
            or semantic["semantic_review"]
        )

        semantic_incremental = (
            semantic["semantic_review"]
            and not core["core_hard_match"]
        )

        record = {
            "case_id": row["case_id"],
            "label": row["label"],
            "category": row["category"],
            "structural_family": row["structural_family"],

            **core,
            **semantic,

            "semantic_incremental": semantic_incremental,
            "combined_signal": combined_signal,
        }

        results.append(record)

        if index % 100 == 0:
            print(
                f"Evaluated {index:4d}/{len(rows)}"
            )

    corpus_hash_after = sha256_file(CORPUS)

    if corpus_hash_after != corpus_hash_before:
        raise RuntimeError(
            "P12 corpus changed during evaluation."
        )

    malicious = [
        r for r in results
        if r["label"] == "malicious"
    ]

    benign = [
        r for r in results
        if r["label"] == "benign"
    ]

    core_tp = sum(
        r["core_hard_match"]
        for r in malicious
    )

    semantic_tp = sum(
        r["semantic_review"]
        for r in malicious
    )

    incremental_tp = sum(
        r["semantic_incremental"]
        for r in malicious
    )

    combined_tp = sum(
        r["combined_signal"]
        for r in malicious
    )

    semantic_fp = sum(
        r["semantic_review"]
        for r in benign
    )

    semantic_positive_total = (
        semantic_tp + semantic_fp
    )

    semantic_precision = (
        semantic_tp / semantic_positive_total
        if semantic_positive_total
        else 0.0
    )

    benign_ci = wilson_interval(
        semantic_fp,
        len(benign),
    )

    malicious_core_ci = wilson_interval(
        core_tp,
        len(malicious),
    )

    malicious_combined_ci = wilson_interval(
        combined_tp,
        len(malicious),
    )

    # Paired comparison: core hard signal vs combined signal.
    b = sum(
        (not r["core_hard_match"])
        and r["combined_signal"]
        for r in malicious
    )

    c = sum(
        r["core_hard_match"]
        and (not r["combined_signal"])
        for r in malicious
    )

    mcnemar_p = exact_mcnemar_two_sided(
        b,
        c,
    )

    summary = {
        "experiment": "P12 semantic-review extension",
        "corpus_sha256_before": corpus_hash_before,
        "corpus_sha256_after": corpus_hash_after,
        "corpus_hash_unchanged": (
            corpus_hash_before == corpus_hash_after
        ),

        "semantic_model": model_name,
        "semantic_threshold": threshold,
        "semantic_action": "review_only",

        "malicious": {
            "n": len(malicious),

            "core_hard_detected": core_tp,
            "core_hard_detection_rate": (
                core_tp / len(malicious)
            ),
            "core_hard_detection_ci95": (
                malicious_core_ci
            ),

            "semantic_reviewed": semantic_tp,
            "semantic_review_rate": (
                semantic_tp / len(malicious)
            ),

            "semantic_incremental": incremental_tp,
            "semantic_incremental_rate": (
                incremental_tp / len(malicious)
            ),

            "combined_detected": combined_tp,
            "combined_signal_detection_rate": (
                combined_tp / len(malicious)
            ),
            "combined_signal_detection_ci95": (
                malicious_combined_ci
            ),
        },

        "benign": {
            "n": len(benign),
            "semantic_reviewed": semantic_fp,
            "semantic_review_fpr": (
                semantic_fp / len(benign)
            ),
            "semantic_review_fpr_ci95": benign_ci,
        },

        "semantic_precision": semantic_precision,

        "paired_mcnemar_malicious": {
            "core_miss_combined_hit": b,
            "core_hit_combined_miss": c,
            "p_value": mcnemar_p,
        },

        "semantic_model_load_ms": model_load_ms,

        "semantic_latency_ms": {
            "p50": percentile(
                semantic_latencies, 0.50
            ),
            "p95": percentile(
                semantic_latencies, 0.95
            ),
            "p99": percentile(
                semantic_latencies, 0.99
            ),
            "mean": statistics.fmean(
                semantic_latencies
            ),
            "max": max(
                semantic_latencies
            ),
        },
    }

    OUTDIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    with (
        OUTDIR / "p12_results.jsonl"
    ).open("w", encoding="utf-8") as f:
        for result in results:
            f.write(
                json.dumps(
                    result,
                    sort_keys=True,
                )
                + "\n"
            )

    (
        OUTDIR / "p12_summary.json"
    ).write_text(
        json.dumps(
            summary,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    categories = category_summary(
        results
    )

    write_category_csv(
        categories
    )

    write_failures(
        results
    )

    write_summary_md(
        summary
    )

    print()
    print("=" * 108)
    print("P12 RESULTS")
    print("=" * 108)

    print(
        "Core hard detection       : "
        f"{core_tp}/{len(malicious)} "
        f"({core_tp / len(malicious):.3f})"
    )

    print(
        "Semantic review malicious : "
        f"{semantic_tp}/{len(malicious)} "
        f"({semantic_tp / len(malicious):.3f})"
    )

    print(
        "Incremental recovery      : "
        f"{incremental_tp}/{len(malicious)} "
        f"({incremental_tp / len(malicious):.3f})"
    )

    print(
        "Combined signal           : "
        f"{combined_tp}/{len(malicious)} "
        f"({combined_tp / len(malicious):.3f})"
    )

    print(
        "Benign semantic reviews   : "
        f"{semantic_fp}/{len(benign)} "
        f"({semantic_fp / len(benign):.3f})"
    )

    print(
        "Semantic precision        : "
        f"{semantic_precision:.3f}"
    )

    print(
        "McNemar exact p           : "
        f"{mcnemar_p:.8g}"
    )

    print(
        "Semantic latency p50/p95  : "
        f"{summary['semantic_latency_ms']['p50']:.3f} / "
        f"{summary['semantic_latency_ms']['p95']:.3f} ms"
    )

    print(
        "Corpus unchanged          : "
        f"{corpus_hash_before == corpus_hash_after}"
    )

    print("=" * 108)


if __name__ == "__main__":
    main()