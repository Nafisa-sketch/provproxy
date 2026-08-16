from __future__ import annotations

import copy
import csv
import hashlib
import json
import math
import statistics
import time
from collections import defaultdict
from pathlib import Path

from provproxy.config import AblationTier, PolicyFile
from provproxy.destination import (
    canonical_network_destination,
    is_destination_allowed,
    primary_domain,
)
from provproxy.pipeline import evaluate, flatten_json_strings
from provproxy.session import Session


ROOT = Path(__file__).resolve().parents[2]

CORPUS = ROOT / "benchmarks" / "p10" / "fixtures" / "p10_frozen_corpus.jsonl"
FREEZE = ROOT / "benchmarks" / "p10" / "FROZEN_CORPUS.json"
POLICY_PATH = ROOT / "benchmarks" / "p10" / "p10_eval_policy.json"

RESULT_DIR = ROOT / "benchmarks" / "results" / "p10"
JSONL_OUT = RESULT_DIR / "p10_frozen_results.jsonl"
CSV_OUT = RESULT_DIR / "p10_summary.csv"
MD_OUT = RESULT_DIR / "p10_summary.md"

SERVER_ID = "network-egress"
TOOL_NAME = "http_request"

CONFIGS = [
    ("B0", AblationTier.V0, False),
    ("B1", AblationTier.V1, False),
    ("B2", AblationTier.V2, False),
    ("B3", AblationTier.V3, False),
    ("B4", AblationTier.V4, False),
    ("B5", AblationTier.V4, True),
]


def percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0

    ordered = sorted(values)

    if len(ordered) == 1:
        return ordered[0]

    pos = (len(ordered) - 1) * q
    lo = math.floor(pos)
    hi = math.ceil(pos)

    if lo == hi:
        return ordered[lo]

    return (
        ordered[lo] * (hi - pos)
        + ordered[hi] * (pos - lo)
    )


def corpus_hash() -> str:
    return hashlib.sha256(CORPUS.read_bytes()).hexdigest().upper()


def verify_frozen_corpus() -> dict:
    freeze = json.loads(FREEZE.read_text(encoding="utf-8-sig"))

    expected = freeze["sha256"].upper()
    actual = corpus_hash()

    if actual != expected:
        raise RuntimeError(
            "P10 CORPUS HASH MISMATCH\n"
            f"Expected: {expected}\n"
            f"Actual:   {actual}\n"
            "Evaluation aborted. Do not modify the frozen corpus."
        )

    return freeze


def load_cases() -> list[dict]:
    records = []

    with CORPUS.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                records.append(json.loads(line))

    return records


def load_policy(tier: AblationTier, fanout: bool) -> PolicyFile:
    raw = json.loads(POLICY_PATH.read_text(encoding="utf-8-sig"))

    raw["active_tier"] = tier.value

    # P10 B5 enables the already-existing optional fan-out REVIEW layer.
    # B0-B4 leave it disabled.
    cross = raw.setdefault("cross_call_window", {})

    if fanout:
        cross["fanout_review_threshold"] = 0.25
        cross["fanout_min_destinations"] = 2
    else:
        cross["fanout_review_threshold"] = None

    return PolicyFile.from_dict(raw)


def payload_to_text(payload) -> str:
    if isinstance(payload, (dict, list)):
        return flatten_json_strings(payload)

    if payload is None:
        return ""

    return str(payload)


def destination_context(policy: PolicyFile, destination: str):
    arguments = {"url": destination}

    allowed = is_destination_allowed(
        policy,
        SERVER_ID,
        TOOL_NAME,
        arguments,
    )

    domain = primary_domain(
        TOOL_NAME,
        arguments,
    )

    canonical = canonical_network_destination(
        TOOL_NAME,
        destination,
    )

    if canonical is not None:
        # Use the actual canonical endpoint identity rather than the
        # presentation URL. repr() is deliberately deterministic for the
        # frozen benchmark within this implementation.
        destination_key = repr(canonical)
    else:
        destination_key = domain

    return allowed, domain, destination_key


def run_case(case: dict, config_name: str, policy: PolicyFile) -> dict:
    session = Session(
        session_id=f"p10-{config_name}-{case['case_id']}",
        policy=policy,
        ttl_seconds=600.0,
    )

    # Synthetic corpus ground truth becomes the provenance source.
    session.register_sensitive_fragment(
        case["source_id"],
        case["synthetic_secret"],
    )

    any_match = False
    any_review = False
    any_block = False

    matched_via = []
    coverages = []
    call_latencies_ms = []

    first_signal_call = None
    first_block_call = None

    for call_index, call in enumerate(case["calls"], start=1):
        destination = call["destination"]
        payload_text = payload_to_text(call.get("payload"))

        allowed, domain, destination_key = destination_context(
            policy,
            destination,
        )

        start = time.perf_counter_ns()

        result = evaluate(
            policy=policy,
            session=session,
            payload_text=payload_text,
            decode_limits=policy.decode_limits,
            destination_allowed=allowed,
            destination_domain=destination_key,
        )

        elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000.0
        call_latencies_ms.append(elapsed_ms)

        signaled = bool(result.matched or result.review_required)

        if signaled and first_signal_call is None:
            first_signal_call = call_index

        if result.enforcement_blocked and first_block_call is None:
            first_block_call = call_index

        any_match = any_match or bool(result.matched)
        any_review = any_review or bool(result.review_required)
        any_block = any_block or bool(result.enforcement_blocked)

        if result.matched_via:
            matched_via.append(result.matched_via)

        if result.approx_coverage is not None:
            coverages.append(float(result.approx_coverage))

    signal = any_match or any_review

    malicious = case["label"] == "malicious"

    return {
        "config": config_name,
        "case_id": case["case_id"],
        "label": case["label"],
        "category": case["category"],
        "transformation": case["transformation"],
        "calls": len(case["calls"]),
        "signal": signal,
        "matched": any_match,
        "review_required": any_review,
        "blocked": any_block,
        "correct_signal": signal if malicious else not signal,
        "correct_enforcement": any_block if malicious else not any_block,
        "first_signal_call": first_signal_call,
        "first_block_call": first_block_call,
        "matched_via": sorted(set(matched_via)),
        "max_coverage": max(coverages) if coverages else None,
        "latency_total_ms": sum(call_latencies_ms),
        "latency_p50_call_ms": percentile(call_latencies_ms, 0.50),
        "latency_p95_call_ms": percentile(call_latencies_ms, 0.95),
        "latency_p99_call_ms": percentile(call_latencies_ms, 0.99),
    }


def summarize(config_name: str, rows: list[dict]) -> dict:
    malicious = [r for r in rows if r["label"] == "malicious"]
    benign = [r for r in rows if r["label"] == "benign"]

    tp = sum(r["signal"] for r in malicious)
    fn = len(malicious) - tp

    fp = sum(r["signal"] for r in benign)
    tn = len(benign) - fp

    enforcement_fp = sum(r["blocked"] for r in benign)

    recall = tp / len(malicious) if malicious else 0.0
    fpr = fp / len(benign) if benign else 0.0
    enforcement_fpr = (
        enforcement_fp / len(benign)
        if benign else 0.0
    )

    precision = tp / (tp + fp) if (tp + fp) else 0.0

    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )

    call_p50 = [r["latency_p50_call_ms"] for r in rows]
    call_p95 = [r["latency_p95_call_ms"] for r in rows]
    call_p99 = [r["latency_p99_call_ms"] for r in rows]

    return {
        "config": config_name,
        "cases": len(rows),
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "detection_rate": recall,
        "signal_fpr": fpr,
        "enforcement_fpr": enforcement_fpr,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "p50_ms": statistics.median(call_p50) if call_p50 else 0.0,
        "p95_ms": percentile(call_p95, 0.95),
        "p99_ms": percentile(call_p99, 0.99),
    }


def category_summary(rows: list[dict]) -> list[dict]:
    grouped = defaultdict(list)

    for row in rows:
        grouped[(row["config"], row["label"], row["category"])].append(row)

    output = []

    for (config, label, category), group in sorted(grouped.items()):
        signal_count = sum(r["signal"] for r in group)
        blocked_count = sum(r["blocked"] for r in group)

        output.append({
            "config": config,
            "label": label,
            "category": category,
            "cases": len(group),
            "signal_rate": signal_count / len(group),
            "block_rate": blocked_count / len(group),
        })

    return output


def write_outputs(
    freeze: dict,
    all_rows: list[dict],
    summaries: list[dict],
) -> None:
    RESULT_DIR.mkdir(parents=True, exist_ok=True)

    with JSONL_OUT.open("w", encoding="utf-8", newline="\n") as fh:
        for row in all_rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")

    fields = [
        "config",
        "cases",
        "tp",
        "fn",
        "fp",
        "tn",
        "detection_rate",
        "signal_fpr",
        "enforcement_fpr",
        "precision",
        "recall",
        "f1",
        "p50_ms",
        "p95_ms",
        "p99_ms",
    ]

    with CSV_OUT.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(summaries)

    categories = category_summary(all_rows)

    lines = [
        "# ProvProxy P10 Frozen-Corpus Evaluation",
        "",
        f"- Corpus: `{freeze['corpus_version']}`",
        f"- SHA-256: `{freeze['sha256']}`",
        f"- Cases: {freeze['cases']}",
        "- Core semantic-review augmentation: disabled",
        "- Network execution: disabled",
        "",
        "## Overall",
        "",
        "| Config | DR | Signal FPR | Enforcement FPR | Precision | F1 | p50 ms | p95 ms | p99 ms |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]

    for s in summaries:
        lines.append(
            f"| {s['config']} "
            f"| {s['detection_rate']:.3f} "
            f"| {s['signal_fpr']:.3f} "
            f"| {s['enforcement_fpr']:.3f} "
            f"| {s['precision']:.3f} "
            f"| {s['f1']:.3f} "
            f"| {s['p50_ms']:.3f} "
            f"| {s['p95_ms']:.3f} "
            f"| {s['p99_ms']:.3f} |"
        )

    lines.extend([
        "",
        "## Category breakdown",
        "",
        "| Config | Label | Category | N | Signal rate | Block rate |",
        "|---|---|---|---:|---:|---:|",
    ])

    for c in categories:
        lines.append(
            f"| {c['config']} | {c['label']} | {c['category']} "
            f"| {c['cases']} | {c['signal_rate']:.3f} "
            f"| {c['block_rate']:.3f} |"
        )

    partial = [
        r for r in all_rows
        if r["category"] == "partial_exfiltration"
    ]

    lines.extend([
        "",
        "## Partial-exfiltration cases",
        "",
        "These cases remain reported separately because a partial leak below "
        "the configured provenance threshold is still malicious ground truth, "
        "but need not satisfy the detector's calibrated decision boundary.",
        "",
        "| Config | Transformation | N | Signal rate | Block rate |",
        "|---|---|---:|---:|---:|",
    ])

    pg = defaultdict(list)
    for row in partial:
        pg[(row["config"], row["transformation"])].append(row)

    for (config, transform), group in sorted(pg.items()):
        lines.append(
            f"| {config} | {transform} | {len(group)} "
            f"| {sum(r['signal'] for r in group)/len(group):.3f} "
            f"| {sum(r['blocked'] for r in group)/len(group):.3f} |"
        )

    MD_OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    freeze = verify_frozen_corpus()
    cases = load_cases()

    if len(cases) != int(freeze["cases"]):
        raise RuntimeError(
            f"Expected {freeze['cases']} cases, found {len(cases)}"
        )

    print("=" * 100)
    print("PROVPROXY P10 FROZEN-CORPUS EVALUATION")
    print("=" * 100)
    print(f"Corpus SHA-256: {corpus_hash()}")
    print(f"Cases: {len(cases)}")
    print("Network execution: DISABLED")
    print("Semantic augmentation: DISABLED in core B0-B5")
    print()

    all_rows = []
    summaries = []

    for config_name, tier, fanout in CONFIGS:
        print(
            f"[RUN] {config_name}: tier={tier.value}, "
            f"fanout={'on' if fanout else 'off'}"
        )

        policy = load_policy(tier, fanout)

        rows = [
            run_case(case, config_name, policy)
            for case in cases
        ]

        all_rows.extend(rows)

        summary = summarize(config_name, rows)
        summaries.append(summary)

        print(
            f"      DR={summary['detection_rate']:.3f} "
            f"signal-FPR={summary['signal_fpr']:.3f} "
            f"enforce-FPR={summary['enforcement_fpr']:.3f} "
            f"precision={summary['precision']:.3f} "
            f"F1={summary['f1']:.3f} "
            f"p95={summary['p95_ms']:.3f} ms"
        )

    write_outputs(freeze, all_rows, summaries)

    print()
    print("-" * 100)
    print("P10 completed without modifying the frozen corpus.")
    print(f"JSONL:    {JSONL_OUT}")
    print(f"CSV:      {CSV_OUT}")
    print(f"Markdown: {MD_OUT}")
    print("-" * 100)


if __name__ == "__main__":
    main()
