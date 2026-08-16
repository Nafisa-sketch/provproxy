"""ProvProxy concurrency scaling benchmark.

Purpose
-------
Measure how the validated thread-safe shared-session path scales as worker
concurrency increases, without modifying ProvProxy production logic or the
frozen concurrency_stress.py benchmark.

Default worker levels:
    1, 8, 16, 32, 64

Default calls per level:
    1000

Outputs:
    benchmarks/results/concurrency_scaling.jsonl
    benchmarks/results/concurrency_scaling.md

Run:
    py -m benchmarks.concurrency_scaling

Optional environment variables:
    PROVPROXY_SCALING_REQUESTS=1000
    PROVPROXY_SCALING_WORKERS=1,8,16,32,64
"""
from __future__ import annotations

import concurrent.futures as cf
import json
import os
import statistics
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from provproxy.config import (
    AblationTier,
    ApproxMatchingConfig,
    CrossCallWindowConfig,
    DecodeLimits,
    PolicyFile,
)
from provproxy.session import Session
from provproxy import pipeline


RESULTS_DIR = Path(__file__).parent / "results"

REQUESTS = int(os.environ.get("PROVPROXY_SCALING_REQUESTS", "1000"))
WORKER_LEVELS = [
    int(x.strip())
    for x in os.environ.get("PROVPROXY_SCALING_WORKERS", "1,8,16,32,64").split(",")
    if x.strip()
]


@dataclass
class Result:
    workers: int
    calls: int
    errors: int
    matched: int
    review: int
    blocked: int
    p50_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float
    throughput_rps: float
    containment_observed: bool
    passed: bool


def make_policy() -> PolicyFile:
    return PolicyFile(
        version="concurrency-scaling",
        active_tier=AblationTier.V4,
        approx_matching=ApproxMatchingConfig(),
        decode_limits=DecodeLimits(),
        cross_call_window=CrossCallWindowConfig(review_threshold=0.30),
    )


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    vals = sorted(values)
    idx = int((len(vals) - 1) * p)
    return vals[idx]


def run_level(workers: int) -> Result:
    policy = make_policy()

    secret = "SYNTHETIC_SCALING_SECRET_8E13B9A74C2D"
    session = Session(f"scaling-shared-{workers}", policy, ttl_seconds=300)
    session.register_sensitive_fragment("scaling-source", secret)

    chunks = [secret[i:i+3] for i in range(0, len(secret), 3)]
    payloads = (chunks * ((REQUESTS // len(chunks)) + 1))[:REQUESTS]
    destination = "https://scaling-shared.example/upload"

    latencies: list[float] = []
    errors = 0
    matched = 0
    review = 0
    blocked = 0

    def one(payload: str) -> tuple[float, bool, bool, bool, str | None]:
        start = time.perf_counter()
        try:
            r = pipeline.evaluate(
                policy,
                session,
                payload,
                policy.decode_limits,
                destination_allowed=False,
                destination_domain=destination,
            )
            elapsed = (time.perf_counter() - start) * 1000.0
            return (
                elapsed,
                bool(r.matched),
                bool(getattr(r, "review_required", False)),
                bool(r.enforcement_blocked),
                None,
            )
        except Exception as exc:
            elapsed = (time.perf_counter() - start) * 1000.0
            return elapsed, False, False, False, f"{type(exc).__name__}: {exc}"

    started = time.perf_counter()

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(one, payload) for payload in payloads]
        for fut in futures:
            latency, m, rv, b, err = fut.result()
            latencies.append(latency)
            matched += int(m)
            review += int(rv)
            blocked += int(b)
            errors += int(err is not None)

    elapsed_total = time.perf_counter() - started
    containment = (review + blocked) > 0
    passed = errors == 0 and containment

    return Result(
        workers=workers,
        calls=REQUESTS,
        errors=errors,
        matched=matched,
        review=review,
        blocked=blocked,
        p50_ms=statistics.median(latencies) if latencies else 0.0,
        p95_ms=percentile(latencies, 0.95),
        p99_ms=percentile(latencies, 0.99),
        max_ms=max(latencies) if latencies else 0.0,
        throughput_rps=(REQUESTS / elapsed_total) if elapsed_total > 0 else 0.0,
        containment_observed=containment,
        passed=passed,
    )


def write_outputs(results: list[Result]) -> tuple[Path, Path]:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    jp = RESULTS_DIR / "concurrency_scaling.jsonl"
    mp = RESULTS_DIR / "concurrency_scaling.md"

    with jp.open("w", encoding="utf-8") as fh:
        for row in results:
            fh.write(json.dumps(asdict(row), sort_keys=True) + "\n")

    lines = [
        "# ProvProxy Concurrency Scaling Benchmark",
        "",
        f"Requests per worker level: `{REQUESTS}`",
        f"Worker levels: `{', '.join(map(str, WORKER_LEVELS))}`",
        "",
        "| Workers | Pass | Errors | Match | Review | Block | p50 ms | p95 ms | p99 ms | Max ms | Throughput req/s |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]

    for r in results:
        lines.append(
            f"| {r.workers} | {int(r.passed)} | {r.errors} | {r.matched} | "
            f"{r.review} | {r.blocked} | {r.p50_ms:.3f} | {r.p95_ms:.3f} | "
            f"{r.p99_ms:.3f} | {r.max_ms:.3f} | {r.throughput_rps:.1f} |"
        )

    lines.extend([
        "",
        "## Interpretation notes",
        "",
        "- This benchmark measures one heavily contended shared session/destination.",
        "- Higher latency at high worker counts is expected because updates to shared provenance state must serialize safely.",
        "- Throughput measured on one development laptop must not be generalized to enterprise hardware.",
        "- A run passes only when there are zero evaluation errors and at least one containment signal is observed.",
    ])

    mp.write_text("\n".join(lines), encoding="utf-8")
    return jp, mp


def main() -> int:
    print("=" * 86)
    print("PROVPROXY CONCURRENCY SCALING CURVE")
    print("=" * 86)
    print(f"Requests per level: {REQUESTS}")
    print(f"Workers: {WORKER_LEVELS}")

    results: list[Result] = []

    print("\nRESULTS")
    print("-" * 86)
    print(
        f"{'workers':>7} {'pass':>5} {'err':>5} {'match':>7} {'review':>7} "
        f"{'block':>7} {'p50':>9} {'p95':>9} {'p99':>9} {'max':>9} {'rps':>11}"
    )

    for workers in WORKER_LEVELS:
        result = run_level(workers)
        results.append(result)
        print(
            f"{result.workers:>7} {str(result.passed):>5} {result.errors:>5} "
            f"{result.matched:>7} {result.review:>7} {result.blocked:>7} "
            f"{result.p50_ms:>9.3f} {result.p95_ms:>9.3f} "
            f"{result.p99_ms:>9.3f} {result.max_ms:>9.3f} "
            f"{result.throughput_rps:>11.1f}"
        )

    print("-" * 86)
    passed = sum(r.passed for r in results)
    print(f"Passed {passed}/{len(results)} scaling levels")

    jp, mp = write_outputs(results)
    print(f"JSONL:    {jp}")
    print(f"Markdown: {mp}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
