"""Repeated concurrency scaling benchmark for ProvProxy.

Why this exists
---------------
A single scaling run can be noisy on a low-resource Windows laptop. This
benchmark repeats each worker level several times and reports median latency,
tail latency, throughput, variability, and any correctness failures.

It does not modify ProvProxy production code.

Run:
    py -m benchmarks.concurrency_scaling_repeated

Optional:
    PROVPROXY_SCALING_REQUESTS=1000
    PROVPROXY_SCALING_REPEATS=5
    PROVPROXY_SCALING_WORKERS=1,8,16,32,64
"""
from __future__ import annotations

import concurrent.futures as cf
import json
import math
import os
import statistics
import time
from dataclasses import asdict, dataclass
from pathlib import Path

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
REPEATS = int(os.environ.get("PROVPROXY_SCALING_REPEATS", "5"))
WORKERS = [
    int(x.strip())
    for x in os.environ.get("PROVPROXY_SCALING_WORKERS", "1,8,16,32,64").split(",")
    if x.strip()
]


@dataclass
class RunResult:
    workers: int
    repeat: int
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
    elapsed_s: float
    passed: bool


@dataclass
class Aggregate:
    workers: int
    repeats: int
    total_calls: int
    total_errors: int
    failed_runs: int
    median_p50_ms: float
    median_p95_ms: float
    median_p99_ms: float
    median_throughput_rps: float
    throughput_cv: float
    p99_cv: float
    min_throughput_rps: float
    max_throughput_rps: float
    max_observed_p99_ms: float


def make_policy() -> PolicyFile:
    return PolicyFile(
        version="concurrency-scaling-repeated",
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


def cv(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = statistics.mean(values)
    if mean == 0:
        return 0.0
    return statistics.stdev(values) / mean


def run_once(workers: int, repeat: int) -> RunResult:
    policy = make_policy()
    secret = f"SYNTHETIC_SCALE_REPEAT_SECRET_{workers}_{repeat}_9C7A1B"
    session = Session(f"scale-r{repeat}-w{workers}", policy, ttl_seconds=300)
    session.register_sensitive_fragment("source", secret)

    chunks = [secret[i:i + 3] for i in range(0, len(secret), 3)]
    payloads = (chunks * ((REQUESTS // len(chunks)) + 1))[:REQUESTS]
    destination = "https://shared-scale.example/upload"

    latencies = []
    errors = matched = review = blocked = 0

    def one(payload: str):
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
            return (
                (time.perf_counter() - start) * 1000.0,
                None,
                bool(r.matched),
                bool(getattr(r, "review_required", False)),
                bool(r.enforcement_blocked),
            )
        except Exception as exc:
            return (
                (time.perf_counter() - start) * 1000.0,
                f"{type(exc).__name__}: {exc}",
                False,
                False,
                False,
            )

    started = time.perf_counter()
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(one, p) for p in payloads]
        for fut in futures:
            latency, err, m, rv, b = fut.result()
            latencies.append(latency)
            errors += int(err is not None)
            matched += int(m)
            review += int(rv)
            blocked += int(b)

    elapsed = time.perf_counter() - started
    contained = (review + blocked) > 0

    return RunResult(
        workers=workers,
        repeat=repeat,
        calls=REQUESTS,
        errors=errors,
        matched=matched,
        review=review,
        blocked=blocked,
        p50_ms=statistics.median(latencies) if latencies else 0.0,
        p95_ms=percentile(latencies, 0.95),
        p99_ms=percentile(latencies, 0.99),
        max_ms=max(latencies) if latencies else 0.0,
        throughput_rps=(REQUESTS / elapsed) if elapsed > 0 else 0.0,
        elapsed_s=elapsed,
        passed=(errors == 0 and contained),
    )


def aggregate(rows: list[RunResult]) -> list[Aggregate]:
    out = []
    for workers in WORKERS:
        group = [r for r in rows if r.workers == workers]
        throughputs = [r.throughput_rps for r in group]
        p50s = [r.p50_ms for r in group]
        p95s = [r.p95_ms for r in group]
        p99s = [r.p99_ms for r in group]

        out.append(
            Aggregate(
                workers=workers,
                repeats=len(group),
                total_calls=sum(r.calls for r in group),
                total_errors=sum(r.errors for r in group),
                failed_runs=sum(not r.passed for r in group),
                median_p50_ms=statistics.median(p50s),
                median_p95_ms=statistics.median(p95s),
                median_p99_ms=statistics.median(p99s),
                median_throughput_rps=statistics.median(throughputs),
                throughput_cv=cv(throughputs),
                p99_cv=cv(p99s),
                min_throughput_rps=min(throughputs),
                max_throughput_rps=max(throughputs),
                max_observed_p99_ms=max(p99s),
            )
        )
    return out


def write_outputs(rows: list[RunResult], aggs: list[Aggregate]):
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    raw_path = RESULTS_DIR / "concurrency_scaling_repeated.jsonl"
    md_path = RESULTS_DIR / "concurrency_scaling_repeated.md"

    with raw_path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(asdict(row), sort_keys=True) + "\n")

    lines = [
        "# ProvProxy Repeated Concurrency Scaling",
        "",
        f"Requests per run: `{REQUESTS}`",
        f"Repeats per worker level: `{REPEATS}`",
        f"Worker levels: `{', '.join(map(str, WORKERS))}`",
        "",
        "| Workers | Failed runs | Total errors | Median p50 ms | Median p95 ms | Median p99 ms | Median req/s | Throughput CV | p99 CV | Max observed p99 ms |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for a in aggs:
        lines.append(
            f"| {a.workers} | {a.failed_runs} | {a.total_errors} | "
            f"{a.median_p50_ms:.3f} | {a.median_p95_ms:.3f} | "
            f"{a.median_p99_ms:.3f} | {a.median_throughput_rps:.1f} | "
            f"{a.throughput_cv:.3f} | {a.p99_cv:.3f} | "
            f"{a.max_observed_p99_ms:.3f} |"
        )

    lines += [
        "",
        "## Notes",
        "",
        "- The workload intentionally uses one shared session and one shared destination to maximize state contention.",
        "- Correctness requires zero evaluation errors and at least one containment signal in every run.",
        "- CV is coefficient of variation (standard deviation / mean); larger values indicate noisier measurements.",
        "- Results are development-laptop measurements, not universal deployment throughput.",
    ]
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return raw_path, md_path


def main() -> int:
    print("=" * 104)
    print("PROVPROXY REPEATED CONCURRENCY SCALING")
    print("=" * 104)
    print(f"Requests/run: {REQUESTS}")
    print(f"Repeats:      {REPEATS}")
    print(f"Workers:      {WORKERS}")

    rows: list[RunResult] = []

    for workers in WORKERS:
        print(f"\n[workers={workers}]")
        for repeat in range(1, REPEATS + 1):
            r = run_once(workers, repeat)
            rows.append(r)
            print(
                f"  r{repeat}: pass={r.passed} err={r.errors} "
                f"p50={r.p50_ms:.3f} p95={r.p95_ms:.3f} "
                f"p99={r.p99_ms:.3f} rps={r.throughput_rps:.1f}"
            )

    aggs = aggregate(rows)

    print("\n" + "=" * 104)
    print("AGGREGATE")
    print("=" * 104)
    print(
        f"{'workers':>7} {'failed':>7} {'errors':>7} {'med_p50':>10} "
        f"{'med_p95':>10} {'med_p99':>10} {'med_rps':>10} "
        f"{'rps_cv':>8} {'p99_cv':>8} {'max_p99':>10}"
    )

    for a in aggs:
        print(
            f"{a.workers:>7} {a.failed_runs:>7} {a.total_errors:>7} "
            f"{a.median_p50_ms:>10.3f} {a.median_p95_ms:>10.3f} "
            f"{a.median_p99_ms:>10.3f} {a.median_throughput_rps:>10.1f} "
            f"{a.throughput_cv:>8.3f} {a.p99_cv:>8.3f} "
            f"{a.max_observed_p99_ms:>10.3f}"
        )

    raw_path, md_path = write_outputs(rows, aggs)
    failed = sum(a.failed_runs for a in aggs)

    print("-" * 104)
    print(f"Failed runs: {failed}/{len(rows)}")
    print(f"JSONL:    {raw_path}")
    print(f"Markdown: {md_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
