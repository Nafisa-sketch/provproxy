"""ProvProxy transaction-level concurrency scaling benchmark.

This benchmark complements the hot-key stress tests. Instead of hammering one
already-saturated shared provenance window, it runs many independent realistic
exfiltration transactions concurrently. Each transaction owns its own session,
destination, and synthetic secret, then sends small fragments sequentially until
ProvProxy contains the flow.

This gives a cleaner measure of multi-session scalability and avoids the
measurement artifact where one shared window reaches containment very early and
later duplicate chunks do almost no state work.

Run:
    py -m benchmarks.transaction_scaling

Optional environment variables:
    PROVPROXY_TX_WORKERS=1,8,16,32,64
    PROVPROXY_TX_COUNT=250
    PROVPROXY_TX_REPEATS=3
"""
from __future__ import annotations

import concurrent.futures as cf
import json
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
WORKERS = [
    int(x.strip())
    for x in os.environ.get("PROVPROXY_TX_WORKERS", "1,8,16,32,64").split(",")
    if x.strip()
]
TX_COUNT = int(os.environ.get("PROVPROXY_TX_COUNT", "250"))
REPEATS = int(os.environ.get("PROVPROXY_TX_REPEATS", "3"))


@dataclass
class TxResult:
    tx_id: int
    contained: bool
    errors: int
    calls: int
    containment_call: int | None
    total_eval_ms: float


@dataclass
class LevelRun:
    workers: int
    repeat: int
    transactions: int
    calls: int
    contained_transactions: int
    errors: int
    p50_tx_ms: float
    p95_tx_ms: float
    p99_tx_ms: float
    p50_calls_to_containment: float
    p95_calls_to_containment: float
    throughput_tx_s: float
    throughput_calls_s: float
    passed: bool


def make_policy() -> PolicyFile:
    return PolicyFile(
        version="transaction-scaling",
        active_tier=AblationTier.V4,
        approx_matching=ApproxMatchingConfig(),
        decode_limits=DecodeLimits(),
        cross_call_window=CrossCallWindowConfig(review_threshold=0.30),
    )


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    vals = sorted(values)
    return vals[int((len(vals) - 1) * p)]


def run_transaction(tx_id: int, policy: PolicyFile) -> TxResult:
    secret = f"SYNTHETIC_TX_SECRET_{tx_id:06d}_9A7C4E2B1D"
    session = Session(f"tx-session-{tx_id}", policy, ttl_seconds=300)
    session.register_sensitive_fragment(f"src-{tx_id}", secret)
    destination = f"https://tx-{tx_id}.example/upload"

    chunks = [secret[i:i+3] for i in range(0, len(secret), 3)]

    errors = 0
    containment_call = None
    total_eval_ms = 0.0
    calls = 0

    for idx, chunk in enumerate(chunks, 1):
        start = time.perf_counter()
        try:
            r = pipeline.evaluate(
                policy,
                session,
                chunk,
                policy.decode_limits,
                destination_allowed=False,
                destination_domain=destination,
            )
        except Exception:
            errors += 1
            calls += 1
            total_eval_ms += (time.perf_counter() - start) * 1000.0
            continue

        total_eval_ms += (time.perf_counter() - start) * 1000.0
        calls += 1

        if bool(r.enforcement_blocked) or bool(getattr(r, "review_required", False)):
            containment_call = idx
            break

    return TxResult(
        tx_id=tx_id,
        contained=containment_call is not None,
        errors=errors,
        calls=calls,
        containment_call=containment_call,
        total_eval_ms=total_eval_ms,
    )


def run_level(workers: int, repeat: int) -> LevelRun:
    policy = make_policy()
    offset = repeat * 1_000_000 + workers * 10_000
    tx_ids = [offset + i for i in range(TX_COUNT)]

    started = time.perf_counter()
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(lambda i: run_transaction(i, policy), tx_ids))
    wall = time.perf_counter() - started

    tx_ms = [r.total_eval_ms for r in results]
    ctc = [float(r.containment_call) for r in results if r.containment_call is not None]
    total_calls = sum(r.calls for r in results)
    errors = sum(r.errors for r in results)
    contained = sum(r.contained for r in results)

    passed = errors == 0 and contained == TX_COUNT

    return LevelRun(
        workers=workers,
        repeat=repeat,
        transactions=TX_COUNT,
        calls=total_calls,
        contained_transactions=contained,
        errors=errors,
        p50_tx_ms=statistics.median(tx_ms),
        p95_tx_ms=percentile(tx_ms, 0.95),
        p99_tx_ms=percentile(tx_ms, 0.99),
        p50_calls_to_containment=statistics.median(ctc) if ctc else 0.0,
        p95_calls_to_containment=percentile(ctc, 0.95),
        throughput_tx_s=TX_COUNT / wall if wall > 0 else 0.0,
        throughput_calls_s=total_calls / wall if wall > 0 else 0.0,
        passed=passed,
    )


def write_results(rows: list[LevelRun]):
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    jp = RESULTS_DIR / "transaction_scaling.jsonl"
    mp = RESULTS_DIR / "transaction_scaling.md"

    with jp.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(asdict(row), sort_keys=True) + "\n")

    lines = [
        "# ProvProxy Transaction-Level Concurrency Scaling",
        "",
        f"Transactions per run: `{TX_COUNT}`",
        f"Repeats: `{REPEATS}`",
        f"Worker levels: `{', '.join(map(str, WORKERS))}`",
        "",
        "| Workers | Repeat | Pass | Errors | Contained | Calls | p50 tx ms | p95 tx ms | p99 tx ms | p50 calls-to-contain | tx/s | calls/s |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in rows:
        lines.append(
            f"| {r.workers} | {r.repeat} | {int(r.passed)} | {r.errors} | "
            f"{r.contained_transactions}/{r.transactions} | {r.calls} | "
            f"{r.p50_tx_ms:.3f} | {r.p95_tx_ms:.3f} | {r.p99_tx_ms:.3f} | "
            f"{r.p50_calls_to_containment:.1f} | {r.throughput_tx_s:.1f} | "
            f"{r.throughput_calls_s:.1f} |"
        )

    lines += [
        "",
        "## Methodological note",
        "",
        "This benchmark measures many independent stateful transactions in parallel.",
        "It complements the single-hot-key contention benchmark and is more representative",
        "of a deployment serving multiple concurrent agent sessions/destinations.",
    ]
    mp.write_text("\n".join(lines), encoding="utf-8")
    return jp, mp


def main() -> int:
    print("=" * 110)
    print("PROVPROXY TRANSACTION-LEVEL CONCURRENCY SCALING")
    print("=" * 110)
    print(f"Transactions/run: {TX_COUNT}")
    print(f"Repeats:          {REPEATS}")
    print(f"Workers:          {WORKERS}")

    rows = []

    print("\nRESULTS")
    print("-" * 110)
    print(
        f"{'workers':>7} {'rep':>4} {'pass':>5} {'err':>5} {'contain':>10} "
        f"{'calls':>7} {'p50tx':>9} {'p95tx':>9} {'p99tx':>9} "
        f"{'ctc50':>7} {'tx/s':>9} {'calls/s':>10}"
    )

    for workers in WORKERS:
        for repeat in range(1, REPEATS + 1):
            r = run_level(workers, repeat)
            rows.append(r)
            print(
                f"{workers:>7} {repeat:>4} {str(r.passed):>5} {r.errors:>5} "
                f"{str(r.contained_transactions) + '/' + str(r.transactions):>10} "
                f"{r.calls:>7} {r.p50_tx_ms:>9.3f} {r.p95_tx_ms:>9.3f} "
                f"{r.p99_tx_ms:>9.3f} {r.p50_calls_to_containment:>7.1f} "
                f"{r.throughput_tx_s:>9.1f} {r.throughput_calls_s:>10.1f}"
            )

    failed = sum(not r.passed for r in rows)
    jp, mp = write_results(rows)

    print("-" * 110)
    print(f"Failed runs: {failed}/{len(rows)}")
    print(f"JSONL:    {jp}")
    print(f"Markdown: {mp}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
