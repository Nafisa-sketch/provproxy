"""ProvProxy concurrency and thread-safety stress benchmark.

This benchmark does NOT modify production code. It stresses the existing
Session + pipeline implementation under concurrent access and checks:
- exceptions/crashes
- cross-session contamination
- destination isolation
- shared-session race behavior
- latency percentiles
- throughput

Run:
    py -m benchmarks.concurrency_stress

Optional environment variables:
    PROVPROXY_CONCURRENCY=32
    PROVPROXY_REQUESTS=2000
"""
from __future__ import annotations

import concurrent.futures as cf
import os
import statistics
import threading
import time
from dataclasses import dataclass
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


CONCURRENCY = int(os.environ.get("PROVPROXY_CONCURRENCY", "32"))
REQUESTS = int(os.environ.get("PROVPROXY_REQUESTS", "2000"))


@dataclass
class CallResult:
    ok: bool
    matched: bool
    review: bool
    blocked: bool
    latency_ms: float
    error: str | None = None


def make_policy() -> PolicyFile:
    return PolicyFile(
        version="concurrency-stress",
        active_tier=AblationTier.V4,
        approx_matching=ApproxMatchingConfig(),
        decode_limits=DecodeLimits(),
        cross_call_window=CrossCallWindowConfig(review_threshold=0.30),
    )


def eval_call(
    policy: PolicyFile,
    session: Session,
    payload: str,
    destination: str,
) -> CallResult:
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
        return CallResult(
            ok=True,
            matched=bool(r.matched),
            review=bool(getattr(r, "review_required", False)),
            blocked=bool(r.enforcement_blocked),
            latency_ms=(time.perf_counter() - start) * 1000.0,
        )
    except Exception as exc:
        return CallResult(
            ok=False,
            matched=False,
            review=False,
            blocked=False,
            latency_ms=(time.perf_counter() - start) * 1000.0,
            error=f"{type(exc).__name__}: {exc}",
        )


def pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = int((len(ordered) - 1) * p)
    return ordered[idx]


def summarize(name: str, results: list[CallResult], elapsed: float) -> dict[str, Any]:
    lat = [r.latency_ms for r in results]
    return {
        "name": name,
        "calls": len(results),
        "errors": sum(not r.ok for r in results),
        "matched": sum(r.matched for r in results),
        "review": sum(r.review for r in results),
        "blocked": sum(r.blocked for r in results),
        "p50_ms": statistics.median(lat) if lat else 0.0,
        "p95_ms": pct(lat, 0.95),
        "p99_ms": pct(lat, 0.99),
        "throughput_rps": len(results) / elapsed if elapsed > 0 else 0.0,
    }


def phase_isolated_sessions(policy: PolicyFile) -> tuple[list[CallResult], bool]:
    """Each call uses an independent session. No state may bleed across sessions."""
    secret = "SYNTHETIC_CONCURRENCY_SECRET_4B829A71"
    sessions: list[Session] = []

    for i in range(REQUESTS):
        s = Session(f"iso-{i}", policy, ttl_seconds=300)
        s.register_sensitive_fragment(f"src-{i}", secret)
        sessions.append(s)

    def worker(i: int) -> CallResult:
        # Benign payload intentionally contains no secret-derived text.
        return eval_call(
            policy,
            sessions[i],
            f"benign-payload-{i}-status-ok",
            f"https://dest-{i % 17}.example/upload",
        )

    start = time.perf_counter()
    with cf.ThreadPoolExecutor(max_workers=CONCURRENCY) as ex:
        results = list(ex.map(worker, range(REQUESTS)))
    elapsed = time.perf_counter() - start

    contamination_free = not any(r.matched or r.review or r.blocked for r in results)
    return results, contamination_free, elapsed


def phase_shared_session(policy: PolicyFile) -> tuple[list[CallResult], bool, float]:
    """Concurrent fragments hit ONE shared session/destination.

    Goal: detect whether state updates crash or lose all cumulative evidence.
    Exact trigger order is intentionally not assumed because concurrent scheduling
    is nondeterministic.
    """
    secret = "SYNTHETIC_SHARED_SESSION_SECRET_9C18D7F2"
    session = Session("shared-session", policy, ttl_seconds=300)
    session.register_sensitive_fragment("shared-src", secret)

    chunks = [secret[i:i+3] for i in range(0, len(secret), 3)]
    payloads = (chunks * ((REQUESTS // len(chunks)) + 1))[:REQUESTS]

    start = time.perf_counter()
    with cf.ThreadPoolExecutor(max_workers=CONCURRENCY) as ex:
        futures = [
            ex.submit(
                eval_call,
                policy,
                session,
                payload,
                "https://same-destination.example/upload",
            )
            for payload in payloads
        ]
        results = [f.result() for f in futures]
    elapsed = time.perf_counter() - start

    # At least one containment signal should occur and no exceptions should occur.
    contained = any(r.review or r.blocked for r in results)
    stable = contained and not any(not r.ok for r in results)
    return results, stable, elapsed


def phase_destination_isolation(policy: PolicyFile) -> tuple[list[CallResult], bool, float]:
    """Split one secret across many destinations concurrently.

    No individual destination receives enough unique evidence to cross the
    configured review threshold, so cross-destination state mixing would be a bug.
    """
    secret = "SYNTHETIC_DESTINATION_ISOLATION_SECRET_71A2B9"
    session = Session("dest-isolation", policy, ttl_seconds=300)
    session.register_sensitive_fragment("dest-src", secret)

    small_chunks = [secret[i:i+2] for i in range(0, min(len(secret), 16), 2)]

    work = []
    for i, chunk in enumerate(small_chunks):
        work.append(
            (chunk, f"https://isolated-{i}.example/upload")
        )

    start = time.perf_counter()
    with cf.ThreadPoolExecutor(max_workers=min(CONCURRENCY, len(work))) as ex:
        futures = [
            ex.submit(eval_call, policy, session, payload, destination)
            for payload, destination in work
        ]
        results = [f.result() for f in futures]
    elapsed = time.perf_counter() - start

    isolated = not any(r.review or r.blocked or r.matched for r in results)
    return results, isolated, elapsed


def main() -> int:
    print("=" * 78)
    print("PROVPROXY CONCURRENCY / THREAD-SAFETY STRESS TEST")
    print("=" * 78)
    print(f"Concurrency: {CONCURRENCY}")
    print(f"Requests:    {REQUESTS}")

    policy = make_policy()

    r1, ok1, e1 = phase_isolated_sessions(policy)
    s1 = summarize("isolated_sessions", r1, e1)

    r2, ok2, e2 = phase_shared_session(policy)
    s2 = summarize("shared_session", r2, e2)

    r3, ok3, e3 = phase_destination_isolation(policy)
    s3 = summarize("destination_isolation", r3, e3)

    print("\nRESULTS")
    print("-" * 78)
    print(
        f"{'phase':24} {'pass':>5} {'calls':>7} {'err':>5} "
        f"{'match':>7} {'review':>7} {'block':>7} "
        f"{'p50':>8} {'p95':>8} {'p99':>8} {'rps':>10}"
    )

    for summary, passed in ((s1, ok1), (s2, ok2), (s3, ok3)):
        print(
            f"{summary['name']:24} {str(passed):>5} "
            f"{summary['calls']:>7} {summary['errors']:>5} "
            f"{summary['matched']:>7} {summary['review']:>7} "
            f"{summary['blocked']:>7} "
            f"{summary['p50_ms']:>8.3f} {summary['p95_ms']:>8.3f} "
            f"{summary['p99_ms']:>8.3f} {summary['throughput_rps']:>10.1f}"
        )

    print("-" * 78)
    print(f"Overall: {sum((ok1, ok2, ok3))}/3 phases passed")

    if not ok1:
        print("[FAIL] Cross-session contamination or unexpected benign blocking detected.")
    if not ok2:
        print("[FAIL] Shared-session concurrent accumulation was unstable or never contained.")
    if not ok3:
        print("[FAIL] Destination-isolation violation detected.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
