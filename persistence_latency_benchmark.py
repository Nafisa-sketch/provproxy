#!/usr/bin/env python3
"""
ProvProxy P6 Persistence Latency Benchmark
==========================================

Compares memory-only state updates against the current persistence design
using the SAME workload.

Run from project root:
    py persistence_latency_benchmark.py

This benchmark:
- performs warm-up iterations first
- runs multiple measured rounds
- compares OFF vs ON directly
- reports p50/p95/p99 and ON-OFF deltas
- reports early-vs-late latency to reveal checkpoint-growth effects
- reports checkpoint file size

Note:
The persistence implementation below mirrors the current prototype supplied
for P6 evaluation. Its reversible "obfuscation" is NOT encryption.
"""

from __future__ import annotations

import gc
import hashlib
import json
import os
import statistics
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List


WARMUP = 30
MEASURED = 300
ROUNDS = 5
TTL_SECONDS = 300


class MemoryOnlyStateRegistry:
    def __init__(self, ttl_seconds: int = TTL_SECONDS):
        self.ttl_seconds = ttl_seconds
        self.state: Dict[str, List[Dict[str, Any]]] = {}

    def _obfuscate_payload(self, data: str) -> str:
        # Mirrors persistent registry CPU work so the delta mainly reflects I/O.
        return hashlib.sha256(data.encode("utf-8")).hexdigest()[:16] + ":" + data[::-1]

    def add_fragment(self, session_id: str, destination: str, source: str, fragment_data: str):
        key = f"{session_id}:{destination}:{source}"
        self.state.setdefault(key, []).append(
            {
                "data": self._obfuscate_payload(fragment_data),
                "timestamp": time.time(),
            }
        )


class PersistentStateRegistry:
    """
    Mirrors the current P6 prototype persistence behavior:
    each add_fragment() rewrites the complete JSON checkpoint.
    """
    def __init__(self, checkpoint_path: str, ttl_seconds: int = TTL_SECONDS):
        self.checkpoint_path = checkpoint_path
        self.ttl_seconds = ttl_seconds
        self.state: Dict[str, List[Dict[str, Any]]] = {}
        self._load_checkpoint()

    def _obfuscate_payload(self, data: str) -> str:
        return hashlib.sha256(data.encode("utf-8")).hexdigest()[:16] + ":" + data[::-1]

    def _load_checkpoint(self):
        if os.path.exists(self.checkpoint_path):
            try:
                with open(self.checkpoint_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                now = time.time()
                self.state = {}
                for key, fragments in data.items():
                    valid = [
                        frag
                        for frag in fragments
                        if now - frag.get("timestamp", 0) <= self.ttl_seconds
                    ]
                    if valid:
                        self.state[key] = valid
            except Exception:
                self.state = {}

    def _save_checkpoint(self):
        with open(self.checkpoint_path, "w", encoding="utf-8") as f:
            json.dump(self.state, f)

    def add_fragment(self, session_id: str, destination: str, source: str, fragment_data: str):
        key = f"{session_id}:{destination}:{source}"
        self.state.setdefault(key, []).append(
            {
                "data": self._obfuscate_payload(fragment_data),
                "timestamp": time.time(),
            }
        )
        self._save_checkpoint()


def percentile(sorted_values: List[float], q: float) -> float:
    if not sorted_values:
        return 0.0
    pos = (len(sorted_values) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(sorted_values) - 1)
    frac = pos - lo
    return sorted_values[lo] * (1 - frac) + sorted_values[hi] * frac


def summary(values: List[float]) -> Dict[str, float]:
    s = sorted(values)
    return {
        "p50_ms": percentile(s, 0.50),
        "p95_ms": percentile(s, 0.95),
        "p99_ms": percentile(s, 0.99),
        "mean_ms": statistics.fmean(s),
        "max_ms": max(s),
    }


def measure_registry(registry, *, warmup: int, measured: int) -> List[float]:
    # Warm-up uses separate IDs so measured phase starts after realistic initialization.
    for i in range(warmup):
        registry.add_fragment(
            f"warm_{i}",
            "evil.com",
            "src",
            f"warm_chunk_{i:04d}",
        )

    latencies: List[float] = []
    for i in range(measured):
        t0 = time.perf_counter_ns()
        registry.add_fragment(
            f"sess_{i}",
            "evil.com",
            "src",
            f"chunk_{i:04d}_CONFIDENTIAL_DATA",
        )
        t1 = time.perf_counter_ns()
        latencies.append((t1 - t0) / 1_000_000.0)
    return latencies


def quarter_stats(values: List[float]) -> Dict[str, Dict[str, float]]:
    n = len(values)
    q = max(1, n // 4)
    return {
        "first_quarter": summary(values[:q]),
        "last_quarter": summary(values[-q:]),
    }


def run_round(round_no: int, temp_dir: Path) -> Dict[str, Any]:
    # Encourage cleaner comparison between modes.
    gc.collect()

    mem = MemoryOnlyStateRegistry()
    off = measure_registry(mem, warmup=WARMUP, measured=MEASURED)

    gc.collect()

    checkpoint = temp_dir / f"p6_latency_round_{round_no}.json"
    if checkpoint.exists():
        checkpoint.unlink()

    pers = PersistentStateRegistry(str(checkpoint))
    on = measure_registry(pers, warmup=WARMUP, measured=MEASURED)

    file_size = checkpoint.stat().st_size if checkpoint.exists() else 0

    return {
        "round": round_no,
        "off": summary(off),
        "on": summary(on),
        "delta": {
            "p50_ms": summary(on)["p50_ms"] - summary(off)["p50_ms"],
            "p95_ms": summary(on)["p95_ms"] - summary(off)["p95_ms"],
            "p99_ms": summary(on)["p99_ms"] - summary(off)["p99_ms"],
        },
        "growth_check": quarter_stats(on),
        "checkpoint_bytes": file_size,
        "raw_off": off,
        "raw_on": on,
    }


def aggregate(rounds: List[Dict[str, Any]]) -> Dict[str, Any]:
    off_all: List[float] = []
    on_all: List[float] = []

    for r in rounds:
        off_all.extend(r["raw_off"])
        on_all.extend(r["raw_on"])

    off_s = summary(off_all)
    on_s = summary(on_all)

    first_q = []
    last_q = []
    for r in rounds:
        n = len(r["raw_on"])
        q = max(1, n // 4)
        first_q.extend(r["raw_on"][:q])
        last_q.extend(r["raw_on"][-q:])

    return {
        "memory_only": off_s,
        "persistence_on": on_s,
        "added_overhead": {
            "p50_ms": on_s["p50_ms"] - off_s["p50_ms"],
            "p95_ms": on_s["p95_ms"] - off_s["p95_ms"],
            "p99_ms": on_s["p99_ms"] - off_s["p99_ms"],
        },
        "persistence_growth_effect": {
            "first_quarter": summary(first_q),
            "last_quarter": summary(last_q),
            "last_vs_first_p95_multiplier": (
                summary(last_q)["p95_ms"] / summary(first_q)["p95_ms"]
                if summary(first_q)["p95_ms"] > 0
                else None
            ),
        },
        "checkpoint_bytes_mean": statistics.fmean(
            r["checkpoint_bytes"] for r in rounds
        ),
    }


def main() -> int:
    print("=" * 92)
    print("PROVPROXY P6 PERSISTENCE LATENCY — OFF vs ON")
    print("=" * 92)
    print(f"warmup={WARMUP}, measured={MEASURED}, rounds={ROUNDS}")
    print()

    with tempfile.TemporaryDirectory(prefix="provproxy_p6_latency_") as td:
        temp_dir = Path(td)
        rounds = []

        for r in range(1, ROUNDS + 1):
            result = run_round(r, temp_dir)
            rounds.append(result)

            print(
                f"Round {r}: "
                f"OFF p95={result['off']['p95_ms']:.3f} ms | "
                f"ON p95={result['on']['p95_ms']:.3f} ms | "
                f"delta={result['delta']['p95_ms']:.3f} ms | "
                f"file={result['checkpoint_bytes']/1024:.1f} KiB"
            )

        agg = aggregate(rounds)

    print("\n" + "-" * 92)
    print(f"{'Mode':24} {'p50 ms':>12} {'p95 ms':>12} {'p99 ms':>12} {'mean ms':>12}")
    print("-" * 92)

    off = agg["memory_only"]
    on = agg["persistence_on"]
    d = agg["added_overhead"]

    print(
        f"{'Memory-only (OFF)':24} "
        f"{off['p50_ms']:12.4f} {off['p95_ms']:12.4f} "
        f"{off['p99_ms']:12.4f} {off['mean_ms']:12.4f}"
    )
    print(
        f"{'Persistence ON':24} "
        f"{on['p50_ms']:12.4f} {on['p95_ms']:12.4f} "
        f"{on['p99_ms']:12.4f} {on['mean_ms']:12.4f}"
    )
    print(
        f"{'Added overhead':24} "
        f"{d['p50_ms']:12.4f} {d['p95_ms']:12.4f} "
        f"{d['p99_ms']:12.4f} {'':>12}"
    )

    growth = agg["persistence_growth_effect"]
    print("\nPersistence growth check:")
    print(
        f"  first-quarter p95: {growth['first_quarter']['p95_ms']:.4f} ms"
    )
    print(
        f"  last-quarter  p95: {growth['last_quarter']['p95_ms']:.4f} ms"
    )
    mult = growth["last_vs_first_p95_multiplier"]
    print(
        f"  late/early p95 multiplier: "
        f"{mult:.2f}x" if mult is not None else
        "  late/early p95 multiplier: n/a"
    )
    print(
        f"  mean final checkpoint size: "
        f"{agg['checkpoint_bytes_mean']/1024:.1f} KiB"
    )

    # Engineering interpretation: these are intentionally not pass/fail claims
    # about the research system; they are flags for what to inspect next.
    added_p50_ok = d["p50_ms"] < 5.0
    added_p95_ok = d["p95_ms"] < 20.0
    scaling_ok = (
        mult is None or mult < 2.0
    )

    print("\nEngineering checks:")
    print(f"  added p50 < 5 ms:   {added_p50_ok}")
    print(f"  added p95 < 20 ms:  {added_p95_ok}")
    print(f"  late/early p95 <2x: {scaling_ok}")

    result = {
        "configuration": {
            "warmup": WARMUP,
            "measured_per_round": MEASURED,
            "rounds": ROUNDS,
        },
        "aggregate": agg,
        "engineering_checks": {
            "added_p50_under_5ms": added_p50_ok,
            "added_p95_under_20ms": added_p95_ok,
            "late_vs_early_p95_under_2x": scaling_ok,
        },
        "important_note": (
            "Current prototype rewrites the complete JSON checkpoint on every "
            "fragment. Rising late-vs-early latency indicates checkpoint-size "
            "scaling cost rather than only OS jitter."
        ),
    }

    out = Path("benchmarks") / "results"
    out.mkdir(parents=True, exist_ok=True)
    result_path = out / "persistence_latency_comparison.json"
    result_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print(f"\nJSON: {result_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
