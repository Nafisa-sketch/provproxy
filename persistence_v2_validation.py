#!/usr/bin/env python3
"""
P6 optimized persistence validation.

Run:
    py persistence_v2_validation.py

On Windows this uses DPAPI automatically.
On non-Windows this benchmark enables the module's local DEV key fallback
only so the validation can run; that fallback is not for production.
"""

from __future__ import annotations

import json
import os
import shutil
import statistics
import tempfile
import time
from pathlib import Path

from secure_persistent_state import (
    PersistenceCorruptionError,
    SecurePersistentStateRegistry,
)


WARMUP = 30
MEASURED = 300
ROUNDS = 5


class MemoryOnlyRegistry:
    def __init__(self):
        self.state = {}

    def add_fragment(self, session_id, destination, source, data):
        self.state.setdefault((session_id, destination, source), []).append(data)


def percentile(values, q):
    s = sorted(values)
    if not s:
        return 0.0
    pos = (len(s) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(s) - 1)
    f = pos - lo
    return s[lo] * (1 - f) + s[hi] * f


def stats(values):
    return {
        "p50_ms": percentile(values, 0.50),
        "p95_ms": percentile(values, 0.95),
        "p99_ms": percentile(values, 0.99),
        "mean_ms": statistics.fmean(values),
        "max_ms": max(values),
    }


def measure(reg):
    for i in range(WARMUP):
        reg.add_fragment(f"warm{i}", "evil.com", "src", f"warm{i}")

    vals = []
    for i in range(MEASURED):
        t0 = time.perf_counter_ns()
        reg.add_fragment(
            f"sess{i}",
            "evil.com",
            "src",
            f"CONFIDENTIAL_CHUNK_{i:04d}",
        )
        vals.append((time.perf_counter_ns() - t0) / 1_000_000)
    return vals


def make_secure(path: Path, **kwargs):
    return SecurePersistentStateRegistry(
        path,
        allow_file_key_fallback=(os.name != "nt"),
        **kwargs,
    )


def test_restart(root: Path):
    d = root / "restart"
    secret = "CONFIDENTIAL_EXFIL_DATA_999"
    frags = ["CONFIDENTIAL_", "EXFIL_", "DATA_", "999"]

    reg = make_secure(d, fsync_every=1)
    reg.add_fragment("s1", "evil.com", "src", frags[0])
    reg.add_fragment("s1", "evil.com", "src", frags[1])
    reg.close()
    del reg

    reg2 = make_secure(d, fsync_every=1)
    reg2.add_fragment("s1", "evil.com", "src", frags[2])
    reg2.add_fragment("s1", "evil.com", "src", frags[3])
    rebuilt = "".join(reg2.get_accumulated("s1", "evil.com", "src"))
    reg2.close()
    return {"reconstructed": rebuilt, "pass": rebuilt == secret}


def test_isolation(root: Path):
    d = root / "isolation"
    reg = make_secure(d)
    reg.add_fragment("A", "evil.com", "src", "SECRET_A")
    reg.add_fragment("B", "evil.com", "src", "SECRET_B")
    reg.add_fragment("A", "other.com", "src", "SECRET_OTHER")
    reg.close()

    reg2 = make_secure(d)
    a = reg2.get_accumulated("A", "evil.com", "src")
    b = reg2.get_accumulated("B", "evil.com", "src")
    other = reg2.get_accumulated("A", "other.com", "src")
    reg2.close()

    return {
        "session_A": a,
        "session_B": b,
        "other_destination": other,
        "pass": (
            a == ["SECRET_A"]
            and b == ["SECRET_B"]
            and other == ["SECRET_OTHER"]
        ),
    }


def test_at_rest(root: Path):
    d = root / "at_rest"
    secret = "SUPER_SECRET_API_KEY_XYZ"
    reg = make_secure(d, fsync_every=1)
    reg.add_fragment("sec", "evil.com", "src", secret)
    reg.compact()
    reg.close()

    raw = b""
    for p in d.iterdir():
        if p.is_file():
            raw += p.read_bytes()

    return {
        "plaintext_found": secret.encode() in raw,
        "reversed_plaintext_found": secret[::-1].encode() in raw,
        "pass": (
            secret.encode() not in raw
            and secret[::-1].encode() not in raw
        ),
    }


def test_tamper_detection(root: Path):
    d = root / "tamper"
    reg = make_secure(d, fsync_every=1)
    reg.add_fragment("s1", "evil.com", "src", "SECRET_DATA")
    reg.close()

    journal = d / "state.journal"
    raw = bytearray(journal.read_bytes())
    # Flip a byte safely inside the Base64 ciphertext text.
    if len(raw) > 20:
        idx = len(raw) // 2
        raw[idx] = ord("A") if raw[idx] != ord("A") else ord("B")
    journal.write_bytes(raw)

    detected = False
    try:
        make_secure(d, fsync_every=1)
    except PersistenceCorruptionError:
        detected = True

    return {"tampering_detected_fail_closed": detected, "pass": detected}


def test_corrupt_truncation(root: Path):
    d = root / "truncate"
    reg = make_secure(d, fsync_every=1)
    reg.add_fragment("s1", "evil.com", "src", "SECRET_DATA")
    reg.close()

    journal = d / "state.journal"
    raw = journal.read_bytes()
    journal.write_bytes(raw[: max(1, len(raw) // 2)])

    detected = False
    try:
        make_secure(d, fsync_every=1)
    except PersistenceCorruptionError:
        detected = True

    return {"truncation_detected_fail_closed": detected, "pass": detected}


def test_ttl(root: Path):
    d = root / "ttl"
    reg = make_secure(d, ttl_seconds=1, fsync_every=1)
    reg.add_fragment("s1", "evil.com", "src", "OLD")
    reg.close()
    time.sleep(1.15)

    reg2 = make_secure(d, ttl_seconds=1, fsync_every=1)
    vals = reg2.get_accumulated("s1", "evil.com", "src")
    reg2.close()
    return {"restored_after_expiry": vals, "pass": vals == []}


def latency(root: Path):
    all_off = []
    all_on = []
    round_rows = []

    for r in range(ROUNDS):
        mem = MemoryOnlyRegistry()
        off = measure(mem)

        d = root / f"perf_{r}"
        reg = make_secure(
            d,
            # Amortized disk sync. Use 1 if power-loss durability per fragment
            # is mandatory, accepting a higher latency cost.
            fsync_every=16,
            compact_every=10000,
        )
        on = measure(reg)
        reg.close()

        all_off.extend(off)
        all_on.extend(on)
        round_rows.append({
            "round": r + 1,
            "off_p95_ms": stats(off)["p95_ms"],
            "on_p95_ms": stats(on)["p95_ms"],
            "journal_kib": (d / "state.journal").stat().st_size / 1024,
        })

    s_off = stats(all_off)
    s_on = stats(all_on)
    delta = {
        k: s_on[k] - s_off[k]
        for k in ("p50_ms", "p95_ms", "p99_ms")
    }
    return {
        "rounds": round_rows,
        "memory_only": s_off,
        "encrypted_append_only": s_on,
        "added_overhead": delta,
        "checks": {
            "added_p50_under_5ms": delta["p50_ms"] < 5.0,
            "added_p95_under_20ms": delta["p95_ms"] < 20.0,
        },
    }


def main():
    print("=" * 92)
    print("PROVPROXY P6 OPTIMIZED PERSISTENCE VALIDATION")
    print("=" * 92)

    with tempfile.TemporaryDirectory(prefix="provproxy_p6_v2_") as td:
        root = Path(td)
        results = {
            "restart_continuity": test_restart(root),
            "isolation": test_isolation(root),
            "ttl": test_ttl(root),
            "at_rest": test_at_rest(root),
            "tamper_detection": test_tamper_detection(root),
            "truncation_detection": test_corrupt_truncation(root),
            "performance": latency(root),
        }

    print(json.dumps(results, indent=2))

    out = Path("benchmarks") / "results"
    out.mkdir(parents=True, exist_ok=True)
    path = out / "persistence_v2_validation.json"
    path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nJSON: {path}")

    mandatory = [
        results["restart_continuity"]["pass"],
        results["isolation"]["pass"],
        results["ttl"]["pass"],
        results["at_rest"]["pass"],
        results["tamper_detection"]["pass"],
        results["truncation_detection"]["pass"],
    ]
    print(f"Security/correctness checks: {sum(mandatory)}/{len(mandatory)} passed")
    return 0 if all(mandatory) else 1


if __name__ == "__main__":
    raise SystemExit(main())
