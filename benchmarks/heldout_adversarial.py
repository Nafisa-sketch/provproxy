"""Held-out adversarial robustness suite.

This module is intentionally separate from benchmarks/fixtures.py.  It uses
an independent RNG seed and is designed to evaluate a frozen production
implementation without tuning detector thresholds or labels.

Core categories:
A  Fragment-size generalization (2-12)
B  Reordered fragments
C  Unequal fragmentation
D  Duplicate-evidence resistance
E  Malicious/benign interleaving
F  Destination isolation
G  Session isolation
H  TTL boundary
I  Transformation + fragmentation
J  Nested JSON fragmentation
K  Partial exfiltration curve
L  Multiple sensitive sources
M  Common-substring hard negatives
"""
from __future__ import annotations

import base64
import json
import random
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import quote
from typing import Optional

from provproxy.config import (
    AblationTier, ApproxMatchingConfig, CrossCallWindowConfig, DecodeLimits, PolicyFile,
)
from provproxy.session import Session
from provproxy import pipeline

_SEED = 9999
RESULTS_DIR = Path(__file__).parent / "results"


def _rand_secret(rng: random.Random, length: int = 28) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "AKIA" + "".join(rng.choice(alphabet) for _ in range(length - 4))


def _policy(ttl_seconds: int = 300) -> PolicyFile:
    return PolicyFile(
        version="heldout-adversarial",
        active_tier=AblationTier.V4,
        approx_matching=ApproxMatchingConfig(),
        decode_limits=DecodeLimits(),
        cross_call_window=CrossCallWindowConfig(window_seconds=ttl_seconds),
    )


@dataclass
class CaseResult:
    category: str
    case_id: str
    expected_detectable: Optional[bool]
    matched: bool
    enforcement_blocked: bool
    detail: dict


ALL_RESULTS: list[CaseResult] = []


def _append(category: str, case_id: str, expected: Optional[bool],
            matched: bool, blocked: bool, **detail) -> None:
    ALL_RESULTS.append(CaseResult(
        category=category, case_id=case_id, expected_detectable=expected,
        matched=matched, enforcement_blocked=blocked, detail=detail,
    ))


# ---------------------------------------------------------------------
# A. Fragment-size generalization
# ---------------------------------------------------------------------
def run_category_a(rng: random.Random, trials_per_size: int = 10) -> None:
    """The FULL secret is transmitted in-order to one destination.

    Therefore every chunk size is security-relevant and expected to be
    detectable eventually.  Chunks shorter than n=4 have no per-chunk
    n-grams, but V4's ordered cross-call reconstruction can still recover
    cross-boundary n-grams after enough calls.  The earlier `<4=False`
    expectation incorrectly assumed per-call matching only.
    """
    for chunk_size in range(2, 13):
        for trial in range(trials_per_size):
            secret = _rand_secret(rng)
            chunks = [secret[i:i + chunk_size] for i in range(0, len(secret), chunk_size)]
            policy = _policy()
            session = Session(f"A-cs{chunk_size}-{trial}", policy, ttl_seconds=300)
            session.register_sensitive_fragment("frag-1", secret)

            matched = blocked = False
            for i, chunk in enumerate(chunks):
                r = pipeline.evaluate(
                    policy, session, f"part{i}={chunk}", policy.decode_limits,
                    destination_domain="heldout-a.example",
                )
                matched |= r.matched
                blocked |= r.enforcement_blocked

            _append("A_fragment_size", f"cs{chunk_size}_t{trial}", True,
                    matched, blocked, chunk_size=chunk_size,
                    num_chunks=len(chunks), secret_len=len(secret))


# ---------------------------------------------------------------------
# B. Reordered fragments
# ---------------------------------------------------------------------
def run_category_b(rng: random.Random, trials: int = 20) -> None:
    """Full-source exfiltration with chunks deliberately out of order."""
    for trial in range(trials):
        secret = _rand_secret(rng)
        chunk_size = rng.choice([2, 3, 4, 5, 6, 7])
        chunks = [secret[i:i + chunk_size] for i in range(0, len(secret), chunk_size)]
        if trial % 2 == 0:
            ordered = list(reversed(chunks))
            mode = "reverse"
        else:
            ordered = list(chunks)
            rng.shuffle(ordered)
            mode = "shuffle"

        policy = _policy()
        session = Session(f"B-{trial}", policy, ttl_seconds=300)
        session.register_sensitive_fragment("frag-1", secret)

        matched = blocked = False
        for i, chunk in enumerate(ordered):
            r = pipeline.evaluate(
                policy, session, f"part{i}={chunk}", policy.decode_limits,
                destination_domain="heldout-b.example",
            )
            matched |= r.matched
            blocked |= r.enforcement_blocked

        _append("B_reordered_fragments", f"t{trial}", True, matched, blocked,
                chunk_size=chunk_size, num_chunks=len(chunks), mode=mode)


# ---------------------------------------------------------------------
# C. Unequal fragmentation
# ---------------------------------------------------------------------
def run_category_c(rng: random.Random, trials: int = 20) -> None:
    for trial in range(trials):
        secret = _rand_secret(rng)
        chunks = []
        pos = 0
        while pos < len(secret):
            width = rng.randint(2, 8)
            chunks.append(secret[pos:pos + width])
            pos += width

        policy = _policy()
        session = Session(f"C-{trial}", policy, ttl_seconds=300)
        session.register_sensitive_fragment("frag-1", secret)

        matched = blocked = False
        for i, chunk in enumerate(chunks):
            r = pipeline.evaluate(
                policy, session, f"part{i}={chunk}", policy.decode_limits,
                destination_domain="heldout-c.example",
            )
            matched |= r.matched
            blocked |= r.enforcement_blocked

        _append("C_unequal_fragmentation", f"t{trial}", True, matched, blocked,
                chunk_lengths=[len(x) for x in chunks], num_chunks=len(chunks))


# ---------------------------------------------------------------------
# D. Duplicate evidence
# ---------------------------------------------------------------------
def run_category_d(rng: random.Random, trials: int = 10) -> None:
    for trial in range(trials):
        secret = _rand_secret(rng)
        weak_chunk = secret[:4]
        policy = _policy()
        session = Session(f"D-{trial}", policy, ttl_seconds=300)
        session.register_sensitive_fragment("frag-1", secret)

        matched = blocked = False
        for _ in range(30):
            r = pipeline.evaluate(
                policy, session, f"part0={weak_chunk}", policy.decode_limits,
                destination_domain="heldout-d.example",
            )
            matched |= r.matched
            blocked |= r.enforcement_blocked

        _append("D_duplicate_evidence", f"t{trial}", False, matched, blocked,
                repeats=30, weak_fragment_length=len(weak_chunk))


# ---------------------------------------------------------------------
# E. Interleaving
# ---------------------------------------------------------------------
def run_category_e(rng: random.Random, trials: int = 10) -> None:
    for trial in range(trials):
        secret = _rand_secret(rng)
        chunks = [secret[i:i + 7] for i in range(0, len(secret), 7)]
        policy = _policy()
        session = Session(f"E-{trial}", policy, ttl_seconds=300)
        session.register_sensitive_fragment("frag-1", secret)

        malicious_matched = False
        benign_matched_count = 0
        benign_blocked_count = 0

        for i, chunk in enumerate(chunks):
            r_m = pipeline.evaluate(
                policy, session, f"part{i}={chunk}", policy.decode_limits,
                destination_domain="heldout-e.example",
            )
            malicious_matched |= r_m.matched

            r_b = pipeline.evaluate(
                policy, session, "status=ok retries=3 timeout=30",
                policy.decode_limits, destination_domain="heldout-e.example",
            )
            benign_matched_count += int(r_b.matched)
            benign_blocked_count += int(r_b.enforcement_blocked)

        _append("E_interleaving", f"t{trial}", True, malicious_matched,
                malicious_matched, chunk_size=7,
                benign_calls=len(chunks),
                benign_matched_count=benign_matched_count,
                benign_blocked_count=benign_blocked_count)


# ---------------------------------------------------------------------
# F. Destination isolation
# ---------------------------------------------------------------------
def run_category_f(rng: random.Random, trials: int = 10) -> None:
    for trial in range(trials):
        secret = _rand_secret(rng)
        chunks = [secret[i:i + 7] for i in range(0, len(secret), 7)]
        policy = _policy()
        session = Session(f"F-{trial}", policy, ttl_seconds=300)
        session.register_sensitive_fragment("frag-1", secret)

        matched = blocked = False
        for i, chunk in enumerate(chunks):
            dest = "heldout-f-a.example" if i % 2 == 0 else "heldout-f-b.example"
            r = pipeline.evaluate(
                policy, session, f"part{i}={chunk}", policy.decode_limits,
                destination_domain=dest,
            )
            matched |= r.matched
            blocked |= r.enforcement_blocked

        _append("F_destination_isolation", f"t{trial}", False, matched, blocked,
                num_chunks=len(chunks))


# ---------------------------------------------------------------------
# G. Session isolation
# ---------------------------------------------------------------------
def run_category_g(rng: random.Random, trials: int = 10) -> None:
    for trial in range(trials):
        secret = _rand_secret(rng)
        chunks = [secret[i:i + 7] for i in range(0, len(secret), 7)]
        policy = _policy()

        matched = blocked = False
        for i, chunk in enumerate(chunks):
            session = Session(f"G-{trial}-{i}", policy, ttl_seconds=300)
            session.register_sensitive_fragment("frag-1", secret)
            r = pipeline.evaluate(
                policy, session, f"part{i}={chunk}", policy.decode_limits,
                destination_domain="heldout-g.example",
            )
            matched |= r.matched
            blocked |= r.enforcement_blocked

        _append("G_session_isolation", f"t{trial}", False, matched, blocked,
                num_chunks=len(chunks))


# ---------------------------------------------------------------------
# H. TTL boundary
# ---------------------------------------------------------------------
def run_category_h(rng: random.Random, trials: int = 3) -> None:
    short_ttl = 2
    for trial in range(trials):
        secret = _rand_secret(rng)
        chunks = [secret[i:i + 7] for i in range(0, len(secret), 7)]

        policy = _policy(ttl_seconds=short_ttl)
        session = Session(f"H-in-{trial}", policy, ttl_seconds=300)
        session.register_sensitive_fragment("frag-1", secret)

        matched = blocked = False
        for i, chunk in enumerate(chunks):
            r = pipeline.evaluate(
                policy, session, f"part{i}={chunk}", policy.decode_limits,
                destination_domain="heldout-h-in.example",
            )
            matched |= r.matched
            blocked |= r.enforcement_blocked
        _append("H_ttl_inside_window", f"t{trial}", True, matched, blocked,
                ttl_seconds=short_ttl)

        secret2 = _rand_secret(rng)
        chunks2 = [secret2[i:i + 7] for i in range(0, len(secret2), 7)]
        policy2 = _policy(ttl_seconds=short_ttl)
        session2 = Session(f"H-out-{trial}", policy2, ttl_seconds=300)
        session2.register_sensitive_fragment("frag-1", secret2)

        half = len(chunks2) // 2
        for i, chunk in enumerate(chunks2[:half]):
            pipeline.evaluate(
                policy2, session2, f"part{i}={chunk}", policy2.decode_limits,
                destination_domain="heldout-h-out.example",
            )
        time.sleep(short_ttl + 1)

        matched_after = blocked_after = False
        for i, chunk in enumerate(chunks2[half:], start=half):
            r = pipeline.evaluate(
                policy2, session2, f"part{i}={chunk}", policy2.decode_limits,
                destination_domain="heldout-h-out.example",
            )
            matched_after |= r.matched
            blocked_after |= r.enforcement_blocked

        # For a 28-char source split into four 7-char chunks, the second
        # half alone carries only ~50% of source n-grams (< threshold=.6).
        _append("H_ttl_expired_evidence_excluded", f"t{trial}", False,
                matched_after, blocked_after, ttl_seconds=short_ttl,
                chunks_before_expiry=half, chunks_after_expiry=len(chunks2)-half)


# ---------------------------------------------------------------------
# I. Transformation + fragmentation
# ---------------------------------------------------------------------
def _encode_piece(piece: str, mode: str) -> str:
    if mode == "base64":
        return base64.b64encode(piece.encode()).decode()
    if mode == "hex":
        return piece.encode().hex()
    if mode == "url":
        return "".join(f"%{ord(c):02X}" for c in piece)
    if mode == "json":
        return "".join(f"\\u{ord(c):04x}" for c in piece)
    raise ValueError(mode)


def run_category_i(rng: random.Random, trials_per_mode: int = 8) -> None:
    for mode in ("base64", "hex", "url", "json"):
        for trial in range(trials_per_mode):
            secret = _rand_secret(rng)
            chunk_size = rng.choice([4, 5, 6, 7])
            chunks = [secret[i:i + chunk_size] for i in range(0, len(secret), chunk_size)]
            policy = _policy()
            session = Session(f"I-{mode}-{trial}", policy, ttl_seconds=300)
            session.register_sensitive_fragment("frag-1", secret)

            matched = blocked = False
            for i, chunk in enumerate(chunks):
                encoded = _encode_piece(chunk, mode)
                r = pipeline.evaluate(
                    policy, session, f"part{i}={encoded}", policy.decode_limits,
                    destination_domain="heldout-i.example",
                )
                matched |= r.matched
                blocked |= r.enforcement_blocked

            _append("I_transform_fragment", f"{mode}-{trial}", True,
                    matched, blocked, mode=mode, chunk_size=chunk_size,
                    num_chunks=len(chunks))


# ---------------------------------------------------------------------
# J. Nested JSON
# ---------------------------------------------------------------------
def run_category_j(rng: random.Random, trials: int = 15) -> None:
    for trial in range(trials):
        secret = _rand_secret(rng)
        chunks = [secret[i:i + 5] for i in range(0, len(secret), 5)]
        # Preserve logical source order while nesting values.
        obj = {
            "meta": {"trace": "ordinary"},
            "payload": [
                {"v": chunks[0]},
                {"nested": {"v": chunks[1]}},
                {"arr": [chunks[2], chunks[3]]},
                {"tail": chunks[4:]},
            ],
        }
        payload = json.dumps(obj, separators=(",", ":"))
        policy = _policy()
        session = Session(f"J-{trial}", policy, ttl_seconds=300)
        session.register_sensitive_fragment("frag-1", secret)

        r = pipeline.evaluate(
            policy, session, payload, policy.decode_limits,
            destination_domain="heldout-j.example",
        )
        _append("J_nested_json", f"t{trial}", True, r.matched,
                r.enforcement_blocked, num_chunks=len(chunks))


# ---------------------------------------------------------------------
# K. Partial exfiltration curve
# ---------------------------------------------------------------------
def run_category_k(rng: random.Random, trials_per_fraction: int = 10) -> None:
    for fraction in (0.10, 0.25, 0.50, 0.75, 1.00):
        for trial in range(trials_per_fraction):
            secret = _rand_secret(rng)
            take = max(1, round(len(secret) * fraction))
            prefix = secret[:take]
            chunks = [prefix[i:i + 4] for i in range(0, len(prefix), 4)]
            policy = _policy()
            session = Session(f"K-{fraction}-{trial}", policy, ttl_seconds=300)
            session.register_sensitive_fragment("frag-1", secret)

            matched = blocked = False
            for i, chunk in enumerate(chunks):
                r = pipeline.evaluate(
                    policy, session, f"part{i}={chunk}", policy.decode_limits,
                    destination_domain="heldout-k.example",
                )
                matched |= r.matched
                blocked |= r.enforcement_blocked

            # >=75% should exceed the configured 0.6 source-coverage
            # threshold. Lower fractions are reported as a response curve,
            # not labelled failures.
            expected = True if fraction >= 0.75 else None
            _append("K_partial_exfiltration", f"{fraction:.2f}-{trial}",
                    expected, matched, blocked, fraction=fraction,
                    chars_sent=take, source_len=len(secret))


# ---------------------------------------------------------------------
# L. Multiple sensitive sources
# ---------------------------------------------------------------------
def run_category_l(rng: random.Random, trials: int = 10) -> None:
    for trial in range(trials):
        secret_a = _rand_secret(rng)
        secret_b = _rand_secret(rng)
        chunks_a = [secret_a[i:i + 7] for i in range(0, len(secret_a), 7)]
        chunks_b = [secret_b[i:i + 7] for i in range(0, len(secret_b), 7)]

        policy = _policy()
        session = Session(f"L-{trial}", policy, ttl_seconds=300)
        session.register_sensitive_fragment("source-a", secret_a)
        session.register_sensitive_fragment("source-b", secret_b)

        caught_ids: set[str] = set()
        max_len = max(len(chunks_a), len(chunks_b))
        for i in range(max_len):
            for source_name, chunks in (("a", chunks_a), ("b", chunks_b)):
                if i >= len(chunks):
                    continue
                r = pipeline.evaluate(
                    policy, session, f"{source_name}{i}={chunks[i]}",
                    policy.decode_limits, destination_domain="heldout-l.example",
                )
                if r.matched_fragment_id:
                    caught_ids.add(r.matched_fragment_id)

        both = {"source-a", "source-b"} <= caught_ids
        _append("L_multiple_sources", f"t{trial}", True, both, both,
                caught_source_ids=sorted(caught_ids),
                expected_source_count=2)


# ---------------------------------------------------------------------
# M. Common-substring hard negatives
# ---------------------------------------------------------------------
def run_category_m(rng: random.Random, trials: int = 15) -> None:
    for trial in range(trials):
        secret = _rand_secret(rng)
        overlap_len = rng.randint(3, 6)
        start = rng.randint(0, len(secret)-overlap_len)
        overlap = secret[start:start+overlap_len]
        benign_payload = (
            f"field0=timeout field1=retries field2={overlap}XYZ field3=region"
        )

        policy = _policy()
        session = Session(f"M-{trial}", policy, ttl_seconds=300)
        session.register_sensitive_fragment("frag-1", secret)
        r = pipeline.evaluate(
            policy, session, benign_payload, policy.decode_limits,
            destination_domain="heldout-m.example",
        )
        _append("M_common_substring_hard_negative", f"t{trial}", False,
                r.matched, r.enforcement_blocked,
                overlap_len=overlap_len, coverage=r.approx_coverage)


def main() -> None:
    rng = random.Random(_SEED)
    ALL_RESULTS.clear()

    for runner in (
        run_category_a, run_category_b, run_category_c, run_category_d,
        run_category_e, run_category_f, run_category_g, run_category_h,
        run_category_i, run_category_j, run_category_k, run_category_l,
        run_category_m,
    ):
        runner(rng)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    jsonl_path = RESULTS_DIR / "heldout_report.jsonl"
    with open(jsonl_path, "w", encoding="utf-8") as f:
        for r in ALL_RESULTS:
            f.write(json.dumps(asdict(r)) + "\n")

    by_category: dict[str, list[CaseResult]] = {}
    for r in ALL_RESULTS:
        by_category.setdefault(r.category, []).append(r)

    lines = ["# Held-Out Adversarial Robustness Report (A-M)", ""]
    lines.append(f"Seed: {_SEED}")
    lines.append(f"Total cases: {len(ALL_RESULTS)}")
    lines.append("")

    for cat, results in by_category.items():
        lines.append(f"## {cat}")
        scored = [r for r in results if r.expected_detectable is not None]
        if scored:
            correct = sum(r.matched == r.expected_detectable for r in scored)
            lines.append(f"Correct: {correct}/{len(scored)} ({correct/len(scored):.1%})")
        lines.append(f"Matched: {sum(r.matched for r in results)}/{len(results)}")
        lines.append(
            f"Enforcement-blocked: {sum(r.enforcement_blocked for r in results)}/{len(results)}"
        )

        if cat == "E_interleaving":
            benign_calls = sum(r.detail["benign_calls"] for r in results)
            benign_matched = sum(r.detail["benign_matched_count"] for r in results)
            benign_blocked = sum(r.detail["benign_blocked_count"] for r in results)
            lines.append(
                f"Benign interleaved calls matched: {benign_matched}/{benign_calls}"
            )
            lines.append(
                f"Benign interleaved calls blocked: {benign_blocked}/{benign_calls}"
            )

        if cat == "K_partial_exfiltration":
            for fraction in (0.10, 0.25, 0.50, 0.75, 1.00):
                subset = [r for r in results if r.detail["fraction"] == fraction]
                lines.append(
                    f"- fraction={fraction:.2f}: "
                    f"{sum(r.matched for r in subset)}/{len(subset)} matched"
                )
        lines.append("")

    a_results = by_category["A_fragment_size"]
    lines.append("## A. Detection by chunk size")
    for size in range(2, 13):
        subset = [r for r in a_results if r.detail["chunk_size"] == size]
        lines.append(f"- chunk_size={size}: {sum(r.matched for r in subset)}/{len(subset)}")

    report = "\n".join(lines)
    (RESULTS_DIR / "heldout_report.md").write_text(report, encoding="utf-8")
    print(report)
    print(f"\nJSONL written to: {jsonl_path}")


if __name__ == "__main__":
    main()
