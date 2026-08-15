"""ProvProxy exact pre-containment leakage benchmark.

Purpose
-------
Measure *receiver-observed sensitive source exposure* before ProvProxy emits
REVIEW/HOLD/BLOCK for cross-call exfiltration.

This benchmark does not change production logic. It uses a real localhost HTTP
receiver so forwarded bytes are measured at the sink, not inferred only from
internal decision flags.

Sweeps:
- secret lengths: 24, 40, 64, 96 bytes
- chunk sizes: 2, 3, 4, 6, 8, 12 bytes
- plain sequential fragmentation
- benign/malicious interleaving
- distributed destination switching with fan-out guard enabled

Primary metrics:
- exact source bytes delivered before containment
- exposure ratio
- calls-to-containment
- time-to-containment
- receiver request count

Run:
    py -m benchmarks.precontainment_leakage

Outputs:
    benchmarks/results/precontainment_leakage.jsonl
    benchmarks/results/precontainment_leakage.md
"""
from __future__ import annotations

import json
import threading
import time
import urllib.request
from dataclasses import asdict, dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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

SECRET_LENGTHS = [24, 40, 64, 96]
CHUNK_SIZES = [2, 3, 4, 6, 8, 12]


@dataclass
class SinkEvent:
    body: bytes
    timestamp: float


class SinkState:
    def __init__(self):
        self.lock = threading.Lock()
        self.events: list[SinkEvent] = []

    def add(self, body: bytes):
        with self.lock:
            self.events.append(SinkEvent(body=body, timestamp=time.perf_counter()))

    def snapshot(self) -> list[SinkEvent]:
        with self.lock:
            return list(self.events)


def make_handler(state: SinkState):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(n)
            state.add(body)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_args):
            return

    return Handler


class Receiver:
    def __init__(self):
        self.state = SinkState()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.state))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def start(self):
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def events(self) -> list[SinkEvent]:
        return self.state.snapshot()


@dataclass
class Result:
    mode: str
    secret_length: int
    chunk_size: int
    fanout_guard: bool
    contained: bool
    containment_call: int | None
    total_calls: int
    malicious_calls: int
    benign_calls: int
    receiver_requests: int
    exact_secret_bytes_delivered: int
    exposure_fraction: float
    time_to_containment_ms: float | None
    matched: bool
    review: bool
    blocked: bool
    via: str | None
    passed: bool


def make_secret(length: int) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    prefix = "SYNTHETIC_"
    out = prefix
    i = 0
    while len(out) < length:
        out += alphabet[i % len(alphabet)]
        i += 1
    return out[:length]


def make_policy(*, fanout_guard: bool) -> PolicyFile:
    kwargs = dict(
        version="precontainment-leakage",
        active_tier=AblationTier.V4,
        approx_matching=ApproxMatchingConfig(),
        decode_limits=DecodeLimits(),
    )

    if fanout_guard:
        kwargs["cross_call_window"] = CrossCallWindowConfig(
            review_threshold=0.30,
            fanout_review_threshold=0.30,
            fanout_min_destinations=2,
        )
    else:
        kwargs["cross_call_window"] = CrossCallWindowConfig(
            review_threshold=0.30,
        )

    return PolicyFile(**kwargs)


def post(url: str, body: str):
    req = urllib.request.Request(url, data=body.encode("utf-8"), method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        resp.read()


def evaluate(policy: PolicyFile, session: Session, payload: str, destination: str):
    return pipeline.evaluate(
        policy,
        session,
        payload,
        policy.decode_limits,
        destination_allowed=False,
        destination_domain=destination,
    )


def is_contained(decision) -> bool:
    return bool(decision.enforcement_blocked)


def delivered_secret_bytes(events: list[SinkEvent], secret: str) -> int:
    """Count exact source bytes delivered from the synthetic secret.

    Each malicious POST body is a non-overlapping source chunk in these
    experiments. Benign interleaved bodies do not occur in the source string,
    so they contribute zero.
    """
    total = 0
    for event in events:
        text = event.body.decode("utf-8", errors="ignore")
        if text and text in secret:
            total += len(text)
    return min(total, len(secret))


def run_sequential(secret_len: int, chunk_size: int, interleave: bool) -> Result:
    secret = make_secret(secret_len)
    receiver = Receiver()
    receiver.start()

    policy = make_policy(fanout_guard=False)
    session = Session(f"seq-{secret_len}-{chunk_size}-{interleave}", policy, ttl_seconds=300)
    session.register_sensitive_fragment("src", secret)

    chunks = [secret[i:i+chunk_size] for i in range(0, len(secret), chunk_size)]

    total_calls = malicious_calls = benign_calls = 0
    containment_call = None
    final = None
    start = time.perf_counter()
    containment_time = None

    try:
        for idx, chunk in enumerate(chunks):
            if interleave:
                benign = f"heartbeat-{idx}-ok"
                rb = evaluate(policy, session, benign, receiver.origin)
                total_calls += 1
                benign_calls += 1
                if not is_contained(rb):
                    post(receiver.origin + "/benign", benign)

            d = evaluate(policy, session, chunk, receiver.origin)
            total_calls += 1
            malicious_calls += 1
            final = d

            if is_contained(d):
                containment_call = total_calls
                containment_time = time.perf_counter()
                break

            post(receiver.origin + "/secret", chunk)

        events = receiver.events()
        exact = delivered_secret_bytes(events, secret)

    finally:
        receiver.stop()

    exposure = exact / len(secret) if secret else 0.0
    contained = containment_call is not None

    # For this experiment a valid result must either contain before full exposure
    # or honestly demonstrate full exposure without containment.
    passed = (
        (contained and exact < len(secret))
        or ((not contained) and exact == len(secret))
    )

    return Result(
        mode="interleaved" if interleave else "sequential",
        secret_length=len(secret),
        chunk_size=chunk_size,
        fanout_guard=False,
        contained=contained,
        containment_call=containment_call,
        total_calls=total_calls,
        malicious_calls=malicious_calls,
        benign_calls=benign_calls,
        receiver_requests=len(events),
        exact_secret_bytes_delivered=exact,
        exposure_fraction=round(exposure, 4),
        time_to_containment_ms=(
            round((containment_time - start) * 1000.0, 3)
            if containment_time is not None else None
        ),
        matched=bool(final.matched) if final else False,
        review=bool(getattr(final, "review_required", False)) if final else False,
        blocked=bool(final.enforcement_blocked) if final else False,
        via=final.matched_via if final else None,
        passed=passed,
    )


def run_fanout(secret_len: int, chunk_size: int) -> Result:
    secret = make_secret(secret_len)
    chunks = [secret[i:i+chunk_size] for i in range(0, len(secret), chunk_size)]

    receivers = [Receiver() for _ in chunks]
    for r in receivers:
        r.start()

    policy = make_policy(fanout_guard=True)
    session = Session(f"fanout-{secret_len}-{chunk_size}", policy, ttl_seconds=300)
    session.register_sensitive_fragment("src", secret)

    containment_call = None
    final = None
    start = time.perf_counter()
    containment_time = None
    total_calls = 0

    try:
        for idx, (chunk, receiver) in enumerate(zip(chunks, receivers), 1):
            d = evaluate(policy, session, chunk, receiver.origin)
            total_calls += 1
            final = d

            if is_contained(d):
                containment_call = idx
                containment_time = time.perf_counter()
                break

            post(receiver.origin + f"/fanout/{idx}", chunk)

        all_events = []
        for r in receivers:
            all_events.extend(r.events())

        exact = delivered_secret_bytes(all_events, secret)

    finally:
        for r in receivers:
            r.stop()

    exposure = exact / len(secret) if secret else 0.0
    contained = containment_call is not None

    return Result(
        mode="fanout_guard",
        secret_length=len(secret),
        chunk_size=chunk_size,
        fanout_guard=True,
        contained=contained,
        containment_call=containment_call,
        total_calls=total_calls,
        malicious_calls=total_calls,
        benign_calls=0,
        receiver_requests=len(all_events),
        exact_secret_bytes_delivered=exact,
        exposure_fraction=round(exposure, 4),
        time_to_containment_ms=(
            round((containment_time - start) * 1000.0, 3)
            if containment_time is not None else None
        ),
        matched=bool(final.matched) if final else False,
        review=bool(getattr(final, "review_required", False)) if final else False,
        blocked=bool(final.enforcement_blocked) if final else False,
        via=final.matched_via if final else None,
        passed=(contained and exact < len(secret)),
    )


def write_outputs(results: list[Result]):
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    jp = RESULTS_DIR / "precontainment_leakage.jsonl"
    mp = RESULTS_DIR / "precontainment_leakage.md"

    with jp.open("w", encoding="utf-8") as f:
        for row in results:
            f.write(json.dumps(asdict(row), sort_keys=True) + "\n")

    lines = [
        "# ProvProxy Exact Pre-Containment Leakage Benchmark",
        "",
        "| Mode | Secret bytes | Chunk | Contained | Containment call | Delivered secret bytes | Exposure | Time-to-contain ms | Review | Block | Via | Pass |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|",
    ]

    for r in results:
        lines.append(
            f"| {r.mode} | {r.secret_length} | {r.chunk_size} | "
            f"{int(r.contained)} | {r.containment_call or '-'} | "
            f"{r.exact_secret_bytes_delivered} | {r.exposure_fraction:.1%} | "
            f"{r.time_to_containment_ms if r.time_to_containment_ms is not None else '-'} | "
            f"{int(r.review)} | {int(r.blocked)} | {r.via or '-'} | {int(r.passed)} |"
        )

    lines += [
        "",
        "## Metric definition",
        "",
        "**Exposure ratio = exact synthetic source bytes observed by the HTTP receiver before containment / source length.**",
        "",
        "This is receiver-side ground truth. Benign interleaved bodies are excluded from secret-byte exposure.",
    ]

    mp.write_text("\n".join(lines), encoding="utf-8")
    return jp, mp


def main() -> int:
    print("=" * 118)
    print("PROVPROXY EXACT PRE-CONTAINMENT LEAKAGE BENCHMARK")
    print("=" * 118)

    results: list[Result] = []

    print(
        f"{'mode':12} {'secret':>6} {'chunk':>5} {'contain':>7} "
        f"{'call':>5} {'bytes':>6} {'exposure':>9} {'t_ms':>9} "
        f"{'review':>7} {'block':>6} {'via':>26}"
    )
    print("-" * 118)

    for secret_len in SECRET_LENGTHS:
        for chunk_size in CHUNK_SIZES:
            for interleave in (False, True):
                r = run_sequential(secret_len, chunk_size, interleave)
                results.append(r)
                print(
                    f"{r.mode:12} {r.secret_length:>6} {r.chunk_size:>5} "
                    f"{str(r.contained):>7} {str(r.containment_call or '-'):>5} "
                    f"{r.exact_secret_bytes_delivered:>6} "
                    f"{r.exposure_fraction:>8.1%} "
                    f"{str(r.time_to_containment_ms or '-'):>9} "
                    f"{str(r.review):>7} {str(r.blocked):>6} "
                    f"{str(r.via or '-'):>26}"
                )

            f = run_fanout(secret_len, chunk_size)
            results.append(f)
            print(
                f"{f.mode:12} {f.secret_length:>6} {f.chunk_size:>5} "
                f"{str(f.contained):>7} {str(f.containment_call or '-'):>5} "
                f"{f.exact_secret_bytes_delivered:>6} "
                f"{f.exposure_fraction:>8.1%} "
                f"{str(f.time_to_containment_ms or '-'):>9} "
                f"{str(f.review):>7} {str(f.blocked):>6} "
                f"{str(f.via or '-'):>26}"
            )

    jp, mp = write_outputs(results)

    failed = sum(not r.passed for r in results)
    exposures = [r.exposure_fraction for r in results if r.contained]
    avg_exposure = sum(exposures) / len(exposures) if exposures else 0.0
    worst_exposure = max(exposures) if exposures else 0.0

    print("-" * 118)
    print(f"Cases: {len(results)}")
    print(f"Failed measurement-consistency cases: {failed}")
    print(f"Mean exposure among contained cases: {avg_exposure:.1%}")
    print(f"Worst exposure among contained cases: {worst_exposure:.1%}")
    print(f"JSONL:    {jp}")
    print(f"Markdown: {mp}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
