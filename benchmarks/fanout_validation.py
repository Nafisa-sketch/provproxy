"""ProvProxy distributed-destination fan-out validation.

Runs the same synthetic secret-splitting attack twice:
1) strict per-destination V4 only -> demonstrates the measured evasion boundary.
2) optional session-wide fan-out REVIEW guard -> demonstrates mitigation.

No Internet is required; each destination is a separate localhost HTTP receiver.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
import urllib.request
from dataclasses import asdict, dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from provproxy.config import AblationTier, ApproxMatchingConfig, CrossCallWindowConfig, DecodeLimits, PolicyFile
from provproxy.session import Session
from provproxy import pipeline

RESULTS_DIR = Path(__file__).parent / "results"


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.count = 0
    def add(self):
        with self.lock:
            self.count += 1


def handler_for(state: State):
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(n)
            state.add()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        def log_message(self, *args):
            return
    return H


class Receiver:
    def __init__(self):
        self.state = State()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(self.state))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
    @property
    def origin(self):
        return f"http://127.0.0.1:{self.server.server_address[1]}"
    def start(self):
        self.thread.start()
    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


@dataclass
class Result:
    mode: str
    passed: bool
    fanout_guard_enabled: bool
    forwarded_requests: int
    receiver_observed_requests: int
    containment_call: int | None
    review: bool
    matched: bool
    via: str | None
    exposure_fraction: float


def policy(enable_fanout: bool) -> PolicyFile:
    return PolicyFile(
        version="fanout-validation",
        active_tier=AblationTier.V4,
        approx_matching=ApproxMatchingConfig(),
        decode_limits=DecodeLimits(),
        cross_call_window=CrossCallWindowConfig(
            review_threshold=0.30,
            fanout_review_threshold=0.30 if enable_fanout else None,
            fanout_min_destinations=2,
        ),
    )


def post(url: str, body: str):
    req = urllib.request.Request(url, data=body.encode(), method="POST")
    with urllib.request.urlopen(req, timeout=5) as r:
        r.read()


def run_case(enable_fanout: bool) -> Result:
    secret = "SYNTHETIC_DISTRIBUTED_SECRET_7A91C4E2B6F5"
    chunks = [secret[i:i+3] for i in range(0, len(secret), 3)]
    receivers = [Receiver() for _ in chunks]
    for r in receivers:
        r.start()

    p = policy(enable_fanout)
    s = Session(f"fanout-{enable_fanout}", p, ttl_seconds=300)
    s.register_sensitive_fragment("src", secret)

    forwarded = 0
    exposed = 0
    containment_call = None
    final = None

    try:
        for idx, (chunk, receiver) in enumerate(zip(chunks, receivers), 1):
            d = pipeline.evaluate(
                p, s, chunk, p.decode_limits,
                destination_allowed=False,
                destination_domain=receiver.origin,
            )
            final = d
            if d.enforcement_blocked:
                containment_call = idx
                break
            post(receiver.origin + f"/chunk/{idx}", chunk)
            forwarded += 1
            exposed += len(chunk)

        observed = sum(r.state.count for r in receivers)
    finally:
        for r in receivers:
            r.stop()

    if enable_fanout:
        passed = containment_call is not None and exposed < len(secret) and observed == forwarded
    else:
        passed = containment_call is None and exposed >= len(secret) and observed == forwarded

    return Result(
        mode="fanout_guard" if enable_fanout else "strict_destination_only",
        passed=passed,
        fanout_guard_enabled=enable_fanout,
        forwarded_requests=forwarded,
        receiver_observed_requests=observed,
        containment_call=containment_call,
        review=bool(getattr(final, "review_required", False)) if final else False,
        matched=bool(final.matched) if final else False,
        via=final.matched_via if final else None,
        exposure_fraction=round(min(exposed, len(secret)) / len(secret), 4),
    )


def main():
    print("=" * 90)
    print("PROVPROXY DISTRIBUTED-DESTINATION FAN-OUT VALIDATION")
    print("=" * 90)

    baseline = run_case(False)
    mitigated = run_case(True)
    results = [baseline, mitigated]

    print(f"{'mode':28} {'pass':>5} {'fwd':>5} {'recv':>5} {'contain':>7} {'review':>7} {'match':>6} {'via':>26} {'exposure':>9}")
    print("-" * 90)
    for r in results:
        print(
            f"{r.mode:28} {str(r.passed):>5} {r.forwarded_requests:>5} "
            f"{r.receiver_observed_requests:>5} {str(r.containment_call or '-'):>7} "
            f"{str(r.review):>7} {str(r.matched):>6} {str(r.via or '-'):>26} "
            f"{r.exposure_fraction:>8.1%}"
        )

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    jp = RESULTS_DIR / "fanout_validation.jsonl"
    mp = RESULTS_DIR / "fanout_validation.md"
    with jp.open("w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(asdict(r), sort_keys=True) + "\n")
    mp.write_text(
        "# ProvProxy Fan-Out Validation\n\n"
        "| Mode | Pass | Forwarded | Receiver observed | Containment call | Review | Match | Via | Exposure |\n"
        "|---|---:|---:|---:|---:|---:|---:|---|---:|\n" +
        "\n".join(
            f"| {r.mode} | {int(r.passed)} | {r.forwarded_requests} | "
            f"{r.receiver_observed_requests} | {r.containment_call or '-'} | "
            f"{int(r.review)} | {int(r.matched)} | {r.via or '-'} | {r.exposure_fraction:.1%} |"
            for r in results
        ) +
        "\n\nBaseline intentionally demonstrates the strict-destination isolation limitation; "
        "the optional fan-out guard mitigates it with REVIEW/HOLD rather than a hard provenance match.\n",
        encoding="utf-8",
    )
    print("-" * 90)
    print(f"JSONL:    {jp}")
    print(f"Markdown: {mp}")


if __name__ == "__main__":
    main()
