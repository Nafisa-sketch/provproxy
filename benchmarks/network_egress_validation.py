"""ProvProxy real localhost HTTP egress validation.

This benchmark proves enforcement with receiver-side network evidence rather
than only internal decision flags.

It starts one or more real localhost HTTP receivers and sends POST requests
only when ProvProxy allows them.

Scenarios:
1. benign outbound POST
2. direct secret
3. Base64 secret
4. cross-call fragmented secret
5. benign/malicious interleaving
6. distributed destination switching

Important:
- All secrets are synthetic.
- No Internet access is required.
- The distributed-destination case is reported as a threat-model boundary,
  not silently re-labeled as a pass/fail benchmark trick.

Run:
    py -m benchmarks.network_egress_validation

Outputs:
    benchmarks/results/network_egress_validation.jsonl
    benchmarks/results/network_egress_validation.md
"""
from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
import urllib.request
from dataclasses import asdict, dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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


@dataclass
class ReceiverEvent:
    path: str
    body_len: int
    body_sha256_8: str
    timestamp: float


@dataclass
class ScenarioResult:
    scenario: str
    passed: bool
    expected_behavior: str
    matched: bool
    review: bool
    blocked: bool
    forwarded_requests: int
    receiver_observed_requests: int
    containment_call: int | None
    secret_length: int
    secret_bytes_forwarded_before_containment: int
    exposure_fraction: float
    distributed_destination_evasion_observed: bool = False
    notes: str = ""
    receiver_events: list[dict[str, Any]] = field(default_factory=list)


class ReceiverState:
    def __init__(self):
        self.lock = threading.Lock()
        self.events: list[ReceiverEvent] = []

    def add(self, path: str, body: bytes):
        with self.lock:
            self.events.append(
                ReceiverEvent(
                    path=path,
                    body_len=len(body),
                    body_sha256_8=hashlib.sha256(body).hexdigest()[:8],
                    timestamp=time.time(),
                )
            )

    def snapshot(self) -> list[ReceiverEvent]:
        with self.lock:
            return list(self.events)


def make_handler(state: ReceiverState):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            state.add(self.path, body)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

        def log_message(self, format, *args):
            return

    return Handler


class LocalReceiver:
    def __init__(self):
        self.state = ReceiverState()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.state))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self.server.server_address[1]

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def events(self) -> list[ReceiverEvent]:
        return self.state.snapshot()


def make_policy() -> PolicyFile:
    return PolicyFile(
        version="network-egress-validation",
        active_tier=AblationTier.V4,
        approx_matching=ApproxMatchingConfig(),
        decode_limits=DecodeLimits(),
        cross_call_window=CrossCallWindowConfig(review_threshold=0.30),
    )


def make_session(name: str, secret: str) -> tuple[PolicyFile, Session]:
    policy = make_policy()
    session = Session(name, policy, ttl_seconds=300)
    session.register_sensitive_fragment(f"src-{name}", secret)
    return policy, session


def inspect(
    policy: PolicyFile,
    session: Session,
    payload: str,
    destination: str,
):
    return pipeline.evaluate(
        policy,
        session,
        payload,
        policy.decode_limits,
        destination_allowed=False,
        destination_domain=destination,
    )


def send_http(url: str, body: str) -> None:
    req = urllib.request.Request(
        url,
        data=body.encode("utf-8"),
        method="POST",
        headers={"Content-Type": "text/plain; charset=utf-8"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        resp.read()


def decision_allows(r) -> bool:
    return not bool(r.enforcement_blocked)


def simple_scenario(
    name: str,
    body: str,
    secret: str,
    receiver: LocalReceiver,
    should_forward: bool,
) -> ScenarioResult:
    policy, session = make_session(name, secret)
    before = len(receiver.events())
    r = inspect(policy, session, body, receiver.origin)

    forwarded = 0
    if decision_allows(r):
        send_http(receiver.origin + f"/{name}", body)
        forwarded = 1

    after_events = receiver.events()[before:]
    observed = len(after_events)

    passed = (forwarded == int(should_forward)) and (observed == int(should_forward))

    return ScenarioResult(
        scenario=name,
        passed=passed,
        expected_behavior="forward" if should_forward else "contain",
        matched=bool(r.matched),
        review=bool(getattr(r, "review_required", False)),
        blocked=bool(r.enforcement_blocked),
        forwarded_requests=forwarded,
        receiver_observed_requests=observed,
        containment_call=1 if not decision_allows(r) else None,
        secret_length=len(secret),
        secret_bytes_forwarded_before_containment=0 if not should_forward else 0,
        exposure_fraction=0.0,
        receiver_events=[asdict(e) for e in after_events],
    )


def cross_call_fragmentation(secret: str, receiver: LocalReceiver) -> ScenarioResult:
    policy, session = make_session("cross-call", secret)
    chunks = [secret[i:i+3] for i in range(0, len(secret), 3)]

    before = len(receiver.events())
    forwarded = 0
    exposed = 0
    containment_call = None
    final_r = None

    for idx, chunk in enumerate(chunks, 1):
        r = inspect(policy, session, chunk, receiver.origin)
        final_r = r

        if not decision_allows(r):
            containment_call = idx
            break

        send_http(receiver.origin + "/cross-call", chunk)
        forwarded += 1
        exposed += len(chunk)

    events = receiver.events()[before:]
    observed = len(events)

    passed = (
        containment_call is not None
        and observed == forwarded
        and exposed < len(secret)
    )

    return ScenarioResult(
        scenario="cross_call_fragmentation",
        passed=passed,
        expected_behavior="partial forwarding followed by REVIEW/BLOCK containment",
        matched=bool(final_r.matched) if final_r else False,
        review=bool(getattr(final_r, "review_required", False)) if final_r else False,
        blocked=bool(final_r.enforcement_blocked) if final_r else False,
        forwarded_requests=forwarded,
        receiver_observed_requests=observed,
        containment_call=containment_call,
        secret_length=len(secret),
        secret_bytes_forwarded_before_containment=exposed,
        exposure_fraction=round(exposed / len(secret), 4),
        receiver_events=[asdict(e) for e in events],
    )


def interleaving(secret: str, receiver: LocalReceiver) -> ScenarioResult:
    policy, session = make_session("interleave", secret)
    chunks = [secret[i:i+3] for i in range(0, len(secret), 3)]

    before = len(receiver.events())
    forwarded = 0
    exposed = 0
    containment_call = None
    final_r = None
    call_idx = 0

    for i, chunk in enumerate(chunks):
        # Benign traffic before each malicious fragment.
        benign = f"heartbeat-{i}-ok"
        rb = inspect(policy, session, benign, receiver.origin)
        call_idx += 1
        if decision_allows(rb):
            send_http(receiver.origin + "/interleave-benign", benign)
            forwarded += 1

        r = inspect(policy, session, chunk, receiver.origin)
        final_r = r
        call_idx += 1
        if not decision_allows(r):
            containment_call = call_idx
            break

        send_http(receiver.origin + "/interleave-secret", chunk)
        forwarded += 1
        exposed += len(chunk)

    events = receiver.events()[before:]
    malicious_observed = sum(e.path == "/interleave-secret" for e in events)

    passed = containment_call is not None and exposed < len(secret)

    return ScenarioResult(
        scenario="interleaving",
        passed=passed,
        expected_behavior="benign traffic forwards; malicious cumulative flow is eventually contained",
        matched=bool(final_r.matched) if final_r else False,
        review=bool(getattr(final_r, "review_required", False)) if final_r else False,
        blocked=bool(final_r.enforcement_blocked) if final_r else False,
        forwarded_requests=forwarded,
        receiver_observed_requests=len(events),
        containment_call=containment_call,
        secret_length=len(secret),
        secret_bytes_forwarded_before_containment=exposed,
        exposure_fraction=round(exposed / len(secret), 4),
        notes=f"receiver observed {malicious_observed} malicious fragment POSTs before containment",
        receiver_events=[asdict(e) for e in events],
    )


def distributed_destination_switch(secret: str) -> ScenarioResult:
    """Fully distribute a secret over many distinct destination origins.

    This intentionally tests a known trade-off: strict destination isolation
    prevents evidence from different sinks from being combined. If every chunk
    is sent to a fresh origin, a distributed attacker may evade per-destination
    accumulation.

    The result is reported explicitly as a threat-model boundary.
    """
    chunks = [secret[i:i+3] for i in range(0, len(secret), 3)]
    receivers = [LocalReceiver() for _ in chunks]

    for r in receivers:
        r.start()

    policy, session = make_session("distributed-switch", secret)

    forwarded = 0
    exposed = 0
    any_containment = False
    any_match = False
    any_review = False
    any_block = False
    all_events: list[dict[str, Any]] = []

    try:
        for idx, (chunk, receiver) in enumerate(zip(chunks, receivers), 1):
            d = inspect(policy, session, chunk, receiver.origin)
            any_match = any_match or bool(d.matched)
            any_review = any_review or bool(getattr(d, "review_required", False))
            any_block = any_block or bool(d.enforcement_blocked)

            if not decision_allows(d):
                any_containment = True
                continue

            send_http(receiver.origin + f"/distributed/{idx}", chunk)
            forwarded += 1
            exposed += len(chunk)

        observed = 0
        for receiver in receivers:
            ev = receiver.events()
            observed += len(ev)
            all_events.extend(asdict(x) for x in ev)

    finally:
        for r in receivers:
            r.stop()

    full_distributed_exposure = exposed >= len(secret)
    evasion_observed = full_distributed_exposure and not any_containment

    # "passed" here means the experiment ran consistently with destination
    # isolation semantics; it does NOT mean the distributed attack was stopped.
    passed = observed == forwarded

    return ScenarioResult(
        scenario="distributed_destination_switch",
        passed=passed,
        expected_behavior="measure destination-isolation trade-off; distributed evasion may be possible",
        matched=any_match,
        review=any_review,
        blocked=any_block,
        forwarded_requests=forwarded,
        receiver_observed_requests=observed,
        containment_call=None,
        secret_length=len(secret),
        secret_bytes_forwarded_before_containment=exposed,
        exposure_fraction=round(min(exposed, len(secret)) / len(secret), 4),
        distributed_destination_evasion_observed=evasion_observed,
        notes=(
            "PASS denotes measurement integrity only. "
            "If distributed_destination_evasion_observed=true, this is a real threat-model limitation."
        ),
        receiver_events=all_events,
    )


def write_outputs(results: list[ScenarioResult]):
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    jp = RESULTS_DIR / "network_egress_validation.jsonl"
    mp = RESULTS_DIR / "network_egress_validation.md"

    with jp.open("w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(asdict(r), sort_keys=True) + "\n")

    lines = [
        "# ProvProxy Real Localhost HTTP Egress Validation",
        "",
        "| Scenario | Pass | Match | Review | Block | Forwarded | Receiver observed | Containment call | Exposure | Distributed evasion |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in results:
        lines.append(
            f"| {r.scenario} | {int(r.passed)} | {int(r.matched)} | "
            f"{int(r.review)} | {int(r.blocked)} | {r.forwarded_requests} | "
            f"{r.receiver_observed_requests} | {r.containment_call or '-'} | "
            f"{r.exposure_fraction:.1%} | {int(r.distributed_destination_evasion_observed)} |"
        )

    lines += [
        "",
        "## Important interpretation",
        "",
        "- Receiver-side observation is the enforcement ground truth for network delivery.",
        "- A blocked request that is absent at the receiver demonstrates prevention of that individual POST.",
        "- Cross-call containment may occur after some fragments have already been delivered.",
        "- Distributed destination switching is intentionally reported as a threat-model boundary rather than hidden.",
    ]
    mp.write_text("\n".join(lines), encoding="utf-8")
    return jp, mp


def main() -> int:
    print("=" * 98)
    print("PROVPROXY REAL LOCALHOST HTTP EGRESS VALIDATION")
    print("=" * 98)

    secret = "SYNTHETIC_NETWORK_SECRET_A91C7E4B205D8F63"
    receiver = LocalReceiver()
    receiver.start()

    try:
        results = [
            simple_scenario(
                "benign_outbound",
                "routine build status: green",
                secret,
                receiver,
                should_forward=True,
            ),
            simple_scenario(
                "direct_secret",
                secret,
                secret,
                receiver,
                should_forward=False,
            ),
            simple_scenario(
                "base64_secret",
                base64.b64encode(secret.encode()).decode(),
                secret,
                receiver,
                should_forward=False,
            ),
            cross_call_fragmentation(secret, receiver),
            interleaving(secret, receiver),
        ]
    finally:
        receiver.stop()

    # Uses independent real receiver origins.
    results.append(distributed_destination_switch(secret))

    print(
        f"{'scenario':34} {'pass':>5} {'match':>6} {'review':>7} "
        f"{'block':>6} {'fwd':>5} {'recv':>5} {'contain':>7} "
        f"{'exposure':>9} {'dist_evasion':>12}"
    )
    print("-" * 98)

    for r in results:
        print(
            f"{r.scenario:34} {str(r.passed):>5} {str(r.matched):>6} "
            f"{str(r.review):>7} {str(r.blocked):>6} "
            f"{r.forwarded_requests:>5} {r.receiver_observed_requests:>5} "
            f"{str(r.containment_call or '-'):>7} "
            f"{r.exposure_fraction:>8.1%} "
            f"{str(r.distributed_destination_evasion_observed):>12}"
        )

    jp, mp = write_outputs(results)

    regular = [r for r in results if r.scenario != "distributed_destination_switch"]
    passed_regular = sum(r.passed for r in regular)

    print("-" * 98)
    print(f"Standard egress scenarios passed: {passed_regular}/{len(regular)}")
    dist = results[-1]
    print(
        "Distributed destination switching evasion observed: "
        f"{dist.distributed_destination_evasion_observed}"
    )
    print(f"JSONL:    {jp}")
    print(f"Markdown: {mp}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
