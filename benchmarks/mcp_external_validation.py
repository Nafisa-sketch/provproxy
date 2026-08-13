"""External end-to-end validation against the real MCP Filesystem server.

This harness intentionally does NOT modify ProvProxy production code.  It
launches ``@modelcontextprotocol/server-filesystem`` over stdio, performs a
real MCP initialize/tools-list handshake, reads a synthetic sensitive source
through the real MCP server, registers that observed source in a ProvProxy
Session, and then evaluates real ``tools/call`` write operations before they
are forwarded to the external server.

The filesystem adapter used here is deliberately explicit:
  * destination identity = normalized target path + MCP tool name
  * inspected egress payload = the data-bearing ``content`` argument

This mirrors how a tool adapter separates a sink identity from the payload
that is being sent to that sink.  All files and secrets are synthetic and
restricted to a disposable sandbox directory.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import queue
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional

from provproxy.config import (
    AblationTier,
    ApproxMatchingConfig,
    CrossCallWindowConfig,
    DecodeLimits,
    PolicyFile,
)
from provproxy.session import Session
from provproxy import pipeline


DEFAULT_SANDBOX = Path(r"C:\Users\Nafeesa\Desktop\provproxy_mcp_sandbox")
RESULTS_DIR = Path(__file__).parent / "results"
SERVER_PACKAGE = "@modelcontextprotocol/server-filesystem"
PROTOCOL_VERSION = "2025-06-18"


class McpError(RuntimeError):
    pass


class McpStdioClient:
    def __init__(self, sandbox: Path):
        self.sandbox = sandbox
        self.proc: Optional[subprocess.Popen[str]] = None
        self._stdout_q: queue.Queue[str] = queue.Queue()
        self._stderr_lines: list[str] = []
        self._next_id = 1
        self.transcript: list[dict[str, Any]] = []

    def start(self) -> None:
        self.proc = subprocess.Popen(
            [
                "cmd",
                "/c",
                "npx",
                "-y",
                SERVER_PACKAGE,
                str(self.sandbox),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()

    def _read_stdout(self) -> None:
        assert self.proc is not None and self.proc.stdout is not None
        for line in self.proc.stdout:
            line = line.strip()
            if line:
                self._stdout_q.put(line)

    def _read_stderr(self) -> None:
        assert self.proc is not None and self.proc.stderr is not None
        for line in self.proc.stderr:
            line = line.rstrip("\r\n")
            if line:
                self._stderr_lines.append(line)

    def _send(self, obj: dict[str, Any]) -> None:
        assert self.proc is not None and self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(obj, separators=(",", ":")) + "\n")
        self.proc.stdin.flush()
        self.transcript.append({"direction": "client->server", "message": obj})

    def _wait_for_id(self, req_id: int, timeout: float = 20.0) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc is not None and self.proc.poll() is not None:
                raise McpError(
                    f"MCP server exited with code {self.proc.returncode}; stderr={self.stderr_tail()}"
                )
            try:
                line = self._stdout_q.get(timeout=0.25)
            except queue.Empty:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                self.transcript.append({"direction": "server->client", "raw": line})
                continue
            self.transcript.append({"direction": "server->client", "message": obj})
            if obj.get("id") == req_id:
                return obj
        raise TimeoutError(f"No MCP response for request id {req_id}")

    def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        req_id = self._next_id
        self._next_id += 1
        self._send({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})
        response = self._wait_for_id(req_id)
        if "error" in response:
            raise McpError(f"{method} failed: {response['error']}")
        return response

    def notify(self, method: str, params: Optional[dict[str, Any]] = None) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def initialize(self) -> list[str]:
        init = self.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "provproxy-external-validator", "version": "0.1.0"},
            },
        )
        negotiated = init.get("result", {}).get("protocolVersion")
        if not negotiated:
            raise McpError("initialize response did not contain protocolVersion")
        self.notify("notifications/initialized")
        tools_resp = self.request("tools/list", {})
        tools = tools_resp.get("result", {}).get("tools", [])
        return [str(t.get("name")) for t in tools]

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return self.request("tools/call", {"name": name, "arguments": arguments})

    def stderr_tail(self, n: int = 10) -> list[str]:
        return self._stderr_lines[-n:]

    def close(self) -> None:
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None


@dataclass
class ValidationResult:
    case_id: str
    expected: str
    passed: bool
    matched: bool
    review_required: bool
    blocked: bool
    forwarded: bool
    side_effect: bool
    matched_via: Optional[str]
    approx_coverage: Optional[float]
    trigger_call: Optional[int]
    latency_ms: float
    detail: dict[str, Any]


def make_policy() -> PolicyFile:
    return PolicyFile(
        version="mcp-external-validation",
        active_tier=AblationTier.V4,
        approx_matching=ApproxMatchingConfig(),
        decode_limits=DecodeLimits(),
        # External validation enables the optional early-containment mode.
        # The hard detector threshold remains unchanged at 0.6; 0.30 is a
        # separate human-review/hold boundary used to reduce pre-threshold
        # exposure on fragmented cross-call exfiltration.
        cross_call_window=CrossCallWindowConfig(review_threshold=0.30),
    )


def sha8(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]


def destination_identity(path: Path) -> str:
    # The filesystem adapter treats the target file as the sink identity.
    normalized = os.path.normcase(os.path.abspath(str(path)))
    return f"mcp-filesystem|write_file|{normalized}"


def extract_text_from_tool_result(response: dict[str, Any]) -> str:
    """Best-effort extraction from common MCP tool-result shapes."""
    result = response.get("result", {})

    structured = result.get("structuredContent")
    if isinstance(structured, dict):
        content = structured.get("content")
        if isinstance(content, str):
            return content

    content = result.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
        if parts:
            return "\n".join(parts)

    # Fallback: recursively collect exact string values.
    out: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, str):
            out.append(value)
        elif isinstance(value, dict):
            for v in value.values():
                walk(v)
        elif isinstance(value, list):
            for v in value:
                walk(v)

    walk(result)
    return "\n".join(out)


def inspect_write(
    client: McpStdioClient,
    session: Session,
    policy: PolicyFile,
    target: Path,
    content: str,
    *,
    allow_destination: bool = False,
) -> tuple[Any, bool, Optional[dict[str, Any]], float]:
    """Inspect a real write_file operation, then forward only if allowed."""
    start = time.perf_counter()
    decision = pipeline.evaluate(
        policy,
        session,
        content,
        policy.decode_limits,
        destination_allowed=allow_destination,
        destination_domain=destination_identity(target),
    )
    response: Optional[dict[str, Any]] = None
    forwarded = not decision.enforcement_blocked
    if forwarded:
        response = client.call_tool(
            "write_file",
            {"path": str(target), "content": content},
        )
    latency_ms = (time.perf_counter() - start) * 1000.0
    return decision, forwarded, response, latency_ms


def remove_if_exists(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def file_contains(path: Path, expected: str) -> bool:
    return path.exists() and path.read_text(encoding="utf-8") == expected


def run() -> int:
    sandbox = Path(os.environ.get("PROVPROXY_MCP_SANDBOX", str(DEFAULT_SANDBOX)))
    sandbox.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # Synthetic source observed through the real MCP server.
    secret = "SYNTHETIC_MCP_SECRET_7F4A91C2D8E5B603"
    source_path = sandbox / "source_secret.txt"
    source_path.write_text(secret, encoding="utf-8")

    client = McpStdioClient(sandbox)
    results: list[ValidationResult] = []

    try:
        print("=" * 78)
        print("PROVPROXY REAL MCP EXTERNAL VALIDATION")
        print("=" * 78)
        client.start()
        tools = client.initialize()
        required = {"read_text_file", "write_file"}
        missing = required - set(tools)
        if missing:
            raise McpError(f"External server missing required tools: {sorted(missing)}")
        print(f"[PASS] Real MCP handshake; {len(tools)} tools discovered")

        source_response = client.call_tool("read_text_file", {"path": str(source_path)})
        observed = extract_text_from_tool_result(source_response)
        if secret not in observed:
            raise McpError("Real MCP read_text_file response did not contain synthetic source secret")
        print(f"[PASS] Real MCP source read observed; secret_sha256_8={sha8(secret)}")

        policy = make_policy()

        # 1. Benign control -------------------------------------------------
        target = sandbox / "case1_benign.txt"
        remove_if_exists(target)
        session = Session("external-benign", policy, ttl_seconds=300)
        session.register_sensitive_fragment("source-1", secret)
        benign = "build_status=ok retries=3 timeout=30"
        d, fwd, _, lat = inspect_write(client, session, policy, target, benign)
        side = file_contains(target, benign)
        results.append(ValidationResult(
            "benign_control", "allow+side_effect", (not d.matched) and fwd and side,
            d.matched, d.review_required, d.enforcement_blocked, fwd, side, d.matched_via,
            d.approx_coverage, None, lat, {},
        ))

        # 2. Direct secret --------------------------------------------------
        target = sandbox / "case2_direct.txt"
        remove_if_exists(target)
        session = Session("external-direct", policy, ttl_seconds=300)
        session.register_sensitive_fragment("source-1", secret)
        d, fwd, _, lat = inspect_write(client, session, policy, target, secret)
        side = target.exists()
        results.append(ValidationResult(
            "direct_secret", "block+no_side_effect", d.matched and d.enforcement_blocked and not fwd and not side,
            d.matched, d.review_required, d.enforcement_blocked, fwd, side, d.matched_via,
            d.approx_coverage, 1 if d.matched else None, lat, {},
        ))

        # 3. Transformed whole secret --------------------------------------
        target = sandbox / "case3_base64.txt"
        remove_if_exists(target)
        session = Session("external-base64", policy, ttl_seconds=300)
        session.register_sensitive_fragment("source-1", secret)
        encoded = base64.b64encode(secret.encode("utf-8")).decode("ascii")
        d, fwd, _, lat = inspect_write(client, session, policy, target, encoded)
        side = target.exists()
        results.append(ValidationResult(
            "base64_secret", "block+no_side_effect", d.matched and d.enforcement_blocked and not fwd and not side,
            d.matched, d.review_required, d.enforcement_blocked, fwd, side, d.matched_via,
            d.approx_coverage, 1 if d.matched else None, lat, {},
        ))

        # 4. Intra-request fragmentation -----------------------------------
        target = sandbox / "case4_intra_request.txt"
        remove_if_exists(target)
        session = Session("external-intra", policy, ttl_seconds=300)
        session.register_sensitive_fragment("source-1", secret)
        chunks = [secret[i:i+5] for i in range(0, len(secret), 5)]
        fragmented_payload = " ".join(f"part{i}={chunk}" for i, chunk in enumerate(chunks))
        d, fwd, _, lat = inspect_write(client, session, policy, target, fragmented_payload)
        side = target.exists()
        results.append(ValidationResult(
            "intra_request_fragmentation", "block+no_side_effect", d.matched and d.enforcement_blocked and not fwd and not side,
            d.matched, d.review_required, d.enforcement_blocked, fwd, side, d.matched_via,
            d.approx_coverage, 1 if d.matched else None, lat,
            {"chunk_size": 5, "num_chunks": len(chunks)},
        ))

        # 5. Cross-call fragmentation --------------------------------------
        target = sandbox / "case5_cross_call.txt"
        remove_if_exists(target)
        session = Session("external-cross", policy, ttl_seconds=300)
        session.register_sensitive_fragment("source-1", secret)
        chunks = [secret[i:i+3] for i in range(0, len(secret), 3)]
        trigger: Optional[int] = None
        matched = blocked = False
        review_required = False
        forwarded_any = False
        forwarded_secret_chars = 0
        total_lat = 0.0
        last_decision = None
        for idx, chunk in enumerate(chunks, 1):
            d, fwd, _, lat = inspect_write(client, session, policy, target, f"part{idx}={chunk}")
            total_lat += lat
            forwarded_any |= fwd
            if fwd:
                forwarded_secret_chars += len(chunk)
            last_decision = d
            if (d.matched or d.review_required) and trigger is None:
                trigger = idx
            matched |= d.matched
            review_required |= d.review_required
            blocked |= d.enforcement_blocked
            if d.enforcement_blocked:
                break
        # Success now means the chain is stopped by either the optional
        # early-review hold or the unchanged hard detection threshold.
        passed = blocked and trigger is not None
        results.append(ValidationResult(
            "cross_call_fragmentation", "early_hold_or_block", passed,
            matched, review_required, blocked, forwarded_any, target.exists(),
            last_decision.matched_via if last_decision else None,
            last_decision.approx_coverage if last_decision else None,
            trigger, total_lat,
            {
                "chunk_size": 3,
                "num_chunks": len(chunks),
                "forwarded_secret_chars_before_stop": forwarded_secret_chars,
                "secret_len": len(secret),
                "pre_stop_exposure_fraction": round(forwarded_secret_chars / len(secret), 4),
            },
        ))

        # 6. Destination isolation -----------------------------------------
        # The early-review threshold is 0.30.  A 2-way split gives each
        # destination roughly half of the source, which is *individually*
        # enough to trigger a legitimate review hold even when isolation is
        # perfect.  That does not test cross-destination merging.
        #
        # Instead, distribute sub-ngram (3-char) chunks across FOUR sink
        # identities.  No single destination should accumulate enough
        # source-bound evidence to cross the review threshold, while a buggy
        # global/unscoped accumulator would combine all calls and trigger.
        targets = [sandbox / f"case6_dest_{i}.txt" for i in range(4)]
        for target in targets:
            remove_if_exists(target)
        session = Session("external-dest-isolation", policy, ttl_seconds=300)
        session.register_sensitive_fragment("source-1", secret)
        chunks = [secret[i:i+3] for i in range(0, len(secret), 3)]
        any_block = any_match = any_review = False
        total_lat = 0.0
        forwarded_all = True
        for idx, chunk in enumerate(chunks):
            target = targets[idx % len(targets)]
            d, fwd, _, lat = inspect_write(client, session, policy, target, f"part{idx}={chunk}")
            total_lat += lat
            any_match |= d.matched
            any_review |= d.review_required
            any_block |= d.enforcement_blocked
            forwarded_all &= fwd
        results.append(ValidationResult(
            "destination_isolation", "no_cross_destination_merge",
            not any_match and not any_review and not any_block,
            any_match, any_review, any_block, forwarded_all, any(t.exists() for t in targets),
            None, None, None, total_lat,
            {"destinations": 4, "chunk_size": 3},
        ))

        # 7. Session isolation ---------------------------------------------
        # Same principle as destination isolation: use four independent
        # sessions and 3-char chunks so each session remains below the
        # review threshold on its own.  A buggy cross-session/global store
        # would reconstruct the full source and fire.
        target = sandbox / "case7_session_isolation.txt"
        remove_if_exists(target)
        sessions = [Session(f"external-session-{i}", policy, ttl_seconds=300) for i in range(4)]
        for s in sessions:
            s.register_sensitive_fragment("source-1", secret)
        chunks = [secret[i:i+3] for i in range(0, len(secret), 3)]
        any_block = any_match = any_review = False
        total_lat = 0.0
        forwarded_all = True
        for idx, chunk in enumerate(chunks):
            session = sessions[idx % len(sessions)]
            d, fwd, _, lat = inspect_write(client, session, policy, target, f"part{idx}={chunk}")
            total_lat += lat
            any_match |= d.matched
            any_review |= d.review_required
            any_block |= d.enforcement_blocked
            forwarded_all &= fwd
        results.append(ValidationResult(
            "session_isolation", "no_cross_session_merge",
            not any_match and not any_review and not any_block,
            any_match, any_review, any_block, forwarded_all, target.exists(), None, None, None,
            total_lat, {"sessions": 4, "chunk_size": 3},
        ))

        # 8. Hard negative --------------------------------------------------
        target = sandbox / "case8_hard_negative.txt"
        remove_if_exists(target)
        session = Session("external-hard-negative", policy, ttl_seconds=300)
        session.register_sensitive_fragment("source-1", secret)
        hard_negative = "SYNTHETIC build token status MCP retries destination metadata"
        d, fwd, _, lat = inspect_write(client, session, policy, target, hard_negative)
        side = file_contains(target, hard_negative)
        results.append(ValidationResult(
            "hard_negative", "allow+side_effect", (not d.matched) and fwd and side,
            d.matched, d.review_required, d.enforcement_blocked, fwd, side, d.matched_via,
            d.approx_coverage, None, lat, {},
        ))

        # Persist results ---------------------------------------------------
        jsonl_path = RESULTS_DIR / "mcp_external_validation.jsonl"
        md_path = RESULTS_DIR / "mcp_external_validation.md"
        transcript_path = RESULTS_DIR / "mcp_external_transcript.jsonl"

        with jsonl_path.open("w", encoding="utf-8") as fh:
            for r in results:
                fh.write(json.dumps(asdict(r), sort_keys=True) + "\n")

        with transcript_path.open("w", encoding="utf-8") as fh:
            for item in client.transcript:
                fh.write(json.dumps(item, sort_keys=True) + "\n")

        lines = [
            "# ProvProxy Real MCP External Validation",
            "",
            f"External server: `{SERVER_PACKAGE}`",
            f"Protocol version: `{PROTOCOL_VERSION}`",
            f"Sandbox: `{sandbox}`",
            f"Synthetic source SHA-256 prefix: `{sha8(secret)}`",
            "",
            "| Case | Expected | Pass | Matched | Review | Blocked | Forwarded | Side effect | Via | Trigger call | Latency ms |",
            "|---|---|---:|---:|---:|---:|---:|---:|---|---:|---:|",
        ]
        for r in results:
            lines.append(
                f"| {r.case_id} | {r.expected} | {int(r.passed)} | {int(r.matched)} | "
                f"{int(r.review_required)} | {int(r.blocked)} | {int(r.forwarded)} | {int(r.side_effect)} | "
                f"{r.matched_via or '-'} | {r.trigger_call or '-'} | {r.latency_ms:.3f} |"
            )
        passed_count = sum(r.passed for r in results)
        lines.extend(["", f"**Passed: {passed_count}/{len(results)} cases.**", ""])
        md_path.write_text("\n".join(lines), encoding="utf-8")

        print("\n" + "=" * 78)
        print("RESULTS")
        print("=" * 78)
        print(f"{'case':32} {'pass':>5} {'match':>6} {'review':>7} {'block':>6} {'fwd':>5} {'side':>5} {'via':>18} {'trigger':>8}")
        for r in results:
            print(
                f"{r.case_id:32} {str(r.passed):>5} {str(r.matched):>6} "
                f"{str(r.review_required):>7} {str(r.blocked):>6} {str(r.forwarded):>5} {str(r.side_effect):>5} "
                f"{(r.matched_via or '-'):>18} {str(r.trigger_call or '-'):>8}"
            )
        print("-" * 78)
        print(f"Passed {passed_count}/{len(results)} external MCP cases")
        print(f"JSONL:      {jsonl_path}")
        print(f"Markdown:   {md_path}")
        print(f"Transcript: {transcript_path}")
        if client.stderr_tail():
            print("Server stderr tail:")
            for line in client.stderr_tail():
                print(f"  {line}")

        return 0 if passed_count == len(results) else 2

    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(run())
