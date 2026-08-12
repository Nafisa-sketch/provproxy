"""STDIO Relay Proxy — spawns the target MCP tool server as a child
process and relays JSON-RPC frames between it and the MCP Host on our own
stdin/stdout. `tools/call` frames are evaluated through the ablation
pipeline before being forwarded; everything else passes through untouched.

Stream isolation: stdin/stdout carry JSON-RPC frames only; stderr carries
structured logs (telemetry plane) — the child's own stderr is inherited
so its diagnostics land in the same place.
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
import threading
from dataclasses import dataclass

from . import pipeline
from .broker import DEFAULT_PORT, LocalSocketApprovalBroker
from .config import EnforcementAction, PolicyFile
from .destination import is_destination_allowed, is_sensitive_source, primary_domain
from .enforcement import Decision, resolve_ask_user
from .rpc import ToolCallFrame, PassThroughFrame, classify, error_response
from .session import Session

logger = logging.getLogger("provproxy.relay")


@dataclass
class RelayConfig:
    target_command: list[str]
    server_id: str
    session_id: str
    approval_broker_port: int = DEFAULT_PORT


class Relay:
    def __init__(self, config: RelayConfig, policy: PolicyFile):
        self.config = config
        self.policy = policy
        self.session = Session(
            session_id=config.session_id,
            policy=policy,
            ttl_seconds=policy.cross_call_window.window_seconds,
        )
        # The approval broker (broker.py) — a small local server the
        # companion CLI (approve_cli.py) connects to. Started/stopped
        # alongside the relay's own lifecycle in run().
        self.broker = LocalSocketApprovalBroker(port=config.approval_broker_port)
        # Tracks tool calls we forwarded that read from a sensitive
        # location (per is_sensitive_source), keyed by JSON-RPC request
        # id, so that when the RESPONSE comes back in _child_to_host we
        # know to register its content as a tracked fragment. Without
        # this, nothing ever gets registered and V1-V3 have nothing real
        # to detect against in a live run.
        self._pending_sensitive_reads: dict = {}

    async def run(self) -> None:
        await self.broker.start()
        logger.info(
            "approval broker ready — run `python approve_cli.py --port %s` in another terminal "
            "to approve/deny matches",
            self.config.approval_broker_port,
        )

        process = await asyncio.create_subprocess_exec(
            *self.config.target_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=None,  # inherit — child diagnostics pass through our own stderr
        )

        out_queue: asyncio.Queue[str] = asyncio.Queue()

        stdout_writer_task = asyncio.create_task(self._stdout_writer(out_queue))
        child_relay_task = asyncio.create_task(self._child_to_host(process, out_queue))

        try:
            await self._host_to_child(process, out_queue)
        finally:
            out_queue.put_nowait(None)  # sentinel to stop the writer
            child_relay_task.cancel()
            await asyncio.gather(stdout_writer_task, return_exceptions=True)
            if process.returncode is None:
                process.terminate()
                await process.wait()
            await self.broker.stop()

    async def _host_to_child(self, process: asyncio.subprocess.Process, out_queue: asyncio.Queue) -> None:
        # WHY A BACKGROUND THREAD (not asyncio.connect_read_pipe):
        # Windows' asyncio has two event loop implementations, and neither
        # one supports everything we need at once — ProactorEventLoop
        # supports spawning subprocesses (which we need for the target MCP
        # server) but NOT connecting a pipe to console stdin the way Unix
        # does; SelectorEventLoop supports the stdin pipe but not
        # subprocesses on Windows. Since we need subprocess support,
        # ProactorEventLoop is what Python picks by default — so instead
        # of connect_read_pipe (which crashes here), we read stdin with a
        # plain, blocking loop in a separate background thread, and hand
        # each line over to the async side through a thread-safe queue.
        # This works identically on Windows, macOS, and Linux.
        stdin_queue: asyncio.Queue = asyncio.Queue()
        loop = asyncio.get_event_loop()

        def _read_stdin_blocking() -> None:
            for raw_line in sys.stdin:
                loop.call_soon_threadsafe(stdin_queue.put_nowait, raw_line)
            loop.call_soon_threadsafe(stdin_queue.put_nowait, None)  # EOF sentinel

        threading.Thread(target=_read_stdin_blocking, daemon=True).start()

        while True:
            raw_line = await stdin_queue.get()
            if raw_line is None:
                break
            line = raw_line.rstrip("\n")
            if not line.strip():
                continue

            try:
                frame = classify(line)
            except json.JSONDecodeError:
                process.stdin.write((line + "\n").encode("utf-8"))
                await process.stdin.drain()
                continue

            if isinstance(frame, ToolCallFrame):
                await self._handle_tool_call(frame, line, process, out_queue)
            else:
                process.stdin.write((line + "\n").encode("utf-8"))
                await process.stdin.drain()

    async def _handle_tool_call(
        self, frame: ToolCallFrame, raw_line: str, process: asyncio.subprocess.Process, out_queue: asyncio.Queue
    ) -> None:
        req = frame.request
        params = req.tool_call_params()

        if params is None:
            resp = error_response(req.id, -32602, "invalid tools/call params")
            await out_queue.put(resp.to_json())
            return

        payload_text = pipeline.flatten_json_strings(params["arguments"])
        destination_allowed = is_destination_allowed(
            self.policy, self.config.server_id, params["name"], params["arguments"]
        )
        destination_domain = primary_domain(params["name"], params["arguments"])

        self.session.expire_if_stale()
        result = pipeline.evaluate(
            self.policy,
            self.session,
            payload_text,
            self.policy.decode_limits,
            destination_allowed=destination_allowed,
            destination_domain=destination_domain,
        )

        logger.info(
            "tools/call evaluated tool=%s tier=%s matched=%s via=%s fragment=%s coverage=%s "
            "destination_allowed=%s enforcement_blocked=%s",
            params["name"],
            result.tier,
            result.matched,
            result.matched_via,
            result.matched_fragment_id,
            result.approx_coverage,
            result.destination_allowed,
            result.enforcement_blocked,
        )

        if not result.enforcement_blocked:
            # Either no provenance match at all, or a match against an
            # allow-listed destination (V0 override) — forward either way.
            await self._forward_to_child(req, params, raw_line, process)
            return

        # Matched AND not on the destination allow-list: resolve via the
        # configured enforcement action (Section 5D).
        if self.policy.enforcement.on_match == EnforcementAction.ASK_USER:
            description = (
                f"tool={params['name']} tier={result.tier} via={result.matched_via or 'unknown'} "
                f"fragment={result.matched_fragment_id or 'unknown'}"
            )
            decision = await resolve_ask_user(
                self.broker, description, self.policy.enforcement.approval_timeout_seconds
            )
            if decision == Decision.ALLOW:
                logger.info("tools/call approved by human (fragment=%s)", result.matched_fragment_id)
                await self._forward_to_child(req, params, raw_line, process)
                return
            # decision == BLOCK: denied, timed out, or broker unreachable —
            # all fail-closed to the same synthetic BLOCK response below.

        resp = error_response(
            req.id,
            -32001,
            f"ProvProxy {result.tier} BLOCK: provenance match via "
            f"{result.matched_via or 'unknown'} (fragment {result.matched_fragment_id or 'unknown'})",
        )
        await out_queue.put(resp.to_json())

    async def _forward_to_child(
        self, req, params: dict, raw_line: str, process: asyncio.subprocess.Process
    ) -> None:
        """Send an approved tool call on to the real MCP server, and — if
        it reads from a sensitive location (e.g. `~/.ssh/*`, per the
        policy's `blocked_paths`) — remember its request id so that when
        the RESPONSE comes back (see _child_to_host), we can register its
        content as a tracked fragment. This is what makes detection
        actually work end-to-end: without it, nothing would ever get
        registered, and the V1-V3 matchers would have nothing real to
        compare against."""
        if is_sensitive_source(self.policy, self.config.server_id, params["name"], params["arguments"]):
            fragment_id = f"sensitive-{req.id}"
            self._pending_sensitive_reads[req.id] = fragment_id
            logger.info(
                "tracking sensitive read (fragment=%s, tool=%s) — its result will be "
                "registered for provenance matching once the response arrives",
                fragment_id, params["name"],
            )

        process.stdin.write((raw_line + "\n").encode("utf-8"))
        await process.stdin.drain()

    async def _child_to_host(self, process: asyncio.subprocess.Process, out_queue: asyncio.Queue) -> None:
        while True:
            line_bytes = await process.stdout.readline()
            if not line_bytes:
                break
            line = line_bytes.decode("utf-8", errors="replace").rstrip("\n")
            self._maybe_register_sensitive_response(line)
            await out_queue.put(line)

    def _maybe_register_sensitive_response(self, line: str) -> None:
        """If this response line corresponds to a tracked sensitive read
        (see _forward_to_child), pull the actual text out of it and
        register it with the session's matchers. Silently does nothing
        for any response that isn't one we're tracking, or that fails to
        parse — a malformed/unexpected line here should never crash the
        relay, since it's already past the point of being passed through
        to the host either way."""
        if not self._pending_sensitive_reads:
            return
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            return

        response_id = parsed.get("id")
        fragment_id = self._pending_sensitive_reads.pop(response_id, None)
        if fragment_id is None:
            return

        result = parsed.get("result")
        if result is None:
            return  # an error response — nothing sensitive was actually returned

        content_text = pipeline.flatten_json_strings(result)
        if content_text.strip():
            self.session.register_sensitive_fragment(fragment_id, content_text)
            logger.info("registered sensitive fragment=%s (%d chars) for provenance matching", fragment_id, len(content_text))

    async def _stdout_writer(self, out_queue: asyncio.Queue) -> None:
        loop = asyncio.get_event_loop()
        while True:
            line = await out_queue.get()
            if line is None:
                break
            await loop.run_in_executor(None, lambda l=line: (sys.stdout.write(l + "\n"), sys.stdout.flush()))
