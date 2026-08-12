"""Local IPC Approval Broker (Section 6, Control & Approval Plane).

WHY THIS FILE EXISTS (plain-language):
When ProvProxy sees a possible secret leak and the policy says
"ask_user", it needs to pause and ask a human. But ProvProxy's own
terminal window is busy relaying messages between the AI and its tools —
we can't print a question there without corrupting that message stream.
So we open a SECOND, separate communication channel (a local network
socket) that a different, small program (the "companion CLI",
`approve_cli.py`) can connect to. That second program is where the human
actually sees "approve or deny?" and types an answer.

WHY TCP INSTEAD OF A "UNIX DOMAIN SOCKET" (as the original proposal said):
Unix domain sockets and Windows named pipes are two different, incompatible
APIs. This project runs on Windows. A plain TCP socket bound to
127.0.0.1 (meaning: "only reachable from this same computer, never over
the real network") behaves identically on Windows, Mac, and Linux, so the
same code works everywhere without an if/else for the operating system.

PROTOCOL (deliberately simple, line-based text — so a person could even
manually test it with a tool like `telnet 127.0.0.1 8765`):

  Server -> client (sent when a new approval is needed, or when a client
  first connects and some requests are still waiting):
      PENDING <id> <description>

  Client -> server (what a human types, via the companion CLI):
      APPROVE <id>
      DENY <id>

  Server -> client (after a decision is made):
      RESOLVED <id> approved
      RESOLVED <id> denied
"""
from __future__ import annotations

import asyncio
import itertools
import logging
from dataclasses import dataclass

from .enforcement import ApprovalBroker, BrokerUnavailableError

logger = logging.getLogger("provproxy.broker")

DEFAULT_PORT = 8765


@dataclass
class _PendingRequest:
    request_id: int
    description: str
    future: asyncio.Future


class LocalSocketApprovalBroker(ApprovalBroker):
    """Implements the `ApprovalBroker` interface from enforcement.py by
    running a small local TCP server. `relay.py` calls
    `request_approval()`; any connected companion-CLI client sees the
    request appear on screen and can approve/deny it."""

    def __init__(self, host: str = "127.0.0.1", port: int = DEFAULT_PORT):
        self.host = host
        self.port = port
        self._id_counter = itertools.count(1)
        self._pending: dict[int, _PendingRequest] = {}
        self._clients: set[asyncio.StreamWriter] = set()
        self._server: asyncio.base_events.Server | None = None

    async def start(self) -> None:
        """Actually open the socket and start listening. Called once,
        when the relay starts up."""
        self._server = await asyncio.start_server(self._handle_client, self.host, self.port)
        logger.info("approval broker listening on %s:%s", self.host, self.port)

    def actual_port(self) -> int:
        """Useful when port=0 was requested (OS picks a free port) — e.g.
        in tests, so we can find out which port we actually got."""
        assert self._server is not None
        return self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        for req in list(self._pending.values()):
            if not req.future.done():
                req.future.cancel()

    # --- ApprovalBroker interface (called from enforcement.py) ---------

    async def request_approval(self, description: str) -> asyncio.Future:
        if self._server is None:
            # Broker was never started, or has already been stopped.
            # enforcement.py treats this the same as "can't reach a human"
            # and fails closed (BLOCK) — see enforcement.resolve_ask_user.
            raise BrokerUnavailableError()

        request_id = next(self._id_counter)
        future: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending[request_id] = _PendingRequest(request_id, description, future)

        # Once the future resolves (approved/denied/timed out/cancelled),
        # stop tracking it — no need to keep replaying it to new clients.
        future.add_done_callback(lambda _f: self._pending.pop(request_id, None))

        await self._broadcast(f"PENDING {request_id} {description}")
        return future

    # --- internal plumbing ----------------------------------------------

    async def _broadcast(self, line: str) -> None:
        dead = []
        for writer in self._clients:
            try:
                writer.write((line + "\n").encode("utf-8"))
                await writer.drain()
            except (ConnectionError, OSError):
                dead.append(writer)
        for w in dead:
            self._clients.discard(w)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._clients.add(writer)
        # Catch a newly-connected client up on anything already waiting.
        for req in list(self._pending.values()):
            writer.write(f"PENDING {req.request_id} {req.description}\n".encode("utf-8"))
        try:
            await writer.drain()
        except (ConnectionError, OSError):
            self._clients.discard(writer)
            return

        try:
            while True:
                line_bytes = await reader.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode("utf-8", errors="replace").strip()
                await self._handle_command(line)
        except (ConnectionError, OSError):
            pass
        finally:
            self._clients.discard(writer)
            writer.close()

    async def _handle_command(self, line: str) -> None:
        parts = line.split(maxsplit=1)
        if len(parts) != 2 or parts[0].upper() not in ("APPROVE", "DENY"):
            return
        action, id_str = parts
        try:
            request_id = int(id_str.strip())
        except ValueError:
            return

        req = self._pending.get(request_id)
        if req is None or req.future.done():
            return  # already resolved, expired, or unknown id — ignore

        approved = action.upper() == "APPROVE"
        req.future.set_result(approved)
        await self._broadcast(f"RESOLVED {request_id} {'approved' if approved else 'denied'}")
