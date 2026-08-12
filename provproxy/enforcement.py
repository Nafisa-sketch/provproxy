"""Enforcement Action (Section 5D) — resolves a provenance match into a
final decision.

`ask_user` is only meaningfully fail-closed if its failure modes are also
closed: an approval timeout or an unreachable broker resolves to BLOCK,
never a silent pass-through ALLOW. The pending state is not a third
outcome — it either becomes ALLOW via an explicit approval, or it degrades
to BLOCK.
"""
from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from enum import Enum

logger = logging.getLogger("provproxy.enforcement")


class Decision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"


class ApprovalBroker(ABC):
    """Abstraction over "ask a human." A real implementation wires this to
    an IPC broker (Unix socket + companion CLI); this interface lets the
    resolution logic below be tested without one."""

    @abstractmethod
    async def request_approval(self, description: str) -> asyncio.Future:
        """Returns a future that resolves to True (approved) or False
        (explicitly denied). Raises BrokerUnavailableError if the broker
        itself can't be reached."""
        ...


class BrokerUnavailableError(Exception):
    pass


async def resolve_ask_user(
    broker: ApprovalBroker, description: str, timeout_seconds: float
) -> Decision:
    """Resolve an `ask_user` enforcement action against a broker, honoring
    the configured timeout. This is the single place the fail-closed
    guarantee is enforced — every caller goes through here rather than
    hand-rolling their own timeout handling."""
    try:
        future = await broker.request_approval(description)
    except BrokerUnavailableError:
        logger.warning("approval broker unreachable — resolving to BLOCK (fail-closed)")
        return Decision.BLOCK

    try:
        approved = await asyncio.wait_for(future, timeout=timeout_seconds)
    except asyncio.TimeoutError:
        logger.warning("approval timed out after %ss — resolving to BLOCK (fail-closed)", timeout_seconds)
        return Decision.BLOCK
    except (asyncio.CancelledError, Exception):
        logger.warning("approval channel closed without a response — resolving to BLOCK")
        return Decision.BLOCK

    return Decision.ALLOW if approved else Decision.BLOCK
