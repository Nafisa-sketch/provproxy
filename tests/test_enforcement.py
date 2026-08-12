import asyncio

import pytest

from provproxy.enforcement import ApprovalBroker, BrokerUnavailableError, Decision, resolve_ask_user


class FakeBroker(ApprovalBroker):
    def __init__(self, respond_with: bool | None, unreachable: bool = False, delay: float = 0.0):
        self.respond_with = respond_with
        self.unreachable = unreachable
        self.delay = delay

    async def request_approval(self, description: str) -> asyncio.Future:
        if self.unreachable:
            raise BrokerUnavailableError()

        future: asyncio.Future = asyncio.get_event_loop().create_future()
        if self.respond_with is not None:
            async def _resolve():
                if self.delay:
                    await asyncio.sleep(self.delay)
                if not future.done():
                    future.set_result(self.respond_with)

            asyncio.create_task(_resolve())
        # If respond_with is None, the future is never resolved — this
        # exercises the timeout path.
        return future


@pytest.mark.asyncio
async def test_explicit_approval_allows():
    broker = FakeBroker(respond_with=True)
    decision = await resolve_ask_user(broker, "test", timeout_seconds=1)
    assert decision == Decision.ALLOW


@pytest.mark.asyncio
async def test_explicit_denial_blocks():
    broker = FakeBroker(respond_with=False)
    decision = await resolve_ask_user(broker, "test", timeout_seconds=1)
    assert decision == Decision.BLOCK


@pytest.mark.asyncio
async def test_broker_unreachable_blocks():
    broker = FakeBroker(respond_with=None, unreachable=True)
    decision = await resolve_ask_user(broker, "test", timeout_seconds=1)
    assert decision == Decision.BLOCK


@pytest.mark.asyncio
async def test_timeout_blocks():
    broker = FakeBroker(respond_with=None)
    decision = await resolve_ask_user(broker, "test", timeout_seconds=0.2)
    assert decision == Decision.BLOCK
