import asyncio

import pytest

from provproxy.broker import LocalSocketApprovalBroker
from provproxy.enforcement import BrokerUnavailableError


@pytest.mark.asyncio
async def test_broker_raises_if_not_started():
    broker = LocalSocketApprovalBroker(port=0)
    with pytest.raises(BrokerUnavailableError):
        await broker.request_approval("test request")


@pytest.mark.asyncio
async def test_full_approve_flow_over_real_socket():
    # port=0 asks the OS for any free port — avoids clashing with a real
    # ProvProxy instance (or another test run) using the default port.
    broker = LocalSocketApprovalBroker(host="127.0.0.1", port=0)
    await broker.start()
    try:
        port = broker.actual_port()

        # Simulate the companion CLI: a plain asyncio client connection.
        client_reader, client_writer = await asyncio.open_connection("127.0.0.1", port)

        # Ask for approval (this is what enforcement.py/relay.py do).
        future = await broker.request_approval("tool=read_file fragment=frag-1")

        # The "companion CLI" should see the PENDING line appear.
        line = await asyncio.wait_for(client_reader.readline(), timeout=2)
        assert line.decode().startswith("PENDING 1 tool=read_file")

        # Human types "approve 1" in the companion CLI.
        client_writer.write(b"APPROVE 1\n")
        await client_writer.drain()

        # The broker resolves the future...
        approved = await asyncio.wait_for(future, timeout=2)
        assert approved is True

        # ...and confirms it back to the client.
        resolved_line = await asyncio.wait_for(client_reader.readline(), timeout=2)
        assert resolved_line.decode().strip() == "RESOLVED 1 approved"

        client_writer.close()
    finally:
        await broker.stop()


@pytest.mark.asyncio
async def test_deny_resolves_future_to_false():
    broker = LocalSocketApprovalBroker(host="127.0.0.1", port=0)
    await broker.start()
    try:
        port = broker.actual_port()
        client_reader, client_writer = await asyncio.open_connection("127.0.0.1", port)

        future = await broker.request_approval("some sensitive call")
        await asyncio.wait_for(client_reader.readline(), timeout=2)  # PENDING line

        client_writer.write(b"DENY 1\n")
        await client_writer.drain()

        approved = await asyncio.wait_for(future, timeout=2)
        assert approved is False

        client_writer.close()
    finally:
        await broker.stop()


@pytest.mark.asyncio
async def test_unknown_request_id_is_ignored_not_crash():
    broker = LocalSocketApprovalBroker(host="127.0.0.1", port=0)
    await broker.start()
    try:
        port = broker.actual_port()
        _reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"APPROVE 999\n")  # nothing pending with this id
        await writer.drain()
        await asyncio.sleep(0.1)  # give the server a moment; should not raise
        writer.close()
    finally:
        await broker.stop()


@pytest.mark.asyncio
async def test_late_connecting_client_sees_still_pending_requests():
    broker = LocalSocketApprovalBroker(host="127.0.0.1", port=0)
    await broker.start()
    try:
        port = broker.actual_port()
        await broker.request_approval("a call nobody has answered yet")

        # Client connects AFTER the request was already made.
        client_reader, client_writer = await asyncio.open_connection("127.0.0.1", port)
        line = await asyncio.wait_for(client_reader.readline(), timeout=2)
        assert line.decode().startswith("PENDING 1")
        client_writer.close()
    finally:
        await broker.stop()
