"""Tests for burp_mcp_client SSE parsing and dispatch logic."""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock

import pytest
from burp_mcp_client.client import McpSseClient, _parse_sse_event


class TestParseSseEvent:
    """Unit tests for _parse_sse_event — line-ending agnostic parsing."""

    def test_crlf_terminated_endpoint_event(self):
        """Burp's real format: lines separated by \r\n, event ends with \r\n\r\n.

        After line-ending normalization, event_raw arrives with \n only.
        """
        event_raw = "event: endpoint\ndata: /message?sessionId=abc-123\n"
        event_type, data, _ = _parse_sse_event(event_raw)
        assert event_type == "endpoint"
        assert data == "/message?sessionId=abc-123"

    def test_crlf_terminated_message_event(self):
        event_raw = "event: message\ndata: {\"id\":1,\"result\":{}}\n"
        event_type, data, _ = _parse_sse_event(event_raw)
        assert event_type == "message"
        assert "id" in data

    def test_multiline_data(self):
        event_raw = "event: message\ndata: line1\ndata: line2\n"
        event_type, data, _ = _parse_sse_event(event_raw)
        assert event_type == "message"
        assert data == "line1\nline2"

    def test_default_event_type(self):
        """No 'event:' field → defaults to 'message'."""
        event_raw = "data: payload\n"
        event_type, data, _ = _parse_sse_event(event_raw)
        assert event_type == "message"
        assert data == "payload"


class TestSseBuffering:
    """Integration tests for McpSseClient's SSE buffering and dispatch.

    Mocks the stream to feed controlled chunks into _read_sse's buffer
    and verify correct event dispatch regardless of chunk boundaries.
    """

    @staticmethod
    def _make_client(timeout: float = 5.0) -> McpSseClient:
        c = McpSseClient(base_url="http://127.0.0.1:9876", timeout=timeout)
        # Replace the httpx client with a bare object so we can assign
        # `stream` without MagicMock intercepting the call.
        c._http = type("FakeHttp", (), {"aclose": AsyncMock()})()
        return c

    async def _feed_chunks(self, client: McpSseClient, chunks: list[str]) -> None:
        """Run _read_sse as a background task, wait for dispatch, then stop.

        _read_sse has a reconnect loop — calling it directly would block
        forever when the fake stream ends.  We run it as a task and cancel
        after the endpoint event arrives.
        """

        class FakeResponse:
            status_code = 200

            def raise_for_status(self):
                pass

            async def aiter_text(self):
                for c in chunks:
                    yield c

        @asynccontextmanager
        async def fake_stream(*args, **kwargs):
            yield FakeResponse()

        client._http.stream = fake_stream
        client._running = True

        task = asyncio.create_task(
            client._read_sse("http://127.0.0.1:9876/sse")
        )

        deadline = time.monotonic() + 3.0
        while client._message_url is None:
            if time.monotonic() > deadline:
                raise TimeoutError("Event was not dispatched within 3s")
            await asyncio.sleep(0.01)

        client._running = False
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    @pytest.mark.asyncio
    async def test_crlf_terminated_events_dispatched(self):
        """A complete endpoint event with \r\n\r\n should be dispatched.

        This is the exact format Burp's MCP Server produces.
        """
        client = self._make_client()
        chunk = "event: endpoint\r\ndata: /msg?sid=abc\r\n\r\n"
        await self._feed_chunks(client, [chunk])

        assert client._message_url == "http://127.0.0.1:9876/msg?sid=abc"

    @pytest.mark.asyncio
    async def test_event_split_across_chunks(self):
        """Terminator \r\n\r\n split across two chunks should still work.

        chunk1 ends mid-terminator: "...ex\r"  (after normalization: "...ex\n")
        chunk2 starts with: "\n\r\n"           (after normalization: "\n\n")
        Combined: "...ex\n\n" → correctly triggers split.
        """
        client = self._make_client()
        chunks = [
            "event: endpoint\r\ndata: /msg?sid=abc\r",
            "\n\r\n",
        ]
        await self._feed_chunks(client, chunks)

        assert client._message_url == "http://127.0.0.1:9876/msg?sid=abc"

    @pytest.mark.asyncio
    async def test_event_split_mid_data(self):
        """A clean \n-split in the middle of a data field, completed by \r\n\r\n."""
        client = self._make_client()
        chunks = [
            "event: endpoint\ndata: /msg?sid=",
            "abc\r\n\r\nnext",
        ]
        await self._feed_chunks(client, chunks)

        assert client._message_url == "http://127.0.0.1:9876/msg?sid=abc"

    @pytest.mark.asyncio
    async def test_bare_cr_boundaries(self):
        """SSE spec allows bare \r line endings and \r\r boundaries."""
        client = self._make_client()
        chunk = "event: endpoint\rdata: /msg?sid=xyz\r\r"
        await self._feed_chunks(client, [chunk])

        assert client._message_url == "http://127.0.0.1:9876/msg?sid=xyz"

    @pytest.mark.asyncio
    async def test_mixed_line_endings(self):
        """A chunk mixing \r\n and \n in the same event."""
        client = self._make_client()
        chunk = "event: endpoint\ndata: /msg?sid=mixed\r\n\r\n"
        await self._feed_chunks(client, [chunk])

        assert client._message_url == "http://127.0.0.1:9876/msg?sid=mixed"


class TestSseReconnect:
    """Reconnection and timeout tests for McpSseClient."""

    @staticmethod
    def _make_client(timeout: float = 5.0) -> McpSseClient:
        c = McpSseClient(base_url="http://127.0.0.1:9876", timeout=timeout)
        c._http = type("FakeHttp", (), {"aclose": AsyncMock()})()
        return c

    @pytest.mark.asyncio
    async def test_stream_timeout_override_has_read_none(self):
        """The SSE stream must be opened with read=None to prevent idle timeouts.

        The client-wide timeout (e.g. 30s) should only apply to short RPC
        POST calls, not the long-lived SSE GET stream.
        """
        import httpx

        client = self._make_client(timeout=1.0)
        stream_kwargs: dict = {}

        class FakeResponse:
            status_code = 200

            def raise_for_status(self):
                pass

            async def aiter_text(self):
                yield "event: endpoint\r\ndata: /m\r\n\r\n"
                client._running = False  # exit reconnect loop after one event
                return

        @asynccontextmanager
        async def fake_stream(*args, **kwargs):
            stream_kwargs.update(kwargs)
            yield FakeResponse()

        client._http.stream = fake_stream
        client._running = True
        try:
            await client._read_sse("http://127.0.0.1:9876/sse")
        except asyncio.CancelledError:
            pass

        timeout = stream_kwargs.get("timeout")
        assert timeout is not None, "stream() was called without a timeout kwarg"
        assert timeout.read is None, (
            f"Expected read=None on SSE stream timeout, got read={timeout.read}"
        )

    @pytest.mark.asyncio
    async def test_reconnect_after_stream_drop(self):
        """After the SSE stream drops, _read_sse should reconnect and
        fetch a new sessionId."""
        client = self._make_client(timeout=1.0)
        connect_count = 0

        class FakeResponse:
            status_code = 200

            def raise_for_status(self):
                pass

            async def aiter_text(self):
                nonlocal connect_count
                connect_count += 1
                if connect_count == 1:
                    yield "event: endpoint\r\ndata: /session1\r\n\r\n"
                    raise ConnectionError("simulated drop")
                else:
                    # Second connection delivers a new endpoint, then
                    # stops the loop so the test can finish.
                    yield "event: endpoint\r\ndata: /session2\r\n\r\n"
                    # Set _running False after yield so the reconnect
                    # loop exits cleanly instead of looping forever.
                    client._running = False
                    return

        @asynccontextmanager
        async def fake_stream(*args, **kwargs):
            yield FakeResponse()

        client._http.stream = fake_stream
        client._running = True

        await client._read_sse("http://127.0.0.1:9876/sse")

        assert connect_count == 2, f"Expected 2 connections, got {connect_count}"
        assert client._message_url == "http://127.0.0.1:9876/session2"

    @pytest.mark.asyncio
    async def test_stream_survives_idle_longer_than_client_timeout(self):
        """With read=None, long idle periods between SSE events must not
        trigger a read timeout — only the short RPC POST calls are affected
        by the client-wide timeout.

        The stream delivers one event, then goes completely silent for longer
        than the client timeout, then delivers another event.  If read=None
        is working, this second event arrives on the *same* connection.  If
        read were set to the client timeout, httpx would kill the stream
        during the idle gap and the reconnect loop (connect_count > 1) would
        be the only path to seeing the second event.
        """
        import httpx

        client_timeout = 0.3
        idle_duration = 1.2  # 4× client_timeout
        client = self._make_client(timeout=client_timeout)
        stream_kwargs: dict = {}
        connect_count = 0

        class FakeResponse:
            status_code = 200

            def raise_for_status(self):
                pass

            async def aiter_text(self):
                nonlocal connect_count
                connect_count += 1
                # First endpoint event
                yield "event: endpoint\r\ndata: /ep1\r\n\r\n"

                # Idle period — must NOT trigger a read timeout
                await asyncio.sleep(idle_duration)

                # Second endpoint event — proves stream survived
                yield "event: endpoint\r\ndata: /ep2\r\n\r\n"
                client._running = False

        @asynccontextmanager
        async def fake_stream(*args, **kwargs):
            stream_kwargs.update(kwargs)
            yield FakeResponse()

        client._http.stream = fake_stream
        client._running = True

        await client._read_sse("http://127.0.0.1:9876/sse")

        # Core assertions
        timeout = stream_kwargs.get("timeout")
        assert timeout is not None, "stream() was called without a timeout kwarg"
        assert timeout.read is None, (
            f"Expected read=None, got read={timeout.read}"
        )

        assert connect_count == 1, (
            f"Stream dropped and reconnected {connect_count} times — "
            "read=None may not be working"
        )
        assert client._message_url == "http://127.0.0.1:9876/ep2", (
            "Second endpoint event was not dispatched — stream likely timed out"
        )
