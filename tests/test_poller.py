"""Tests for the Poller module (with mocked MCP client)."""

from __future__ import annotations

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from ai_scraper.config import PollerConfig
from ai_scraper.poller.models import RawBurpRecord, CursorMode, PollerState
from ai_scraper.poller.poller import BurpPoller


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_raw(**overrides) -> RawBurpRecord:
    defaults = {
        "id": 1, "host": "api.example.com", "port": 443, "protocol": "https",
        "method": "GET", "path": "/test", "query": "",
        "request_headers": "Host: api.example.com\r\n",
        "request_body": None, "response_status": 200,
        "response_headers": "Content-Type: application/json\r\n",
        "response_body": '{"ok":true}', "timestamp": "2026-07-18T10:00:00Z",
    }
    defaults.update(overrides)
    return RawBurpRecord(**defaults)


class FakeMcpClient:
    """Fake MCP client that returns pre-configured data."""

    def __init__(self, tool_responses: dict | None = None):
        self.tool_responses = tool_responses or {}
        self.connected = False
        self.calls: list[tuple[str, dict]] = []

    async def connect(self):
        self.connected = True

    async def disconnect(self):
        self.connected = False

    async def call_tool(self, tool_name: str, arguments: dict | None = None):
        self.calls.append((tool_name, arguments or {}))
        return self.tool_responses.get(tool_name, [])


# ── Tests ────────────────────────────────────────────────────────────────────

class TestPollerCursor:
    """Tests for cursor management and incremental polling."""

    def test_initial_state(self):
        config = PollerConfig(cursor_mode="by_id")
        poller = BurpPoller(config=config)
        state = poller.get_state()
        assert state.mode == CursorMode.BY_ID
        assert state.last_seen_id is None
        assert state.total_polled == 0

    def test_reset_cursor(self):
        config = PollerConfig(cursor_mode="by_id")
        poller = BurpPoller(config=config)
        # Simulate some polling
        poller._state.last_seen_id = 42
        poller._state.total_polled = 100
        poller.reset_cursor()
        state = poller.get_state()
        assert state.last_seen_id is None
        assert state.total_polled == 0

    @pytest.mark.asyncio
    async def test_poll_once_with_mock_client(self):
        """poll_once should fetch records and update cursor."""
        raw1 = _make_raw(id=10, host="a.com", path="/a")
        raw2 = _make_raw(id=20, host="b.com", path="/b")

        fake = FakeMcpClient(tool_responses={
            "getProxyHistory": [raw1.model_dump(), raw2.model_dump()],
        })

        config = PollerConfig(cursor_mode="by_id", proxy_history_tool="getProxyHistory")
        poller = BurpPoller(config=config, mcp_client=fake)

        records = await poller.poll_once()

        assert len(records) == 2
        assert records[0].id == 10
        assert records[1].id == 20

        state = poller.get_state()
        assert state.last_seen_id == 20  # max id
        assert state.total_polled == 2

        # The MCP client should have been called with after_id=None (first poll)
        assert len(fake.calls) == 1
        assert fake.calls[0][0] == "getProxyHistory"
        assert fake.calls[0][1].get("after_id") is None

    @pytest.mark.asyncio
    async def test_cursor_by_id_incremental(self):
        """Second poll should pass after_id from the first poll's max id."""
        raw = _make_raw(id=50, host="c.com", path="/c")

        fake = FakeMcpClient(tool_responses={
            "getProxyHistory": [raw.model_dump()],
        })

        config = PollerConfig(cursor_mode="by_id", proxy_history_tool="getProxyHistory")
        poller = BurpPoller(config=config, mcp_client=fake)

        # First poll
        await poller.poll_once()
        # Second poll
        await poller.poll_once()

        # Second call should include after_id=50
        assert fake.calls[1][1].get("after_id") == 50

    @pytest.mark.asyncio
    async def test_client_side_cursor_filter(self):
        """Even if MCP returns already-seen records, client-side filter removes them."""
        raw1 = _make_raw(id=10)
        raw2 = _make_raw(id=20)
        raw3 = _make_raw(id=30)

        fake = FakeMcpClient(tool_responses={
            "getProxyHistory": [raw1.model_dump(), raw2.model_dump(), raw3.model_dump()],
        })

        config = PollerConfig(cursor_mode="by_id", proxy_history_tool="getProxyHistory")
        poller = BurpPoller(config=config, mcp_client=fake)

        # First poll: all 3 are new
        records1 = await poller.poll_once()
        assert len(records1) == 3

        # Reset client responses (MCP hypothetically returns same data again)
        fake.tool_responses = {
            "getProxyHistory": [raw1.model_dump(), raw2.model_dump(), raw3.model_dump()],
        }
        fake.calls = []

        # Second poll: client-side filter should remove all (id <= last_seen_id 30)
        records2 = await poller.poll_once()
        assert len(records2) == 0


class TestPollerUrlFiltering:
    """Tests for URL regex filters."""

    @pytest.mark.asyncio
    async def test_include_filter(self):
        raw1 = _make_raw(id=1, host="include.com", path="/api/test")
        raw2 = _make_raw(id=2, host="exclude.com", path="/api/test")

        fake = FakeMcpClient(tool_responses={
            "getProxyHistory": [raw1.model_dump(), raw2.model_dump()],
        })

        config = PollerConfig(
            cursor_mode="by_id",
            include_url_patterns=[r"include\.com"],
            proxy_history_tool="getProxyHistory",
        )
        poller = BurpPoller(config=config, mcp_client=fake)
        records = await poller.poll_once()

        assert len(records) == 1
        assert records[0].host == "include.com"

    @pytest.mark.asyncio
    async def test_exclude_filter(self):
        raw1 = _make_raw(id=1, host="keep.com", path="/api/test")
        raw2 = _make_raw(id=2, host="drop.com", path="/api/test")

        fake = FakeMcpClient(tool_responses={
            "getProxyHistory": [raw1.model_dump(), raw2.model_dump()],
        })

        config = PollerConfig(
            cursor_mode="by_id",
            exclude_url_patterns=[r"drop\.com"],
            proxy_history_tool="getProxyHistory",
        )
        poller = BurpPoller(config=config, mcp_client=fake)
        records = await poller.poll_once()

        assert len(records) == 1
        assert records[0].host == "keep.com"

    @pytest.mark.asyncio
    async def test_include_and_exclude(self):
        """include takes precedence, then exclude removes."""
        raw = _make_raw(id=1, host="target.com", path="/admin/secret")

        fake = FakeMcpClient(tool_responses={
            "getProxyHistory": [raw.model_dump()],
        })

        config = PollerConfig(
            cursor_mode="by_id",
            include_url_patterns=[r"target\.com"],
            exclude_url_patterns=[r"/admin/"],
            proxy_history_tool="getProxyHistory",
        )
        poller = BurpPoller(config=config, mcp_client=fake)
        records = await poller.poll_once()

        assert len(records) == 0  # included by host but excluded by path


class TestPollerAuthorizedScope:
    """Tests for authorized_scope whitelist validation."""

    @pytest.mark.asyncio
    async def test_authorized_host_passes(self):
        raw = _make_raw(id=1, host="api.example.com")

        fake = FakeMcpClient(tool_responses={
            "getProxyHistory": [raw.model_dump()],
        })

        config = PollerConfig(
            cursor_mode="by_id",
            authorized_scope=["*.example.com"],
            proxy_history_tool="getProxyHistory",
        )
        poller = BurpPoller(config=config, mcp_client=fake)
        records = await poller.poll_once()

        assert len(records) == 1

    @pytest.mark.asyncio
    async def test_unauthorized_host_dropped(self):
        raw = _make_raw(id=1, host="evil.com")

        fake = FakeMcpClient(tool_responses={
            "getProxyHistory": [raw.model_dump()],
        })

        config = PollerConfig(
            cursor_mode="by_id",
            authorized_scope=["*.example.com"],
            proxy_history_tool="getProxyHistory",
        )
        poller = BurpPoller(config=config, mcp_client=fake)
        records = await poller.poll_once()

        assert len(records) == 0

    @pytest.mark.asyncio
    async def test_empty_scope_allows_all(self):
        raw = _make_raw(id=1, host="random.com")

        fake = FakeMcpClient(tool_responses={
            "getProxyHistory": [raw.model_dump()],
        })

        config = PollerConfig(
            cursor_mode="by_id",
            authorized_scope=[],  # empty = allow all
            proxy_history_tool="getProxyHistory",
        )
        poller = BurpPoller(config=config, mcp_client=fake)
        records = await poller.poll_once()

        assert len(records) == 1


class TestPollerCallbacks:
    """Tests for the callback mechanism."""

    @pytest.mark.asyncio
    async def test_callback_invoked_on_new_records(self):
        raw = _make_raw(id=1)

        fake = FakeMcpClient(tool_responses={
            "getProxyHistory": [raw.model_dump()],
        })

        received = []

        async def my_callback(records):
            received.extend(records)

        config = PollerConfig(cursor_mode="by_id", proxy_history_tool="getProxyHistory")
        poller = BurpPoller(config=config, mcp_client=fake)
        poller.on_new_records(my_callback)

        await poller.poll_once()

        assert len(received) == 1
        assert received[0].id == 1


class TestPollerParseRecords:
    """Tests for the _parse_records method."""

    def test_parse_list(self):
        config = PollerConfig()
        poller = BurpPoller(config=config)
        data = [_make_raw(id=1).model_dump(), _make_raw(id=2).model_dump()]
        records = poller._parse_records(data)
        assert len(records) == 2

    def test_parse_dict_with_items_key(self):
        config = PollerConfig()
        poller = BurpPoller(config=config)
        data = {"items": [_make_raw(id=1).model_dump()]}
        records = poller._parse_records(data)
        assert len(records) == 1

    def test_parse_dict_with_entries_key(self):
        config = PollerConfig()
        poller = BurpPoller(config=config)
        data = {"entries": [_make_raw(id=1).model_dump()]}
        records = poller._parse_records(data)
        assert len(records) == 1

    def test_parse_single_record_dict(self):
        config = PollerConfig()
        poller = BurpPoller(config=config)
        data = _make_raw(id=1).model_dump()
        records = poller._parse_records(data)
        assert len(records) == 1

    def test_parse_none(self):
        config = PollerConfig()
        poller = BurpPoller(config=config)
        records = poller._parse_records(None)
        assert records == []

    def test_parse_empty_list(self):
        config = PollerConfig()
        poller = BurpPoller(config=config)
        records = poller._parse_records([])
        assert records == []
