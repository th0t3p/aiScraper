"""Tests for the Poller module (with mocked MCP client)."""

from __future__ import annotations

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from ai_scraper.config import PollerConfig
from ai_scraper.poller.models import RawBurpRecord, PollerState
from ai_scraper.poller.poller import BurpPoller


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_raw_request(host: str = "api.example.com", path: str = "/test") -> str:
    return f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n"


def _make_raw(**overrides) -> RawBurpRecord:
    request = overrides.pop("_request", _make_raw_request())
    defaults = {"request": request, "response": None, "notes": ""}
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
    """Tests for cursor management and offset-based polling."""

    def test_initial_state(self):
        config = PollerConfig()
        poller = BurpPoller(config=config)
        state = poller.get_state()
        assert state.consumed_count == 0
        assert state.total_polled == 0
        assert state.last_poll_at is None

    def test_reset_cursor(self):
        config = PollerConfig()
        poller = BurpPoller(config=config)
        poller._state.consumed_count = 42
        poller._state.total_polled = 100
        poller.reset_cursor()
        state = poller.get_state()
        assert state.consumed_count == 0
        assert state.total_polled == 0

    @pytest.mark.asyncio
    async def test_poll_once_with_mock_client(self):
        """poll_once should fetch records and advance consumed_count."""
        raw1 = _make_raw(_request=_make_raw_request(host="a.com", path="/a"))
        raw2 = _make_raw(_request=_make_raw_request(host="b.com", path="/b"))

        fake = FakeMcpClient(tool_responses={
            "get_proxy_http_history": [raw1.model_dump(), raw2.model_dump()],
        })

        config = PollerConfig(
            proxy_history_tool="get_proxy_http_history",
            allow_unscoped=True,
        )
        poller = BurpPoller(config=config, mcp_client=fake)

        records = await poller.poll_once()

        assert len(records) == 2
        state = poller.get_state()
        assert state.consumed_count == 2
        assert state.total_polled == 2
        assert state.last_poll_at is not None

        # First call should use offset=0
        assert len(fake.calls) == 1
        assert fake.calls[0][0] == "get_proxy_http_history"
        assert fake.calls[0][1] == {"count": 50, "offset": 0}

    @pytest.mark.asyncio
    async def test_cursor_offset_incremental(self):
        """Second poll should pass offset from the first poll's count."""
        raw = _make_raw(_request=_make_raw_request(host="c.com", path="/c"))

        fake = FakeMcpClient(tool_responses={
            "get_proxy_http_history": [raw.model_dump()],
        })

        config = PollerConfig(
            proxy_history_tool="get_proxy_http_history",
            allow_unscoped=True,
            batch_size=10,
        )
        poller = BurpPoller(config=config, mcp_client=fake)

        # First poll
        await poller.poll_once()
        # Second poll
        await poller.poll_once()

        # Second call should include offset=1
        assert fake.calls[1][1] == {"count": 10, "offset": 1}

    @pytest.mark.asyncio
    async def test_empty_batch_sets_last_poll_at(self):
        """A poll returning zero records should still set last_poll_at
        (healthy connection) and not crash."""
        fake = FakeMcpClient(tool_responses={
            "get_proxy_http_history": [],
        })

        config = PollerConfig(
            proxy_history_tool="get_proxy_http_history",
            allow_unscoped=True,
        )
        poller = BurpPoller(config=config, mcp_client=fake)

        records = await poller.poll_once()
        assert records == []
        state = poller.get_state()
        assert state.last_poll_at is not None, (
            "last_poll_at should be set even when poll returns 0 records"
        )

    @pytest.mark.asyncio
    async def test_caught_up_resets_on_zero_at_high_offset(self):
        """If offset > 0 and 0 records are returned, reset consumed_count
        as a recovery measure (history might have been cleared)."""
        raw = _make_raw(_request=_make_raw_request(host="x.com", path="/x"))

        fake = FakeMcpClient(tool_responses={
            "get_proxy_http_history": [raw.model_dump()],
        })

        config = PollerConfig(
            proxy_history_tool="get_proxy_http_history",
            allow_unscoped=True,
        )
        poller = BurpPoller(config=config, mcp_client=fake)

        # First poll: returns 1 record, consumed_count → 1
        await poller.poll_once()
        assert poller.get_state().consumed_count == 1

        # Second poll: returns 0 records at offset=1 → should reset
        fake.tool_responses = {"get_proxy_http_history": []}
        await poller.poll_once()
        assert poller.get_state().consumed_count == 0, (
            "consumed_count should reset to 0 when offset > 0 returns nothing"
        )


class TestPollerUrlFiltering:
    """Tests for URL regex filters operating on raw request text."""

    @pytest.mark.asyncio
    async def test_include_filter(self):
        raw1 = _make_raw(_request=_make_raw_request(host="include.com", path="/api/test"))
        raw2 = _make_raw(_request=_make_raw_request(host="exclude.com", path="/api/test"))

        fake = FakeMcpClient(tool_responses={
            "get_proxy_http_history": [raw1.model_dump(), raw2.model_dump()],
        })

        config = PollerConfig(
            include_url_patterns=[r"include\.com"],
            allow_unscoped=True,
            proxy_history_tool="get_proxy_http_history",
        )
        poller = BurpPoller(config=config, mcp_client=fake)
        records = await poller.poll_once()

        assert len(records) == 1

    @pytest.mark.asyncio
    async def test_exclude_filter(self):
        raw1 = _make_raw(_request=_make_raw_request(host="keep.com", path="/api/test"))
        raw2 = _make_raw(_request=_make_raw_request(host="drop.com", path="/api/test"))

        fake = FakeMcpClient(tool_responses={
            "get_proxy_http_history": [raw1.model_dump(), raw2.model_dump()],
        })

        config = PollerConfig(
            exclude_url_patterns=[r"drop\.com"],
            allow_unscoped=True,
            proxy_history_tool="get_proxy_http_history",
        )
        poller = BurpPoller(config=config, mcp_client=fake)
        records = await poller.poll_once()

        assert len(records) == 1

    @pytest.mark.asyncio
    async def test_include_and_exclude(self):
        """include takes precedence, then exclude removes."""
        raw = _make_raw(_request=_make_raw_request(host="target.com", path="/admin/secret"))

        fake = FakeMcpClient(tool_responses={
            "get_proxy_http_history": [raw.model_dump()],
        })

        config = PollerConfig(
            include_url_patterns=[r"target\.com"],
            exclude_url_patterns=[r"/admin/"],
            allow_unscoped=True,
            proxy_history_tool="get_proxy_http_history",
        )
        poller = BurpPoller(config=config, mcp_client=fake)
        records = await poller.poll_once()

        assert len(records) == 0  # included by host but excluded by path


class TestPollerAuthorizedScope:
    """Tests for authorized_scope whitelist validation."""

    @pytest.mark.asyncio
    async def test_authorized_host_passes(self):
        raw = _make_raw(_request=_make_raw_request(host="api.example.com"))

        fake = FakeMcpClient(tool_responses={
            "get_proxy_http_history": [raw.model_dump()],
        })

        config = PollerConfig(
            authorized_scope=["*.example.com"],
            proxy_history_tool="get_proxy_http_history",
        )
        poller = BurpPoller(config=config, mcp_client=fake)
        records = await poller.poll_once()

        assert len(records) == 1

    @pytest.mark.asyncio
    async def test_unauthorized_host_dropped(self):
        raw = _make_raw(_request=_make_raw_request(host="evil.com"))

        fake = FakeMcpClient(tool_responses={
            "get_proxy_http_history": [raw.model_dump()],
        })

        config = PollerConfig(
            authorized_scope=["*.example.com"],
            proxy_history_tool="get_proxy_http_history",
        )
        poller = BurpPoller(config=config, mcp_client=fake)
        records = await poller.poll_once()

        assert len(records) == 0

    @pytest.mark.asyncio
    async def test_empty_scope_drops_all_by_default(self):
        """Fail-closed: empty scope + allow_unscoped=False → all dropped."""
        raw = _make_raw(_request=_make_raw_request(host="random.com"))

        fake = FakeMcpClient(tool_responses={
            "get_proxy_http_history": [raw.model_dump()],
        })

        config = PollerConfig(
            authorized_scope=[],
            allow_unscoped=False,
            proxy_history_tool="get_proxy_http_history",
        )
        poller = BurpPoller(config=config, mcp_client=fake)
        records = await poller.poll_once()

        assert len(records) == 0

    @pytest.mark.asyncio
    async def test_empty_scope_allow_unscoped_passes_all(self):
        """allow_unscoped=True restores old behavior: empty scope passes all."""
        raw = _make_raw(_request=_make_raw_request(host="random.com"))

        fake = FakeMcpClient(tool_responses={
            "get_proxy_http_history": [raw.model_dump()],
        })

        config = PollerConfig(
            authorized_scope=[],
            allow_unscoped=True,
            proxy_history_tool="get_proxy_http_history",
        )
        poller = BurpPoller(config=config, mcp_client=fake)
        records = await poller.poll_once()

        assert len(records) == 1


class TestPollerCallbacks:
    """Tests for the callback mechanism."""

    @pytest.mark.asyncio
    async def test_callback_invoked_on_new_records(self):
        raw = _make_raw(_request=_make_raw_request(host="x.com", path="/a"))

        fake = FakeMcpClient(tool_responses={
            "get_proxy_http_history": [raw.model_dump()],
        })

        received = []

        async def my_callback(records):
            received.extend(records)

        config = PollerConfig(
            proxy_history_tool="get_proxy_http_history",
            allow_unscoped=True,
        )
        poller = BurpPoller(config=config, mcp_client=fake)
        poller.on_new_records(my_callback)

        await poller.poll_once()

        assert len(received) == 1


class TestPollerParseRecords:
    """Tests for the _parse_records method."""

    def test_parse_list(self):
        config = PollerConfig()
        poller = BurpPoller(config=config)
        data = [
            _make_raw(_request="GET /a HTTP/1.1\r\nHost: a.com\r\n\r\n").model_dump(),
            _make_raw(_request="GET /b HTTP/1.1\r\nHost: b.com\r\n\r\n").model_dump(),
        ]
        records, _ = poller._parse_records(data)
        assert len(records) == 2

    def test_parse_dict_with_items_key(self):
        config = PollerConfig()
        poller = BurpPoller(config=config)
        data = {"items": [_make_raw(_request="GET /a HTTP/1.1\r\nHost: a.com\r\n\r\n").model_dump()]}
        records, _ = poller._parse_records(data)
        assert len(records) == 1

    def test_parse_dict_with_entries_key(self):
        config = PollerConfig()
        poller = BurpPoller(config=config)
        data = {"entries": [_make_raw(_request="GET /a HTTP/1.1\r\nHost: a.com\r\n\r\n").model_dump()]}
        records, _ = poller._parse_records(data)
        assert len(records) == 1

    def test_parse_single_record_dict(self):
        config = PollerConfig()
        poller = BurpPoller(config=config)
        data = _make_raw(_request="GET /a HTTP/1.1\r\nHost: a.com\r\n\r\n").model_dump()
        records, _ = poller._parse_records(data)
        assert len(records) == 1

    def test_parse_none(self):
        config = PollerConfig()
        poller = BurpPoller(config=config)
        records, _ = poller._parse_records(None)
        assert records == []

    def test_parse_empty_list(self):
        config = PollerConfig()
        poller = BurpPoller(config=config)
        records, _ = poller._parse_records([])
        assert records == []

    def test_parse_blank_line_separated_json_string(self):
        """Real Burp MCP tool returns a string of JSON objects separated
        by blank lines (\\n\\n).  _parse_records must handle this."""
        import json as _json

        config = PollerConfig()
        poller = BurpPoller(config=config)

        rec1 = _make_raw(_request="GET /a HTTP/1.1\r\nHost: a.com\r\n\r\n")
        rec2 = _make_raw(_request="GET /b HTTP/1.1\r\nHost: b.com\r\n\r\n")
        raw_str = (
            _json.dumps(rec1.model_dump()) + "\n\n"
            + _json.dumps(rec2.model_dump()) + "\n\n"
        )

        records, _ = poller._parse_records(raw_str)
        assert len(records) == 2

    def test_parse_blank_line_separated_json_with_crlf(self):
        """The blank-line separator should also tolerate \\r\\n\\r\\n."""
        import json as _json

        config = PollerConfig()
        poller = BurpPoller(config=config)

        rec = _make_raw(_request="GET /a HTTP/1.1\r\nHost: a.com\r\n\r\n")
        raw_str = _json.dumps(rec.model_dump()) + "\r\n\r\n"

        records, _ = poller._parse_records(raw_str)
        assert len(records) == 1

    def test_parse_malformed_object_with_embedded_newline(self):
        """A malformed object containing an unescaped newline inside a JSON
        string value (matching a confirmed Burp MCP serialization bug) must
        not corrupt adjacent valid objects — only the malformed one is skipped
        via the ``{"request":`` resynchronization recovery."""
        import json as _json

        config = PollerConfig()
        poller = BurpPoller(config=config)

        rec1 = _make_raw(_request="GET /a HTTP/1.1\r\nHost: a.com\r\n\r\n")
        rec3 = _make_raw(_request="GET /c HTTP/1.1\r\nHost: c.com\r\n\r\n")

        # JSON with a literal unescaped newline inside a string value.
        # \\r\\n → valid JSON escapes (CR+LF); \\n alone → real LF that
        # breaks the JSON string (invalid control character).
        malformed = (
            '{"request": "GET /b HTTP/1.1\\r\\nHost: b.com\\r\\n\\r\\n", '
            '"response": "bogus\nunescaped newline", "notes": ""}'
        )

        raw_str = (
            _json.dumps(rec1.model_dump()) + "\n\n"
            + malformed + "\n\n"
            + _json.dumps(rec3.model_dump()) + "\n\n"
        )

        records, failures = poller._parse_records(raw_str)
        assert len(records) == 2, (
            f"Expected 2 valid records recovered, got {len(records)}"
        )
        assert failures == 1, (
            f"Expected 1 parse failure, got {failures}"
        )


class TestCursorAdvancementWithFilters:
    """Regression: cursor must advance even when url/scope filters drop all records."""

    @pytest.mark.asyncio
    async def test_cursor_advances_when_scope_filters_drop_all(self):
        """Even if authorized_scope drops every record, cursor must still advance."""
        raw1 = _make_raw(_request=_make_raw_request(host="evil.com", path="/a"))
        raw2 = _make_raw(_request=_make_raw_request(host="evil.com", path="/b"))
        raw3 = _make_raw(_request=_make_raw_request(host="evil.com", path="/c"))

        fake = FakeMcpClient(tool_responses={
            "get_proxy_http_history": [raw1.model_dump(), raw2.model_dump(), raw3.model_dump()],
        })

        config = PollerConfig(
            authorized_scope=["*.example.com"],  # none match evil.com
            proxy_history_tool="get_proxy_http_history",
        )
        poller = BurpPoller(config=config, mcp_client=fake)

        records = await poller.poll_once()

        # All 3 records dropped by scope filter
        assert len(records) == 0

        # Cursor must still advance past the count of this batch (3)
        state = poller.get_state()
        assert state.consumed_count == 3, (
            f"Cursor should advance to 3 even though all records were filtered, "
            f"got consumed_count={state.consumed_count}"
        )
        assert state.total_polled == 3

    @pytest.mark.asyncio
    async def test_cursor_advances_when_only_some_pass_filters(self):
        """Cursor advances past all records; only authorized ones are returned."""
        raw1 = _make_raw(_request=_make_raw_request(host="in.example.com", path="/a"))
        raw2 = _make_raw(_request=_make_raw_request(host="out.com", path="/b"))
        raw3 = _make_raw(_request=_make_raw_request(host="in.example.com", path="/c"))

        fake = FakeMcpClient(tool_responses={
            "get_proxy_http_history": [raw1.model_dump(), raw2.model_dump(), raw3.model_dump()],
        })

        config = PollerConfig(
            authorized_scope=["*.example.com"],
            proxy_history_tool="get_proxy_http_history",
        )
        poller = BurpPoller(config=config, mcp_client=fake)

        records = await poller.poll_once()

        # Only records from in.example.com pass scope
        assert len(records) == 2

        # Cursor must advance past all 3 fetched records
        state = poller.get_state()
        assert state.consumed_count == 3
        assert state.total_polled == 3
