"""Shared test fixtures and helpers."""

from __future__ import annotations

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

from ai_scraper.config import AppConfig, ApiConfig, set_config
from ai_scraper.poller.models import RawBurpRecord, CursorMode, PollerState
from ai_scraper.normalizer.models import TrafficRecord
from burp_mcp_client import McpSseClient


# ── Config isolation ──────────────────────────────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def _pin_test_config():
    """Override the global AppConfig before any test runs.

    Without this, tests would silently pick up whatever .env is sitting on
    the developer's disk — meaning test behaviour changes depending on who
    is running them and what their local environment looks like.

    The api_key is set to a known value so the auth path is exercised in
    API tests rather than bypassed when api_key=None.
    """
    set_config(AppConfig(
        api=ApiConfig(api_key="test-api-key"),
    ))


# ── Sample raw Burp records ──────────────────────────────────────────────────

@pytest.fixture
def sample_raw_record() -> RawBurpRecord:
    return RawBurpRecord(
        id=1,
        host="api.example.com",
        port=443,
        protocol="https",
        method="GET",
        path="/users/123/orders",
        query="status=active&limit=10",
        request_headers="Host: api.example.com\r\nAuthorization: Bearer eyJxxx\r\nContent-Type: application/json\r\n",
        request_body=None,
        response_status=200,
        response_headers="Content-Type: application/json\r\nContent-Length: 42\r\n",
        response_body='{"orders": [{"id": 1, "total": 99}]}',
        timestamp="2026-07-18T10:00:00Z",
    )


@pytest.fixture
def sample_raw_records() -> list[RawBurpRecord]:
    return [
        RawBurpRecord(
            id=i,
            host="api.example.com",
            port=443,
            protocol="https",
            method="GET",
            path=f"/users/{i}/profile",
            query="",
            request_headers=f"Host: api.example.com\r\nCookie: session=abc{i}\r\n",
            request_body=None,
            response_status=200 if i % 2 == 0 else 404,
            response_headers="Content-Type: application/json\r\n",
            response_body='{"user": {"id": ' + str(i) + '}}',
            timestamp=f"2026-07-18T10:00:{i:02d}Z",
        )
        for i in range(1, 11)
    ]


@pytest.fixture
def sample_raw_record_with_url_param() -> RawBurpRecord:
    return RawBurpRecord(
        id=100,
        host="webhook.example.com",
        port=443,
        protocol="https",
        method="POST",
        path="/api/callback",
        query="url=https://evil.com&redirect=https://target.com",
        request_headers="Host: webhook.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nCookie: sess=123\r\n",
        request_body="webhook=https://attacker.net/hook",
        response_status=302,
        response_headers="Location: https://safe.com\r\n",
        response_body="",
        timestamp="2026-07-18T11:00:00Z",
    )


@pytest.fixture
def sample_raw_record_multipart() -> RawBurpRecord:
    return RawBurpRecord(
        id=200,
        host="upload.example.com",
        port=443,
        protocol="https",
        method="POST",
        path="/api/upload",
        query="",
        request_headers="Host: upload.example.com\r\nContent-Type: multipart/form-data; boundary=xxx\r\nAuthorization: Bearer token\r\n",
        request_body="--xxx\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\n...\r\n--xxx--",
        response_status=201,
        response_headers="Content-Type: application/json\r\n",
        response_body='{"ok": true}',
        timestamp="2026-07-18T12:00:00Z",
    )


# ── Sample TrafficRecords ────────────────────────────────────────────────────

@pytest.fixture
def sample_traffic_record(sample_raw_record) -> TrafficRecord:
    from ai_scraper.normalizer.normalizer import Normalizer
    return Normalizer().normalize(sample_raw_record)


@pytest.fixture
def sample_traffic_records(sample_raw_records) -> list[TrafficRecord]:
    from ai_scraper.normalizer.normalizer import Normalizer
    return Normalizer().normalize_batch(sample_raw_records)


# ── Mock MCP Client ──────────────────────────────────────────────────────────

class FakeMcpClient:
    """Fake MCP SSE client that returns pre-configured tool responses."""

    def __init__(self, responses: dict | None = None, base_url: str = "", timeout: float = 30):
        self.base_url = base_url
        self.timeout = timeout
        self.connected = False
        self._responses = responses or {}
        self._call_log: list[tuple[str, dict]] = []

    async def connect(self) -> None:
        self.connected = True

    async def disconnect(self) -> None:
        self.connected = False

    async def call_tool(self, tool_name: str, arguments: dict | None = None) -> list[dict]:
        self._call_log.append((tool_name, arguments or {}))
        key = (tool_name, arguments.get("after_id") if arguments else None)
        if tool_name in self._responses:
            return self._responses[tool_name]
        # Default: return empty list
        return []

    async def list_tools(self) -> list[dict]:
        return [{"name": "getProxyHistory", "description": "Get proxy history"}]


@pytest.fixture
def fake_mcp_client() -> FakeMcpClient:
    return FakeMcpClient()


@pytest.fixture
def fake_mcp_client_with_data(sample_raw_record) -> FakeMcpClient:
    return FakeMcpClient(responses={
        "getProxyHistory": [sample_raw_record.model_dump()],
    })
