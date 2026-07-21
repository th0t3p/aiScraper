"""Shared test fixtures and helpers."""

from __future__ import annotations

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

from ai_scraper.config import AppConfig, ApiConfig, set_config
from ai_scraper.poller.models import RawBurpRecord, PollerState
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


# ── Helpers to build raw HTTP text blobs ─────────────────────────────────────

def _make_request(
    method: str = "GET",
    path: str = "/",
    host: str = "api.example.com",
    port: int | None = None,
    headers: list[tuple[str, str]] | None = None,
    body: str | None = None,
) -> str:
    """Build a raw HTTP request text blob."""
    hdr_lines = [f"{method} {path} HTTP/1.1"]
    host_hdr = host
    if port and port not in (80, 443):
        host_hdr = f"{host}:{port}"
    hdr_lines.append(f"Host: {host_hdr}")
    if headers:
        for k, v in headers:
            hdr_lines.append(f"{k}: {v}")
    raw = "\r\n".join(hdr_lines)
    if body:
        raw += f"\r\n\r\n{body}"
    else:
        raw += "\r\n\r\n"
    return raw


def _make_response(
    status_code: int = 200,
    headers: list[tuple[str, str]] | None = None,
    body: str | None = None,
    date_str: str = "Mon, 21 Jul 2026 10:00:00 GMT",
) -> str:
    """Build a raw HTTP response text blob."""
    status_text = {200: "OK", 201: "Created", 302: "Found", 404: "Not Found"}
    hdr_lines = [f"HTTP/1.1 {status_code} {status_text.get(status_code, '')}"]
    if date_str:
        hdr_lines.append(f"Date: {date_str}")
    if headers:
        for k, v in headers:
            hdr_lines.append(f"{k}: {v}")
    raw = "\r\n".join(hdr_lines)
    if body:
        raw += f"\r\n\r\n{body}"
    else:
        raw += "\r\n\r\n"
    return raw


# ── Sample raw Burp records ──────────────────────────────────────────────────

@pytest.fixture
def sample_raw_record() -> RawBurpRecord:
    return RawBurpRecord(
        request=_make_request(
            method="GET",
            path="/users/123/orders?status=active&limit=10",
            host="api.example.com",
            headers=[
                ("Authorization", "Bearer eyJxxx"),
                ("Content-Type", "application/json"),
            ],
        ),
        response=_make_response(
            status_code=200,
            headers=[
                ("Content-Type", "application/json"),
                ("Content-Length", "42"),
            ],
            body='{"orders": [{"id": 1, "total": 99}]}',
        ),
    )


@pytest.fixture
def sample_raw_records() -> list[RawBurpRecord]:
    return [
        RawBurpRecord(
            request=_make_request(
                method="GET",
                path=f"/users/{i}/profile",
                host="api.example.com",
                headers=[("Cookie", f"session=abc{i}")],
            ),
            response=_make_response(
                status_code=200 if i % 2 == 0 else 404,
                headers=[("Content-Type", "application/json")],
                body='{"user": {"id": ' + str(i) + '}}',
            ),
        )
        for i in range(1, 11)
    ]


@pytest.fixture
def sample_raw_record_with_url_param() -> RawBurpRecord:
    return RawBurpRecord(
        request=_make_request(
            method="POST",
            path="/api/callback?url=https://evil.com&redirect=https://target.com",
            host="webhook.example.com",
            headers=[
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Cookie", "sess=123"),
            ],
            body="webhook=https://attacker.net/hook",
        ),
        response=_make_response(
            status_code=302,
            headers=[("Location", "https://safe.com")],
        ),
    )


@pytest.fixture
def sample_raw_record_multipart() -> RawBurpRecord:
    return RawBurpRecord(
        request=_make_request(
            method="POST",
            path="/api/upload",
            host="upload.example.com",
            headers=[
                ("Content-Type", "multipart/form-data; boundary=xxx"),
                ("Authorization", "Bearer token"),
            ],
            body='--xxx\r\nContent-Disposition: form-data; name="file"\r\n\r\n...\r\n--xxx--',
        ),
        response=_make_response(
            status_code=201,
            headers=[("Content-Type", "application/json")],
            body='{"ok": true}',
        ),
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
        if tool_name in self._responses:
            return self._responses[tool_name]
        return []

    async def list_tools(self) -> list[dict]:
        return [{"name": "get_proxy_http_history", "description": "Get proxy history"}]


@pytest.fixture
def fake_mcp_client() -> FakeMcpClient:
    return FakeMcpClient()


@pytest.fixture
def fake_mcp_client_with_data(sample_raw_record) -> FakeMcpClient:
    return FakeMcpClient(responses={
        "get_proxy_http_history": [sample_raw_record.model_dump()],
    })
