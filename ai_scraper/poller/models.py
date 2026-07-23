"""Poller data models."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class PollerState(BaseModel):
    consumed_count: int = 0
    total_polled: int = 0
    last_poll_at: Optional[datetime] = None


class RawBurpRecord(BaseModel):
    """A single proxy history entry from Burp's get_proxy_http_history tool.

    The official PortSwigger MCP server returns flat items with raw HTTP
    text blobs — no separate host/port/method/path fields.  All extraction
    happens during normalization.

    BurpMCP-Ultra additionally provides pre-parsed structured fields
    (host, method, path, status_code, request_headers, etc.) directly on
    each item.  These are declared as optional fields below (all defaulting
    to ``None``) so the official-server path is completely unaffected.
    """

    request: str
    response: Optional[str] = None
    notes: str = ""

    # ── Structured fields (populated by BurpMCP-Ultra, None otherwise) ──────
    index: Optional[int] = None
    host: Optional[str] = None
    port: Optional[int] = None
    secure: Optional[bool] = None
    method: Optional[str] = None
    url: Optional[str] = None
    path: Optional[str] = None
    mime_type: Optional[str] = None
    has_response: Optional[bool] = None
    status_code: Optional[int] = None
    response_mime_type: Optional[str] = None
    time: Optional[str] = None
    # [{"name": "Host", "value": "example.com"}, ...]
    request_headers: Optional[list[dict]] = None
