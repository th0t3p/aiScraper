"""Poller data models."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class CursorMode(str, Enum):
    BY_ID = "by_id"
    BY_TIME = "by_time"


class PollerState(BaseModel):
    mode: CursorMode = CursorMode.BY_ID
    last_seen_id: Optional[int] = None
    last_seen_timestamp: Optional[datetime] = None
    total_polled: int = 0
    last_poll_at: Optional[datetime] = None


class RawBurpRecord(BaseModel):
    """A single proxy history entry as returned by Burp MCP Server.

    This is intentionally a flat, raw representation — no normalization
    happens at this layer.  Fields correspond to what the Burp MCP
    `getProxyHistory` tool returns.
    """

    id: int
    host: str
    port: int
    protocol: str  # "http" | "https"
    method: str
    path: str
    query: Optional[str] = None
    request_headers: str = ""  # raw HTTP header block as text
    request_body: Optional[str] = None
    response_status: Optional[int] = None
    response_headers: Optional[str] = None
    response_body: Optional[str] = None
    timestamp: Optional[str] = None  # ISO-8601, may be absent for old entries
    # Extra fields that Burp MCP may include — keep them for debugging
    extra: dict = Field(default_factory=dict)
