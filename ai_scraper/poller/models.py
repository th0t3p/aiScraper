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

    The real Burp MCP tool returns flat items with raw HTTP text blobs —
    no separate host/port/method/path/id/timestamp fields.  All extraction
    happens during normalization.
    """

    request: str
    response: Optional[str] = None
    notes: str = ""
