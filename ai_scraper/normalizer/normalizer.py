"""Normalizer — convert RawBurpRecord into the unified TrafficRecord schema.

This is the only place where Burp-specific fields are mapped.  When a new
traffic source (Caido, ZAP, …) is added, a new normalizer adapter is the
only thing that needs to change — everything downstream stays the same.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from ai_scraper.poller.models import RawBurpRecord
from ai_scraper.normalizer.models import TrafficRecord
from ai_scraper.normalizer.models import DecompressConfig

logger = logging.getLogger(__name__)


class Normalizer:
    """Converts RawBurpRecord → TrafficRecord (unified schema)."""

    def __init__(self, decompress: DecompressConfig | None = None):
        self._decompress = decompress or DecompressConfig()

    # ── Public API ───────────────────────────────────────────────────────────

    def normalize(self, raw: RawBurpRecord) -> TrafficRecord:
        """Convert a single raw Burp record into the unified schema."""
        full_url = self._build_full_url(raw)
        parsed = urlparse(full_url)

        return TrafficRecord(
            request_id=f"burp:{raw.id}",
            method=raw.method.upper(),
            url=full_url,
            host=raw.host,
            path=raw.path,
            query_params=self._parse_query(parsed.query),
            headers=self._parse_headers(raw.request_headers),
            body=raw.request_body,
            response_status=raw.response_status,
            response_headers=self._parse_headers(raw.response_headers or ""),
            response_body=raw.response_body,
            timestamp=self._parse_timestamp(raw.timestamp),
            source_tool="burp",
        )

    def normalize_batch(self, raw_records: list[RawBurpRecord]) -> list[TrafficRecord]:
        """Batch-convert a list of raw records."""
        return [self.normalize(r) for r in raw_records]

    # ── Internal helpers ─────────────────────────────────────────────────────

    @staticmethod
    def _build_full_url(raw: RawBurpRecord) -> str:
        base = f"{raw.protocol}://{raw.host}"
        if raw.port and raw.port not in (80, 443):
            base += f":{raw.port}"
        url = base + raw.path
        if raw.query:
            url += "?" + raw.query
        return url

    @staticmethod
    def _parse_query(query_string: str) -> dict[str, list[str]]:
        if not query_string:
            return {}
        return parse_qs(query_string, keep_blank_values=True)

    @staticmethod
    def _parse_headers(raw_headers: str) -> dict[str, str]:
        """Parse a raw HTTP header block into a lowercase-keyed dict.

        Example input::

            Host: example.com\r\nContent-Type: application/json\r\n\r\n
        """
        result: dict[str, str] = {}
        if not raw_headers:
            return result
        for line in raw_headers.splitlines():
            line = line.strip()
            if not line:
                continue
            if ":" not in line:
                continue  # malformed line, skip
            key, _, value = line.partition(":")
            result[key.strip().lower()] = value.strip()
        return result

    @staticmethod
    def _parse_timestamp(raw_ts: Optional[str]) -> datetime:
        """Parse an ISO-8601 timestamp string; fall back to UTC now."""
        if not raw_ts:
            return datetime.now(timezone.utc)
        try:
            # Handle various ISO-8601 variants
            ts = raw_ts.replace("Z", "+00:00")
            return datetime.fromisoformat(ts)
        except ValueError:
            logger.debug("Unparseable timestamp '%s', using now()", raw_ts)
            return datetime.now(timezone.utc)
