"""Normalizer — convert RawBurpRecord into the unified TrafficRecord schema.

The real Burp MCP get_proxy_http_history tool returns raw HTTP text blobs
(request + response).  This module parses those blobs into the structured
TrafficRecord that all downstream modules consume.
"""

from __future__ import annotations

import re
import logging
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import parse_qs, urlparse

from ai_scraper.poller.models import RawBurpRecord
from ai_scraper.normalizer.models import TrafficRecord
from ai_scraper.normalizer.models import DecompressConfig

logger = logging.getLogger(__name__)


class Normalizer:
    """Converts RawBurpRecord → TrafficRecord (unified schema).

    Parses the raw HTTP request/response text blobs that Burp's MCP tool
    returns and extracts all structured fields from them.
    """

    _REQUEST_LINE_RE = re.compile(r"^(\S+)\s+(\S+)\s+HTTP/(\d\.\d)$")
    _STATUS_LINE_RE = re.compile(r"^HTTP/(\d\.\d)\s+(\d{3})\s")
    _DATE_RE = re.compile(
        r"^[Dd][Aa][Tt][Ee]:\s*(.+)$", re.MULTILINE
    )
    _HEADER_LINE_RE = re.compile(r"^([\w-]+):\s*(.+?)\s*$")

    def __init__(self, decompress: DecompressConfig | None = None):
        self._decompress = decompress or DecompressConfig()

    # ── Public API ───────────────────────────────────────────────────────────

    def normalize(self, raw: RawBurpRecord) -> TrafficRecord:
        """Convert a single raw Burp record into the unified schema.

        When structured fields (host, method, path, status_code, etc.) are
        present on the raw record (BurpMCP-Ultra backend), they are used
        directly.  Otherwise the existing regex-based parsing of the raw
        HTTP text blobs applies unchanged (official PortSwigger server).
        """
        # Parse raw HTTP text blobs (only when available — BurpMCP-Ultra
        # always includes these when include_request/include_response are
        # set, but we defend against a missing blob regardless).
        parsed = self._parse_http_request(raw.request) if raw.request else {}
        resp_parsed = (
            self._parse_http_response(raw.response) if raw.response else {}
        )

        # ── Prefer structured fields when available ────────────────────────
        host = raw.host if raw.host is not None else parsed.get("host", "unknown")
        method = raw.method if raw.method is not None else parsed.get("method", "UNKNOWN")
        path = raw.path if raw.path is not None else parsed.get("path", "/")
        port = raw.port if raw.port is not None else parsed.get("port")

        # Protocol: use raw.secure when available, otherwise infer
        if raw.secure is not None:
            protocol = "https" if raw.secure else "http"
        else:
            protocol = self._infer_protocol(parsed)

        # Full URL: use raw.url when available, otherwise construct
        if raw.url is not None:
            full_url = raw.url
        else:
            full_url = f"{protocol}://{host}"
            if port and port not in (80, 443):
                full_url += f":{port}"
            full_url += path
            if parsed.get("query"):
                full_url += "?" + parsed["query"]

        # Headers: convert BurpMCP-Ultra's request_headers list-of-dicts
        # to the {name: value} dict shape, or fall back to regex-parsed
        if raw.request_headers is not None:
            headers = {
                h["name"]: h["value"]
                for h in raw.request_headers
                if isinstance(h, dict) and "name" in h and "value" in h
            }
        else:
            headers = parsed.get("headers", {})

        query_params = parse_qs(parsed.get("query", ""), keep_blank_values=True)

        response_status = (
            raw.status_code if raw.status_code is not None
            else resp_parsed.get("status_code")
        )

        # Generate a synthetic request_id
        req_id = self._make_request_id(raw)

        # Timestamp: prefer response Date header, fallback to now
        timestamp = self._extract_timestamp(raw.response, resp_parsed)

        return TrafficRecord(
            request_id=req_id,
            method=method,
            url=full_url,
            host=host,
            path=path,
            query_params=query_params,
            headers=headers,
            body=parsed.get("body"),
            response_status=response_status,
            response_headers=resp_parsed.get("headers") or {},
            response_body=resp_parsed.get("body"),
            timestamp=timestamp,
            source_tool="burp",
        )

    def normalize_batch(self, raw_records: list[RawBurpRecord]) -> list[TrafficRecord]:
        """Batch-convert a list of raw records."""
        return [self.normalize(r) for r in raw_records]

    # ── HTTP request parsing ─────────────────────────────────────────────────

    def _parse_http_request(self, request_raw: str) -> dict:
        """Parse a raw HTTP request text blob into structured fields.

        Returns a dict with keys: method, path, query, host, port, headers, body.
        """
        result: dict = {}

        # Find the blank-line separator between headers and body
        header_end = request_raw.find("\r\n\r\n")
        if header_end == -1:
            header_end = request_raw.find("\n\n")
        if header_end == -1:
            header_end = len(request_raw)

        header_section = request_raw[:header_end]
        body = request_raw[header_end:].lstrip("\r\n") if header_end < len(request_raw) else None
        if body is not None and body == "":
            body = None
        result["body"] = body

        # Split headers section into lines
        lines = header_section.split("\n")

        # First line is the request line: "METHOD /path?query HTTP/1.1"
        request_line = lines[0].rstrip("\r") if lines else ""
        rm = self._REQUEST_LINE_RE.match(request_line)
        if rm:
            result["method"] = rm.group(1).upper()
            raw_uri = rm.group(2)
            # Parse path + query
            if "?" in raw_uri:
                result["path"], result["query"] = raw_uri.split("?", 1)
            else:
                result["path"] = raw_uri
                result["query"] = ""
        else:
            result["method"] = "UNKNOWN"
            result["path"] = "/"
            result["query"] = ""

        # Parse header lines
        headers: dict[str, str] = {}
        for line in lines[1:]:
            line = line.rstrip("\r")
            if not line.strip():
                continue  # blank line
            hm = self._HEADER_LINE_RE.match(line)
            if hm:
                key = hm.group(1).lower()
                value = hm.group(2)
                if key in headers:
                    headers[key] = headers[key] + "; " + value
                else:
                    headers[key] = value

        result["headers"] = headers

        # Extract host (and port) from Host header
        host_value = headers.get("host", "")
        if host_value:
            if ":" in host_value.split("]")[-1] if "[" in host_value else ("[" not in host_value and ":" in host_value):
                # Host contains a port — handle IPv6 like [::1]:8080
                if host_value.startswith("["):
                    # IPv6 literal
                    end_bracket = host_value.find("]")
                    result["host"] = host_value[1:end_bracket]
                    rest = host_value[end_bracket + 1:]
                    if rest.startswith(":"):
                        try:
                            result["port"] = int(rest[1:])
                        except ValueError:
                            pass
                else:
                    # host:port
                    try:
                        h, p = host_value.rsplit(":", 1)
                        result["host"] = h
                        result["port"] = int(p)
                    except ValueError:
                        result["host"] = host_value
            else:
                result["host"] = host_value
        else:
            result["host"] = "unknown"

        return result

    # ── HTTP response parsing ────────────────────────────────────────────────

    def _parse_http_response(self, response_raw: str) -> dict:
        """Parse a raw HTTP response text blob into structured fields.

        Returns a dict with keys: status_code, headers, body.
        """
        result: dict = {}

        header_end = response_raw.find("\r\n\r\n")
        if header_end == -1:
            header_end = response_raw.find("\n\n")
        if header_end == -1:
            header_end = len(response_raw)

        header_section = response_raw[:header_end]
        body = response_raw[header_end:].lstrip("\r\n") if header_end < len(response_raw) else None
        if body is not None and body == "":
            body = None
        result["body"] = body

        lines = header_section.split("\n")

        # First line is the status line: "HTTP/1.1 200 OK"
        status_line = lines[0].rstrip("\r") if lines else ""
        sm = self._STATUS_LINE_RE.match(status_line)
        if sm:
            result["status_code"] = int(sm.group(2))
        else:
            result["status_code"] = None

        # Parse header lines
        headers: dict[str, str] = {}
        for line in lines[1:]:
            line = line.rstrip("\r")
            if not line.strip():
                continue
            hm = self._HEADER_LINE_RE.match(line)
            if hm:
                key = hm.group(1).lower()
                value = hm.group(2)
                if key in headers:
                    headers[key] = headers[key] + "; " + value
                else:
                    headers[key] = value

        result["headers"] = headers
        return result

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _infer_protocol(self, parsed: dict) -> str:
        """Infer https vs http from the parsed request.

        Priority: X-Forwarded-Proto header → :scheme pseudo-header →
        port number → default to https (safer for bug bounty traffic).
        """
        headers = parsed.get("headers", {})
        if "x-forwarded-proto" in headers:
            return headers["x-forwarded-proto"].split(",")[0].strip()
        if ":scheme" in headers:
            return headers[":scheme"]
        port = parsed.get("port")
        if port is not None:
            return "https" if port == 443 else "http"
        return "https"  # default assumption

    def _extract_timestamp(
        self, response_raw: Optional[str], resp_parsed: dict
    ) -> datetime:
        """Extract a timestamp from the response Date header, or fallback.

        Handles both HTTP/1.1 ``Date:`` and HTTP/2 lowercased ``date:``.
        """
        # First try the raw response text directly (catches casing variations)
        if response_raw:
            m = self._DATE_RE.search(response_raw)
            if m:
                try:
                    return self._parse_http_date(m.group(1).strip())
                except ValueError:
                    pass

        # Fallback: try parsed response headers
        resp_headers = resp_parsed.get("headers", {})
        date_val = resp_headers.get("date")
        if date_val:
            try:
                return self._parse_http_date(date_val)
            except ValueError:
                pass

        logger.debug("No parseable Date header, using now()")
        return datetime.now(timezone.utc)

    @staticmethod
    def _parse_http_date(date_str: str) -> datetime:
        """Parse an HTTP date string (RFC 7231) to a datetime.

        Handles both the preferred IMF-fixdate format (e.g.
        "Mon, 21 Jul 2026 10:00:00 GMT") and obsolete RFC 850 / asctime
        formats.
        """
        import email.utils
        from datetime import timezone as tz

        parsed = email.utils.parsedate_to_datetime(date_str)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=tz.utc)
        return parsed

    @staticmethod
    def _make_request_id(raw: RawBurpRecord) -> str:
        """Generate a deterministic request_id from the raw record.

        Prefers hashing the raw request text.  Falls back to hashing the
        structured fields if the request blob is missing (defensive —
        shouldn't happen with include_request=True, but guards against a
        future misconfiguration).
        """
        import hashlib
        payload = raw.request
        if not payload:
            # Fallback: hash whatever structured fields are available
            payload = f"{raw.method}|{raw.host}|{raw.path}|{raw.url}"
        h = hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()[:12]
        return f"burp:{h}"
