"""BurpPoller — incremental proxy history poller with offset-based cursor."""

from __future__ import annotations

import asyncio
import fnmatch
import json as _json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, List, Optional

from ai_scraper.config import PollerConfig, get_config
from burp_mcp_client import McpSseClient
from ai_scraper.poller.models import PollerState, RawBurpRecord

logger = logging.getLogger(__name__)

Callback = Callable[[list[RawBurpRecord]], Awaitable[None]]

# Regex to extract the Host header value from raw HTTP request text.
# Matches "Host: value" case-insensitively, anchored at line start.
_HOST_RE = re.compile(r"^[Hh][Oo][Ss][Tt]:\s*(.+)$", re.MULTILINE)

# Regex to extract the request line (method + path + query).
_REQUEST_LINE_RE = re.compile(r"^(\S+)\s+(\S+)\s+HTTP/")


def _extract_host_and_path(request_raw: str) -> tuple[str, str]:
    """Return (host, path_with_query) from a raw HTTP request blob.

    Returns (\"unknown\", \"/\") on any parse failure — callers must handle
    these sentinel values gracefully.
    """
    # Request line: "METHOD /path?query HTTP/1.1"
    line_end = request_raw.find("\r\n")
    if line_end == -1:
        line_end = request_raw.find("\n")
    first_line = request_raw[:line_end] if line_end > 0 else request_raw[:200]

    m = _REQUEST_LINE_RE.match(first_line)
    path = m.group(2) if m else "/"

    # Host header
    m = _HOST_RE.search(request_raw)
    host = m.group(1).strip() if m else "unknown"

    return host, path


class BurpPoller:
    """Polls Burp MCP Server for proxy history using offset-based cursor.

    The real Burp MCP get_proxy_http_history tool accepts:

        { "count": int, "offset": int }

    and returns a flat list of {request, response, notes} dicts.  We track
    ``consumed_count`` as our cursor — the next poll requests
    ``offset=consumed_count`` to get only new records.

    Usage::

        poller = BurpPoller()
        poller.on_new_records(my_handler)
        await poller.start()          # background polling
        # or
        records = await poller.poll_once()   # manual one-shot
    """

    def __init__(
        self,
        config: PollerConfig | None = None,
        *,
        mcp_client: McpSseClient | None = None,
    ):
        self._config = config or get_config().poller
        self._state = PollerState()
        self._mcp_client: Optional[McpSseClient] = mcp_client
        self._client: Optional[McpSseClient] = None
        self._discovered_tool: Optional[str] = None
        self._callbacks: list[Callback] = []
        self._poll_task: Optional[asyncio.Task] = None
        self._running = False
        self._include_res: list[re.Pattern] = self._compile_patterns(
            self._config.include_url_patterns
        )
        self._exclude_res: list[re.Pattern] = self._compile_patterns(
            self._config.exclude_url_patterns
        )

    # ── Public API ───────────────────────────────────────────────────────────

    def on_new_records(self, callback: Callback) -> None:
        """Register an async callback invoked with each batch of new raw records."""
        self._callbacks.append(callback)

    async def start(self) -> None:
        """Connect to Burp MCP and start background polling loop."""
        if self._running:
            return
        self._running = True
        self._client = self._mcp_client or self._build_mcp_client()
        await self._client.connect()
        await self._discover_proxy_tool()
        logger.info(
            "Poller started (interval=%ds, tool=%s, consumed_count=%d)",
            self._config.poll_interval_seconds,
            self._tool_name,
            self._state.consumed_count,
        )
        self._poll_task = asyncio.create_task(self._poll_loop())

    async def stop(self) -> None:
        """Stop polling and disconnect."""
        self._running = False
        if self._poll_task:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
            self._poll_task = None
        if self._client:
            await self._client.disconnect()
            self._client = None
        logger.info("Poller stopped (total polled=%d)", self._state.total_polled)

    async def poll_once(self) -> list[RawBurpRecord]:
        """Execute a single poll immediately.  Does not require start()."""
        if self._client is None:
            self._client = self._mcp_client or self._build_mcp_client()
            await self._client.connect()

        try:
            await self._discover_proxy_tool()
            return await self._do_poll()
        finally:
            # Keep the connection open if we are in background mode;
            # otherwise tear it down.
            if not self._running:
                await self._client.disconnect()
                self._client = None

    def get_state(self) -> PollerState:
        """Return a copy of the current cursor state."""
        return self._state.model_copy(deep=True)

    def reset_cursor(self) -> None:
        """Reset the cursor so the next poll fetches everything from scratch."""
        self._state.consumed_count = 0
        self._state.total_polled = 0
        logger.info("Cursor reset")

    # ── MCP Tool Discovery ──────────────────────────────────────────────────

    # Common proxy-history tool name patterns across Burp MCP versions.
    # get_proxy_http_history is the official Burp MCP Server tool name.
    _PROXY_TOOL_CANDIDATES = [
        "get_proxy_http_history", "getProxyHttpHistory",
        "getProxyHistory", "get_proxy_history", "proxyHistory",
        "listProxyHistory", "list_proxy_history", "getHistory",
        "proxy_history", "getProxyHist", "getAllProxyHistory",
    ]

    @property
    def _tool_name(self) -> str:
        """Return the discovered tool name or fall back to the configured one."""
        return self._discovered_tool or self._config.proxy_history_tool

    async def _discover_proxy_tool(self) -> str:
        """Call MCP tools/list and heuristically find the proxy history tool.

        If already discovered or the client doesn't support list_tools,
        returns the configured tool name without error.
        """
        if self._discovered_tool is not None:
            return self._discovered_tool

        assert self._client is not None

        try:
            tools = await self._client.list_tools()
        except Exception:
            logger.debug("tools/list not available, using configured: '%s'",
                         self._config.proxy_history_tool)
            return self._config.proxy_history_tool

        tool_names = {t.get("name", "").lower() for t in tools if isinstance(t, dict)}

        for candidate in self._PROXY_TOOL_CANDIDATES:
            if candidate.lower() in tool_names:
                self._discovered_tool = candidate
                logger.info("Auto-discovered proxy history tool: '%s'", candidate)
                return candidate

        # Fuzzy match: any tool name containing "proxy" AND "history"/"hist"
        for name in tool_names:
            if "proxy" in name and ("history" in name or "hist" in name):
                self._discovered_tool = name
                logger.info("Fuzzy-matched proxy history tool: '%s'", name)
                return name

        logger.info("No proxy history tool auto-detected, using configured: '%s'",
                     self._config.proxy_history_tool)
        return self._config.proxy_history_tool

    def _build_mcp_client(self) -> McpSseClient:
        """Construct an McpSseClient from the current config."""
        kwargs: dict[str, Any] = dict(
            base_url=self._config.mcp_sse_url,
            timeout=self._config.request_timeout,
            sse_path=self._config.mcp_sse_path,
        )
        headers: dict[str, str] = dict(self._config.mcp_extra_headers)
        if self._config.mcp_auth_token:
            headers["Authorization"] = f"Bearer {self._config.mcp_auth_token}"
        if headers:
            kwargs["headers"] = headers
        return McpSseClient(**kwargs)

    # ── Internals ────────────────────────────────────────────────────────────

    async def _poll_loop(self) -> None:
        while self._running:
            try:
                await self._do_poll()
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Poll cycle failed, will retry")
            await asyncio.sleep(self._config.poll_interval_seconds)

    _COUNT_FLOOR = 10

    async def _do_poll(self) -> list[RawBurpRecord]:
        assert self._client is not None

        count = self._config.batch_size
        offset = self._state.consumed_count

        # 1. Fetch raw proxy history from Burp MCP — with timeout retry.
        #    If count exceeds Burp's practical limit, the call hangs
        #    indefinitely rather than returning available data.  On timeout
        #    we halve count and retry immediately, down to a floor.
        raw_data = None
        error = None

        for attempt in range(3):
            tool_args = {"count": count, "offset": offset}
            logger.debug("Calling %s with args=%s (attempt %d)", self._tool_name, tool_args, attempt + 1)
            try:
                raw_data = await self._client.call_tool(
                    self._tool_name, tool_args
                )
                break  # success
            except TimeoutError as exc:
                error = exc
                count = max(count // 2, self._COUNT_FLOOR)
                logger.warning(
                    "get_proxy_http_history timed out with count=%d — "
                    "retrying with count=%d in this cycle",
                    tool_args["count"], count,
                )
            except Exception:
                # Non-timeout errors (connection, etc.) — re-raise immediately
                raise

        if raw_data is None:
            if error:
                raise error
            return []

        # 2. Parse into RawBurpRecord list
        records, failed_chunks = self._parse_records(raw_data)
        returned_count = len(records)

        # 3. Mark the cycle as successful — even if zero records returned.
        #    An empty batch at a valid offset just means we're caught up.
        self._state.last_poll_at = datetime.now(timezone.utc)

        # 4. Handle "caught up" / "history possibly cleared" cases
        if returned_count == 0 and offset > 0:
            # Could be caught up, or Burp history was cleared entirely
            # while we still hold a high offset.  Reset as a recovery.
            logger.warning(
                "Offset %d returned 0 records — history may have been cleared. "
                "Resetting consumed_count to 0.",
                offset,
            )
            self._state.consumed_count = 0
            self._state.total_polled = 0
        elif returned_count == 0:
            logger.debug("No records at offset 0 — Burp history is empty")
            return []
        elif returned_count < count:
            # Fewer than requested = we've reached the current end of history
            logger.debug(
                "Caught up: offset=%d returned %d/%d records",
                offset, returned_count, count,
            )

        if returned_count == 0:
            return []

        # 5. Advance cursor by actual returned count (BEFORE filtering —
        #    see next step for rationale).
        self._state.consumed_count += returned_count
        self._state.total_polled += returned_count

        # 6. Apply URL regex and authorized-scope filters.
        #    Filters run POST-cursor-advance to prevent the poller from
        #    getting stuck when all new records are out of scope.
        records = self._apply_url_filters(records)
        records = self._validate_authorized_scope(records)

        passed_through = len(records)
        logger.info(
            "Polled %d records (offset=%d→%d); %d passed filters; "
            "%d objects failed to parse (total consumed=%d)",
            returned_count, offset, self._state.consumed_count,
            passed_through, failed_chunks, self._state.total_polled,
        )

        # 7. Notify callbacks (only with records that passed filters)
        for cb in self._callbacks:
            try:
                await cb(records)
            except Exception:
                logger.exception("Callback %s raised an error", cb.__name__)

        return records

    # ── Parsing ──────────────────────────────────────────────────────────────

    def _parse_records(self, raw_data: object) -> tuple[list[RawBurpRecord], int]:
        """Convert the MCP tool response into a list of RawBurpRecord.

        The real Burp MCP get_proxy_http_history tool returns its result as
        a string of whitespace-separated JSON objects.  Parsing uses
        json.JSONDecoder().raw_decode() to determine each object's real
        boundaries from JSON syntax, not a fragile blank-line heuristic
        (see `_parse_records_from_string`).

        Returns (records, parse_failure_count).
        """
        if raw_data is None:
            return [], 0

        if isinstance(raw_data, str):
            return self._parse_records_from_string(raw_data)

        # Legacy shapes — kept as fallback in case the server-side format
        # changes to return proper JSON arrays/dicts in a future version.
        items: list[dict] = []

        if isinstance(raw_data, list):
            items = raw_data
        elif isinstance(raw_data, dict):
            items = raw_data.get("items") or raw_data.get("entries") or raw_data.get("history") or []
            if not items and all(isinstance(v, dict) for v in raw_data.values()):
                items = list(raw_data.values())
            if not items and "request" in raw_data:
                items = [raw_data]
        else:
            return [], 0

        return self._build_records(items), 0

    def _parse_records_from_string(self, raw: str) -> tuple[list[RawBurpRecord], int]:
        """Parse a string of whitespace-separated JSON objects.

        Uses json.JSONDecoder().raw_decode() to determine each object's real
        end from JSON syntax rather than a blank-line heuristic.  This
        handles objects whose string values contain unescaped newline
        characters (a known serialization bug in Burp MCP).

        Returns (records, parse_failure_count).
        """
        decoder = _json.JSONDecoder()
        idx = 0
        text = raw.strip()
        parsed_objects: list[dict] = []
        parse_failures = 0

        while idx < len(text):
            # Skip whitespace / blank-line separators between objects
            while idx < len(text) and text[idx] in " \t\r\n":
                idx += 1
            if idx >= len(text):
                break
            try:
                obj, end_idx = decoder.raw_decode(text, idx)
                if isinstance(obj, dict):
                    parsed_objects.append(obj)
                elif isinstance(obj, list):
                    parsed_objects.extend(obj)
                idx = end_idx
            except _json.JSONDecodeError as exc:
                parse_failures += 1
                logger.warning(
                    "Failed to decode JSON object at position %d: %s at "
                    "line %d col %d. Context: %r",
                    idx, exc.msg, exc.lineno, exc.colno,
                    text[max(0, idx - 20):idx + 150],
                )
                # Recovery: search for next `{"request":` anchor after the
                # failure point, which is a reliable per-record boundary
                # regardless of what's broken inside the current object.
                next_anchor = text.find('{"request":', idx + 1)
                if next_anchor == -1:
                    logger.warning(
                        "Could not resynchronize after malformed object at "
                        "position %d — %d objects recovered before giving up "
                        "on the rest of this batch",
                        idx, len(parsed_objects),
                    )
                    break
                idx = next_anchor

        if parse_failures:
            logger.warning(
                "%d of %d objects failed to parse this cycle (recovered %d)",
                parse_failures, parse_failures + len(parsed_objects),
                len(parsed_objects),
            )

        return self._build_records(parsed_objects), parse_failures

    @staticmethod
    def _build_records(items: list[dict]) -> list[RawBurpRecord]:
        records: list[RawBurpRecord] = []
        for item in items:
            try:
                records.append(RawBurpRecord(**item))
            except Exception:
                logger.debug("Failed to parse raw record: %s", str(item)[:200])
        return records

    # ── URL filtering ────────────────────────────────────────────────────────

    def _apply_url_filters(self, records: list[RawBurpRecord]) -> list[RawBurpRecord]:
        """Apply include/exclude URL regex filters.

        Filters now parse the target URL from the raw request text blob
        since RawBurpRecord no longer has separate host/path fields.
        """
        if not self._include_res and not self._exclude_res:
            return records

        result: list[RawBurpRecord] = []
        for r in records:
            host, path = _extract_host_and_path(r.request)
            url = f"https://{host}{path}"  # protocol is unknown, assume https

            if self._include_res and not any(p.search(url) for p in self._include_res):
                continue
            if self._exclude_res and any(p.search(url) for p in self._exclude_res):
                continue
            result.append(r)
        return result

    # ── Authorized scope validation ──────────────────────────────────────────

    def _validate_authorized_scope(self, records: list[RawBurpRecord]) -> list[RawBurpRecord]:
        """Drop records whose host is not in the authorized_scope whitelist.

        Fail-closed by default: if authorized_scope is empty, ALL records are
        dropped unless allow_unscoped is explicitly set to True.
        """
        scopes = self._config.authorized_scope
        if not scopes:
            if self._config.allow_unscoped:
                logger.warning(
                    "authorized_scope is empty and allow_unscoped=True — "
                    "ALL traffic is being accepted without scope validation. "
                    "Set authorized_scope for production use."
                )
                return records
            logger.warning(
                "authorized_scope is empty — all traffic will be dropped "
                "until configured. Set authorized_scope in your config."
            )
            return []

        result: list[RawBurpRecord] = []
        for r in records:
            host, _ = _extract_host_and_path(r.request)
            for scope in scopes:
                if fnmatch.fnmatch(host, scope):
                    result.append(r)
                    break
            else:
                logger.debug(
                    "Dropped record host=%s (not in authorized_scope)", host,
                )
        return result

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _compile_patterns(patterns: list[str]) -> list[re.Pattern]:
        compiled: list[re.Pattern] = []
        for p in patterns:
            try:
                compiled.append(re.compile(p))
            except re.error as exc:
                logger.warning("Invalid regex pattern '%s': %s", p, exc)
        return compiled
