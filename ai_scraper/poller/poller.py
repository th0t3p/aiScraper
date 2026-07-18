"""BurpPoller — incremental proxy history poller with cursor management."""

from __future__ import annotations

import asyncio
import fnmatch
import logging
import re
from datetime import datetime, timezone
from typing import Awaitable, Callable, List, Optional

from ai_scraper.config import PollerConfig, get_config
from burp_mcp_client import McpSseClient
from ai_scraper.poller.models import CursorMode, PollerState, RawBurpRecord

logger = logging.getLogger(__name__)

Callback = Callable[[list[RawBurpRecord]], Awaitable[None]]


class BurpPoller:
    """Polls Burp MCP Server for proxy history using incremental cursor.

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
        self._state = PollerState(
            mode=CursorMode(self._config.cursor_mode)
        )
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
            "Poller started (interval=%ds, cursor=%s, tool=%s)",
            self._config.poll_interval_seconds,
            self._state.mode.value,
            self._tool_name,
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
        self._state.last_seen_id = None
        self._state.last_seen_timestamp = None
        self._state.total_polled = 0
        logger.info("Cursor reset")

    # ── MCP Tool Discovery ──────────────────────────────────────────────────

    # Common proxy-history tool name patterns across Burp MCP versions
    _PROXY_TOOL_CANDIDATES = [
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
        if self._config.mcp_auth_token:
            kwargs["headers"] = {
                "Authorization": f"Bearer {self._config.mcp_auth_token}"
            }
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

    async def _do_poll(self) -> list[RawBurpRecord]:
        assert self._client is not None

        # 1. Fetch raw proxy history from Burp MCP
        tool_args = self._build_tool_args()
        logger.debug("Calling %s with args=%s", self._tool_name, tool_args)
        raw_data = await self._client.call_tool(
            self._tool_name, tool_args
        )

        # 2. Parse into RawBurpRecord list
        records = self._parse_records(raw_data)
        if not records:
            logger.debug("No new records in this poll cycle")
            return []

        # 3. Apply cursor filtering (safety net in case the tool doesn't support it)
        records = self._apply_cursor_filter(records)
        if not records:
            logger.debug("No new records beyond cursor in this poll cycle")
            return []

        # 4. Advance cursors NOW — BEFORE url/scope filtering.
        #    This prevents the poller from getting stuck when all new records
        #    happen to be excluded by url/scope filters.
        cursor_advanced = len(records)
        self._update_cursor(records)
        self._state.total_polled += cursor_advanced
        self._state.last_poll_at = datetime.now(timezone.utc)

        # 5. Apply regex filters (post-cursor — safe to drop here)
        records = self._apply_url_filters(records)

        # 6. Validate authorized scope (post-cursor — safe to drop here)
        records = self._validate_authorized_scope(records)

        passed_through = len(records)
        logger.info(
            "Polled %d new records (cursor advanced); %d passed filters (total cursor=%d)",
            cursor_advanced, passed_through, self._state.total_polled,
        )

        # 7. Notify callbacks
        for cb in self._callbacks:
            try:
                await cb(records)
            except Exception:
                logger.exception("Callback %s raised an error", cb.__name__)

        return records

    def _build_tool_args(self) -> dict:
        """Build the arguments dict for the proxy history MCP tool."""
        args: dict = {"limit": self._config.batch_size}

        if self._state.mode == CursorMode.BY_ID and self._state.last_seen_id is not None:
            # Request records with id > last_seen_id
            args["after_id"] = self._state.last_seen_id
        elif self._state.mode == CursorMode.BY_TIME and self._state.last_seen_timestamp is not None:
            args["since"] = self._state.last_seen_timestamp.isoformat()

        return args

    # ── Parsing ──────────────────────────────────────────────────────────────

    def _parse_records(self, raw_data: object) -> list[RawBurpRecord]:
        """Convert the MCP tool response into a list of RawBurpRecord."""
        if raw_data is None:
            return []

        # The tool may return different shapes — handle common ones.
        items: list[dict] = []

        if isinstance(raw_data, list):
            items = raw_data
        elif isinstance(raw_data, dict):
            # Sometimes the response is {"items": [...], "total": N} etc.
            items = raw_data.get("items") or raw_data.get("entries") or raw_data.get("history") or []
            if not items and all(isinstance(v, dict) for v in raw_data.values()):
                # Maybe it's a dict of id→record
                items = list(raw_data.values())
            if not items and "id" in raw_data:
                # Single record
                items = [raw_data]
        else:
            return []

        records: list[RawBurpRecord] = []
        for item in items:
            try:
                records.append(RawBurpRecord(**item))
            except Exception:
                logger.debug("Failed to parse raw record: %s", str(item)[:200])
        return records

    # ── Cursor filtering ─────────────────────────────────────────────────────

    def _apply_cursor_filter(self, records: list[RawBurpRecord]) -> list[RawBurpRecord]:
        """Client-side cursor filter as a safety net.

        Even if we pass cursor args to the MCP tool, some implementations
        may ignore them — this filter guarantees incrementality.
        """
        if self._state.mode == CursorMode.BY_ID and self._state.last_seen_id is not None:
            threshold = self._state.last_seen_id
            records = [r for r in records if r.id > threshold]
        elif self._state.mode == CursorMode.BY_TIME and self._state.last_seen_timestamp is not None:
            threshold = self._state.last_seen_timestamp
            filtered: list[RawBurpRecord] = []
            for r in records:
                if r.timestamp:
                    try:
                        ts = datetime.fromisoformat(r.timestamp.replace("Z", "+00:00"))
                        if ts > threshold:
                            filtered.append(r)
                    except ValueError:
                        # Unparseable timestamp — include it to be safe
                        filtered.append(r)
                else:
                    # No timestamp — include it
                    filtered.append(r)
            records = filtered
        return records

    def _update_cursor(self, records: list[RawBurpRecord]) -> None:
        if not records:
            return
        if self._state.mode == CursorMode.BY_ID:
            max_id = max(r.id for r in records)
            self._state.last_seen_id = max_id
        else:
            latest: Optional[datetime] = None
            for r in records:
                if r.timestamp:
                    try:
                        ts = datetime.fromisoformat(r.timestamp.replace("Z", "+00:00"))
                        if latest is None or ts > latest:
                            latest = ts
                    except ValueError:
                        pass
            if latest:
                self._state.last_seen_timestamp = latest

    # ── URL filtering ────────────────────────────────────────────────────────

    def _apply_url_filters(self, records: list[RawBurpRecord]) -> list[RawBurpRecord]:
        """Apply include/exclude URL regex filters."""
        if not self._include_res and not self._exclude_res:
            return records

        result: list[RawBurpRecord] = []
        for r in records:
            url = f"{r.protocol}://{r.host}{r.path}"
            if r.query:
                url += f"?{r.query}"

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
            for scope in scopes:
                if fnmatch.fnmatch(r.host, scope):
                    result.append(r)
                    break
            else:
                logger.debug(
                    "Dropped record id=%d host=%s (not in authorized_scope)",
                    r.id, r.host,
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
