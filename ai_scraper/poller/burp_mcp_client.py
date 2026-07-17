"""Minimal MCP-over-SSE client for communicating with Burp MCP Server.

Protocol summary:
  1. GET  /sse               → long-lived SSE stream
  2. Wait for "endpoint" event → message endpoint URL (e.g. /message?sessionId=...)
  3. POST JSON-RPC body to that endpoint
  4. Response arrives via the SSE "message" event

JSON-RPC methods used:
  - tools/list          → discover available tools
  - tools/call          → invoke a Burp tool (e.g. getProxyHistory)
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urljoin

import httpx

logger = logging.getLogger(__name__)

# ── SSE line parser ──────────────────────────────────────────────────────────

_SSE_LINE_RE = re.compile(r"^(?P<field>[^:\n\r]+):\s?(?P<value>.*)$")


def _parse_sse_event(raw: str) -> tuple[str, str, str]:
    """Parse a single SSE event block into (event_type, data, id).

    Returns ("message", data, "") if no 'event:' field is present.
    """
    event_type = "message"
    data_parts: list[str] = []
    event_id = ""

    for line in raw.splitlines():
        m = _SSE_LINE_RE.match(line)
        if not m:
            continue  # skip comments / empty lines
        field, value = m.group("field"), m.group("value")
        if field == "event":
            event_type = value
        elif field == "data":
            data_parts.append(value)
        elif field == "id":
            event_id = value
        # field "retry" is ignored here

    return event_type, "\n".join(data_parts), event_id


# ── MCP Client ────────────────────────────────────────────────────────────────

class McpSseClient:
    """Async MCP SSE client.

    Manages the SSE connection lifecycle and provides a simple `call_tool()`
    interface that hides the JSON-RPC transport details.
    """

    def __init__(self, base_url: str = "http://127.0.0.1:9876", timeout: float = 30.0):
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._http = httpx.AsyncClient(timeout=httpx.Timeout(timeout))
        self._message_url: Optional[str] = None
        self._pending: dict[int, asyncio.Future] = {}
        self._next_id = 1
        self._sse_task: Optional[asyncio.Task] = None
        self._running = False

    # ── Connection management ────────────────────────────────────────────────

    async def connect(self) -> None:
        """Open the SSE connection and wait for the endpoint handshake."""
        if self._running:
            return

        sse_url = f"{self._base_url}/sse"
        logger.info("Connecting to MCP SSE endpoint: %s", sse_url)

        self._running = True
        self._sse_task = asyncio.create_task(self._read_sse(sse_url))

        # Wait for the endpoint event (with timeout)
        deadline = time.monotonic() + self._timeout
        while self._message_url is None:
            if time.monotonic() > deadline:
                raise TimeoutError(
                    f"Timed out waiting for MCP endpoint handshake after {self._timeout}s"
                )
            await asyncio.sleep(0.1)

        logger.info("MCP SSE connected, message endpoint: %s", self._message_url)

    async def disconnect(self) -> None:
        """Close the SSE stream and release resources."""
        self._running = False
        if self._sse_task:
            self._sse_task.cancel()
            try:
                await self._sse_task
            except asyncio.CancelledError:
                pass
            self._sse_task = None
        # Reject all pending futures
        for fut in self._pending.values():
            if not fut.done():
                fut.set_exception(ConnectionError("MCP SSE connection closed"))
        self._pending.clear()
        await self._http.aclose()
        logger.info("MCP SSE disconnected")

    # ── Tool invocation ──────────────────────────────────────────────────────

    async def list_tools(self) -> list[dict]:
        """Return the tool list from the MCP server."""
        result = await self._rpc_call("tools/list", {})
        return result.get("tools", [])

    async def call_tool(self, tool_name: str, arguments: dict | None = None) -> Any:
        """Invoke a named MCP tool and return its *content* (the 'result' key)."""
        params: dict[str, Any] = {"name": tool_name}
        if arguments:
            params["arguments"] = arguments
        result = await self._rpc_call("tools/call", params)
        # MCP tool results are wrapped in { "content": [...] }
        content = result.get("content", [])
        if isinstance(content, list) and len(content) > 0:
            first = content[0]
            if isinstance(first, dict) and "text" in first:
                try:
                    return json.loads(first["text"])
                except (json.JSONDecodeError, TypeError):
                    return first["text"]
        return content

    # ── Internal helpers ─────────────────────────────────────────────────────

    async def _read_sse(self, sse_url: str) -> None:
        """Background task: read SSE events and dispatch them."""
        try:
            async with self._http.stream("GET", sse_url) as resp:
                resp.raise_for_status()
                buffer = ""
                async for chunk in resp.aiter_text():
                    if not self._running:
                        break
                    buffer += chunk
                    # SSE events are separated by double newlines
                    while "\n\n" in buffer:
                        event_raw, buffer = buffer.split("\n\n", 1)
                        self._dispatch_sse_event(event_raw)
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.error("SSE stream error: %s", exc)
            # Reject all pending futures on connection loss
            for fut in self._pending.values():
                if not fut.done():
                    fut.set_exception(exc)
            self._pending.clear()

    def _dispatch_sse_event(self, event_raw: str) -> None:
        event_type, data, _ = _parse_sse_event(event_raw)

        if event_type == "endpoint":
            # The server tells us where to POST JSON-RPC messages
            self._message_url = urljoin(f"{self._base_url}/", data.strip("/"))
            logger.debug("Received endpoint: %s", self._message_url)

        elif event_type == "message":
            try:
                msg = json.loads(data)
            except json.JSONDecodeError:
                logger.debug("Unparseable SSE message data: %s", data[:200])
                return
            rpc_id = msg.get("id")
            if rpc_id is not None and rpc_id in self._pending:
                fut = self._pending.pop(rpc_id)
                if "error" in msg:
                    fut.set_exception(
                        RuntimeError(
                            f"MCP RPC error (code={msg['error'].get('code')}): "
                            f"{msg['error'].get('message')}"
                        )
                    )
                else:
                    fut.set_result(msg.get("result", {}))
            else:
                logger.debug("Unmatched RPC response for id=%s", rpc_id)

        else:
            logger.debug("Ignored SSE event type=%s", event_type)

    async def _rpc_call(self, method: str, params: dict) -> Any:
        """Send a JSON-RPC request via POST and await the SSE response."""
        if self._message_url is None:
            raise RuntimeError("Not connected — call connect() first")

        rid = self._next_id
        self._next_id += 1

        payload = {
            "jsonrpc": "2.0",
            "id": rid,
            "method": method,
            "params": params,
        }
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        self._pending[rid] = fut

        try:
            resp = await self._http.post(
                self._message_url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
        except Exception as exc:
            self._pending.pop(rid, None)
            raise ConnectionError(f"Failed to POST RPC request: {exc}") from exc

        try:
            return await asyncio.wait_for(fut, timeout=self._timeout)
        except asyncio.TimeoutError:
            self._pending.pop(rid, None)
            raise TimeoutError(f"RPC call '{method}' timed out after {self._timeout}s")
