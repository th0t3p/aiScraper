"""Normalizer data models — the unified TrafficRecord schema.

This is the **single data contract** that every downstream module
(IDOR scanner, SSRF scanner, …) relies on.
"""

from __future__ import annotations

import json as _json
import re
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class DecompressConfig(BaseModel):
    """Optional decompression settings (reserved for future use)."""
    auto_decompress: bool = True
    max_body_size: int = 10 * 1024 * 1024  # 10 MB


class TrafficRecord(BaseModel):
    """Unified traffic record — the canonical representation.

    All downstream vulnerability scanners consume this schema exclusively.
    """

    request_id: str
    method: str
    url: str
    host: str
    path: str
    query_params: dict[str, list[str]] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    response_status: Optional[int] = None
    response_headers: Optional[dict[str, str]] = None
    response_body: Optional[str] = None
    timestamp: datetime
    source_tool: str = "burp"

    # Enrichment tags — populated later by the enrichment module
    tags: dict[str, Any] = Field(default_factory=dict)

    # ── Computed helpers ─────────────────────────────────────────────────

    @property
    def param_names(self) -> list[str]:
        """Return a sorted list of query + body parameter names.

        Handles four body types: urlencoded form, multipart, JSON, and plain text.
        For JSON bodies, recursively collects all keys (including nested objects).
        """
        names: set[str] = set(self.query_params.keys())
        if not self.body:
            return sorted(names)

        if self._looks_like_form_body():
            for part in self.body.split("&"):
                if "=" in part:
                    names.add(part.split("=", 1)[0])
        elif self._looks_like_multipart():
            for m in re.finditer(r'name="([^"]+)"', self.body):
                names.add(m.group(1))
        elif self._looks_like_json_body():
            try:
                self._extract_json_keys(self.body, names)
            except Exception:
                logger.debug("Failed to parse JSON body for param extraction", exc_info=True)

        return sorted(names)

    def has_param_named(self, name: str) -> bool:
        """Check whether a parameter with the given name exists across all sources.

        Checks: query_params, form body, multipart body, and JSON body.
        """
        if name in self.query_params:
            return True
        if not self.body:
            return False
        if self._looks_like_form_body():
            return f"{name}=" in self.body
        if self._looks_like_multipart():
            return f'name="{name}"' in self.body
        if self._looks_like_json_body():
            try:
                keys: set[str] = set()
                self._extract_json_keys(self.body, keys)
                return name in keys
            except Exception:
                return False
        return False

    def _looks_like_form_body(self) -> bool:
        ct = self.headers.get("content-type", "")
        return "application/x-www-form-urlencoded" in ct

    def _looks_like_multipart(self) -> bool:
        ct = self.headers.get("content-type", "")
        return "multipart/form-data" in ct

    def _looks_like_json_body(self) -> bool:
        ct = self.headers.get("content-type", "")
        return "application/json" in ct or "+json" in ct

    @staticmethod
    def _extract_json_keys(body: str, keys: set[str]) -> None:
        """Recursively extract all object keys from a JSON string.

        Does NOT use path prefixes — collects bare key names only.
        Silently returns on invalid JSON (caller traps).
        """
        data = _json.loads(body)

        def _walk(obj: Any) -> None:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    keys.add(k)
                    _walk(v)
            elif isinstance(obj, list):
                for item in obj:
                    _walk(item)

        _walk(data)

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }
