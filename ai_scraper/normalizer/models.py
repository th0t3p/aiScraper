"""Normalizer data models — the unified TrafficRecord schema.

This is the **single data contract** that every downstream module
(IDOR scanner, SSRF scanner, …) relies on.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


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
        """Return a sorted list of query + body parameter names."""
        names: set[str] = set(self.query_params.keys())
        if self.body:
            if self._looks_like_form_body():
                for part in self.body.split("&"):
                    if "=" in part:
                        names.add(part.split("=", 1)[0])
            elif self._looks_like_multipart():
                import re
                for m in re.finditer(r'name="([^"]+)"', self.body):
                    names.add(m.group(1))
        return sorted(names)

    def _looks_like_form_body(self) -> bool:
        ct = self.headers.get("content-type", "")
        return "application/x-www-form-urlencoded" in ct

    def _looks_like_multipart(self) -> bool:
        ct = self.headers.get("content-type", "")
        return "multipart/form-data" in ct

    def has_param_named(self, name: str) -> bool:
        """Check whether a parameter with the given name exists."""
        return name in self.query_params or (
            self.body is not None
            and self._looks_like_form_body()
            and f"{name}=" in self.body
        )

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }
