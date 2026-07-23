"""Storage data models."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from ai_scraper.normalizer.models import TrafficRecord


class TrafficQuery(BaseModel):
    """Query filters for pulling traffic records from storage."""

    methods: Optional[list[str]] = None
    hosts: Optional[list[str]] = None
    param_categories: Optional[list[str]] = None  # e.g. ["url_like", "identifier_like"]
    content_type_category: Optional[str] = None
    is_authenticated: Optional[bool] = None
    time_start: Optional[datetime] = None
    time_end: Optional[datetime] = None
    source_tool: Optional[str] = None
    has_param_name: Optional[str] = None            # record has a param with this name
    request_id: Optional[str] = None                 # exact match
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class TrafficQueryResult(BaseModel):
    total: int
    records: list[TrafficRecord]


class TrafficStats(BaseModel):
    total_records: int
    total_hosts: int
    hosts: list[dict[str, Any]]          # [{host, count}, ...]
    method_distribution: dict[str, int]
    content_type_distribution: dict[str, int]                # request side
    response_content_type_distribution: dict[str, int]       # response side
    param_category_distribution: dict[str, int]
    authenticated_count: int
    latest_timestamp: Optional[datetime] = None
