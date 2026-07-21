"""Deduplicator data models."""

from __future__ import annotations

from typing import List

from pydantic import BaseModel

from ai_scraper.normalizer.models import TrafficRecord


class DedupGroup(BaseModel):
    """A group of records sharing the same dedup key."""

    dedup_key: str
    sample_count: int   # how many samples were retained
    total_count: int    # how many records in the raw group
    samples: list[TrafficRecord]
