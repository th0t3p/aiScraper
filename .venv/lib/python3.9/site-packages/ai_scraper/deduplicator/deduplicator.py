"""Deduplicator — group similar traffic records & keep representative samples."""

from __future__ import annotations

import hashlib
import json
import logging
import re
from typing import List, Optional, Set

from ai_scraper.config import DedupConfig, get_config
from ai_scraper.normalizer.models import TrafficRecord
from ai_scraper.deduplicator.models import DedupGroup

logger = logging.getLogger(__name__)

# Patterns to replace concrete values in URL path segments
_PATH_VALUE_RE = re.compile(
    r"""
    \b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b  # UUID
    |\b[0-9a-f]{24,}\b                                                    # Mongo ObjectId / long hex
    |(?<=/)\d+(?=/|$)                                                     # numeric ID segment
    |(?<=/)[0-9a-f]{8,}(?=/|$)                                            # MD5 / short hex segment
    """,
    re.VERBOSE | re.IGNORECASE,
)

_PATH_PLACEHOLDER = "{id}"


class Deduplicator:
    """Deduplicates TrafficRecords by configurable key and keeps N samples per group.

    Default key: method + host + path_template + sorted(param_names)

    Samples are selected to maximize diversity (different response status codes
    and body lengths) so downstream modules can perform response-diff analysis.
    """

    def __init__(self, config: DedupConfig | None = None):
        self._config = config or get_config().dedup

    # ── Public API ───────────────────────────────────────────────────────────

    def deduplicate(
        self,
        records: list[TrafficRecord],
        max_samples: int | None = None,
    ) -> list[DedupGroup]:
        """Group records by dedup key, returning one DedupGroup per unique key.

        Args:
            records: List of normalized traffic records.
            max_samples: Override the configured max_samples (default 3).
        """
        if not self._config.enabled:
            # Pass-through: treat each record as its own group
            return [
                DedupGroup(
                    dedup_key=r.request_id,
                    sample_count=1,
                    total_count=1,
                    samples=[r],
                )
                for r in records
            ]

        limit = max_samples if max_samples is not None else self._config.max_samples

        # Phase 1: group by dedup key
        groups: dict[str, list[TrafficRecord]] = {}
        for record in records:
            key = self._compute_key(record)
            groups.setdefault(key, []).append(record)

        # Phase 2: select representative samples per group
        result: list[DedupGroup] = []
        for key, group_records in groups.items():
            samples = self._select_samples(group_records, limit)
            result.append(
                DedupGroup(
                    dedup_key=key,
                    sample_count=len(samples),
                    total_count=len(group_records),
                    samples=samples,
                )
            )

        logger.debug(
            "Dedup: %d records → %d groups (max_samples=%d)",
            len(records), len(result), limit,
        )
        return result

    def is_duplicate(self, record: TrafficRecord, existing_keys: set[str]) -> bool:
        """Check if a single record is a duplicate of any already-seen key."""
        return self._compute_key(record) in existing_keys

    # ── Key computation ──────────────────────────────────────────────────────

    def _compute_key(self, record: TrafficRecord) -> str:
        """Build a stable dedup key string."""
        parts: list[str] = []

        for field in self._config.key_fields:
            if field == "method":
                parts.append(record.method.upper())
            elif field == "host":
                parts.append(record.host)
            elif field == "path_template":
                parts.append(self._path_to_template(record.path))
            elif field == "sorted_param_names":
                names = record.param_names
                parts.append(",".join(sorted(names)))
            elif field == "url":
                parts.append(record.url)
            elif field == "path":
                parts.append(record.path)
            else:
                # Any arbitrary attribute access
                val = getattr(record, field, None)
                parts.append(str(val) if val is not None else "")

        raw = "|".join(parts)
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    @staticmethod
    def _path_to_template(path: str) -> str:
        """Replace dynamic segments (IDs, UUIDs, numeric values) with {id}.

        /users/123/orders/a1b2c3 → /users/{id}/orders/{id}
        """
        return _PATH_VALUE_RE.sub(_PATH_PLACEHOLDER, path)

    # ── Sample selection ─────────────────────────────────────────────────────

    @staticmethod
    def _select_samples(
        records: list[TrafficRecord], limit: int
    ) -> list[TrafficRecord]:
        """Pick up to `limit` records, maximizing response diversity.

        Strategy:
          1. Take one record per unique response status code.
          2. If still under limit, take one per unique response body length bucket.
          3. Fill remaining slots with records in timestamp order.
        """
        if len(records) <= limit:
            return list(records)

        selected: list[TrafficRecord] = []
        remaining = list(records)

        # Round 1: unique status codes
        seen_status: set[int] = set()
        round1_rest: list[TrafficRecord] = []
        for r in remaining:
            status = r.response_status or 0
            if status not in seen_status and len(selected) < limit:
                seen_status.add(status)
                selected.append(r)
            else:
                round1_rest.append(r)
        remaining = round1_rest

        # Round 2: unique body-length buckets (1000-byte granularity)
        if len(selected) < limit:
            seen_buckets: set[int] = set()
            round2_rest: list[TrafficRecord] = []
            for r in remaining:
                body_len = len(r.response_body or "")
                bucket = (body_len // 1000) * 1000
                if bucket not in seen_buckets and len(selected) < limit:
                    seen_buckets.add(bucket)
                    selected.append(r)
                else:
                    round2_rest.append(r)
            remaining = round2_rest

        # Round 3: fill remaining slots in timestamp order
        if len(selected) < limit:
            remaining.sort(key=lambda r: r.timestamp)
            needed = limit - len(selected)
            selected.extend(remaining[:needed])

        return selected[:limit]
