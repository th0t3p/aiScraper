"""PostgreSQL storage — async write & query for TrafficRecord."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import asyncpg

from ai_scraper.config import PostgresConfig, get_config
from ai_scraper.normalizer.models import TrafficRecord
from ai_scraper.storage.models import TrafficQuery, TrafficQueryResult, TrafficStats

logger = logging.getLogger(__name__)

# ── DDL ──────────────────────────────────────────────────────────────────────

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS traffic_log (
    request_id       TEXT PRIMARY KEY,
    method           TEXT NOT NULL,
    url              TEXT NOT NULL,
    host             TEXT NOT NULL,
    path             TEXT NOT NULL,
    query_params     JSONB DEFAULT '{}',
    headers          JSONB DEFAULT '{}',
    body             TEXT,
    response_status  INTEGER,
    response_headers JSONB,
    response_body    TEXT,
    timestamp        TIMESTAMPTZ NOT NULL,
    source_tool      TEXT NOT NULL DEFAULT 'burp',
    tags             JSONB DEFAULT '{}',
    created_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_traffic_host ON traffic_log(host);
CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_traffic_method ON traffic_log(method);
CREATE INDEX IF NOT EXISTS idx_traffic_tags ON traffic_log USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_traffic_source_tool ON traffic_log(source_tool);
"""


class PostgresStorage:
    """Async PostgreSQL-backed storage for traffic records."""

    def __init__(self, config: PostgresConfig | None = None):
        self._config = config or get_config().postgres
        self._pool: Optional[asyncpg.Pool] = None

    # ── Lifecycle ────────────────────────────────────────────────────────────

    async def connect(self) -> None:
        """Create the connection pool (call once on startup)."""
        self._pool = await asyncpg.create_pool(
            dsn=self._config.dsn,
            min_size=self._config.min_pool,
            max_size=self._config.max_pool,
        )
        logger.info("Connected to PostgreSQL at %s:%d", self._config.host, self._config.port)

    async def disconnect(self) -> None:
        """Close the connection pool."""
        if self._pool:
            await self._pool.close()
            self._pool = None
            logger.info("Disconnected from PostgreSQL")

    async def init_schema(self) -> None:
        """Ensure the traffic_log table and indexes exist (idempotent)."""
        assert self._pool is not None, "Call connect() first"
        async with self._pool.acquire() as conn:
            await conn.execute(_CREATE_TABLE_SQL)
        logger.info("Schema initialized")

    # ── Write ────────────────────────────────────────────────────────────────

    async def save(self, records: list[TrafficRecord]) -> int:
        """Insert or update records using batch executemany. Returns count written."""
        if not records:
            return 0
        assert self._pool is not None

        sql = """
        INSERT INTO traffic_log (
            request_id, method, url, host, path, query_params,
            headers, body, response_status, response_headers,
            response_body, timestamp, source_tool, tags
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
        ON CONFLICT (request_id) DO UPDATE SET
            response_status   = EXCLUDED.response_status,
            response_headers  = EXCLUDED.response_headers,
            response_body     = EXCLUDED.response_body,
            tags              = traffic_log.tags || EXCLUDED.tags,
            timestamp         = EXCLUDED.timestamp
        """

        params_list = [self._record_to_params(r) for r in records]

        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await conn.executemany(sql, params_list)

        logger.debug("Saved %d records to PostgreSQL (batch)", len(records))
        return len(records)

    # ── Query ────────────────────────────────────────────────────────────────

    async def query(self, filters: TrafficQuery) -> TrafficQueryResult:
        """Query records with filters; returns paginated result + total count."""
        assert self._pool is not None

        conditions: list[str] = []
        params: list[Any] = []
        p = 1  # parameter counter

        if filters.methods:
            conditions.append(f"method = ANY(${p})")
            params.append(filters.methods)
            p += 1
        if filters.hosts:
            conditions.append(f"host = ANY(${p})")
            params.append(filters.hosts)
            p += 1
        if filters.content_type_category:
            conditions.append(f"tags->>'content_type_category' = ${p}")
            params.append(filters.content_type_category)
            p += 1
        if filters.is_authenticated is not None:
            conditions.append(f"tags->>'is_authenticated' = ${p}::text")
            params.append(str(filters.is_authenticated).lower())
            p += 1
        if filters.time_start:
            conditions.append(f"timestamp >= ${p}")
            params.append(filters.time_start)
            p += 1
        if filters.time_end:
            conditions.append(f"timestamp <= ${p}")
            params.append(filters.time_end)
            p += 1
        if filters.source_tool:
            conditions.append(f"source_tool = ${p}")
            params.append(filters.source_tool)
            p += 1
        if filters.has_param_name:
            conditions.append(f"tags->'param_categories' ? ${p}")
            params.append(filters.has_param_name)
            p += 1
        if filters.request_id:
            conditions.append(f"request_id = ${p}")
            params.append(filters.request_id)
            p += 1
        if filters.param_categories:
            # Check if any value in tags->param_categories matches a requested category
            cat_list = [json.dumps(c) for c in filters.param_categories]
            conditions.append(
                f"EXISTS (SELECT 1 FROM jsonb_each_text(tags->'param_categories') AS kv "
                f"WHERE kv.value = ANY(${p}))"
            )
            params.append(cat_list)
            p += 1

        where_clause = ""
        if conditions:
            where_clause = "WHERE " + " AND ".join(conditions)

        # Count query
        count_sql = f"SELECT COUNT(*) FROM traffic_log {where_clause}"
        # Data query
        data_sql = (
            f"SELECT * FROM traffic_log {where_clause} "
            f"ORDER BY timestamp DESC LIMIT ${p} OFFSET ${p + 1}"
        )

        async with self._pool.acquire() as conn:
            total = await conn.fetchval(count_sql, *params)
            rows = await conn.fetch(data_sql, *params, filters.limit, filters.offset)

        records = [self._row_to_record(row) for row in rows]
        return TrafficQueryResult(total=total or 0, records=records)

    async def get_by_request_id(self, request_id: str) -> Optional[TrafficRecord]:
        """Get a single record by request_id."""
        assert self._pool is not None
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM traffic_log WHERE request_id = $1", request_id
            )
        if row is None:
            return None
        return self._row_to_record(row)

    async def get_stats(self) -> TrafficStats:
        """Return aggregate statistics."""
        assert self._pool is not None
        async with self._pool.acquire() as conn:
            total = await conn.fetchval("SELECT COUNT(*) FROM traffic_log") or 0
            total_hosts = await conn.fetchval(
                "SELECT COUNT(DISTINCT host) FROM traffic_log"
            ) or 0
            host_rows = await conn.fetch(
                "SELECT host, COUNT(*) as cnt FROM traffic_log "
                "GROUP BY host ORDER BY cnt DESC LIMIT 20"
            )
            method_rows = await conn.fetch(
                "SELECT method, COUNT(*) as cnt FROM traffic_log "
                "GROUP BY method ORDER BY cnt DESC"
            )
            ct_rows = await conn.fetch(
                "SELECT tags->>'content_type_category' as ct, COUNT(*) as cnt "
                "FROM traffic_log GROUP BY ct ORDER BY cnt DESC"
            )
            param_rows = await conn.fetch(
                "SELECT kv.value as cat, COUNT(*) as cnt "
                "FROM traffic_log, jsonb_each_text(tags->'param_categories') AS kv "
                "GROUP BY kv.value ORDER BY cnt DESC"
            )
            auth_count = await conn.fetchval(
                "SELECT COUNT(*) FROM traffic_log WHERE tags->>'is_authenticated' = 'true'"
            ) or 0
            latest = await conn.fetchval(
                "SELECT MAX(timestamp) FROM traffic_log"
            )

        return TrafficStats(
            total_records=total,
            total_hosts=total_hosts,
            hosts=[{"host": r["host"], "count": r["cnt"]} for r in host_rows],
            method_distribution={r["method"]: r["cnt"] for r in method_rows},
            content_type_distribution={r["ct"] or "unknown": r["cnt"] for r in ct_rows},
            param_category_distribution={r["cat"]: r["cnt"] for r in param_rows},
            authenticated_count=auth_count,
            latest_timestamp=latest,
        )

    # ── Internal helpers ─────────────────────────────────────────────────────

    @staticmethod
    def _decode_json_field(value):
        """Decode a JSONB column that asyncpg returned as a raw string.

        Without a ``set_type_codec`` registration on the pool, asyncpg
        returns JSONB columns as plain ``str`` (the JSON text), not as
        already-deserialized Python objects.  This helper handles all
        three cases:

        * ``None`` → ``None`` (NULL column, e.g. response_headers when
          there was no response).
        * already a dict / list → returned as-is (defensive, in case a
          codec is added later).
        * raw ``str`` → ``json.loads(value)``.
        """
        if value is None:
            return None
        if isinstance(value, (dict, list)):
            return value
        return json.loads(value)

    @staticmethod
    def _record_to_params(record: TrafficRecord) -> list[Any]:
        return [
            record.request_id,
            record.method,
            record.url,
            record.host,
            record.path,
            json.dumps(record.query_params),
            json.dumps(record.headers),
            record.body,
            record.response_status,
            json.dumps(record.response_headers) if record.response_headers else None,
            record.response_body,
            record.timestamp,
            record.source_tool,
            json.dumps(record.tags),
        ]

    @staticmethod
    def _row_to_record(row: asyncpg.Record) -> TrafficRecord:
        d = dict(row)
        # asyncpg returns JSONB columns as raw JSON text strings unless a
        # type codec is explicitly registered on the pool (_decode_json_field
        # handles decoding; the dict/list isinstance check is defensive in
        # case a codec gets added later).
        return TrafficRecord(
            request_id=d["request_id"],
            method=d["method"],
            url=d["url"],
            host=d["host"],
            path=d["path"],
            query_params=PostgresStorage._decode_json_field(d.get("query_params")) or {},
            headers=PostgresStorage._decode_json_field(d.get("headers")) or {},
            body=d.get("body"),
            response_status=d.get("response_status"),
            response_headers=PostgresStorage._decode_json_field(d.get("response_headers")) or {},
            response_body=d.get("response_body"),
            timestamp=d["timestamp"],
            source_tool=d.get("source_tool", "burp"),
            tags=PostgresStorage._decode_json_field(d.get("tags")) or {},
        )
