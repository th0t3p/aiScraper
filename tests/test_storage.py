"""Tests for the PostgresStorage layer (unit-level, no real DB required)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

from ai_scraper.config import PostgresConfig
from ai_scraper.normalizer.models import TrafficRecord
from ai_scraper.storage.storage import PostgresStorage


class TestDecodeJsonField:

    def test_none_returns_none(self):
        assert PostgresStorage._decode_json_field(None) is None

    def test_already_dict_returns_as_is(self):
        d = {"key": "value"}
        assert PostgresStorage._decode_json_field(d) is d

    def test_already_list_returns_as_is(self):
        lst = [1, 2, 3]
        assert PostgresStorage._decode_json_field(lst) is lst

    def test_json_string_decodes_to_dict(self):
        result = PostgresStorage._decode_json_field('{"host": "example.com"}')
        assert result == {"host": "example.com"}
        assert isinstance(result, dict)

    def test_json_string_decodes_to_list(self):
        result = PostgresStorage._decode_json_field('["a", "b"]')
        assert result == ["a", "b"]
        assert isinstance(result, list)

    def test_empty_json_object_string_decodes_to_dict(self):
        result = PostgresStorage._decode_json_field("{}")
        assert result == {}
        assert isinstance(result, dict)


class TestRowToRecordJsonbRoundTrip:
    """Verify that JSONB columns returned as raw strings by asyncpg
    (no type codec registered) are correctly decoded back into dicts
    by _row_to_record — the exact regression that was causing 500s."""

    @staticmethod
    def _make_mock_row(**overrides) -> MagicMock:
        """Build a mock asyncpg.Record whose dict() returns column values
        with JSONB fields as raw JSON strings (the default asyncpg
        behaviour without a registered type codec)."""
        defaults = {
            "request_id": "req-001",
            "method": "GET",
            "url": "https://api.example.com/test?x=1",
            "host": "api.example.com",
            "path": "/test",
            "query_params": '{"x": ["1"]}',
            "headers": '{"Host": "api.example.com", "Authorization": "Bearer tok"}',
            "body": None,
            "response_status": 200,
            "response_headers": '{"Content-Type": "application/json"}',
            "response_body": '{"ok": true}',
            "timestamp": datetime(2026, 7, 22, 12, 0, 0, tzinfo=timezone.utc),
            "source_tool": "burp",
            "tags": '{"content_type_category": "json", "is_authenticated": "true"}',
        }
        defaults.update(overrides)
        row = MagicMock()
        row.__getitem__ = lambda self, k: defaults[k]
        row.get = lambda self, k, default=None: defaults.get(k, default)
        row.__iter__ = lambda self: iter(defaults.items())
        # asyncpg.Record → dict conversion
        row.keys = lambda: defaults.keys()

        # Make dict(row) work by providing items()
        def _items():
            return defaults.items()
        row.items = _items
        return row

    def test_query_params_decoded_to_dict(self):
        row = self._make_mock_row()
        record = PostgresStorage._row_to_record(row)
        assert isinstance(record.query_params, dict)
        assert record.query_params == {"x": ["1"]}

    def test_headers_decoded_to_dict(self):
        row = self._make_mock_row()
        record = PostgresStorage._row_to_record(row)
        assert isinstance(record.headers, dict)
        assert record.headers["Authorization"] == "Bearer tok"

    def test_response_headers_decoded_to_dict(self):
        row = self._make_mock_row()
        record = PostgresStorage._row_to_record(row)
        assert isinstance(record.response_headers, dict)
        assert record.response_headers["Content-Type"] == "application/json"

    def test_tags_decoded_to_dict(self):
        row = self._make_mock_row()
        record = PostgresStorage._row_to_record(row)
        assert isinstance(record.tags, dict)
        assert record.tags["content_type_category"] == "json"

    def test_null_response_headers_handled(self):
        """response_headers can legitimately be None (no response captured)."""
        row = self._make_mock_row(response_headers=None)
        record = PostgresStorage._row_to_record(row)
        assert record.response_headers == {}

    def test_empty_json_object_preserved(self):
        """{} should decode to an empty dict, not be swallowed."""
        row = self._make_mock_row(query_params="{}", tags="{}")
        record = PostgresStorage._row_to_record(row)
        assert record.query_params == {}
        assert record.tags == {}
        assert isinstance(record.query_params, dict)
        assert isinstance(record.tags, dict)

    def test_full_record_round_trip(self):
        """Insert → read-back: all JSONB columns survive the round-trip
        with correct types and values."""
        original = TrafficRecord(
            request_id="req-roundtrip",
            method="POST",
            url="https://api.example.com/callback?url=https://evil.com",
            host="api.example.com",
            path="/callback",
            query_params={"url": ["https://evil.com"], "redirect": ["https://target.com"]},
            headers={"Host": "api.example.com", "Content-Type": "application/json"},
            body='{"payload": "test"}',
            response_status=302,
            response_headers={"Location": "https://safe.com"},
            response_body=None,
            timestamp=datetime(2026, 7, 22, 12, 0, 0, tzinfo=timezone.utc),
            source_tool="burp",
            tags={"content_type_category": "json", "param_categories": {"url": "url_like"}},
        )

        # Simulate the write path: json.dumps each JSONB field
        params = PostgresStorage._record_to_params(original)
        # params order: request_id, method, url, host, path, query_params,
        #   headers, body, response_status, response_headers, response_body,
        #   timestamp, source_tool, tags
        assert params[5] == json.dumps(original.query_params)
        assert params[6] == json.dumps(original.headers)
        assert params[9] == json.dumps(original.response_headers)
        assert params[13] == json.dumps(original.tags)

        # Simulate the read path: build a mock row with JSONB fields as
        # raw strings (asyncpg's default behaviour)
        row = self._make_mock_row(
            request_id=original.request_id,
            method=original.method,
            url=original.url,
            host=original.host,
            path=original.path,
            query_params=params[5],       # raw JSON string
            headers=params[6],            # raw JSON string
            body=original.body,
            response_status=original.response_status,
            response_headers=params[9],   # raw JSON string
            response_body=original.response_body,
            timestamp=original.timestamp,
            source_tool=original.source_tool,
            tags=params[13],              # raw JSON string
        )

        record = PostgresStorage._row_to_record(row)

        # All JSONB-backed fields must be dicts, not strings
        assert isinstance(record.query_params, dict)
        assert isinstance(record.headers, dict)
        assert isinstance(record.response_headers, dict)
        assert isinstance(record.tags, dict)

        # Values must survive the round-trip
        assert record.query_params == original.query_params
        assert record.headers == original.headers
        assert record.response_headers == original.response_headers
        assert record.tags == original.tags

        # Non-JSONB fields
        assert record.request_id == original.request_id
        assert record.method == original.method
        assert record.url == original.url
        assert record.body == original.body
        assert record.response_status == original.response_status
