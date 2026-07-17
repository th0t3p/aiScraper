"""Tests for the Normalizer module."""

from __future__ import annotations

from datetime import datetime, timezone

from ai_scraper.poller.models import RawBurpRecord
from ai_scraper.normalizer.normalizer import Normalizer


class TestNormalize:
    """Tests for single-record normalization."""

    def test_basic_fields(self, sample_raw_record):
        norm = Normalizer()
        result = norm.normalize(sample_raw_record)

        assert result.request_id == "burp:1"
        assert result.method == "GET"
        assert result.host == "api.example.com"
        assert result.path == "/users/123/orders"
        assert result.url == "https://api.example.com/users/123/orders?status=active&limit=10"
        assert result.source_tool == "burp"
        assert result.response_status == 200

    def test_query_params_parsing(self, sample_raw_record):
        norm = Normalizer()
        result = norm.normalize(sample_raw_record)

        assert result.query_params == {"status": ["active"], "limit": ["10"]}

    def test_headers_parsing(self, sample_raw_record):
        norm = Normalizer()
        result = norm.normalize(sample_raw_record)

        assert result.headers["host"] == "api.example.com"
        assert result.headers["authorization"] == "Bearer eyJxxx"
        assert result.headers["content-type"] == "application/json"

    def test_response_headers_parsing(self, sample_raw_record):
        norm = Normalizer()
        result = norm.normalize(sample_raw_record)

        assert result.response_headers is not None
        assert result.response_headers["content-type"] == "application/json"
        assert result.response_headers["content-length"] == "42"

    def test_timestamp_parsing(self):
        raw = RawBurpRecord(
            id=1, host="x.com", port=443, protocol="https",
            method="GET", path="/", query=None,
            request_headers="", request_body=None,
            response_status=None, response_headers=None, response_body=None,
            timestamp="2026-07-18T10:00:00+00:00",
        )
        norm = Normalizer()
        result = norm.normalize(raw)
        assert result.timestamp.year == 2026
        assert result.timestamp.month == 7
        assert result.timestamp.day == 18

    def test_timestamp_fallback(self):
        """Missing timestamp → falls back to now()."""
        raw = RawBurpRecord(
            id=1, host="x.com", port=443, protocol="https",
            method="GET", path="/", query=None,
            request_headers="", request_body=None,
            response_status=None, response_headers=None, response_body=None,
            timestamp=None,
        )
        norm = Normalizer()
        result = norm.normalize(raw)
        # Should be close to current time
        delta = abs((datetime.now(timezone.utc) - result.timestamp).total_seconds())
        assert delta < 5, f"Timestamp fallback too far off: {delta}s"

    def test_port_in_url(self):
        """Non-standard port should appear in URL."""
        raw = RawBurpRecord(
            id=1, host="x.com", port=8080, protocol="http",
            method="GET", path="/test", query="a=1",
            request_headers="", request_body=None,
            response_status=200, response_headers=None, response_body=None,
            timestamp="2026-01-01T00:00:00Z",
        )
        norm = Normalizer()
        result = norm.normalize(raw)
        assert result.url == "http://x.com:8080/test?a=1"

    def test_standard_port_omitted(self):
        """Port 80 for http / 443 for https should be omitted."""
        raw = RawBurpRecord(
            id=1, host="x.com", port=80, protocol="http",
            method="GET", path="/", query=None,
            request_headers="", request_body=None,
            response_status=200, response_headers=None, response_body=None,
            timestamp="2026-01-01T00:00:00Z",
        )
        norm = Normalizer()
        result = norm.normalize(raw)
        assert result.url == "http://x.com/"

    def test_empty_headers(self):
        raw = RawBurpRecord(
            id=1, host="x.com", port=443, protocol="https",
            method="GET", path="/", query=None,
            request_headers="", request_body=None,
            response_status=None, response_headers="", response_body=None,
            timestamp=None,
        )
        norm = Normalizer()
        result = norm.normalize(raw)
        assert result.headers == {}
        assert result.response_headers == {}

    def test_malformed_headers_skipped(self):
        raw = RawBurpRecord(
            id=1, host="x.com", port=443, protocol="https",
            method="GET", path="/", query=None,
            request_headers="This is not a header\nHost: example.com\nNoColonHere\n",
            request_body=None,
            response_status=None, response_headers=None, response_body=None,
            timestamp=None,
        )
        norm = Normalizer()
        result = norm.normalize(raw)
        # "This is not a header" and "NoColonHere" should be skipped
        assert result.headers == {"host": "example.com"}


class TestNormalizeBatch:
    """Tests for batch normalization."""

    def test_batch_returns_same_count(self, sample_raw_records):
        norm = Normalizer()
        results = norm.normalize_batch(sample_raw_records)
        assert len(results) == len(sample_raw_records)
        for r in results:
            assert r.source_tool == "burp"
            assert r.request_id.startswith("burp:")
