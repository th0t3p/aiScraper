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

    def test_duplicate_set_cookie_merged(self):
        """Multiple Set-Cookie headers should be merged, not silently overwritten."""
        raw = RawBurpRecord(
            id=1, host="x.com", port=443, protocol="https",
            method="GET", path="/", query=None,
            request_headers="Host: x.com\r\nSet-Cookie: session=abc\r\nSet-Cookie: csrf=xyz\r\n",
            request_body=None,
            response_status=200,
            response_headers="Set-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Type: text/html\r\n",
            response_body=None,
            timestamp=None,
        )
        norm = Normalizer()
        result = norm.normalize(raw)
        # Both Set-Cookie values should be present (merged with "; ")
        assert "session=abc" in result.headers["set-cookie"]
        assert "csrf=xyz" in result.headers["set-cookie"]
        # Response headers too
        assert result.response_headers is not None
        assert "a=1" in result.response_headers["set-cookie"]
        assert "b=2" in result.response_headers["set-cookie"]


class TestNormalizeBatch:
    """Tests for batch normalization."""

    def test_batch_returns_same_count(self, sample_raw_records):
        norm = Normalizer()
        results = norm.normalize_batch(sample_raw_records)
        assert len(results) == len(sample_raw_records)
        for r in results:
            assert r.source_tool == "burp"
            assert r.request_id.startswith("burp:")


class TestParamNamesJsonBody:
    """Tests for param_names with JSON body parsing."""

    def test_flat_json_body(self, sample_raw_record):
        from ai_scraper.normalizer.models import TrafficRecord
        from datetime import datetime, timezone
        record = TrafficRecord(
            request_id="burp:1", method="POST",
            url="https://api.example.com/items",
            host="api.example.com", path="/items",
            headers={"content-type": "application/json"},
            body='{"name": "test", "price": 100, "qty": 5}',
            timestamp=datetime.now(timezone.utc),
            source_tool="burp",
        )
        names = record.param_names
        assert "name" in names
        assert "price" in names
        assert "qty" in names

    def test_nested_json_body(self):
        from ai_scraper.normalizer.models import TrafficRecord
        from datetime import datetime, timezone
        record = TrafficRecord(
            request_id="burp:1", method="POST",
            url="https://api.example.com/order",
            host="api.example.com", path="/order",
            headers={"content-type": "application/json"},
            body='{"order": {"id": 1, "items": [{"sku": "A", "qty": 2}]}, "customer_id": 42}',
            timestamp=datetime.now(timezone.utc),
            source_tool="burp",
        )
        names = record.param_names
        assert "order" in names
        assert "id" in names
        assert "items" in names
        assert "sku" in names
        assert "qty" in names
        assert "customer_id" in names

    def test_invalid_json_silently_skipped(self):
        from ai_scraper.normalizer.models import TrafficRecord
        from datetime import datetime, timezone
        record = TrafficRecord(
            request_id="burp:1", method="POST",
            url="https://api.example.com/data",
            host="api.example.com", path="/data",
            headers={"content-type": "application/json"},
            body="{not valid json",
            timestamp=datetime.now(timezone.utc),
            source_tool="burp",
        )
        names = record.param_names
        assert isinstance(names, list)

    def test_has_param_named_json(self):
        from ai_scraper.normalizer.models import TrafficRecord
        from datetime import datetime, timezone
        record = TrafficRecord(
            request_id="burp:1", method="POST",
            url="https://api.example.com/data",
            host="api.example.com", path="/data",
            headers={"content-type": "application/json"},
            body='{"url": "https://evil.com", "id": 123}',
            timestamp=datetime.now(timezone.utc),
            source_tool="burp",
        )
        assert record.has_param_named("url") is True
        assert record.has_param_named("id") is True
        assert record.has_param_named("nonexistent") is False

    def test_has_param_named_multipart(self):
        from ai_scraper.normalizer.models import TrafficRecord
        from datetime import datetime, timezone
        record = TrafficRecord(
            request_id="burp:1", method="POST",
            url="https://api.example.com/upload",
            host="api.example.com", path="/upload",
            headers={"content-type": "multipart/form-data; boundary=x"},
            body='--x\r\nContent-Disposition: form-data; name="file"\r\n\r\ndata\r\n--x--',
            timestamp=datetime.now(timezone.utc),
            source_tool="burp",
        )
        assert record.has_param_named("file") is True
        assert record.has_param_named("nonexistent") is False

    def test_param_names_json_plus_query(self):
        from ai_scraper.normalizer.models import TrafficRecord
        from datetime import datetime, timezone
        record = TrafficRecord(
            request_id="burp:1", method="POST",
            url="https://api.example.com/data?token=abc",
            host="api.example.com", path="/data",
            query_params={"token": ["abc"]},
            headers={"content-type": "application/json"},
            body='{"user": "john", "role": "admin"}',
            timestamp=datetime.now(timezone.utc),
            source_tool="burp",
        )
        names = record.param_names
        assert "token" in names
        assert "user" in names
        assert "role" in names
