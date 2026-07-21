"""Tests for the Normalizer module — raw HTTP text parsing."""

from __future__ import annotations

from datetime import datetime, timezone

from ai_scraper.poller.models import RawBurpRecord
from ai_scraper.normalizer.normalizer import Normalizer


class TestNormalize:
    """Tests for single-record normalization from raw HTTP text blobs."""

    def test_basic_fields(self, sample_raw_record):
        norm = Normalizer()
        result = norm.normalize(sample_raw_record)

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

    def test_timestamp_from_date_header(self):
        raw = RawBurpRecord(
            request="GET / HTTP/1.1\r\nHost: x.com\r\n\r\n",
            response="HTTP/1.1 200 OK\r\nDate: Mon, 21 Jul 2026 10:00:00 GMT\r\n\r\n",
        )
        norm = Normalizer()
        result = norm.normalize(raw)
        assert result.timestamp.year == 2026
        assert result.timestamp.month == 7
        assert result.timestamp.day == 21

    def test_timestamp_fallback(self):
        """Missing Date header → falls back to now()."""
        raw = RawBurpRecord(
            request="GET / HTTP/1.1\r\nHost: x.com\r\n\r\n",
            response="HTTP/1.1 200 OK\r\n\r\n",
        )
        norm = Normalizer()
        result = norm.normalize(raw)
        delta = abs((datetime.now(timezone.utc) - result.timestamp).total_seconds())
        assert delta < 5, f"Timestamp fallback too far off: {delta}s"

    def test_timestamp_lowercase_date_header(self):
        """HTTP/2 style lowercase 'date:' header."""
        raw = RawBurpRecord(
            request="GET / HTTP/1.1\r\nHost: x.com\r\n\r\n",
            response="HTTP/2 200 OK\r\ndate: Mon, 21 Jul 2026 14:30:00 GMT\r\n\r\n",
        )
        norm = Normalizer()
        result = norm.normalize(raw)
        assert result.timestamp.hour == 14
        assert result.timestamp.minute == 30

    def test_port_in_url(self):
        """Non-standard port should appear in URL."""
        raw = RawBurpRecord(
            request="GET /test?a=1 HTTP/1.1\r\nHost: x.com:8080\r\n\r\n",
            response="HTTP/1.1 200 OK\r\nDate: Mon, 01 Jan 2026 00:00:00 GMT\r\n\r\n",
        )
        norm = Normalizer()
        result = norm.normalize(raw)
        assert result.url == "http://x.com:8080/test?a=1"

    def test_standard_ports_omitted(self):
        """Port 80 → http, port 443 → https, omitted from URL."""
        raw_http = RawBurpRecord(
            request="GET / HTTP/1.1\r\nHost: x.com:80\r\n\r\n",
            response="HTTP/1.1 200 OK\r\nDate: Mon, 01 Jan 2026 00:00:00 GMT\r\n\r\n",
        )
        norm = Normalizer()
        assert norm.normalize(raw_http).url == "http://x.com/"

        raw_https = RawBurpRecord(
            request="GET / HTTP/1.1\r\nHost: x.com:443\r\n\r\n",
            response="HTTP/1.1 200 OK\r\nDate: Mon, 01 Jan 2026 00:00:00 GMT\r\n\r\n",
        )
        assert norm.normalize(raw_https).url == "https://x.com/"

    def test_protocol_from_x_forwarded_proto(self):
        raw = RawBurpRecord(
            request="GET / HTTP/1.1\r\nHost: x.com\r\nX-Forwarded-Proto: http\r\n\r\n",
            response="HTTP/1.1 200 OK\r\nDate: Mon, 01 Jan 2026 00:00:00 GMT\r\n\r\n",
        )
        norm = Normalizer()
        result = norm.normalize(raw)
        assert result.url.startswith("http://")

    def test_empty_headers(self):
        raw = RawBurpRecord(
            request="GET / HTTP/1.1\r\nHost: x.com\r\n\r\n",
            response="HTTP/1.1 200 OK\r\n\r\n",
        )
        norm = Normalizer()
        result = norm.normalize(raw)
        assert result.headers == {"host": "x.com"}
        assert result.response_headers == {}

    def test_malformed_headers_skipped(self):
        raw = RawBurpRecord(
            request="GET / HTTP/1.1\r\nHost: example.com\r\nThisIsNotAHeader\r\nNoColonHere\r\n\r\n",
            response="HTTP/1.1 200 OK\r\nDate: Mon, 01 Jan 2026 00:00:00 GMT\r\n\r\n",
        )
        norm = Normalizer()
        result = norm.normalize(raw)
        assert result.headers["host"] == "example.com"
        # Malformed lines are silently skipped

    def test_duplicate_set_cookie_merged(self):
        """Multiple Set-Cookie headers should be merged, not silently overwritten."""
        raw = RawBurpRecord(
            request="GET / HTTP/1.1\r\nHost: x.com\r\nSet-Cookie: session=abc\r\nSet-Cookie: csrf=xyz\r\n\r\n",
            response="HTTP/1.1 200 OK\r\nDate: Mon, 01 Jan 2026 00:00:00 GMT\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Type: text/html\r\n\r\n",
        )
        norm = Normalizer()
        result = norm.normalize(raw)
        assert "session=abc" in result.headers["set-cookie"]
        assert "csrf=xyz" in result.headers["set-cookie"]
        assert result.response_headers is not None
        assert "a=1" in result.response_headers["set-cookie"]
        assert "b=2" in result.response_headers["set-cookie"]

    def test_request_body_parsing(self):
        raw = RawBurpRecord(
            request="POST /api/login HTTP/1.1\r\nHost: x.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 19\r\n\r\nuser=admin&pass=123",
            response="HTTP/1.1 302 Found\r\nDate: Mon, 01 Jan 2026 00:00:00 GMT\r\n\r\n",
        )
        norm = Normalizer()
        result = norm.normalize(raw)
        assert result.body == "user=admin&pass=123"

    def test_method_and_path_extracted(self):
        raw = RawBurpRecord(
            request="POST /api/v2/submit?debug=1 HTTP/1.1\r\nHost: x.com\r\n\r\n",
            response="HTTP/1.1 201 Created\r\nDate: Mon, 01 Jan 2026 00:00:00 GMT\r\n\r\n",
        )
        norm = Normalizer()
        result = norm.normalize(raw)
        assert result.method == "POST"
        assert result.path == "/api/v2/submit"
        assert result.query_params == {"debug": ["1"]}

    def test_ipv6_host(self):
        raw = RawBurpRecord(
            request="GET /api HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n",
            response="HTTP/1.1 200 OK\r\nDate: Mon, 01 Jan 2026 00:00:00 GMT\r\n\r\n",
        )
        norm = Normalizer()
        result = norm.normalize(raw)
        assert result.host == "::1"
        assert "8080" in result.url


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
    """Tests for param_names with JSON body parsing.
    These tests construct TrafficRecord directly — they test the model
    logic, not the normalizer."""

    def test_flat_json_body(self):
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
