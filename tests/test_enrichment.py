"""Tests for the Enrichment module."""

from __future__ import annotations

import pytest

from ai_scraper.enrichment.enricher import Enricher, ParamCategory, ContentTypeCategory
from ai_scraper.normalizer.models import TrafficRecord
from datetime import datetime, timezone


def _make_record(
    method: str = "GET",
    host: str = "api.example.com",
    path: str = "/test",
    query_params: dict | None = None,
    headers: dict | None = None,
    body: str | None = None,
    response_status: int = 200,
    response_headers: dict | None = None,
    response_body: str | None = None,
) -> TrafficRecord:
    qp = query_params or {}
    qs = "&".join(f"{k}={v[0]}" for k, v in qp.items()) if qp else ""
    url = f"https://{host}{path}"
    if qs:
        url += "?" + qs
    return TrafficRecord(
        request_id="burp:test",
        method=method,
        url=url,
        host=host,
        path=path,
        query_params=qp,
        headers=headers or {},
        body=body,
        response_status=response_status,
        response_headers=response_headers or {},
        response_body=response_body,
        timestamp=datetime.now(timezone.utc),
        source_tool="burp",
    )


class TestParamClassification:
    """Tests for parameter name classification."""

    def test_url_like_params(self):
        enricher = Enricher()
        record = _make_record(query_params={
            "url": ["https://evil.com"],
            "webhook": ["https://hook.com"],
            "callback": ["https://cb.com"],
            "redirect": ["/dashboard"],
        })
        result = enricher.enrich(record)
        cats = result.tags["param_categories"]
        assert cats["url"] == ParamCategory.URL_LIKE.value
        assert cats["webhook"] == ParamCategory.URL_LIKE.value
        assert cats["callback"] == ParamCategory.URL_LIKE.value
        assert cats["redirect"] == ParamCategory.URL_LIKE.value

    def test_identifier_like_params(self):
        enricher = Enricher()
        record = _make_record(query_params={
            "id": ["123"],
            "uid": ["abc"],
            "order_id": ["456"],
        })
        result = enricher.enrich(record)
        cats = result.tags["param_categories"]
        assert cats["id"] == ParamCategory.IDENTIFIER_LIKE.value
        assert cats["uid"] == ParamCategory.IDENTIFIER_LIKE.value
        assert cats["order_id"] == ParamCategory.IDENTIFIER_LIKE.value

    def test_token_like_params(self):
        enricher = Enricher()
        record = _make_record(query_params={
            "token": ["xxx"],
            "api_key": ["yyy"],
        })
        result = enricher.enrich(record)
        cats = result.tags["param_categories"]
        assert cats["token"] == ParamCategory.TOKEN_LIKE.value
        assert cats["api_key"] == ParamCategory.TOKEN_LIKE.value

    def test_file_like_params(self):
        enricher = Enricher()
        record = _make_record(query_params={"file": ["test.pdf"], "path": ["/etc/passwd"]})
        result = enricher.enrich(record)
        cats = result.tags["param_categories"]
        assert cats["file"] == ParamCategory.FILE_LIKE.value
        assert cats["path"] == ParamCategory.FILE_LIKE.value

    def test_generic_id_params(self):
        """Params ending in _id/Id/ID but not in specific lists → generic_id."""
        enricher = Enricher()
        record = _make_record(query_params={"customer_id": ["1"], "productId": ["2"]})
        result = enricher.enrich(record)
        cats = result.tags["param_categories"]
        assert cats["customer_id"] == ParamCategory.GENERIC_ID.value
        assert cats["productId"] == ParamCategory.GENERIC_ID.value

    def test_unclassified_params(self):
        enricher = Enricher()
        record = _make_record(query_params={"q": ["search"], "page": ["1"]})
        result = enricher.enrich(record)
        cats = result.tags["param_categories"]
        assert cats["q"] == ParamCategory.UNCLASSIFIED.value
        assert cats["page"] == ParamCategory.UNCLASSIFIED.value

    def test_form_body_params_classified(self):
        """Params from urlencoded form body should also be classified."""
        enricher = Enricher()
        record = _make_record(
            headers={"content-type": "application/x-www-form-urlencoded"},
            body="url=https://evil.com&id=123",
        )
        result = enricher.enrich(record)
        cats = result.tags["param_categories"]
        assert "url" in cats
        assert cats["url"] == ParamCategory.URL_LIKE.value
        assert "id" in cats
        assert cats["id"] == ParamCategory.IDENTIFIER_LIKE.value

    def test_case_insensitive_param_names(self):
        """URL=/Url= should all match."""
        enricher = Enricher()
        record = _make_record(query_params={"URL": ["https://evil.com"], "Id": ["1"]})
        result = enricher.enrich(record)
        cats = result.tags["param_categories"]
        assert cats["URL"] == ParamCategory.URL_LIKE.value
        assert cats["Id"] == ParamCategory.IDENTIFIER_LIKE.value


class TestContentTypeClassification:
    """Tests for Content-Type classification."""

    def test_json(self):
        ct = Enricher._classify_content_type("application/json")
        assert ct == ContentTypeCategory.JSON

    def test_json_with_charset(self):
        ct = Enricher._classify_content_type("application/json; charset=utf-8")
        assert ct == ContentTypeCategory.JSON

    def test_form_urlencoded(self):
        ct = Enricher._classify_content_type("application/x-www-form-urlencoded")
        assert ct == ContentTypeCategory.FORM

    def test_multipart(self):
        ct = Enricher._classify_content_type("multipart/form-data; boundary=abc")
        assert ct == ContentTypeCategory.MULTIPART

    def test_xml(self):
        ct = Enricher._classify_content_type("text/xml")
        assert ct == ContentTypeCategory.XML

    def test_html(self):
        ct = Enricher._classify_content_type("text/html")
        assert ct == ContentTypeCategory.HTML

    def test_binary(self):
        assert Enricher._classify_content_type("application/octet-stream") == ContentTypeCategory.BINARY
        assert Enricher._classify_content_type("image/png") == ContentTypeCategory.BINARY

    def test_empty(self):
        assert Enricher._classify_content_type("") == ContentTypeCategory.UNKNOWN
        assert Enricher._classify_content_type("") == ContentTypeCategory.UNKNOWN


class TestAuthDetection:
    """Tests for authentication state detection."""

    def test_authorization_header(self):
        record = _make_record(headers={"authorization": "Bearer xxx"})
        result = Enricher().enrich(record)
        assert result.tags["is_authenticated"] is True

    def test_cookie_header(self):
        record = _make_record(headers={"cookie": "session=abc"})
        result = Enricher().enrich(record)
        assert result.tags["is_authenticated"] is True

    def test_no_auth(self):
        record = _make_record(headers={"accept": "application/json"})
        result = Enricher().enrich(record)
        assert result.tags["is_authenticated"] is False

    def test_case_insensitive_auth(self):
        record = _make_record(headers={"Authorization": "Bearer xxx"})
        result = Enricher().enrich(record)
        assert result.tags["is_authenticated"] is True


class TestFileUploadDetection:
    """Tests for file upload detection."""

    def test_multipart_with_file_param(self):
        record = _make_record(
            headers={"content-type": "multipart/form-data; boundary=x"},
            body="--x\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\ndata\r\n--x--",
        )
        result = Enricher().enrich(record)
        assert result.tags["has_file_upload"] is True

    def test_multipart_without_file_param(self):
        record = _make_record(
            headers={"content-type": "multipart/form-data; boundary=x"},
            body="--x\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nJohn\r\n--x--",
        )
        result = Enricher().enrich(record)
        assert result.tags["has_file_upload"] is False

    def test_not_multipart(self):
        record = _make_record(headers={"content-type": "application/json"})
        result = Enricher().enrich(record)
        assert result.tags["has_file_upload"] is False


class TestBatchEnrich:
    """Tests for batch enrichment."""

    def test_enrich_batch(self):
        records = [
            _make_record(query_params={"id": ["1"]}),
            _make_record(query_params={"url": ["https://a.com"]}),
        ]
        results = Enricher().enrich_batch(records)
        assert results[0].tags["param_categories"]["id"] == "identifier_like"
        assert results[1].tags["param_categories"]["url"] == "url_like"
