"""Tests for the Deduplicator module."""

from __future__ import annotations

import pytest

from ai_scraper.config import DedupConfig
from ai_scraper.deduplicator.deduplicator import Deduplicator
from ai_scraper.normalizer.models import TrafficRecord
from datetime import datetime, timezone


def _make_record(
    request_id: str = "burp:1",
    method: str = "GET",
    host: str = "api.example.com",
    path: str = "/users/123/orders",
    query_params: dict | None = None,
    response_status: int = 200,
    response_body: str = "{}",
    timestamp: datetime | None = None,
) -> TrafficRecord:
    return TrafficRecord(
        request_id=request_id,
        method=method,
        url=f"https://{host}{path}",
        host=host,
        path=path,
        query_params=query_params or {},
        headers={},
        body=None,
        response_status=response_status,
        response_headers={},
        response_body=response_body,
        timestamp=timestamp or datetime.now(timezone.utc),
        source_tool="burp",
    )


class TestPathTemplate:
    """Tests for path_to_template normalization."""

    def test_numeric_id_replaced(self):
        assert Deduplicator._path_to_template("/users/123/profile") == "/users/{id}/profile"

    def test_uuid_replaced(self):
        assert Deduplicator._path_to_template(
            "/items/a1b2c3d4-e5f6-7890-abcd-ef1234567890/detail"
        ) == "/items/{id}/detail"

    def test_mongo_objectid_replaced(self):
        assert Deduplicator._path_to_template(
            "/docs/507f1f77bcf86cd799439011/view"
        ) == "/docs/{id}/view"

    def test_multiple_replacements(self):
        result = Deduplicator._path_to_template("/users/42/posts/108/comments/abc123def456")
        assert result == "/users/{id}/posts/{id}/comments/{id}"

    def test_static_path_unchanged(self):
        assert Deduplicator._path_to_template("/api/health") == "/api/health"
        assert Deduplicator._path_to_template("/users/me") == "/users/me"


class TestDedupKey:
    """Tests for dedup key computation."""

    def test_same_path_different_ids_same_key(self):
        d = Deduplicator()
        r1 = _make_record(path="/users/1/profile")
        r2 = _make_record(path="/users/999/profile")
        assert d._compute_key(r1) == d._compute_key(r2)

    def test_different_methods_different_key(self):
        d = Deduplicator()
        r1 = _make_record(method="GET", path="/users/1")
        r2 = _make_record(method="POST", path="/users/1")
        assert d._compute_key(r1) != d._compute_key(r2)

    def test_different_hosts_different_key(self):
        d = Deduplicator()
        r1 = _make_record(host="a.com")
        r2 = _make_record(host="b.com")
        assert d._compute_key(r1) != d._compute_key(r2)

    def test_same_params_different_values_same_key(self):
        d = Deduplicator()
        r1 = _make_record(query_params={"id": ["1"], "token": ["a"]})
        r2 = _make_record(query_params={"token": ["b"], "id": ["2"]})
        # sorted_param_names should be the same: ["id", "token"]
        assert d._compute_key(r1) == d._compute_key(r2)


class TestDeduplicate:
    """Tests for the main deduplicate method."""

    def test_single_group(self):
        d = Deduplicator()
        records = [
            _make_record(request_id="burp:1", path="/users/1", response_status=200, response_body="a"),
            _make_record(request_id="burp:2", path="/users/2", response_status=200, response_body="b"),
            _make_record(request_id="burp:3", path="/users/3", response_status=404, response_body="c"),
            _make_record(request_id="burp:4", path="/users/4", response_status=200, response_body="d"),
        ]
        groups = d.deduplicate(records, max_samples=3)

        assert len(groups) == 1
        g = groups[0]
        assert g.total_count == 4
        assert g.sample_count <= 3
        assert len(g.samples) == g.sample_count

    def test_multiple_groups(self):
        d = Deduplicator()
        records = [
            _make_record(request_id="1", method="GET", path="/users/1"),
            _make_record(request_id="2", method="GET", path="/users/2"),
            _make_record(request_id="3", method="POST", path="/users/1"),
            _make_record(request_id="4", method="POST", path="/users/2"),
            _make_record(request_id="5", host="other.com", path="/users/1"),
        ]
        groups = d.deduplicate(records, max_samples=3)

        # GET api.example.com /users/{id}, POST api.example.com /users/{id}, GET other.com /users/{id}
        assert len(groups) == 3

    def test_diversity_selection_prefers_different_statuses(self):
        """Samples should include different response status codes."""
        d = Deduplicator()
        records = [
            _make_record(request_id=f"burp:{i}", path="/api/item", response_status=code, response_body=str(i))
            for i, code in enumerate([200, 200, 200, 403, 403, 500])
        ]
        groups = d.deduplicate(records, max_samples=3)
        g = groups[0]
        statuses = {s.response_status for s in g.samples}
        # Should have at least 2 different status codes if possible
        assert len(statuses) >= 2

    def test_disabled_passthrough(self):
        config = DedupConfig(enabled=False)
        d = Deduplicator(config=config)
        records = [
            _make_record(request_id="1", path="/users/1"),
            _make_record(request_id="2", path="/users/2"),
        ]
        groups = d.deduplicate(records)
        assert len(groups) == 2  # each record is its own group

    def test_fewer_records_than_limit(self):
        d = Deduplicator()
        records = [_make_record(request_id="1", path="/users/1")]
        groups = d.deduplicate(records, max_samples=3)
        assert groups[0].sample_count == 1
        assert groups[0].total_count == 1

    def test_is_duplicate(self):
        d = Deduplicator()
        r1 = _make_record(path="/users/1")
        r2 = _make_record(path="/users/2")
        keys = {d._compute_key(r1)}
        assert d.is_duplicate(r2, keys) is True
        assert d.is_duplicate(_make_record(host="other.com"), keys) is False
