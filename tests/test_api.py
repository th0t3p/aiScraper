"""Tests for the FastAPI REST endpoints."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from ai_scraper.api.routes import router, health_router
from ai_scraper.service import get_service
from ai_scraper.normalizer.models import TrafficRecord
from ai_scraper.storage.models import TrafficQueryResult, TrafficStats
from ai_scraper.config import ApiConfig, AppConfig, get_config, set_config
from datetime import datetime, timezone


@pytest.fixture
def mock_service():
    """Create a fully mocked AiScraperService."""
    svc = MagicMock()
    svc.poller = MagicMock()
    svc.poller.get_state.return_value = MagicMock()
    svc.poller.get_state.return_value.model_dump.return_value = {
        "consumed_count": 0, "total_polled": 0, "last_poll_at": None,
    }
    svc.storage = MagicMock()
    svc.storage.query = AsyncMock()
    svc.storage.get_by_request_id = AsyncMock()
    svc.storage.get_stats = AsyncMock()
    svc.run_once = AsyncMock()
    return svc


@pytest.fixture
def client(mock_service):
    """Create a TestClient with mocked service — bypasses lifespan/PostgreSQL.

    Includes the correct X-API-Key header matching the autouse config fixture
    in conftest.py, so tests exercise the real auth path.
    """
    app = FastAPI()
    app.include_router(router)
    app.include_router(health_router)
    app.dependency_overrides[get_service] = lambda: mock_service
    with TestClient(app, headers={"X-API-Key": "test-api-key"}) as c:
        yield c


@pytest.fixture
def unauth_client(mock_service):
    """TestClient that does NOT send an X-API-Key header.

    Used by auth tests to verify that requests without the correct key
    are rejected.
    """
    app = FastAPI()
    app.include_router(router)
    app.include_router(health_router)
    app.dependency_overrides[get_service] = lambda: mock_service
    with TestClient(app) as c:
        yield c


class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        assert "status" in response.json()


class TestStateEndpoint:
    def test_state_returns_poller_info(self, client):
        response = client.get("/api/v1/state")
        assert response.status_code == 200
        data = response.json()
        assert "consumed_count" in data
        assert "total_polled" in data


class TestTrafficQueryEndpoint:
    def test_query_with_filters(self, client, mock_service):
        mock_service.storage.query.return_value = TrafficQueryResult(
            total=1,
            records=[
                TrafficRecord(
                    request_id="burp:1",
                    method="GET",
                    url="https://api.example.com/users/1",
                    host="api.example.com",
                    path="/users/1",
                    query_params={"id": ["1"]},
                    headers={"authorization": "Bearer xxx"},
                    body=None,
                    response_status=200,
                    response_headers={"content-type": "application/json"},
                    response_body='{"user":{"id":1}}',
                    timestamp=datetime.now(timezone.utc),
                    source_tool="burp",
                    tags={"param_categories": {"id": "identifier_like"}, "is_authenticated": True},
                )
            ],
        )
        response = client.get(
            "/api/v1/traffic?param_categories=identifier_like&is_authenticated=true&limit=10"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert len(data["records"]) == 1
        assert data["records"][0]["host"] == "api.example.com"

    def test_query_empty_result(self, client, mock_service):
        mock_service.storage.query.return_value = TrafficQueryResult(total=0, records=[])
        response = client.get("/api/v1/traffic")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0


class TestGetTrafficById:
    def test_found(self, client, mock_service):
        record = TrafficRecord(
            request_id="burp:42",
            method="POST",
            url="https://api.example.com/webhook",
            host="api.example.com",
            path="/webhook",
            query_params={"url": ["https://evil.com"]},
            headers={},
            body=None,
            response_status=200,
            response_headers={},
            response_body="ok",
            timestamp=datetime.now(timezone.utc),
            source_tool="burp",
            tags={},
        )
        mock_service.storage.get_by_request_id.return_value = record
        response = client.get("/api/v1/traffic/burp:42")
        assert response.status_code == 200
        assert response.json()["request_id"] == "burp:42"

    def test_not_found(self, client, mock_service):
        mock_service.storage.get_by_request_id.return_value = None
        response = client.get("/api/v1/traffic/burp:999")
        assert response.status_code == 404


class TestStatsEndpoint:
    def test_stats(self, client, mock_service):
        mock_service.storage.get_stats.return_value = TrafficStats(
            total_records=100,
            total_hosts=3,
            hosts=[{"host": "api.example.com", "count": 80}],
            method_distribution={"GET": 60, "POST": 40},
            content_type_distribution={"json": 70, "form": 30},
            response_content_type_distribution={"json": 65, "html": 35},
            param_category_distribution={"identifier_like": 50, "url_like": 20},
            authenticated_count=45,
            latest_timestamp=datetime.now(timezone.utc),
        )
        response = client.get("/api/v1/traffic/stats")
        assert response.status_code == 200
        data = response.json()
        assert data["total_records"] == 100
        assert len(data["hosts"]) == 1


class TestPollEndpoint:
    def test_manual_poll(self, client, mock_service):
        mock_service.run_once.return_value = 5
        response = client.post("/api/v1/traffic/poll")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["new_records_stored"] == 5

    def test_poll_error(self, client, mock_service):
        mock_service.run_once.side_effect = RuntimeError("MCP unreachable")
        response = client.post("/api/v1/traffic/poll")
        assert response.status_code == 500


class TestAuth:
    """Verify that the verify_api_key dependency actually enforces auth.

    These tests exist because the entire auth path was previously
    untested — requests were silently succeeding or failing depending
    on whether the developer's disk had a .env with an api_key set.
    """

    def test_missing_key_returns_401(self, unauth_client):
        response = unauth_client.get("/api/v1/state")
        assert response.status_code == 401
        assert "Missing X-API-Key" in response.json()["detail"]

    def test_wrong_key_returns_401(self, mock_service):
        app = FastAPI()
        app.include_router(router)
        app.include_router(health_router)
        app.dependency_overrides[get_service] = lambda: mock_service
        with TestClient(app, headers={"X-API-Key": "wrong-key"}) as c:
            response = c.get("/api/v1/state")
            assert response.status_code == 401
            assert "Invalid API key" in response.json()["detail"]

    def test_correct_key_passes_through(self, client):
        response = client.get("/api/v1/state")
        assert response.status_code == 200

    def test_no_key_required_when_api_key_is_none(self, unauth_client):
        """When api_key is None, all authenticated endpoints pass through."""
        original = get_config()
        try:
            set_config(AppConfig(api=ApiConfig(api_key=None)))
            response = unauth_client.get("/api/v1/state")
            assert response.status_code == 200
        finally:
            set_config(original)

    def test_health_always_open(self, unauth_client):
        """Health endpoint must return 200 without auth even when api_key is set.

        Docker HEALTHCHECK has no mechanism to supply an X-API-Key header,
        so /health is intentionally outside the authenticated router.
        """
        response = unauth_client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "mcp_connected" in data

    def test_state_still_requires_auth(self, unauth_client):
        """Regression guard: /state must remain behind auth.

        /health was the only endpoint moved to the unauthenticated router.
        If /state ever stops returning 401 here, someone accidentally
        moved it out of the authenticated router.
        """
        response = unauth_client.get("/api/v1/state")
        assert response.status_code == 401
