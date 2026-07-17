"""FastAPI REST routes for downstream vulnerability scanners."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from ai_scraper.config import get_config
from ai_scraper.service import AiScraperService, get_service
from ai_scraper.storage.models import TrafficQuery, TrafficQueryResult, TrafficStats

logger = logging.getLogger(__name__)


# ── API Key Auth ─────────────────────────────────────────────────────────────

def verify_api_key(request: Request) -> None:
    """FastAPI dependency: validate X-API-Key header against configured api_key.

    If api_key is not configured, a WARNING is logged once but all requests
    are allowed through (for local development convenience).
    """
    config = get_config()
    expected = config.api.api_key
    if expected is None:
        # Log once per process start — use a module-level flag
        if not getattr(verify_api_key, "_warned", False):
            logger.warning(
                "API key not set — all endpoints are unauthenticated. "
                "Set AI_SCRAPER__API__API_KEY in your environment."
            )
            verify_api_key._warned = True  # type: ignore[attr-defined]
        return

    provided = request.headers.get("X-API-Key") or request.headers.get("x-api-key")
    if not provided:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")
    if provided != expected:
        raise HTTPException(status_code=401, detail="Invalid API key")


router = APIRouter(
    prefix="/api/v1",
    tags=["traffic"],
    dependencies=[Depends(verify_api_key)],
)


# ── Traffic Query ────────────────────────────────────────────────────────────

@router.get("/traffic", response_model=TrafficQueryResult)
async def list_traffic(
    methods: Optional[str] = Query(None, description="Comma-separated HTTP methods"),
    hosts: Optional[str] = Query(None, description="Comma-separated hostnames"),
    param_categories: Optional[str] = Query(
        None, description="Comma-separated: url_like,identifier_like,token_like,file_like,generic_id"
    ),
    content_type_category: Optional[str] = Query(None),
    is_authenticated: Optional[bool] = Query(None),
    time_start: Optional[datetime] = Query(None),
    time_end: Optional[datetime] = Query(None),
    source_tool: Optional[str] = Query(None),
    has_param_name: Optional[str] = Query(None),
    request_id: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    service: AiScraperService = Depends(get_service),
):
    """Query traffic records with flexible filters.

    Downstream modules (IDOR, SSRF, etc.) use this as their primary data source.
    """
    filters = TrafficQuery(
        methods=methods.split(",") if methods else None,
        hosts=hosts.split(",") if hosts else None,
        param_categories=param_categories.split(",") if param_categories else None,
        content_type_category=content_type_category,
        is_authenticated=is_authenticated,
        time_start=time_start,
        time_end=time_end,
        source_tool=source_tool,
        has_param_name=has_param_name,
        request_id=request_id,
        limit=limit,
        offset=offset,
    )
    return await service.storage.query(filters)


@router.get("/traffic/stats", response_model=TrafficStats)
async def get_stats(
    service: AiScraperService = Depends(get_service),
):
    """Return aggregate statistics about stored traffic."""
    return await service.storage.get_stats()


@router.get("/traffic/{request_id}", response_model=dict)
async def get_traffic(
    request_id: str,
    service: AiScraperService = Depends(get_service),
):
    """Get a single traffic record by request_id."""
    record = await service.storage.get_by_request_id(request_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Record not found")
    return record.model_dump(mode="json")


# ── Stats ────────────────────────────────────────────────────────────────────

# ── Polling control ──────────────────────────────────────────────────────────

@router.post("/traffic/poll")
async def trigger_poll(
    service: AiScraperService = Depends(get_service),
):
    """Manually trigger a full pipeline cycle (poll → normalize → dedup → enrich → store)."""
    try:
        count = await service.run_once()
        state = service.poller.get_state()
        return {
            "status": "ok",
            "new_records_stored": count,
            "poller_state": state.model_dump(mode="json"),
        }
    except Exception as exc:
        logger.exception("Manual poll failed")
        raise HTTPException(status_code=500, detail=str(exc))


# ── Health ───────────────────────────────────────────────────────────────────

@router.get("/health")
async def health(
    service: AiScraperService = Depends(get_service),
):
    """Health check — includes Burp MCP connectivity status."""
    mcp_ok = False
    try:
        # Quick connectivity check by polling once (will fail fast if MCP is down)
        state = service.poller.get_state()
        mcp_ok = state.last_poll_at is not None
    except Exception:
        pass

    return {
        "status": "ok" if mcp_ok else "degraded",
        "mcp_connected": mcp_ok,
        "poller_state": service.poller.get_state().model_dump(mode="json"),
    }


# ── State ────────────────────────────────────────────────────────────────────

@router.get("/state")
async def get_state(
    service: AiScraperService = Depends(get_service),
):
    """Return the poller's current cursor state."""
    return service.poller.get_state().model_dump(mode="json")
