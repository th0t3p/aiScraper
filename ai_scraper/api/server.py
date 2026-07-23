"""FastAPI application factory."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ai_scraper.api.routes import router, health_router
from ai_scraper.config import ApiConfig, apply_cli_overrides, get_config
from ai_scraper.service import AiScraperService, init_service, shutdown_service

logger = logging.getLogger(__name__)


def _configure_logging() -> None:
    """Set up application-wide logging.

    Called from both `__main__.py` and `run_server()` so every entrypoint
    has consistent output.  Respects the `AI_SCRAPER__DEBUG` config flag:
    DEBUG=true → DEBUG level, otherwise INFO.
    """
    level = logging.DEBUG if get_config().debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle for the FastAPI app."""
    # Startup
    logger.info("Starting AI Scraper service...")
    service = await init_service()
    await service.start()
    yield
    # Shutdown
    logger.info("Shutting down AI Scraper service...")
    await shutdown_service()


def create_app(config: ApiConfig | None = None) -> FastAPI:
    """Build and return a configured FastAPI application."""
    api_config = config or get_config().api

    app = FastAPI(
        title="AI Scraper",
        description="Burp Suite proxy traffic ingestion & normalization service for bug bounty orchestration",
        version="0.1.0",
        lifespan=lifespan,
    )

    # CORS — validate dangerous combinations
    origins = api_config.cors_origins
    if "*" in origins and len(origins) > 1:
        logger.error(
            "CORS misconfiguration: allow_origins contains '*' alongside other origins. "
            "This is invalid — '*' must be the sole origin when used."
        )
    if "*" in origins:
        # When allow_credentials=True, allow_origins=["*"] is a CORS spec violation.
        # Browsers will reject the response. Force allow_credentials=False for safety.
        logger.warning(
            "CORS: allow_origins=['*'] is incompatible with allow_credentials=True. "
            "Forcing allow_credentials=False. To use credentials, specify explicit origins."
        )
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=False,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    else:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=bool(origins),  # only allow credentials if explicit origins are set
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # Routes
    app.include_router(router)
    app.include_router(health_router)

    return app


def run_server(cli_overrides=None) -> None:
    """Entry point for `python -m ai_scraper.api.server`.

    Parameters
    ----------
    cli_overrides:
        An ``argparse.Namespace`` from ``_parse_args()``, or ``None``.
        When provided, CLI values take precedence over .env-derived
        config for this run only.
    """
    import uvicorn

    _configure_logging()
    config = get_config()
    if cli_overrides is not None:
        apply_cli_overrides(config, cli_overrides)
    uvicorn.run(
        "ai_scraper.api.server:create_app",
        host=config.api.host,
        port=config.api.port,
        reload=config.reload,
        factory=True,
    )


if __name__ == "__main__":
    run_server()
