"""Entry point: `python -m ai_scraper` to start the API server."""

from __future__ import annotations

import argparse

from ai_scraper.api.server import run_server, _configure_logging


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ai_scraper",
        description="AI Scraper — Burp proxy traffic ingestion service",
    )
    parser.add_argument(
        "--mcp-backend",
        choices=["portswigger", "burpmcp_ultra"],
        default=None,
        help="Which MCP server implementation to connect to "
             "(overrides AI_SCRAPER__POLLER__MCP_BACKEND from .env "
             "for this run only). Default: value from .env, or "
             "'portswigger' if unset.",
    )
    parser.add_argument(
        "--mcp-sse-url",
        default=None,
        help="MCP server base URL, e.g. http://127.0.0.1:9876 "
             "(overrides AI_SCRAPER__POLLER__MCP_SSE_URL for this run only).",
    )
    parser.add_argument(
        "--mcp-auth-token",
        default=None,
        help="Bearer token for MCP backends that require auth "
             "(e.g. BurpMCP-Ultra). Overrides "
             "AI_SCRAPER__POLLER__MCP_AUTH_TOKEN for this run only. "
             "Prefer .env over this flag on shared machines, since "
             "CLI args are visible in shell history and `ps`.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    _configure_logging()
    run_server(cli_overrides=args)
