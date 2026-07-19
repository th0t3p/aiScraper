"""Entry point: `python -m ai_scraper` to start the API server."""

from ai_scraper.api.server import run_server, _configure_logging

if __name__ == "__main__":
    _configure_logging()
    run_server()
