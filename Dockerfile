# ── AI Scraper Dockerfile ───────────────────────────────────────────────────
# Build:  docker build -t ai-scraper .
# Run:    docker run -p 8700:8700 --env-file .env ai-scraper

FROM python:3.11-slim

WORKDIR /app

# Install system dependencies:
#   libpq-dev + gcc → required to build asyncpg
#   git              → required to resolve the git+https:// dependency in pyproject.toml
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc git \
    && rm -rf /var/lib/apt/lists/*

# NOTE: All Python dependencies are now sourced entirely from pyproject.toml.
# Do NOT hardcode a separate pip install list here — use `pip install .` only.
COPY pyproject.toml .
COPY ai_scraper/ ai_scraper/
RUN pip install --no-cache-dir .

# Create non-root user
RUN useradd --create-home --shell /bin/bash scraper \
    && chown -R scraper:scraper /app
USER scraper

EXPOSE 8700

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8700/api/v1/health')" || exit 1

CMD ["python", "-m", "ai_scraper"]
