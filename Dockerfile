# ── AI Scraper Dockerfile ───────────────────────────────────────────────────
# Build:  docker build -t ai-scraper .
# Run:    docker run -p 8700:8700 --env-file .env ai-scraper

FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for asyncpg
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir \
    httpx pydantic pydantic-settings asyncpg \
    fastapi "uvicorn[standard]" apscheduler \
    && pip cache purge

# Copy application code
COPY ai_scraper/ ai_scraper/

# Create non-root user
RUN useradd --create-home --shell /bin/bash scraper \
    && chown -R scraper:scraper /app
USER scraper

EXPOSE 8700

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8700/api/v1/health')" || exit 1

CMD ["python", "-m", "ai_scraper"]
