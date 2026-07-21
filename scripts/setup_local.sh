#!/usr/bin/env bash
# ── aiScraper local setup ──────────────────────────────────────────────────
# Sets up a native aiScraper install — only Postgres runs in
# Docker (Burp's MCP Server requires genuine localhost and rejects
# container-originated connections).
#
# Usage:  bash scripts/setup_local.sh
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== aiScraper local setup ==="
echo ""

# ── Prerequisites ──────────────────────────────────────────────────────────

if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 not found.  Install Python 3.10+ first."
    exit 1
fi

if ! command -v docker &>/dev/null; then
    echo "ERROR: docker not found.  Docker is needed for the Postgres"
    echo "       container (the app itself runs natively)."
    exit 1
fi

# ── Virtualenv ─────────────────────────────────────────────────────────────

if [ ! -d ".venv" ]; then
    echo "[1/3] Creating virtual environment..."
    python3 -m venv .venv
fi

echo "[1/3] Activating virtual environment..."
# shellcheck disable=SC1091
source .venv/bin/activate

echo "[2/3] Installing aiScraper + dependencies..."
pip install --upgrade pip -q
pip install "." -q

# ── Env file ───────────────────────────────────────────────────────────────

if [ ! -f ".env" ]; then
    echo "[3/3] Copying .env.example → .env..."
    cp .env.example .env
    echo ""
    echo "    ⚠️  .env created from template."
    echo "       Edit .env to set a strong POSTGRES__PASSWORD and API__API_KEY:"
    echo "         Python:  python3 -c 'import secrets; print(secrets.token_urlsafe(32))'"
    echo "         OpenSSL: openssl rand -hex 32"
else
    echo "[3/3] .env already exists — skipping (not overwriting)."
fi

# ── Done ───────────────────────────────────────────────────────────────────

echo ""
echo "Setup complete. Next steps:"
echo ""
echo "  1. Start Postgres (Docker only — the app runs natively):"
echo "       docker compose up -d postgres"
echo ""
echo "  2. Start aiScraper:"
echo "       source .venv/bin/activate"
echo "       python -m ai_scraper"
echo ""
echo "  3. Verify (use your X-API-Key if configured):"
echo "       curl -H 'X-API-Key: <key>' http://127.0.0.1:8700/api/v1/health"
echo ""
echo "  For persistent background running, see deploy/README.md"
