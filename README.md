# aiScraper

Passive traffic capture layer for bug bounty tooling. Polls Burp Suite's
MCP server for proxy history, normalizes it into a consistent schema,
deduplicates, tags it with objective labels, and stores it in Postgres
behind a REST API — so downstream vulnerability-detection modules
(`aiSSRF`, IDOR testing, etc.) have one common place to pull candidate
traffic from, instead of each reimplementing its own Burp integration.

> **This service only reads and labels.** It never judges whether
> something is a vulnerability, never sends its own traffic, and never
> decides what's in scope beyond filtering to what you've configured.
> Judgment is a downstream module's job — see `aiSSRF`.

---

## Where it sits in the pipeline

```
┌─────────────┐     proxied      ┌──────────────┐
│  aiBrowser   │ ───traffic────▶ │  Burp Suite  │
│ (Playwright) │                 │  127.0.0.1:  │
└─────────────┘                 │  8080 (proxy)│
                                 │  9876 (MCP)  │
                                 └──────┬───────┘
                                        │ polled via MCP
                                        ▼
                              ┌───────────────────┐
                              │     aiScraper       │
                              │  poll → normalize   │
                              │  → dedup → enrich    │
                              │  → store             │
                              └─────────┬───────────┘
                                        │ REST API
                                        ▼
                              ┌───────────────────┐
                              │  aiSSRF, IDOR, …    │
                              │  (downstream        │
                              │   consumers)         │
                              └───────────────────┘
```

`aiScraper` never talks to `aiBrowser` directly, and never sends its own
HTTP requests to any target. It only polls Burp — anything Burp has
captured (from `aiBrowser`, from manual testing, from any other
Burp-proxied source) becomes visible here automatically.

---

## Prerequisites

| Component | Needed for | Notes |
|---|---|---|
| **Python 3.10+** | Running locally | Or skip straight to Docker — see below |
| **PostgreSQL** | Storage | `docker-compose up -d postgres` handles this for you |
| **Burp Suite + an MCP extension**, running | Everything | This is the most common setup snag — see below |

### Getting Burp's MCP server actually working

This trips people up more than anything else, so check it explicitly
before starting `aiScraper` — a silent connection failure here just looks
like "no traffic ever shows up."

```bash
curl -i http://127.0.0.1:9876/sse
```

- **Connection refused** → nothing is listening. Check Burp's
  **Extensions → Installed** tab for the MCP extension; if it's not
  there, install it (official PortSwigger MCP Server is in the BApp
  Store; BurpMCP-Ultra is a manually-loaded JAR).
- **404 Not Found** (with real HTTP headers, not a connection error) →
  something IS listening, just not on that path. If you're running
  **BurpMCP-Ultra**, its convention is the root path `/`, not `/sse`, and
  it requires a Bearer token on every request. Set
  `AI_SCRAPER__POLLER__MCP_SSE_PATH=/` and
  `AI_SCRAPER__POLLER__MCP_AUTH_TOKEN=<token>` (token is shown in
  BurpMCP-Ultra's own Server panel tab in Burp).
- **A stream that opens and starts sending `event: endpoint`** → you're
  good, this is what `aiScraper` expects.

---

## Installing

```bash
git clone https://github.com/th0t3p/aiScraper.git
cd aiScraper
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip     # older pip can't do editable installs from pyproject.toml alone
pip install -e ".[dev]"
```

---

## Configuration

All configuration is environment-variable driven (or a `.env` file),
prefixed `AI_SCRAPER__`, with `__` as the nesting delimiter:

```bash
# .env
AI_SCRAPER__POSTGRES__PASSWORD=<something-strong>
AI_SCRAPER__POLLER__AUTHORIZED_SCOPE=["*.tiktok.com"]
AI_SCRAPER__API__API_KEY=<generate-one>
```

### `authorized_scope` — fail-closed by design

```bash
AI_SCRAPER__POLLER__AUTHORIZED_SCOPE=["*.example.com","specific-host.com"]
```

If left empty, **the poller drops everything** rather than defaulting to
permissive — this is deliberate, not a bug. If you genuinely want
unscoped local testing, you must explicitly opt in:

```bash
AI_SCRAPER__POLLER__ALLOW_UNSCOPED=true
```

### `api_key` — also worth setting deliberately

If unset, every API endpoint is open with no authentication (a warning is
logged once at startup, but requests are still allowed through — this is
for local development convenience, not production use). Set
`AI_SCRAPER__API__API_KEY` before running this anywhere the port might be
reachable by anything other than you.

### Full config reference

| Section | Key | Default | Notes |
|---|---|---|---|
| `postgres` | `host` / `port` / `database` / `user` / `password` | `127.0.0.1:5432/bugbounty` | |
| `poller` | `mcp_sse_url` | `http://127.0.0.1:9876` | |
| `poller` | `mcp_sse_path` | `/sse` | Set to `/` for BurpMCP-Ultra |
| `poller` | `mcp_auth_token` | `None` | Bearer token, needed for BurpMCP-Ultra |
| `poller` | `mcp_extra_headers` | `{}` | Extra HTTP headers on every MCP request (e.g. Host/Origin overrides for Docker DNS rebinding) |
| `poller` | `poll_interval_seconds` | `30` | |
| `poller` | `authorized_scope` | `[]` (fail-closed) | Glob patterns |
| `poller` | `allow_unscoped` | `false` | Explicit opt-out of fail-closed behavior |
| `poller` | `include_url_patterns` / `exclude_url_patterns` | `[]` | Regex filters |
| `poller` | `batch_size` | `200` | Records per poll cycle |
| `dedup` | `enabled` / `max_samples` / `key_fields` | `true` / `3` / method+host+path+params | |
| `enrichment` | `url_like_params` / `identifier_like_params` / `token_like_params` / `file_like_params` | see `config.py` | Extend these dictionaries for your own heuristics |
| `api` | `host` / `port` | `127.0.0.1:8700` | |
| `api` | `cors_origins` | `[]` (deny all) | |
| `api` | `api_key` | `None` (unauthenticated) | |

---

## Running

### Locally

```bash
python -m ai_scraper
```

This starts the FastAPI server **and** the poller loop in the same
process — the poller runs as a background task attached to the API
server's lifespan, so there's nothing separate to start.

### Docker

```bash
docker-compose --env-file .env up -d
```

Ports are intentionally commented out in `docker-compose.yml` by
default — the API and Postgres are only reachable from within the
docker network unless you explicitly uncomment the `ports:` sections
(each has a comment explaining the tradeoff). Burp is assumed to be
running on the **host** machine; the container reaches it via
`host.docker.internal`, already wired into the compose file.

---

## Verifying it's actually working

```bash
curl -H "X-API-Key: $YOUR_KEY" http://127.0.0.1:8700/api/v1/health
```

Returns `mcp_connected: true` once the poller has successfully completed
at least one cycle. If it's stuck on `false`/`degraded`, that points back
to the Burp MCP connectivity check above, not a bug in `aiScraper` itself.

```bash
curl -H "X-API-Key: $YOUR_KEY" http://127.0.0.1:8700/api/v1/state
```

Shows the poller's current cursor position — useful for confirming it's
actually advancing over time, not stuck (see the cursor-starvation note
below if it looks frozen).

```bash
curl -H "X-API-Key: $YOUR_KEY" \
  "http://127.0.0.1:8700/api/v1/traffic?param_categories=url_like&limit=10"
```

The real end-to-end check — generate some traffic (e.g. run `aiBrowser`
against an in-scope target), wait one poll interval, then confirm it
shows up here.

---

## API reference

All endpoints under `/api/v1`, all requiring `X-API-Key` header if
`api.api_key` is configured.

| Endpoint | Method | Purpose |
|---|---|---|
| `/traffic` | GET | Query traffic records — filterable by method, host, `param_categories` (`url_like`/`identifier_like`/`token_like`/`file_like`/`generic_id`), content type, auth state, time range, source tool, or a specific param name present. This is the primary interface downstream modules use. |
| `/traffic/{request_id}` | GET | Fetch a single record by ID |
| `/traffic/stats` | GET | Aggregate statistics about stored traffic |
| `/traffic/poll` | POST | Manually trigger one full pipeline cycle immediately, rather than waiting for the next scheduled interval |
| `/health` | GET | Service + Burp MCP connectivity status |
| `/state` | GET | Poller's current cursor position |

---

## Module layout

```
ai_scraper/
├── config.py               # Environment-driven settings (AppConfig)
├── service.py               # AiScraperService — wires poller → normalizer
│                            #   → dedup → enrichment → storage together
├── poller/
│   ├── poller.py             # BurpPoller — incremental MCP polling, cursor
│   │                          #   management, scope enforcement
│   └── models.py               # RawBurpRecord, PollerState
├── normalizer/
│   ├── normalizer.py         # Raw MCP record → TrafficRecord (unified schema)
│   └── models.py               # TrafficRecord — param extraction (query,
│                              #   form, multipart, JSON body), header parsing
├── deduplicator/
│   └── deduplicator.py       # Groups by configurable key, keeps N samples
├── enrichment/
│   └── enricher.py            # Rule-based param/content-type/auth-state tagging
├── storage/
│   ├── storage.py             # Postgres persistence, batch upsert, query API
│   └── models.py               # TrafficQuery, TrafficQueryResult, TrafficStats
└── api/
    ├── routes.py               # REST endpoints (see API reference above)
    └── server.py                 # FastAPI app, CORS, lifespan (starts poller)
```

---

## Key design decisions

### Fail-closed scope, not fail-open

An earlier version of the poller defaulted to "pass everything through"
when `authorized_scope` was empty — this was a bug, not a feature. The
current behavior requires either an explicit scope list or an explicit
`allow_unscoped=true` opt-in. If you deploy this and suddenly nothing is
being captured, check this setting first — it's very likely working
exactly as configured.

### Cursor advances independently of filtering

The poller's cursor position is updated based on every record it
receives from Burp — **before** `include_url_patterns`,
`exclude_url_patterns`, or `authorized_scope` filtering is applied. This
matters: if a batch of records happens to be entirely out-of-scope noise,
the cursor still advances past them, so the poller doesn't get stuck
re-fetching the same excluded batch forever. Filtering only affects what
gets stored, never what the poller considers "already seen."

### JSON body parameters are parsed, not just form/multipart

`TrafficRecord.param_names` recursively extracts keys from JSON request
bodies (including nested objects), not just `application/x-www-form-urlencoded`
or `multipart/form-data`. Most modern APIs send JSON — if this weren't
handled, a large fraction of real candidate parameters (`webhook_url`,
`callback` embedded in a JSON payload) would never surface to downstream
enrichment at all.

### This service captures, it never verifies or attacks

No outbound requests to any target originate from `aiScraper` — it only
reads what Burp already captured. Verification (OOB callbacks, payload
injection, exploit confirmation) is deliberately out of scope for this
service and lives in downstream consumers like `aiSSRF`, which maintain
their own independent scope checks rather than trusting this service's
filtering blindly.

---

## Programmatic usage

```python
import httpx

resp = httpx.get(
    "http://127.0.0.1:8700/api/v1/traffic",
    params={"param_categories": "url_like", "limit": 50},
    headers={"X-API-Key": "..."},
)
candidates = resp.json()["records"]
```
