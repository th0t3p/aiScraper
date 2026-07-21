"""Pipeline orchestration — poller → normalizer → dedup → enrich → storage.

This is the main service that wires together all five modules and exposes
the unified data layer to downstream vulnerability scanners.
"""

from __future__ import annotations

import logging
from typing import Optional

from ai_scraper.config import get_config
from ai_scraper.poller.poller import BurpPoller
from ai_scraper.normalizer.normalizer import Normalizer
from ai_scraper.deduplicator.deduplicator import Deduplicator
from ai_scraper.enrichment.enricher import Enricher
from ai_scraper.storage.storage import PostgresStorage

logger = logging.getLogger(__name__)

# ── Global singleton ─────────────────────────────────────────────────────────

_service: Optional["AiScraperService"] = None


class AiScraperService:
    """Top-level orchestrator that chains the full pipeline.

    Usage::

        # Initialization (called once at startup)
        await init_service()

        # Direct access
        svc = get_service()
        count = await svc.run_once()

        # Background polling
        await svc.start()
    """

    def __init__(self):
        self.poller = BurpPoller()
        self.normalizer = Normalizer()
        self.deduplicator = Deduplicator()
        self.enricher = Enricher()
        self.storage = PostgresStorage()

    # ── Lifecycle ────────────────────────────────────────────────────────────

    async def initialize(self) -> None:
        """Connect to PostgreSQL and init schema."""
        await self.storage.connect()
        await self.storage.init_schema()
        logger.info("Service initialized")

    async def shutdown(self) -> None:
        """Stop polling and disconnect storage."""
        await self.poller.stop()
        await self.storage.disconnect()
        logger.info("Service shut down")

    # ── Pipeline ─────────────────────────────────────────────────────────────

    async def run_once(self) -> int:
        """Execute one full pipeline cycle manually.

        Returns the number of newly stored records (after dedup).
        """
        # 1. Poll
        raw_records = await self.poller.poll_once()
        if not raw_records:
            logger.info("No new records to process")
            return 0

        logger.info("Polled %d raw records", len(raw_records))

        # 2. Normalize
        records = self.normalizer.normalize_batch(raw_records)
        logger.info("Normalized %d records", len(records))

        # 3. Deduplicate
        groups = self.deduplicator.deduplicate(records)

        # Flatten: collect all samples from all groups
        deduped: list = []
        for g in groups:
            deduped.extend(g.samples)
        logger.info(
            "Dedup: %d records → %d groups → %d samples",
            len(records), len(groups), len(deduped),
        )

        # 4. Enrich
        enriched = self.enricher.enrich_batch(deduped)
        logger.info("Enriched %d records", len(enriched))

        # 5. Store
        stored = await self.storage.save(enriched)
        logger.info("Stored %d records", stored)

        return stored

    # ── Background polling ───────────────────────────────────────────────────

    async def start(self) -> None:
        """Start background polling (poller → pipeline on every cycle)."""
        # Register the pipeline as a callback on the poller
        async def pipeline_callback(raw_records):
            if not raw_records:
                return
            # Steps 2-5 inline (doesn't count as a full "run_once" for stats)
            records = self.normalizer.normalize_batch(raw_records)
            groups = self.deduplicator.deduplicate(records)
            deduped = []
            for g in groups:
                deduped.extend(g.samples)
            enriched = self.enricher.enrich_batch(deduped)
            await self.storage.save(enriched)

        self.poller.on_new_records(pipeline_callback)
        await self.poller.start()
        logger.info("Background polling started")

    async def stop(self) -> None:
        """Stop background polling."""
        await self.poller.stop()


# ── Module-level helpers ─────────────────────────────────────────────────────


def get_service() -> AiScraperService:
    """Return the global AiScraperService singleton.

    Must be called after `init_service()`.
    """
    if _service is None:
        raise RuntimeError(
            "Service not initialized — call init_service() first"
        )
    return _service


async def init_service() -> AiScraperService:
    """Initialize and return the global service singleton."""
    global _service
    if _service is not None:
        return _service
    _service = AiScraperService()
    await _service.initialize()
    return _service


async def shutdown_service() -> None:
    """Shut down the global service singleton."""
    global _service
    if _service is not None:
        await _service.shutdown()
        _service = None
