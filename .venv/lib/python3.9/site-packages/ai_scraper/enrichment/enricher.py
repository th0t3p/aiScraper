"""Enrichment — rule-based objective tagging (NO vulnerability judgment)."""

from __future__ import annotations

import logging
from enum import Enum
from typing import Optional

from ai_scraper.config import EnrichmentConfig, get_config
from ai_scraper.normalizer.models import TrafficRecord

logger = logging.getLogger(__name__)


class ParamCategory(str, Enum):
    URL_LIKE = "url_like"
    IDENTIFIER_LIKE = "identifier_like"
    TOKEN_LIKE = "token_like"
    FILE_LIKE = "file_like"
    GENERIC_ID = "generic_id"   # ends with _id / Id / ID but not in the above lists
    UNCLASSIFIED = "unclassified"


class ContentTypeCategory(str, Enum):
    JSON = "json"
    XML = "xml"
    FORM = "form"
    MULTIPART = "multipart"
    HTML = "html"
    TEXT = "text"
    BINARY = "binary"
    UNKNOWN = "unknown"


class Enricher:
    """Applies objective tags to TrafficRecord — never makes vulnerability judgments.

    Tags applied:
      - param_categories:     param_name → ParamCategory map
      - content_type_category: request Content-Type classification
      - is_authenticated:     whether request carries Authorization / Cookie
      - has_file_upload:      multipart + file-like params
      - response_content_type_category: response Content-Type classification
    """

    def __init__(self, config: EnrichmentConfig | None = None):
        self._config = config or get_config().enrichment
        # Pre-compile lookup sets for O(1) membership tests
        self._url_set = set(self._config.url_like_params)
        self._id_set = set(self._config.identifier_like_params)
        self._token_set = set(self._config.token_like_params)
        self._file_set = set(self._config.file_like_params)

    # ── Public API ───────────────────────────────────────────────────────────

    def enrich(self, record: TrafficRecord) -> TrafficRecord:
        """Tag a single record in-place (returns the same object)."""
        if not self._config.enabled:
            return record

        record.tags["param_categories"] = self._classify_params(record)
        record.tags["content_type_category"] = self._classify_content_type(
            record.headers.get("content-type", "")
        ).value
        record.tags["is_authenticated"] = self._check_authenticated(record)
        record.tags["has_file_upload"] = self._check_file_upload(record)
        record.tags["response_content_type_category"] = self._classify_content_type(
            (record.response_headers or {}).get("content-type", "")
        ).value
        return record

    def enrich_batch(self, records: list[TrafficRecord]) -> list[TrafficRecord]:
        """Batch-tag all records."""
        for r in records:
            self.enrich(r)
        return records

    # ── Param classification ─────────────────────────────────────────────────

    def _classify_params(self, record: TrafficRecord) -> dict[str, str]:
        """Classify every parameter name found in the request."""
        result: dict[str, str] = {}
        for name in record.param_names:
            lower = name.lower()
            if lower in self._url_set:
                result[name] = ParamCategory.URL_LIKE.value
            elif lower in self._id_set:
                result[name] = ParamCategory.IDENTIFIER_LIKE.value
            elif lower in self._token_set:
                result[name] = ParamCategory.TOKEN_LIKE.value
            elif lower in self._file_set:
                result[name] = ParamCategory.FILE_LIKE.value
            elif lower.endswith("_id") or lower.endswith("id") or lower.endswith("Id"):
                result[name] = ParamCategory.GENERIC_ID.value
            else:
                result[name] = ParamCategory.UNCLASSIFIED.value
        return result

    # ── Content-Type classification ──────────────────────────────────────────

    @staticmethod
    def _classify_content_type(content_type: str) -> ContentTypeCategory:
        if not content_type:
            return ContentTypeCategory.UNKNOWN
        ct = content_type.lower()
        if "application/json" in ct or "+json" in ct:
            return ContentTypeCategory.JSON
        if "application/xml" in ct or "text/xml" in ct or "+xml" in ct:
            return ContentTypeCategory.XML
        if "application/x-www-form-urlencoded" in ct:
            return ContentTypeCategory.FORM
        if "multipart/form-data" in ct:
            return ContentTypeCategory.MULTIPART
        if "text/html" in ct:
            return ContentTypeCategory.HTML
        if ct.startswith("text/"):
            return ContentTypeCategory.TEXT
        if "octet-stream" in ct or "image/" in ct or "audio/" in ct or "video/" in ct or "application/pdf" in ct:
            return ContentTypeCategory.BINARY
        return ContentTypeCategory.UNKNOWN

    # ── Auth check ───────────────────────────────────────────────────────────

    @staticmethod
    def _check_authenticated(record: TrafficRecord) -> bool:
        """A request is 'authenticated' if it carries Authorization or Cookie headers."""
        headers = record.headers
        for key in headers:
            lower = key.lower()
            if lower in ("authorization", "cookie"):
                return True
        return False

    # ── File upload check ────────────────────────────────────────────────────

    def _check_file_upload(self, record: TrafficRecord) -> bool:
        """True if the request is multipart AND contains file-like params."""
        ct = record.headers.get("content-type", "")
        if "multipart/form-data" not in ct.lower():
            return False
        for name in record.param_names:
            if name.lower() in self._file_set:
                return True
        return False
