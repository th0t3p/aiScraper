"""Global configuration for AI Scraper."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


# ── PostgreSQL ────────────────────────────────────────────────────────────────

class PostgresConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 5432
    database: str = "bugbounty"
    user: str = "postgres"
    password: str = ""
    min_pool: int = 2
    max_pool: int = 10

    @property
    def dsn(self) -> str:
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.database}"


# ── Poller ────────────────────────────────────────────────────────────────────

class PollerConfig(BaseModel):
    mcp_sse_url: str = "http://127.0.0.1:9876"
    poll_interval_seconds: int = 30
    cursor_mode: str = "by_id"  # "by_id" | "by_time"
    # 拉取时的正则过滤（URL 匹配任一 pattern 才保留）
    include_url_patterns: list[str] = Field(default_factory=list)
    exclude_url_patterns: list[str] = Field(default_factory=list)
    # 授权范围白名单（域名 glob 模式，如 *.example.com）
    authorized_scope: list[str] = Field(default_factory=list)
    # 仅当为 True 时才允许空 authorized_scope 放行所有流量（仅限本地测试）
    allow_unscoped: bool = False
    # Burp MCP 工具名（如果实际部署不同可覆盖）
    proxy_history_tool: str = "getProxyHistory"
    request_content_tool: str = "getRequest"
    response_content_tool: str = "getResponse"
    # 每次拉取的最大记录数
    batch_size: int = 200
    # MCP 请求超时（秒）
    request_timeout: float = 30.0


# ── Deduplicator ──────────────────────────────────────────────────────────────

class DedupConfig(BaseModel):
    enabled: bool = True
    max_samples: int = 3
    key_fields: list[str] = Field(
        default_factory=lambda: ["method", "host", "path_template", "sorted_param_names"]
    )


# ── Enrichment ────────────────────────────────────────────────────────────────

class EnrichmentConfig(BaseModel):
    enabled: bool = True
    # 可扩展的参数名分类字典
    url_like_params: list[str] = Field(default_factory=lambda: [
        "url", "webhook", "callback", "redirect", "src",
        "redirect_uri", "redirect_url", "next", "return_url",
        "return", "goto", "target", "link", "ref", "origin",
    ])
    identifier_like_params: list[str] = Field(default_factory=lambda: [
        "id", "uid", "uuid", "order_id", "user_id", "account_id",
        "pid", "item_id", "tid", "cid", "sid",
    ])
    token_like_params: list[str] = Field(default_factory=lambda: [
        "token", "api_key", "access_token", "auth", "secret",
        "apikey", "jwt", "bearer", "signature", "sig",
    ])
    file_like_params: list[str] = Field(default_factory=lambda: [
        "file", "path", "filename", "filepath", "upload",
        "attachment", "document",
    ])


# ── API ───────────────────────────────────────────────────────────────────────

class ApiConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8700
    cors_origins: list[str] = Field(default_factory=list)  # default: deny all cross-origin
    api_key: Optional[str] = None  # if set, X-API-Key header is required


# ── Root Config ───────────────────────────────────────────────────────────────

class AppConfig(BaseSettings):
    """从环境变量 / .env 文件加载的根配置。

    环境变量前缀 AI_SCRAPER__ ，支持嵌套：
      AI_SCRAPER__POSTGRES__HOST=localhost
      AI_SCRAPER__POLLER__POLL_INTERVAL_SECONDS=60
    """

    model_config = SettingsConfigDict(
        env_prefix="AI_SCRAPER__",
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    postgres: PostgresConfig = Field(default_factory=PostgresConfig)
    poller: PollerConfig = Field(default_factory=PollerConfig)
    dedup: DedupConfig = Field(default_factory=DedupConfig)
    enrichment: EnrichmentConfig = Field(default_factory=EnrichmentConfig)
    api: ApiConfig = Field(default_factory=ApiConfig)
    debug: bool = False


# ── Singleton ─────────────────────────────────────────────────────────────────

_config: Optional[AppConfig] = None


def get_config() -> AppConfig:
    global _config
    if _config is None:
        _config = AppConfig()
    return _config


def set_config(config: AppConfig) -> None:
    global _config
    _config = config
