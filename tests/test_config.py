"""Tests for config loading and CLI override application."""

from __future__ import annotations

import argparse

from ai_scraper.config import AppConfig, apply_cli_overrides


def _make_args(**overrides) -> argparse.Namespace:
    """Build an argparse.Namespace as if produced by _parse_args()."""
    defaults = {
        "mcp_backend": None,
        "mcp_sse_url": None,
        "mcp_auth_token": None,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class TestApplyCliOverrides:

    def test_no_overrides_leaves_config_unchanged(self):
        """When no CLI flags are passed, the config is untouched."""
        config = AppConfig()
        original_backend = config.poller.mcp_backend
        original_path = config.poller.mcp_sse_path
        original_url = config.poller.mcp_sse_url
        original_token = config.poller.mcp_auth_token

        args = _make_args()
        apply_cli_overrides(config, args)

        assert config.poller.mcp_backend == original_backend
        assert config.poller.mcp_sse_path == original_path
        assert config.poller.mcp_sse_url == original_url
        assert config.poller.mcp_auth_token == original_token

    def test_mcp_backend_portswigger(self):
        """--mcp-backend portswigger sets the field, leaves sse_path unchanged."""
        config = AppConfig()
        before = config.poller.mcp_sse_path
        args = _make_args(mcp_backend="portswigger")
        apply_cli_overrides(config, args)

        assert config.poller.mcp_backend == "portswigger"
        assert config.poller.mcp_sse_path == before

    def test_mcp_backend_burpmcp_ultra_switches_sse_path(self):
        """--mcp-backend burpmcp_ultra sets the field AND switches sse_path
        to '/' (the default for BurpMCP-Ultra), provided the user hasn't
        already customized sse_path away from the default /sse."""
        config = AppConfig()
        # Force the PortSwigger default so we can verify the switch.
        config.poller.mcp_sse_path = "/sse"
        args = _make_args(mcp_backend="burpmcp_ultra")
        apply_cli_overrides(config, args)

        assert config.poller.mcp_backend == "burpmcp_ultra"
        assert config.poller.mcp_sse_path == "/"

    def test_mcp_backend_does_not_overwrite_custom_sse_path(self):
        """When the user has already set a non-default sse_path (e.g. in
        .env), switching to burpmcp_ultra should NOT overwrite it."""
        config = AppConfig()
        config.poller.mcp_sse_path = "/custom-sse"
        args = _make_args(mcp_backend="burpmcp_ultra")
        apply_cli_overrides(config, args)

        assert config.poller.mcp_backend == "burpmcp_ultra"
        assert config.poller.mcp_sse_path == "/custom-sse"

    def test_mcp_sse_url_override(self):
        """--mcp-sse-url overrides the default URL."""
        config = AppConfig()
        assert config.poller.mcp_sse_url == "http://127.0.0.1:9876"

        args = _make_args(mcp_sse_url="http://192.168.1.50:9876")
        apply_cli_overrides(config, args)
        assert config.poller.mcp_sse_url == "http://192.168.1.50:9876"

    def test_mcp_auth_token_override(self):
        """--mcp-auth-token overrides the auth token."""
        config = AppConfig()
        assert config.poller.mcp_auth_token is None

        args = _make_args(mcp_auth_token="secret-token")
        apply_cli_overrides(config, args)
        assert config.poller.mcp_auth_token == "secret-token"

    def test_multiple_overrides_at_once(self):
        """All three flags can be combined in a single invocation."""
        config = AppConfig()
        # Force the PortSwigger default so we can verify the switch.
        config.poller.mcp_sse_path = "/sse"
        args = _make_args(
            mcp_backend="burpmcp_ultra",
            mcp_sse_url="http://10.0.0.1:9876",
            mcp_auth_token="abc123",
        )
        apply_cli_overrides(config, args)

        assert config.poller.mcp_backend == "burpmcp_ultra"
        assert config.poller.mcp_sse_path == "/"
        assert config.poller.mcp_sse_url == "http://10.0.0.1:9876"
        assert config.poller.mcp_auth_token == "abc123"
