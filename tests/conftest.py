"""Shared test fixtures."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def set_test_env(monkeypatch, tmp_path):
    """Set required env vars and redirect storage to tmp_path for all tests."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")
    monkeypatch.setenv("MODEL_PROVIDER", "anthropic")
    monkeypatch.setenv("MODEL", "claude-test")
    for key_var in (
        "ABUSEIPDB_API_KEY",
        "VIRUSTOTAL_API_KEY",
        "SHODAN_API_KEY",
        "OTX_API_KEY",
        "RECORDED_FUTURE_API_KEY",
        "MISP_API_KEY",
    ):
        monkeypatch.setenv(key_var, "")
    for proxy_var in (
        "ALL_PROXY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "all_proxy",
        "http_proxy",
        "https_proxy",
    ):
        monkeypatch.delenv(proxy_var, raising=False)
    monkeypatch.setenv("CACHE_DIR", str(tmp_path / ".cache"))
    monkeypatch.setenv("DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("CASES_DIR", str(tmp_path / "cases"))
    monkeypatch.setenv("REPORTS_DIR", str(tmp_path / "reports"))
    # Clear settings singleton so each test gets fresh settings
    from argus.config.settings import get_settings
    from argus.storage.cache import get_cache

    get_settings.cache_clear()
    get_cache.cache_clear()
