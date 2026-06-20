"""Parameterized availability tests for the tool registry."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from argus.tools import registry


def _settings(**overrides) -> MagicMock:
    """Build a mock settings object with sensible defaults for availability checks."""
    s = MagicMock()
    s.api_key = MagicMock(return_value=None)
    s.misp_url = None
    s.siem_type = "file"
    s.siem_url = None
    s.siem_log_path = None
    s.siem_api_key = None
    s.splunk_username = ""
    s.splunk_password = MagicMock(get_secret_value=MagicMock(return_value=""))
    for key, value in overrides.items():
        setattr(s, key, value)
    return s


# ---------------------------------------------------------------------------
# Always-available tools
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tool_name",
    [
        "mitre_attack_lookup",
        "nvd_cve_lookup",
        "urlhaus_lookup",
        "web_search",
        "ssl_cert_lookup",
        "whois_lookup",
    ],
)
def test_always_available(tool_name: str) -> None:
    check = registry._AVAILABILITY[tool_name]
    assert check(_settings()) is True


# ---------------------------------------------------------------------------
# Key-gated tools — available iff the API key is configured
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tool_name,api_key_name",
    [
        ("virustotal_lookup", "virustotal"),
        ("shodan_lookup", "shodan"),
        ("recorded_future_search", "recorded_future"),
        ("abuseipdb_check", "abuseipdb"),
        ("otx_lookup", "otx"),
        ("passive_dns_lookup", "virustotal"),
    ],
)
def test_key_gated_unavailable_without_key(tool_name: str, api_key_name: str) -> None:
    check = registry._AVAILABILITY[tool_name]
    assert check(_settings()) is False


@pytest.mark.parametrize(
    "tool_name,api_key_name",
    [
        ("virustotal_lookup", "virustotal"),
        ("shodan_lookup", "shodan"),
        ("recorded_future_search", "recorded_future"),
        ("abuseipdb_check", "abuseipdb"),
        ("otx_lookup", "otx"),
        ("passive_dns_lookup", "virustotal"),
    ],
)
def test_key_gated_available_with_key(tool_name: str, api_key_name: str) -> None:
    check = registry._AVAILABILITY[tool_name]
    s = _settings()
    s.api_key = MagicMock(side_effect=lambda name: "key" if name == api_key_name else None)
    assert check(s) is True


# ---------------------------------------------------------------------------
# MISP — needs a URL
# ---------------------------------------------------------------------------


def test_misp_unavailable_without_url() -> None:
    assert registry._AVAILABILITY["misp_search"](_settings()) is False


def test_misp_available_with_url() -> None:
    assert registry._AVAILABILITY["misp_search"](_settings(misp_url="https://misp.local")) is True


# ---------------------------------------------------------------------------
# SIEM — file backend
# ---------------------------------------------------------------------------


def test_siem_file_unavailable_without_log_path() -> None:
    s = _settings(siem_type="file", siem_log_path=None)
    assert registry._AVAILABILITY["siem_query"](s) is False


def test_siem_file_available_with_log_path() -> None:
    s = _settings(siem_type="file", siem_log_path="/var/log/siem.json")
    assert registry._AVAILABILITY["siem_query"](s) is True


# ---------------------------------------------------------------------------
# SIEM — Splunk backend (token auth)
# ---------------------------------------------------------------------------


def test_siem_splunk_unavailable_without_url() -> None:
    s = _settings(siem_type="splunk", siem_url=None)
    assert registry._AVAILABILITY["siem_query"](s) is False


def test_siem_splunk_unavailable_url_but_no_auth() -> None:
    s = _settings(siem_type="splunk", siem_url="https://splunk:8089", siem_api_key=None)
    s.splunk_username = ""
    s.splunk_password = MagicMock(get_secret_value=MagicMock(return_value=""))
    assert registry._AVAILABILITY["siem_query"](s) is False


def test_siem_splunk_available_with_token() -> None:
    s = _settings(siem_type="splunk", siem_url="https://splunk:8089")
    s.siem_api_key = MagicMock(get_secret_value=MagicMock(return_value="mytoken"))
    assert registry._AVAILABILITY["siem_query"](s) is True


def test_siem_splunk_available_with_basic_auth() -> None:
    s = _settings(siem_type="splunk", siem_url="https://splunk:8089", siem_api_key=None)
    s.splunk_username = "admin"
    s.splunk_password = MagicMock(get_secret_value=MagicMock(return_value="argus_splunk_1"))
    assert registry._AVAILABILITY["siem_query"](s) is True


# ---------------------------------------------------------------------------
# SIEM — webhook/api backend
# ---------------------------------------------------------------------------


def test_siem_webhook_unavailable_without_url() -> None:
    s = _settings(siem_type="webhook", siem_url=None)
    assert registry._AVAILABILITY["siem_query"](s) is False


def test_siem_webhook_available_with_url() -> None:
    s = _settings(siem_type="webhook", siem_url="https://siem.internal/api")
    assert registry._AVAILABILITY["siem_query"](s) is True


# ---------------------------------------------------------------------------
# get_available_tools filters correctly
# ---------------------------------------------------------------------------


def test_get_available_tools_no_keys_returns_free_tools(monkeypatch) -> None:
    monkeypatch.setattr(registry, "get_settings", lambda: _settings())
    tools = registry.get_available_tools("ioc")
    names = {t["name"] for t in tools}
    assert "ssl_cert_lookup" in names
    assert "whois_lookup" in names
    assert "virustotal_lookup" not in names
    assert "abuseipdb_check" not in names


def test_get_available_tools_with_virustotal_key(monkeypatch) -> None:
    s = _settings()
    s.api_key = MagicMock(side_effect=lambda name: "key" if name == "virustotal" else None)
    monkeypatch.setattr(registry, "get_settings", lambda: s)
    tools = registry.get_available_tools("ioc")
    names = {t["name"] for t in tools}
    assert "virustotal_lookup" in names
    assert "passive_dns_lookup" in names


def test_tool_status_returns_entry_for_every_tool(monkeypatch) -> None:
    monkeypatch.setattr(registry, "get_settings", lambda: _settings())
    statuses = registry.tool_status()
    names = {s["name"] for s in statuses}
    assert names == set(registry._AVAILABILITY.keys())
    for entry in statuses:
        assert "name" in entry
        assert "available" in entry
        assert "reason" in entry
