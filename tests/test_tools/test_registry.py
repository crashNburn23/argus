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
    s.disclosure_mode = "unrestricted"
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


def test_get_available_tools_local_only_blocks_external_tools(monkeypatch) -> None:
    s = _settings(disclosure_mode="local-only")
    s.api_key = MagicMock(side_effect=lambda name: "key" if name == "virustotal" else None)
    monkeypatch.setattr(registry, "get_settings", lambda: s)

    tools = registry.get_available_tools("ioc")

    assert tools == []


def test_tool_status_returns_entry_for_every_tool(monkeypatch) -> None:
    monkeypatch.setattr(registry, "get_settings", lambda: _settings())
    statuses = registry.tool_status()
    names = {s["name"] for s in statuses}
    assert names == set(registry._AVAILABILITY.keys())
    for entry in statuses:
        assert "name" in entry
        assert "available" in entry
        assert "reason" in entry


def test_tool_status_marks_local_only_blocks(monkeypatch) -> None:
    monkeypatch.setattr(registry, "get_settings", lambda: _settings(disclosure_mode="local-only"))

    statuses = registry.tool_status()
    mitre = next(s for s in statuses if s["name"] == "mitre_attack_lookup")
    virustotal = next(s for s in statuses if s["name"] == "virustotal_lookup")

    assert mitre["available"] is False
    assert mitre["blocked"] is True
    assert mitre["configured"] is True
    assert mitre["reason"] == "blocked by local-only disclosure mode"
    assert virustotal["available"] is False
    assert virustotal["blocked"] is True
    assert virustotal["configured"] is False
    assert virustotal["reason"] == "blocked by local-only disclosure mode"


@pytest.mark.asyncio
async def test_dispatch_tool_local_only_blocks_external_tools(monkeypatch) -> None:
    monkeypatch.setattr(registry, "get_settings", lambda: _settings(disclosure_mode="local-only"))

    result = await registry.dispatch_tool("mitre_attack_lookup", {"group_name": "APT29"})

    assert "Tool blocked by disclosure policy" in result
    assert "mitre_attack_lookup" in result
