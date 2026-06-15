"""Integration tests for URLhaus tool."""
from __future__ import annotations

import json

import pytest
from pytest_httpx import HTTPXMock

from argus.tools.urlhaus import urlhaus_lookup

_URLHAUS_SAMPLE = {
    "query_status": "is_host",
    "threat": "malware_download",
    "tags": ["Emotet", "banking-trojan"],
    "urls": [
        {"url": "http://evil.com/payload.exe", "url_status": "online", "threat": "malware_download"}
    ],
    "payloads": [],
}


@pytest.mark.asyncio
async def test_urlhaus_host_lookup(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        method="POST",
        url="https://urlhaus-api.abuse.ch/v1/host/",
        json=_URLHAUS_SAMPLE,
    )

    result_str = await urlhaus_lookup(host="evil.com")
    result = json.loads(result_str)

    assert result["query_status"] == "is_host"
    assert result["threat"] == "malware_download"
    assert "Emotet" in result["tags"]
    assert result["urls_count"] == 1
