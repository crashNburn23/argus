"""Integration tests for NVD tool using pytest-httpx."""

from __future__ import annotations

import json

import pytest
from pytest_httpx import HTTPXMock

from argus.tools.nvd import nvd_cve_lookup

_NVD_SAMPLE = {
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "format": "NVD_CVE",
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "published": "2021-12-10T10:15:09.143",
                "lastModified": "2024-01-01T00:00:00.000",
                "descriptions": [
                    {"lang": "en", "value": "Apache Log4j2 remote code execution vulnerability"},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 10.0,
                                "baseSeverity": "CRITICAL",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                            }
                        }
                    ]
                },
                "weaknesses": [{"description": [{"value": "CWE-917"}]}],
                "references": [{"url": "https://logging.apache.org/log4j/2.x/security.html"}],
            }
        }
    ],
}

_CISA_KEV_SAMPLE = {"vulnerabilities": [{"cveID": "CVE-2021-44228", "vendorProject": "Apache"}]}


@pytest.mark.asyncio
async def test_nvd_cve_lookup(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        json=_CISA_KEV_SAMPLE,
    )
    httpx_mock.add_response(
        method="GET",
        url="https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228",
        json=_NVD_SAMPLE,
    )

    result_str = await nvd_cve_lookup(cve_id="CVE-2021-44228")
    result = json.loads(result_str)

    assert result["total_results"] == 1
    assert len(result["vulnerabilities"]) == 1
    vuln = result["vulnerabilities"][0]
    assert vuln["cve_id"] == "CVE-2021-44228"
    assert vuln["cvss_v3_score"] == 10.0
    assert vuln["severity"] == "critical"
    assert vuln["in_cisa_kev"] is True
    assert "CVE-2021-44228" in result["cisa_kev_matches"]
