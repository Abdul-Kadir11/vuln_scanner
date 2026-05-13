"""Small NVD API client for CVE enrichment."""

from __future__ import annotations

import os
from typing import Dict, List, Optional

import requests

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cve(cve_id: str, timeout: float = 8.0) -> Optional[Dict[str, object]]:
    """Fetch a CVE record from NVD; returns None if unavailable."""
    headers = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    try:
        response = requests.get(
            NVD_BASE_URL,
            params={"cveId": cve_id},
            headers=headers,
            timeout=timeout,
        )
        response.raise_for_status()
        payload = response.json()
        vulnerabilities = payload.get("vulnerabilities", [])
        if not vulnerabilities:
            return None
        return vulnerabilities[0]
    except requests.RequestException:
        return None


def search_cves_by_keyword(
    keyword: str,
    timeout: float = 8.0,
    max_results: int = 5,
) -> List[str]:
    """Search CVE IDs from NVD using keyword search."""
    if not keyword.strip():
        return []

    headers = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    try:
        response = requests.get(
            NVD_BASE_URL,
            params={"keywordSearch": keyword, "resultsPerPage": max_results},
            headers=headers,
            timeout=timeout,
        )
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException:
        return []

    vulnerabilities = payload.get("vulnerabilities", [])
    results: List[str] = []
    for item in vulnerabilities:
        cve = item.get("cve", {})
        cve_id = str(cve.get("id", "")).strip().upper()
        if cve_id:
            results.append(cve_id)
    return results
