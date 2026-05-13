"""CISA KEV parser helpers."""

from __future__ import annotations

from typing import Set

import requests

CISA_KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_known_exploited_cves(timeout: float = 8.0) -> Set[str]:
    """Fetch and parse Known Exploited Vulnerabilities CVE IDs."""
    try:
        response = requests.get(CISA_KEV_JSON_URL, timeout=timeout)
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException:
        return set()

    vulnerabilities = payload.get("vulnerabilities", [])
    return {
        item.get("cveID", "").strip().upper()
        for item in vulnerabilities
        if item.get("cveID")
    }

