"""Service/version to CVE enrichment helpers."""

from __future__ import annotations

from typing import Dict, List

from intelligence.nvd_client import search_cves_by_keyword

SERVICE_VERSION_CVE_MAP: Dict[str, Dict[str, List[str]]] = {
    "ftp": {"2.3.4": ["CVE-2011-2523"]},
    "ssh": {"4.0": ["CVE-2008-0166"], "4.3": ["CVE-2018-15473"]},
    "smb": {"3.0": ["CVE-2017-7494"]},
    "mysql": {"5.0": ["CVE-2012-2122"]},
    "http": {"2.2": ["CVE-2017-5638"]},
}


def _signature_match(service: str, version: str) -> List[str]:
    svc_map = SERVICE_VERSION_CVE_MAP.get(service.lower(), {})
    for needle, cves in svc_map.items():
        if version.startswith(needle):
            return cves
    return []


def map_service_version_to_cves(
    service: str,
    version: str,
    use_nvd_lookup: bool = True,
    max_results: int = 5,
) -> List[str]:
    """Map service/version to CVE IDs using signatures and optional NVD lookup."""
    normalized_service = (service or "").strip().lower()
    normalized_version = (version or "").strip().lower()
    if not normalized_service:
        return []

    local_hits = _signature_match(normalized_service, normalized_version)
    if local_hits:
        return sorted({item.upper() for item in local_hits})

    if not use_nvd_lookup or not normalized_version:
        return []

    keyword = f"{normalized_service} {normalized_version}"
    return sorted({item.upper() for item in search_cves_by_keyword(keyword, max_results=max_results)})

