"""Safe path discovery checks (non-destructive)."""

from __future__ import annotations

import time
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urljoin

import requests

from scanner.evidence import standardize_finding
from scanner.request_context import build_request_kwargs

DEFAULT_CANDIDATE_PATHS = (
    "/.git/config",
    "/.env",
    "/backup.zip",
    "/admin",
    "/api",
    "/swagger",
)


def run_safe_fuzz_checks(
    base_urls: Iterable[str],
    auth_context: Optional[Dict[str, Any]] = None,
    timeout: float = 4.0,
    delay: float = 0.1,
    candidate_paths: Iterable[str] = DEFAULT_CANDIDATE_PATHS,
) -> Dict[str, object]:
    """Probe likely sensitive paths with GET only; no mutation payloads."""
    findings: List[Dict[str, object]] = []
    checked_urls: List[str] = []
    kwargs = build_request_kwargs(auth_context=auth_context, timeout=timeout)

    for base in base_urls:
        for path in candidate_paths:
            url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
            checked_urls.append(url)
            try:
                response = requests.get(url, **kwargs)
            except requests.RequestException:
                time.sleep(delay)
                continue
            status = response.status_code
            if status in {200, 206}:
                findings.append(
                    standardize_finding(
                        title=f"Sensitive path exposed: {path}",
                        severity="High",
                        evidence={
                            "module": "fuzz_checks",
                            "url": url,
                            "status_code": status,
                            "content_type": response.headers.get("Content-Type"),
                        },
                        remediation="Restrict access to sensitive files/endpoints and return 404/403.",
                        category="web_app",
                        service="http",
                        base_cvss=7.5,
                        internet_exposed=True,
                    )
                )
            time.sleep(delay)
    return {"findings": findings, "checked_urls": checked_urls}

