"""HTTP security header checks."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import requests
from urllib.parse import urlparse

from scanner.request_context import build_request_kwargs
from scanner.evidence import standardize_finding

REQUIRED_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
)


def _target_urls(target: str) -> List[str]:
    if target.startswith(("http://", "https://")):
        return [target]
    host = (urlparse(f"//{target}").hostname or target).strip()
    return [f"https://{host}", f"http://{host}"]


def check_http_security_headers(
    target: str,
    timeout: float = 5.0,
    auth_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, object]:
    """Check required HTTP security headers and capture evidence."""
    findings = []
    checked_url = None
    response_headers: Dict[str, str] = {}
    status_code = None
    error_message = None

    for candidate in _target_urls(target):
        try:
            response = requests.get(candidate, **build_request_kwargs(auth_context=auth_context, timeout=timeout))
            checked_url = response.url
            status_code = response.status_code
            response_headers = {k: v for k, v in response.headers.items()}
            break
        except requests.RequestException as exc:
            error_message = str(exc)
            continue

    if not checked_url:
        findings.append(
            standardize_finding(
                title="HTTP service unreachable for header analysis",
                severity="Low",
                evidence={
                    "module": "http_checks",
                    "target": target,
                    "timeout_sec": timeout,
                    "error": error_message or "request_failed",
                },
                remediation="Ensure the target host is reachable and serving HTTP(S).",
                category="web",
                base_cvss=2.0,
                known_exploited=False,
            )
        )
        return {"findings": findings, "checked_url": None, "headers": {}, "status_code": None}

    missing = [name for name in REQUIRED_HEADERS if name not in response_headers]
    for name in missing:
        findings.append(
            standardize_finding(
                title=f"Missing security header: {name}",
                severity="Medium",
                evidence={
                    "module": "http_checks",
                    "url": checked_url,
                    "status_code": status_code,
                    "missing_header": name,
                    "response_headers": response_headers,
                },
                remediation=f"Configure the web server/app to emit `{name}` for all responses.",
                category="web",
                port=443 if checked_url.startswith("https://") else 80,
                base_cvss=5.0,
                internet_exposed=True,
                known_exploited=False,
            )
        )

    return {
        "findings": findings,
        "checked_url": checked_url,
        "headers": response_headers,
        "status_code": status_code,
    }
