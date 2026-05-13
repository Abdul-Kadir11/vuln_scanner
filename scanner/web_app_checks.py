"""Passive web application checks."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

import requests

from scanner.evidence import standardize_finding
from scanner.request_context import build_request_kwargs


def _base_url(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return target.rstrip("/")
    host = (urlparse(f"//{target}").hostname or target).strip()
    return f"https://{host}"


def run_web_app_passive_checks(
    target: str,
    timeout: float = 5.0,
    auth_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, object]:
    """Collect passive web app findings without active exploitation."""
    findings: List[Dict[str, object]] = []
    checked = {"base_url": None, "robots_status": None, "security_txt_status": None}
    base = _base_url(target)

    try:
        response = requests.get(base, **build_request_kwargs(auth_context=auth_context, timeout=timeout))
    except requests.RequestException as exc:
        findings.append(
            standardize_finding(
                title="Web app passive checks could not reach target",
                severity="Low",
                evidence={"module": "web_app_checks", "target": target, "error": str(exc)},
                remediation="Validate DNS, routing, and web server availability.",
                category="web_app",
                base_cvss=2.0,
            )
        )
        return {"findings": findings, "checked": checked}

    checked["base_url"] = response.url
    headers = {k: v for k, v in response.headers.items()}

    server_header = headers.get("Server")
    if server_header:
        findings.append(
            standardize_finding(
                title="Server banner exposed in HTTP headers",
                severity="Low",
                evidence={
                    "module": "web_app_checks",
                    "url": response.url,
                    "server_header": server_header,
                },
                remediation="Minimize or remove verbose server version banners.",
                category="web_app",
                service="http",
                version=server_header,
                base_cvss=3.0,
                internet_exposed=True,
            )
        )

    cookies = response.cookies
    for cookie in cookies:
        missing_flags = []
        if not cookie.secure:
            missing_flags.append("Secure")
        if "httponly" not in (cookie._rest or {}):
            missing_flags.append("HttpOnly")
        if missing_flags:
            findings.append(
                standardize_finding(
                    title=f"Cookie missing security flags: {cookie.name}",
                    severity="Medium",
                    evidence={
                        "module": "web_app_checks",
                        "url": response.url,
                        "cookie_name": cookie.name,
                        "missing_flags": missing_flags,
                    },
                    remediation="Set Secure and HttpOnly flags on session/auth cookies.",
                    category="web_app",
                    service="http",
                    base_cvss=5.0,
                    internet_exposed=True,
                )
            )

    body_preview = response.text[:500].lower()
    if "index of /" in body_preview:
        findings.append(
            standardize_finding(
                title="Potential directory listing exposure",
                severity="Medium",
                evidence={"module": "web_app_checks", "url": response.url, "body_preview": response.text[:300]},
                remediation="Disable directory indexing at web server level.",
                category="web_app",
                service="http",
                base_cvss=5.5,
                internet_exposed=True,
            )
        )

    for path, label in (("/robots.txt", "robots.txt"), ("/.well-known/security.txt", "security.txt")):
        url = urljoin(response.url.rstrip("/") + "/", path.lstrip("/"))
        try:
            check = requests.get(url, **build_request_kwargs(auth_context=auth_context, timeout=timeout))
            checked_key = "robots_status" if label == "robots.txt" else "security_txt_status"
            checked[checked_key] = check.status_code
            if check.status_code >= 400:
                findings.append(
                    standardize_finding(
                        title=f"{label} not available",
                        severity="Info",
                        evidence={"module": "web_app_checks", "url": url, "status_code": check.status_code},
                        remediation=f"Publish {label} when applicable for better operational/security posture.",
                        category="web_app",
                        service="http",
                        base_cvss=1.0,
                    )
                )
        except requests.RequestException:
            continue

    return {"findings": findings, "checked": checked}
