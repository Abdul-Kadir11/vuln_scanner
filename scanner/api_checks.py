"""Passive API surface checks."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlparse, urljoin

import requests

from scanner.differential import DifferentialAnalyzer
from scanner.evidence import standardize_finding
from scanner.request_context import build_request_kwargs

API_DOC_PATHS = ("/openapi.json", "/swagger.json", "/v3/api-docs")
DIFF_BASE_PATHS = ("/", "/api", "/graphql")


def _base_url(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return target.rstrip("/")
    host = (urlparse(f"//{target}").hostname or target).strip()
    return f"https://{host}"


def _response_snapshot(response: requests.Response) -> Dict[str, object]:
    content_type = response.headers.get("Content-Type", "")
    body = response.text or ""
    return {
        "url": response.url,
        "status_code": response.status_code,
        "content_type": content_type,
        "content_length": len(body.encode("utf-8", errors="ignore")),
        "body_preview": body[:200],
    }


def _compare_baseline_modified(
    endpoint: str,
    baseline: Dict[str, object],
    modified: Dict[str, object],
) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    baseline_status = int(baseline.get("status_code") or 0)
    modified_status = int(modified.get("status_code") or 0)
    baseline_len = int(baseline.get("content_length") or 0)
    modified_len = int(modified.get("content_length") or 0)

    # Auth-bypass signal: modified request becomes successful while baseline denied.
    if baseline_status in {401, 403} and modified_status < 300:
        findings.append(
            standardize_finding(
                title="Potential auth bypass behavior detected",
                severity="High",
                evidence={
                    "module": "api_checks",
                    "endpoint": endpoint,
                    "baseline": baseline,
                    "modified": modified,
                    "comparison": "baseline_denied_modified_success",
                },
                remediation="Review authentication/authorization middleware consistency on this endpoint.",
                category="api",
                service="http",
                base_cvss=8.0,
                internet_exposed=True,
            )
        )

    # Generic differential behavior signal.
    status_changed = baseline_status != modified_status
    length_delta = abs(modified_len - baseline_len)
    length_ratio = (length_delta / baseline_len) if baseline_len else (1.0 if modified_len else 0.0)

    if status_changed or length_ratio >= 0.5:
        findings.append(
            standardize_finding(
                title="Differential API behavior on modified request",
                severity="Medium",
                evidence={
                    "module": "api_checks",
                    "endpoint": endpoint,
                    "baseline": baseline,
                    "modified": modified,
                    "status_changed": status_changed,
                    "content_length_delta": length_delta,
                    "content_length_ratio": round(length_ratio, 3),
                },
                remediation="Review request normalization and authorization logic for parameter/header variants.",
                category="api",
                service="http",
                base_cvss=6.0,
                internet_exposed=True,
            )
        )

    return findings


def _run_baseline_modified_diff(
    base: str,
    timeout: float,
    auth_context: Optional[Dict[str, Any]],
) -> Dict[str, object]:
    findings: List[Dict[str, object]] = []
    comparisons: List[Dict[str, object]] = []
    request_kwargs = build_request_kwargs(auth_context=auth_context, timeout=timeout)

    for path in DIFF_BASE_PATHS:
        endpoint = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
        baseline_url = endpoint
        modified_url = f"{endpoint}?{urlencode({'scan_mode': 'modified', 'debug': '1'})}"

        try:
            baseline_resp = requests.get(baseline_url, **request_kwargs)
            modified_headers = dict(request_kwargs.get("headers") or {})
            modified_headers["X-Forwarded-For"] = "127.0.0.1"
            modified_headers["X-Original-URL"] = path
            modified_kwargs = dict(request_kwargs)
            modified_kwargs["headers"] = modified_headers
            modified_resp = requests.get(modified_url, **modified_kwargs)
        except requests.RequestException:
            continue

        baseline_snap = _response_snapshot(baseline_resp)
        modified_snap = _response_snapshot(modified_resp)
        endpoint_findings = _compare_baseline_modified(endpoint, baseline_snap, modified_snap)
        findings.extend(endpoint_findings)
        comparisons.append({"endpoint": endpoint, "baseline": baseline_snap, "modified": modified_snap})

    return {"findings": findings, "comparisons": comparisons}


def run_api_passive_checks(
    target: str,
    timeout: float = 5.0,
    auth_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, object]:
    """Perform passive API checks (discovery and policy signals)."""
    findings: List[Dict[str, object]] = []
    discovered_docs: List[str] = []
    base = _base_url(target)

    for path in API_DOC_PATHS:
        url = urljoin(base + "/", path.lstrip("/"))
        try:
            response = requests.get(url, **build_request_kwargs(auth_context=auth_context, timeout=timeout))
        except requests.RequestException:
            continue

        if response.status_code < 300 and "application/json" in response.headers.get("Content-Type", "").lower():
            discovered_docs.append(response.url)
            findings.append(
                standardize_finding(
                    title="Public API schema endpoint exposed",
                    severity="Medium",
                    evidence={
                        "module": "api_checks",
                        "url": response.url,
                        "status_code": response.status_code,
                        "content_type": response.headers.get("Content-Type"),
                    },
                    remediation="Restrict API schema exposure to authenticated/admin contexts if not intended public.",
                    category="api",
                    service="http",
                    base_cvss=5.0,
                    internet_exposed=True,
                )
            )

    try:
        options_kwargs = build_request_kwargs(auth_context=auth_context, timeout=timeout)
        options_response = requests.options(base, **options_kwargs)
        allow_origin = options_response.headers.get("Access-Control-Allow-Origin", "")
        allow_credentials = options_response.headers.get("Access-Control-Allow-Credentials", "")
        allow_methods = options_response.headers.get("Access-Control-Allow-Methods", "")

        if allow_origin.strip() == "*" and allow_credentials.lower() == "true":
            findings.append(
                standardize_finding(
                    title="Overly permissive CORS policy detected",
                    severity="High",
                    evidence={
                        "module": "api_checks",
                        "url": options_response.url,
                        "access_control_allow_origin": allow_origin,
                        "access_control_allow_credentials": allow_credentials,
                        "access_control_allow_methods": allow_methods,
                    },
                    remediation="Avoid wildcard origins with credentials; restrict trusted origins explicitly.",
                    category="api",
                    service="http",
                    base_cvss=7.0,
                    internet_exposed=True,
                )
            )
    except requests.RequestException:
        pass

    diff_result = _run_baseline_modified_diff(base=base, timeout=timeout, auth_context=auth_context)
    findings.extend(diff_result.get("findings", []))
    analyzer = DifferentialAnalyzer(timeout=timeout, delay=0.2)
    analyzer_vectors: List[Dict[str, object]] = []
    for path in DIFF_BASE_PATHS:
        endpoint = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
        analysis = analyzer.analyze(
            url=endpoint,
            param_name="q",
            auth_context=auth_context,
        )
        findings.extend(analysis.get("findings", []))
        analyzer_vectors.extend(analysis.get("vectors", []))

    return {
        "findings": findings,
        "api_docs": discovered_docs,
        "diff_checks": diff_result.get("comparisons", []),
        "differential_vectors": analyzer_vectors,
    }
