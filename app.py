"""Flask API entrypoint for the modular vulnerability scanner."""

from __future__ import annotations

from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

from flask import Flask, jsonify, render_template, request

from intelligence.kev_parser import fetch_known_exploited_cves
from intelligence.risk_engine import apply_risk_to_finding
from intelligence.vuln_mapper import map_service_version_to_cves
from reporting.json_export import export_scan_json
from reporting.pdf_report import generate_pdf_report
from scanner.api_checks import run_api_passive_checks
from scanner.crawler import crawl_same_origin
from scanner.dns_checks import run_dns_checks
from scanner.exploit_validation import validate_potential_exploitability
from scanner.fuzz_checks import run_safe_fuzz_checks
from scanner.http_checks import check_http_security_headers
from scanner.ports import tcp_connect_scan
from scanner.tls_checks import check_tls_certificate
from scanner.web_app_checks import run_web_app_passive_checks
from storage.db import save_scan_result

app = Flask(__name__)

SAFETY_WARNING = "Only scan systems you own or have permission to test."
MAX_DISTRIBUTED_TARGETS = 20
MAX_DISTRIBUTED_WORKERS = 8


def _map_compliance(title: str) -> List[Dict[str, str]]:
    title_l = title.lower()
    mappings: List[Dict[str, str]] = []

    if "port" in title_l or "tls" in title_l or "header" in title_l:
        mappings.append({"framework": "ISO 27001", "control": "A.8.20 Network Security"})
        mappings.append({"framework": "NIST CSF", "control": "PR.PT-4 Communications Protected"})
    if "header" in title_l:
        mappings.append({"framework": "OWASP ASVS", "control": "V14 Configuration"})
    if "spf" in title_l or "dmarc" in title_l:
        mappings.append({"framework": "NIST CSF", "control": "PR.DS-2 Data-in-Transit"})
    if "expired" in title_l or "hostname mismatch" in title_l:
        mappings.append({"framework": "OWASP Top 10", "control": "A02:2021 Cryptographic Failures"})

    return mappings


def _summarize(findings: List[Dict[str, object]]) -> Dict[str, int]:
    bucket = Counter(item.get("severity", "Info").lower() for item in findings)
    return {
        "critical": int(bucket.get("critical", 0)),
        "high": int(bucket.get("high", 0)),
        "medium": int(bucket.get("medium", 0)),
        "low": int(bucket.get("low", 0)),
        "info": int(bucket.get("info", 0)),
    }


def _enrich_and_score_findings(
    findings: List[Dict[str, object]],
    internet_exposed: bool,
    use_nvd_lookup: bool,
) -> List[Dict[str, object]]:
    kev_set = fetch_known_exploited_cves(timeout=8.0)
    for finding in findings:
        service = str(finding.get("service", "") or "").strip().lower()
        version = str(finding.get("version", "") or "").strip().lower()
        mapped_cves = map_service_version_to_cves(
            service=service,
            version=version,
            use_nvd_lookup=use_nvd_lookup,
        )

        if mapped_cves:
            finding["cves"] = mapped_cves
            finding["cve"] = mapped_cves[0]

        cve_ids = set()
        explicit_cve = str(finding.get("cve", "") or "").strip().upper()
        if explicit_cve:
            cve_ids.add(explicit_cve)
        for cve_item in finding.get("cves", []) or []:
            cve_ids.add(str(cve_item).strip().upper())

        kev_flag = any(cve_id in kev_set for cve_id in cve_ids)
        finding["kev_flag"] = kev_flag
        if kev_flag:
            finding["known_exploited"] = True

        finding["internet_exposed"] = bool(finding.get("internet_exposed", internet_exposed))
        scored = apply_risk_to_finding(finding, internet_exposed_default=internet_exposed)
        scored["compliance"] = _map_compliance(str(scored.get("title", "")))
    return findings


def _run_single_scan(payload: Dict[str, object], persist: bool = True) -> Dict[str, object]:
    target = str(payload.get("target", "")).strip()
    if not target:
        raise ValueError("target is required")

    exploit_mode = str(payload.get("exploit_mode", "safe") or "safe").strip().lower()
    if exploit_mode != "safe":
        raise ValueError("active exploit attempts are not supported; use exploit_mode='safe'")

    internet_exposed = bool(payload.get("internet_exposed", True))
    include_pdf = bool(payload.get("generate_pdf", True))
    include_json = bool(payload.get("generate_json", True))
    use_nvd_lookup = bool(payload.get("use_nvd_lookup", False))
    enable_deep_crawl = bool(payload.get("enable_deep_crawl", True))
    enable_fuzz_checks = bool(payload.get("enable_fuzz_checks", True))
    auth_context = payload.get("auth_context") if isinstance(payload.get("auth_context"), dict) else {}

    port_result = tcp_connect_scan(target=target, timeout=1.0, inter_probe_delay=0.06)
    http_result = check_http_security_headers(target=target, timeout=5.0, auth_context=auth_context)
    tls_result = check_tls_certificate(target=target, timeout=5.0)
    dns_result = run_dns_checks(target=target, timeout=4.0)
    web_app_result = run_web_app_passive_checks(target=target, timeout=5.0, auth_context=auth_context)
    api_result = run_api_passive_checks(target=target, timeout=5.0, auth_context=auth_context)

    findings: List[Dict[str, object]] = []
    findings.extend(port_result.get("findings", []))
    findings.extend(http_result.get("findings", []))
    findings.extend(tls_result.get("findings", []))
    findings.extend(dns_result.get("findings", []))
    findings.extend(web_app_result.get("findings", []))
    findings.extend(api_result.get("findings", []))

    crawl_result = {"start_url": None, "visited": []}
    fuzz_result = {"findings": [], "checked_urls": []}
    if enable_deep_crawl:
        crawl_result = crawl_same_origin(
            target=target,
            auth_context=auth_context,
            max_depth=min(int(payload.get("crawl_depth", 2) or 2), 4),
            max_pages=min(int(payload.get("max_crawl_pages", 30) or 30), 100),
            timeout=5.0,
            delay=0.15,
        )

    if enable_fuzz_checks:
        base_urls = crawl_result.get("visited", [])[:20]
        if not base_urls:
            checked_url = http_result.get("checked_url")
            if checked_url:
                base_urls = [str(checked_url)]
        fuzz_result = run_safe_fuzz_checks(
            base_urls=base_urls,
            auth_context=auth_context,
            timeout=4.0,
            delay=0.1,
        )
        findings.extend(fuzz_result.get("findings", []))

    findings = _enrich_and_score_findings(
        findings=findings,
        internet_exposed=internet_exposed,
        use_nvd_lookup=use_nvd_lookup,
    )

    validation_findings = validate_potential_exploitability(findings)
    if validation_findings:
        validation_findings = _enrich_and_score_findings(
            findings=validation_findings,
            internet_exposed=internet_exposed,
            use_nvd_lookup=False,
        )
        findings.extend(validation_findings)

    summary = _summarize(findings)
    response: Dict[str, object] = {
        "target": target,
        "warning": SAFETY_WARNING,
        "findings": findings,
        "summary": summary,
        "scan_metadata": {
            "open_ports": port_result.get("open_ports", []),
            "http_checked_url": http_result.get("checked_url"),
            "dns_records": dns_result.get("records", {}),
            "tls_expiry_days": tls_result.get("expiry_days"),
            "web_app": web_app_result.get("checked", {}),
            "api_docs": api_result.get("api_docs", []),
            "api_diff_checks": api_result.get("diff_checks", []),
            "api_differential_vectors": api_result.get("differential_vectors", []),
            "crawler": crawl_result,
            "fuzz_checked_urls": fuzz_result.get("checked_urls", []),
            "exploit_validation_mode": "safe_non_invasive",
        },
    }

    if include_json:
        response["json_report_path"] = export_scan_json(response)
    if include_pdf:
        response["pdf_report_path"] = generate_pdf_report(response)
    if persist:
        response["scan_id"] = save_scan_result(response)
    return response


@app.get("/")
def dashboard():
    """Render dashboard UI."""
    return render_template("index.html", safety_warning=SAFETY_WARNING)


@app.post("/api/scan")
def api_scan():
    """
    Run safe evidence-based vulnerability checks.
    """
    payload = request.get_json(silent=True) or {}
    try:
        response = _run_single_scan(payload=payload, persist=True)
    except ValueError as exc:
        return jsonify({"error": str(exc), "warning": SAFETY_WARNING}), 400
    return jsonify(response), 200


@app.post("/api/scan/distributed")
def api_scan_distributed():
    """Run distributed multi-target scans using bounded worker pool."""
    payload = request.get_json(silent=True) or {}
    targets = payload.get("targets")
    if not isinstance(targets, list) or not targets:
        return jsonify({"error": "targets must be a non-empty list", "warning": SAFETY_WARNING}), 400
    if len(targets) > MAX_DISTRIBUTED_TARGETS:
        return jsonify(
            {
                "error": f"too many targets: max {MAX_DISTRIBUTED_TARGETS}",
                "warning": SAFETY_WARNING,
            }
        ), 400

    worker_count = max(1, min(int(payload.get("workers", 4) or 4), MAX_DISTRIBUTED_WORKERS))
    scan_payload = {k: v for k, v in payload.items() if k not in {"targets", "workers"}}

    results: List[Dict[str, object]] = []
    errors: List[Dict[str, str]] = []
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {}
        for target in targets:
            target_payload = dict(scan_payload)
            target_payload["target"] = str(target).strip()
            future = executor.submit(_run_single_scan, target_payload, False)
            future_map[future] = str(target)

        for future in as_completed(future_map):
            target = future_map[future]
            try:
                result = future.result()
                result["scan_id"] = save_scan_result(result)
                results.append(result)
            except (ValueError, RuntimeError, OSError) as exc:
                errors.append({"target": target, "error": str(exc)})

    aggregate_findings = []
    for item in results:
        aggregate_findings.extend(item.get("findings", []))

    return jsonify(
        {
            "warning": SAFETY_WARNING,
            "mode": "distributed",
            "workers": worker_count,
            "results": results,
            "errors": errors,
            "summary": _summarize(aggregate_findings),
        }
    ), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
