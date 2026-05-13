"""DNS resolution and email security record checks."""

from __future__ import annotations

from typing import Dict, List
from urllib.parse import urlparse

import dns.resolver
import dns.exception

from scanner.evidence import standardize_finding


def _extract_host(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"//{target}")
    return (parsed.hostname or target).strip().rstrip(".")


def _safe_resolve(name: str, record_type: str, timeout: float) -> List[str]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    try:
        answers = resolver.resolve(name, record_type)
        return sorted([str(answer).strip() for answer in answers])
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []


def run_dns_checks(target: str, timeout: float = 4.0) -> Dict[str, object]:
    """Resolve A/MX and detect missing SPF/DMARC records."""
    findings = []
    host = _extract_host(target)

    a_records = _safe_resolve(host, "A", timeout)
    mx_records = _safe_resolve(host, "MX", timeout)
    txt_records = _safe_resolve(host, "TXT", timeout)
    dmarc_records = _safe_resolve(f"_dmarc.{host}", "TXT", timeout)

    spf_present = any("v=spf1" in txt.lower() for txt in txt_records)
    dmarc_present = any("v=dmarc1" in txt.lower() for txt in dmarc_records)

    if not spf_present:
        findings.append(
            standardize_finding(
                title="SPF record missing",
                severity="Medium",
                evidence={
                    "module": "dns_checks",
                    "host": host,
                    "a_records": a_records,
                    "mx_records": mx_records,
                    "txt_records": txt_records,
                },
                remediation="Publish an SPF TXT record to limit mail sender spoofing.",
                category="dns",
                base_cvss=5.3,
                port=53,
            )
        )

    if not dmarc_present:
        findings.append(
            standardize_finding(
                title="DMARC record missing",
                severity="Medium",
                evidence={
                    "module": "dns_checks",
                    "host": host,
                    "dmarc_records": dmarc_records,
                },
                remediation="Publish a DMARC policy at `_dmarc.<domain>`.",
                category="dns",
                base_cvss=5.8,
                port=53,
            )
        )

    return {
        "findings": findings,
        "records": {
            "A": a_records,
            "MX": mx_records,
            "TXT": txt_records,
            "DMARC_TXT": dmarc_records,
        },
    }

