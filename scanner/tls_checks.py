"""TLS certificate checks."""

from __future__ import annotations

import socket
import ssl
import fnmatch
from datetime import datetime, timezone
from typing import Dict, List
from urllib.parse import urlparse

from scanner.evidence import standardize_finding


def _extract_host(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"//{target}")
    return (parsed.hostname or target).strip()


def _hostname_matches(cert: Dict[str, object], host: str) -> bool:
    san = cert.get("subjectAltName", ()) or ()
    dns_names = [value for key, value in san if key == "DNS"]
    if dns_names:
        return any(fnmatch.fnmatch(host.lower(), pattern.lower()) for pattern in dns_names)

    subject = cert.get("subject", ()) or ()
    common_names = []
    for tuple_group in subject:
        for key, value in tuple_group:
            if key == "commonName":
                common_names.append(value)
    return any(fnmatch.fnmatch(host.lower(), pattern.lower()) for pattern in common_names)


def check_tls_certificate(target: str, timeout: float = 5.0) -> Dict[str, object]:
    """Validate TLS certificate attributes for a target."""
    findings: List[Dict[str, object]] = []
    host = _extract_host(target)
    cert: Dict[str, object] = {}
    cert_expiry_days = None

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert() or {}
    except (socket.timeout, socket.gaierror, OSError, ssl.SSLError) as exc:
        findings.append(
            standardize_finding(
                title="TLS handshake/certificate check failed",
                severity="Low",
                evidence={
                    "module": "tls_checks",
                    "host": host,
                    "port": 443,
                    "timeout_sec": timeout,
                    "error": str(exc),
                },
                remediation="Ensure TLS is correctly configured and reachable on port 443.",
                category="tls",
                port=443,
                base_cvss=2.0,
            )
        )
        return {"findings": findings, "certificate": cert, "expiry_days": cert_expiry_days}

    not_after = cert.get("notAfter")
    if not_after:
        expires_at = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        cert_expiry_days = (expires_at - datetime.now(timezone.utc)).days
        if cert_expiry_days < 0:
            findings.append(
                standardize_finding(
                    title="TLS certificate is expired",
                    severity="High",
                    evidence={
                        "module": "tls_checks",
                        "host": host,
                        "expires_at": expires_at.isoformat(),
                        "days_to_expiry": cert_expiry_days,
                    },
                    remediation="Renew and deploy a valid certificate immediately.",
                    category="tls",
                    port=443,
                    base_cvss=8.0,
                    known_exploited=False,
                )
            )
        elif cert_expiry_days <= 30:
            findings.append(
                standardize_finding(
                    title="TLS certificate expires soon",
                    severity="Medium",
                    evidence={
                        "module": "tls_checks",
                        "host": host,
                        "expires_at": expires_at.isoformat(),
                        "days_to_expiry": cert_expiry_days,
                    },
                    remediation="Rotate certificate before expiry to avoid service disruption.",
                    category="tls",
                    port=443,
                    base_cvss=5.0,
                )
            )

    if not _hostname_matches(cert, host):
        findings.append(
            standardize_finding(
                title="TLS certificate hostname mismatch",
                severity="High",
                evidence={
                    "module": "tls_checks",
                    "host": host,
                    "error": "certificate_common_name_or_san_mismatch",
                    "certificate_subject_alt_name": cert.get("subjectAltName", []),
                },
                remediation="Install a certificate with SAN/CN matching the scanned hostname.",
                category="tls",
                port=443,
                base_cvss=7.5,
            )
        )

    subject = cert.get("subject", ())
    issuer = cert.get("issuer", ())
    if subject and issuer and subject == issuer:
        findings.append(
            standardize_finding(
                title="Self-signed TLS certificate detected",
                severity="Medium",
                evidence={
                    "module": "tls_checks",
                    "host": host,
                    "subject": subject,
                    "issuer": issuer,
                },
                remediation="Use a certificate issued by a trusted public or internal CA.",
                category="tls",
                port=443,
                base_cvss=5.5,
            )
        )

    return {"findings": findings, "certificate": cert, "expiry_days": cert_expiry_days}
