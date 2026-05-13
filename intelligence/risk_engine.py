"""Risk scoring engine."""

from __future__ import annotations

from typing import Dict, Iterable

CRITICAL_PORTS = {21, 22, 53, 80, 443, 3306, 8080}


def _severity_from_score(score: float) -> str:
    if score >= 85:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    if score >= 15:
        return "Low"
    return "Info"


def calculate_risk_score(
    base_cvss: float = 0.0,
    internet_exposed: bool = False,
    port: int | None = None,
    known_exploited: bool = False,
    critical_ports: Iterable[int] = CRITICAL_PORTS,
) -> Dict[str, object]:
    """
    Calculate normalized risk score [0, 100] from weighted factors.
    """
    score = max(0.0, min(base_cvss, 10.0)) * 10.0

    if known_exploited:
        score += 25.0
    if internet_exposed:
        score += 15.0
    if port is not None and port in set(critical_ports):
        score += 10.0

    normalized = max(0.0, min(score, 100.0))
    severity = _severity_from_score(normalized)
    return {"risk_score": round(normalized, 2), "severity": severity}


def apply_risk_to_finding(
    finding: Dict[str, object],
    internet_exposed_default: bool = False,
) -> Dict[str, object]:
    """Attach risk_score and normalized severity onto a finding dict."""
    evidence = finding.get("evidence", {}) or {}
    port = finding.get("port")
    if port is None and isinstance(evidence, dict):
        port = evidence.get("port")

    scoring = calculate_risk_score(
        base_cvss=float(finding.get("base_cvss", 0.0) or 0.0),
        internet_exposed=bool(finding.get("internet_exposed", internet_exposed_default)),
        port=int(port) if isinstance(port, int) else None,
        known_exploited=bool(finding.get("known_exploited", False)),
    )
    finding["risk_score"] = scoring["risk_score"]
    finding["severity"] = scoring["severity"]
    return finding

