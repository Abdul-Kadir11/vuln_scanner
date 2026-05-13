"""Evidence normalization utilities for scanner findings."""

from __future__ import annotations

from typing import Any, Dict, Optional


def standardize_finding(
    title: str,
    severity: str = "Info",
    evidence: Optional[Dict[str, Any]] = None,
    remediation: str = "",
    **extra: Any,
) -> Dict[str, Any]:
    """Return a normalized finding payload used by all scanner modules."""
    finding: Dict[str, Any] = {
        "title": title,
        "severity": severity,
        "evidence": evidence or {},
        "remediation": remediation,
    }
    finding.update(extra)
    return finding

