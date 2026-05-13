"""Differential request analyzer for safe input variation testing."""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import requests

from scanner.evidence import standardize_finding
from scanner.request_context import build_request_kwargs


class DifferentialAnalyzer:
    """Run baseline vs mutated request comparisons for anomaly detection."""

    SAFE_PAYLOADS = (
        "'",
        '"',
        "<script>alert(1)</script>",
        "1 OR 1=1",
        "../../etc/passwd",
    )

    def __init__(self, timeout: float = 5.0, delay: float = 0.2) -> None:
        self.timeout = timeout
        self.delay = delay

    def send_request(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        auth_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Send GET request and return normalized response snapshot."""
        request_kwargs = build_request_kwargs(auth_context=auth_context, timeout=self.timeout)
        try:
            started = time.time()
            response = requests.get(url, params=params or {}, **request_kwargs)
            elapsed = time.time() - started
            return {
                "status_code": response.status_code,
                "content_length": len(response.text),
                "headers": dict(response.headers),
                "body_sample": response.text[:500],
                "time": round(elapsed, 5),
                "url": response.url,
            }
        except requests.RequestException as exc:
            return {"error": str(exc)}

    def compare(self, baseline: Dict[str, Any], mutated: Dict[str, Any]) -> Dict[str, Any]:
        """Compare baseline and mutated response profiles."""
        result = {
            "status_diff": False,
            "length_diff": False,
            "time_diff": False,
            "error_pattern": False,
            "confidence": 0,
        }
        if "error" in baseline or "error" in mutated:
            return result

        if baseline["status_code"] != mutated["status_code"]:
            result["status_diff"] = True
            result["confidence"] += 25

        length_delta = abs(baseline["content_length"] - mutated["content_length"])
        if length_delta > 50:
            result["length_diff"] = True
            result["confidence"] += 20

        time_delta = abs(baseline["time"] - mutated["time"])
        if time_delta > 1.0:
            result["time_diff"] = True
            result["confidence"] += 20

        error_keywords = (
            "sql",
            "syntax error",
            "exception",
            "stack trace",
            "unexpected token",
            "warning",
            "fatal error",
        )
        body = str(mutated.get("body_sample", "")).lower()
        if any(keyword in body for keyword in error_keywords):
            result["error_pattern"] = True
            result["confidence"] += 35
        return result

    def analyze(
        self,
        url: str,
        param_name: str,
        auth_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Analyze one endpoint with safe mutated payloads."""
        findings: List[Dict[str, Any]] = []
        vectors: List[Dict[str, Any]] = []

        baseline = self.send_request(url=url, auth_context=auth_context)
        for payload in self.SAFE_PAYLOADS:
            mutated = self.send_request(
                url=url,
                params={param_name: payload},
                auth_context=auth_context,
            )
            comparison = self.compare(baseline, mutated)
            vectors.append(
                {
                    "param": param_name,
                    "payload": payload,
                    "baseline": baseline,
                    "mutated": mutated,
                    "analysis": comparison,
                }
            )

            confidence = int(comparison["confidence"])
            if confidence >= 40:
                findings.append(
                    standardize_finding(
                        title="Suspicious differential input behavior detected",
                        severity=self.map_severity(confidence),
                        evidence={
                            "module": "differential_analyzer",
                            "url": url,
                            "vector": f"{param_name}={payload}",
                            "baseline_status": baseline.get("status_code"),
                            "mutated_status": mutated.get("status_code"),
                            "comparison": comparison,
                        },
                        remediation="Validate/sanitize input and enforce strict parameter handling and output encoding.",
                        category="api",
                        service="http",
                        base_cvss=self.map_risk(confidence) / 10.0,
                        internet_exposed=True,
                        vector=f"{param_name}={payload}",
                        confidence_score=confidence,
                    )
                )
            time.sleep(self.delay)

        return {"findings": findings, "vectors": vectors}

    @staticmethod
    def map_severity(score: int) -> str:
        if score >= 70:
            return "High"
        if score >= 50:
            return "Medium"
        return "Low"

    @staticmethod
    def map_risk(score: int) -> int:
        return min(100, score + 20)

