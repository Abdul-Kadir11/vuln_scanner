from typing import List, Dict, Any


class FindingContract:

    REQUIRED_KEYS = {
        "title",
        "severity",
        "cve",
        "evidence",
        "port",
        "service"
    }

    @staticmethod
    def normalize_list(findings: Any) -> List[Dict[str, Any]]:

        if not isinstance(findings, list):
            return []

        normalized = []

        for f in findings:
            if not isinstance(f, dict):
                continue

            clean = {
                "title": f.get("title", "Unknown issue"),
                "severity": f.get("severity", "LOW"),
                "cve": f.get("cve"),
                "evidence": f.get("evidence"),
                "port": f.get("port"),
                "service": f.get("service"),
            }

            normalized.append(clean)

        return normalized
