import requests
from core.plugin_base import PluginBase


class SecurityHeaders(PluginBase):

    name = "Security Headers Check"
    category = "web"

    def run(self, target):

        if not target.startswith("http"):
            target = "http://" + target

        try:
            r = requests.get(target, timeout=5)

            headers = r.headers
            findings = []

            if "Content-Security-Policy" not in headers:
                findings.append({
                    "title": "Missing Content-Security-Policy",
                    "severity": "MEDIUM",
                    "cve": None,
                    "evidence": None,
                    "port": 80,
                    "service": "http"
                })

            if "X-Frame-Options" not in headers:
                findings.append({
                    "title": "Missing X-Frame-Options",
                    "severity": "MEDIUM",
                    "cve": None,
                    "evidence": None,
                    "port": 80,
                    "service": "http"
                })

            return findings

        except Exception:
            return [{
                "title": "Target unreachable",
                "severity": "LOW",
                "cve": None,
                "evidence": None,
                "port": None,
                "service": None
            }]
