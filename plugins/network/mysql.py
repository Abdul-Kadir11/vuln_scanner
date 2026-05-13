from core.plugin_base import PluginBase
import socket
import re


def extract_version(banner):
    match = re.search(r"\d+\.\d+(\.\d+)?", banner)
    return match.group(0) if match else "unknown"


class MySQLSecurityCheck(PluginBase):
    name = "MySQL Security Check"
    category = "mysql"

    def run(self, target):
        findings = []

        try:
            host = target.replace("http://", "").replace("https://", "")
            s = socket.socket()
            s.settimeout(3)
            s.connect((host, 3306))

            banner = s.recv(1024).decode(errors="ignore")
            s.close()

            version = extract_version(banner)

            findings.append({
                "title": f"MySQL Banner detected ({version})",
                "severity": "MEDIUM",
                "cve": None,
                "evidence": banner.strip(),
                "port": 3306,
                "service": "mysql"
            })

            if version.startswith("5.0") or version.startswith("5.1"):
                findings.append({
                    "title": "Outdated MySQL version detected",
                    "severity": "HIGH",
                    "cve": None,
                    "evidence": version,
                    "port": 3306,
                    "service": "mysql"
                })

        except Exception as e:
            findings.append({
                "title": f"MySQL scan failed: {str(e)}",
                "severity": "LOW",
                "cve": None,
                "evidence": None,
                "port": 3306,
                "service": "mysql"
            })

        return findings
