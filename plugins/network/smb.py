from core.plugin_base import PluginBase
import socket


class SMBSecurityCheck(PluginBase):

    name = "SMB Security Check"
    category = "smb"

    def run(self, target):

        findings = []

        try:
            s = socket.socket()
            s.settimeout(5)
            result = s.connect_ex(
                (target.replace("http://", "").replace("https://", ""), 445)
            )

            if result == 0:
                findings.append({
                    "title": "SMB port open",
                    "severity": "MEDIUM",
                    "cve": None,
                    "evidence": "Port 445 reachable",
                    "port": 445,
                    "service": "smb"
                })

            s.close()

        except Exception as e:
            findings.append({
                "title": f"SMB unreachable: {str(e)}",
                "severity": "LOW",
                "cve": None,
                "evidence": None,
                "port": 445,
                "service": "smb"
            })

        return findings
