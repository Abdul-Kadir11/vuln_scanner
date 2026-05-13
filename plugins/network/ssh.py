from core.plugin_base import PluginBase
import socket


class SSHSecurityCheck(PluginBase):

    name = "SSH Security Check"
    category = "ssh"

    def run(self, target):

        findings = []

        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect((target.replace("http://", "").replace("https://", ""), 22))

            banner = s.recv(1024).decode(errors="ignore")

            findings.append({
                "title": f"SSH Banner: {banner.strip()}",
                "severity": "MEDIUM",
                "cve": None,
                "evidence": banner,
                "port": 22,
                "service": "ssh"
            })

            if "OpenSSH_4" in banner:
                findings.append({
                    "title": "Outdated SSH version detected",
                    "severity": "HIGH",
                    "cve": "CVE-2008-0166",
                    "evidence": banner,
                    "port": 22,
                    "service": "ssh"
                })

            s.close()

        except Exception as e:
            findings.append({
                "title": f"SSH unreachable: {str(e)}",
                "severity": "LOW",
                "cve": None,
                "evidence": None,
                "port": 22,
                "service": "ssh"
            })

        return findings
