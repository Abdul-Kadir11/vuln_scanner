from core.plugin_base import PluginBase
import socket


class FTPSecurityCheck(PluginBase):

    name = "FTP Security Check"
    category = "ftp"

    def run(self, target):

        findings = []

        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect((target.replace("http://", "").replace("https://", ""), 21))

            banner = s.recv(1024).decode(errors="ignore")

            findings.append({
                "title": f"FTP Banner: {banner.strip()}",
                "severity": "CRITICAL" if "vsFTPd 2.3.4" in banner else "MEDIUM",
                "cve": "CVE-2011-2523" if "vsFTPd 2.3.4" in banner else None,
                "evidence": banner,
                "port": 21,
                "service": "ftp"
            })

            s.close()

        except Exception as e:
            findings.append({
                "title": f"FTP unreachable: {str(e)}",
                "severity": "LOW",
                "cve": None,
                "evidence": None,
                "port": 21,
                "service": "ftp"
            })

        return findings
