class Finding:
    def __init__(self, title, severity="LOW", cve=None, evidence=None, port=None, service=None):
        self.title = title
        self.severity = severity
        self.cve = cve
        self.evidence = evidence
        self.port = port
        self.service = service

    def to_dict(self):
        return {
            "title": self.title,
            "severity": self.severity,
            "cve": self.cve,
            "evidence": self.evidence,
            "port": self.port,
            "service": self.service
        }
