def score_issue(text):
    text = text.lower()

    if "critical" in text or "bindshell" in text or "vsftpd 2.3.4" in text:
        return "CRITICAL"

    if "outdated" in text or "weak" in text or "telnet" in text:
        return "HIGH"

    if "missing" in text or "banner" in text:
        return "MEDIUM"

    return "LOW"
