import re


def score_issue(title: str) -> str:
    title = title.lower()

    if any(x in title for x in ["rce", "remote code", "exploit", "bindshell"]):
        return "CRITICAL"

    if any(x in title for x in ["outdated", "vulnerable", "cve"]):
        return "HIGH"

    if any(x in title for x in ["missing", "weak", "banner"]):
        return "MEDIUM"

    return "LOW"


def match_cve(text: str):
    """
    Extract CVE identifiers if present in text.
    """
    match = re.findall(r"CVE-\d{4}-\d{4,7}", text)
    return match[0] if match else None
