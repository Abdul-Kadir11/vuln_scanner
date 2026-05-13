def normalize_findings(raw_findings):
    normalized = []

    for item in raw_findings:
        if isinstance(item, dict):
            normalized.append(item)

        elif isinstance(item, str):
            normalized.append({
                "title": item,
                "severity": "LOW",
                "cve": None,
                "evidence": item,
                "port": None,
                "service": None
            })

    return normalized
