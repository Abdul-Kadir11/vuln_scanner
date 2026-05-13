import json
import shutil
import subprocess
import tempfile


def scan(targets):
    normalized_targets = [target.strip() for target in targets if target and target.strip()]
    if not normalized_targets:
        return []

    if shutil.which("nuclei") is None:
        raise RuntimeError("nuclei binary not found in PATH")

    with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8") as target_file:
        target_file.write("\n".join(normalized_targets))
        target_file.flush()

        command = ["nuclei", "-silent", "-jsonl", "-l", target_file.name]
        result = subprocess.run(command, capture_output=True, text=True, timeout=300, check=False)

    if result.returncode != 0 and not result.stdout.strip():
        raise RuntimeError(result.stderr.strip() or "nuclei failed")

    findings = []
    for line in result.stdout.splitlines():
        cleaned = line.strip()
        if not cleaned:
            continue
        try:
            item = json.loads(cleaned)
        except json.JSONDecodeError:
            continue

        info = item.get("info", {})
        findings.append({
            "name": info.get("name") or item.get("template-id") or "Nuclei finding",
            "severity": str(info.get("severity", "info")).upper(),
            "matched_at": item.get("matched-at"),
            "template_id": item.get("template-id"),
        })

    return findings
