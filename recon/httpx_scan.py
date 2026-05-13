import re
import shutil
import subprocess


HTTPX_STATUS_RE = re.compile(r"\[(\d{3})\]")
HTTPX_BIN_CANDIDATES = ("httpx-toolkit", "httpx")


def _resolve_httpx_binary():
    for candidate in HTTPX_BIN_CANDIDATES:
        binary = shutil.which(candidate)
        if binary is None:
            continue

        help_output = subprocess.run(
            [binary, "-h"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        combined_help = f"{help_output.stdout}\n{help_output.stderr}".lower()
        if "-tech-detect" in combined_help or "projectdiscovery" in combined_help:
            return binary

    return None


def scan(targets):
    normalized_targets = [target.strip() for target in targets if target and target.strip()]
    if not normalized_targets:
        return []

    binary = _resolve_httpx_binary()
    if binary is None:
        raise RuntimeError("ProjectDiscovery httpx binary not found in PATH")

    command = [binary, "-silent", "-status-code", "-title", "-tech-detect", "-web-server", "-no-color"]
    payload = "\n".join(normalized_targets) + "\n"
    result = subprocess.run(
        command,
        input=payload,
        capture_output=True,
        text=True,
        timeout=240,
        check=False,
    )

    if result.returncode != 0 and not result.stdout.strip():
        raise RuntimeError(result.stderr.strip() or "httpx failed")

    findings = []
    for line in result.stdout.splitlines():
        cleaned = line.strip()
        if not cleaned:
            continue
        endpoint = cleaned.split(" ", 1)[0]
        status_match = HTTPX_STATUS_RE.search(cleaned)
        findings.append({
            "endpoint": endpoint,
            "status_code": int(status_match.group(1)) if status_match else None,
            "raw": cleaned,
        })

    return findings
