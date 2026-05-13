import ipaddress
import shutil
import subprocess
from urllib.parse import urlparse


def _extract_host(target):
    parsed = urlparse(target if "://" in target else f"//{target}")
    return parsed.hostname or target


def _is_ip_address(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def scan(target):
    host = _extract_host(target).strip().lower()

    if not host or _is_ip_address(host):
        return []

    if shutil.which("amass") is None:
        raise RuntimeError("amass binary not found in PATH")

    cmd = ["amass", "enum", "-passive", "-norecursive", "-noalts", "-d", host]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=240, check=False)

    if result.returncode != 0 and not result.stdout.strip():
        raise RuntimeError(result.stderr.strip() or "amass failed")

    discovered = {
        line.strip().lower()
        for line in result.stdout.splitlines()
        if line.strip() and line.strip().lower().endswith(host)
    }

    return sorted(discovered)
