"""TCP connect scan module."""

from __future__ import annotations

import socket
import time
import re
from typing import Dict, List
from urllib.parse import urlparse

from scanner.evidence import standardize_finding

# Only scan systems you own or have permission to test.
DEFAULT_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 3306, 8080]
CRITICAL_PORTS = {21, 22, 53, 80, 443, 3306, 8080}
PORT_BASE_CVSS: Dict[int, float] = {
    21: 7.5,
    22: 6.5,
    25: 5.0,
    53: 6.0,
    80: 5.0,
    110: 5.0,
    143: 5.0,
    443: 4.0,
    3306: 8.0,
    8080: 6.0,
}
PORT_SERVICES: Dict[int, str] = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    3306: "mysql",
    8080: "http-alt",
}


def _extract_host(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"//{target}")
    return (parsed.hostname or target).strip()


def _extract_version(banner: str) -> str | None:
    match = re.search(r"\d+\.\d+(?:\.\d+)?(?:[a-zA-Z0-9\-_]+)?", banner)
    return match.group(0) if match else None


def _grab_banner(host: str, port: int, timeout: float) -> str | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if port in {80, 8080}:
                request = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
                sock.sendall(request)
                return sock.recv(2048).decode(errors="ignore").strip()
            return sock.recv(2048).decode(errors="ignore").strip()
    except (socket.timeout, socket.gaierror, OSError):
        return None


def tcp_connect_scan(
    target: str,
    ports: List[int] | None = None,
    timeout: float = 1.0,
    inter_probe_delay: float = 0.05,
) -> Dict[str, object]:
    """Perform a safe TCP connect scan with timeout and speed limiting."""
    host = _extract_host(target)
    scan_ports = ports or DEFAULT_PORTS
    open_ports: List[int] = []
    findings = []

    for port in scan_ports:
        started_at = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((host, port))
            latency_ms = round((time.time() - started_at) * 1000, 2)
            if result == 0:
                open_ports.append(port)
                service = PORT_SERVICES.get(port, "unknown")
                banner = _grab_banner(host, port, timeout)
                version = _extract_version(banner or "")
                findings.append(
                    standardize_finding(
                        title=f"Open TCP port detected: {port}",
                        severity="Medium",
                        evidence={
                            "module": "ports",
                            "host": host,
                            "port": port,
                            "service": service,
                            "version": version,
                            "banner": banner,
                            "protocol": "tcp",
                            "latency_ms": latency_ms,
                            "timeout_sec": timeout,
                        },
                        remediation="Restrict exposed services using firewall rules or service ACLs.",
                        category="network",
                        port=port,
                        service=service,
                        version=version,
                        internet_exposed=True,
                        known_exploited=False,
                        base_cvss=PORT_BASE_CVSS.get(port, 5.0),
                    )
                )
        except (socket.timeout, socket.gaierror, OSError):
            continue
        finally:
            sock.close()
            time.sleep(inter_probe_delay)

    return {"host": host, "open_ports": open_ports, "findings": findings}
