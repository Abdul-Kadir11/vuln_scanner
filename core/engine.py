import socket
import importlib
import os
import pkgutil
from urllib.parse import urlparse
from core.cve_map import match_cve
from recon.sublist3r_scan import scan as sublist3r_scan
from recon.subfinder_scan import scan as subfinder_scan
from recon.amass_scan import scan as amass_scan
from recon.httpx_scan import scan as httpx_scan
from recon.nuclei_scan import scan as nuclei_scan


COMMON_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    139: "netbios",
    445: "smb",
    3306: "mysql",
    5432: "postgresql"
}

SUPPORTED_ADVANCED_TOOLS = {"sublist3r", "subfinder", "amass", "httpx", "nuclei"}


def _extract_host(target):
    parsed = urlparse(target if "://" in target else f"//{target}")
    return parsed.hostname or target


def _normalize_probe_targets(target, subdomains):
    candidates = set()

    if target and target.strip():
        candidates.add(target.strip())

    for subdomain in subdomains:
        if subdomain and subdomain.strip():
            candidates.add(subdomain.strip())

    normalized = set()
    for candidate in candidates:
        if "://" in candidate:
            normalized.add(candidate)
            continue

        normalized.add(f"http://{candidate}")
        normalized.add(f"https://{candidate}")

    return sorted(normalized)


def _resolve_enabled_tools(disabled_tools):
    disabled = {item.lower() for item in (disabled_tools or [])}
    unknown = sorted(disabled - SUPPORTED_ADVANCED_TOOLS)
    if unknown:
        raise ValueError(f"Unknown tool(s): {', '.join(unknown)}")
    return {tool: tool not in disabled for tool in SUPPORTED_ADVANCED_TOOLS}


def _detect_version(host, port):
    try:
        with socket.create_connection((host, port), timeout=1.5) as sock:
            sock.settimeout(1.5)

            if port == 80:
                request = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
                sock.sendall(request)
                response = sock.recv(2048).decode(errors="ignore")
                for line in response.splitlines():
                    if line.lower().startswith("server:"):
                        return line.split(":", 1)[1].strip()
                return None

            banner = sock.recv(1024)

            if not banner:
                return None

            if port == 3306 and len(banner) > 5:
                payload = banner[4:]
                version_raw = payload[1:].split(b"\x00", 1)[0]
                return version_raw.decode(errors="ignore").strip() or None

            line = banner.decode(errors="ignore").strip().splitlines()
            if not line:
                return None

            first_line = line[0]
            printable_ratio = sum(ch.isprintable() for ch in first_line) / len(first_line)
            if printable_ratio < 0.85 or not any(ch.isalnum() for ch in first_line):
                return None

            return first_line
    except Exception:
        return None


def scan_ports(target):
    open_ports = []
    services = {}
    versions = {}
    cves = {}
    host = _extract_host(target)

    for port in COMMON_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)

        result = sock.connect_ex((host, port))

        if result == 0:
            open_ports.append(port)
            services[port] = COMMON_PORTS[port]
            version = _detect_version(host, port)
            versions[port] = version

            cve_input = f"{services[port]} {version}" if version else services[port]
            cves[port] = match_cve(cve_input)

        sock.close()

    return open_ports, services, versions, cves


def load_plugins():
    plugins = []

    for category in os.listdir("plugins"):
        category_path = os.path.join("plugins", category)

        if os.path.isdir(category_path):
            for _, module_name, _ in pkgutil.iter_modules([category_path]):
                module = importlib.import_module(
                    f"plugins.{category}.{module_name}"
                )

                if hasattr(module, "Plugin"):
                    plugins.append(module.Plugin())
                    continue

                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if isinstance(attr, type) and hasattr(attr, "run") and hasattr(attr, "name"):
                        if attr.__module__ != module.__name__:
                            continue
                        if attr.__name__ == "PluginBase":
                            continue
                        plugins.append(attr())
                        break

    return plugins


def run_scan(target, no_recon=False, generate_report=False, disabled_tools=None):
    print(f"[+] Running scan on {target}")

    open_ports, services, versions, cves = scan_ports(target)
    subdomains = []
    live_endpoints = []
    enabled_tools = _resolve_enabled_tools(disabled_tools)

    plugins = load_plugins()

    results = []

    recon_sources = []
    if not no_recon:
        if enabled_tools["sublist3r"]:
            recon_sources.append(("Sublist3r Recon", sublist3r_scan))
        if enabled_tools["subfinder"]:
            recon_sources.append(("Subfinder Recon", subfinder_scan))
        if enabled_tools["amass"]:
            recon_sources.append(("Amass Recon", amass_scan))

    collected_subdomains = set()
    for source_name, recon_func in recon_sources:
        try:
            discovered = recon_func(target)
            if discovered:
                collected_subdomains.update(discovered)
                results.append({
                    "plugin": source_name,
                    "issues": [{
                        "severity": "INFO",
                        "title": f"Discovered subdomain: {subdomain}",
                        "cve": None
                    } for subdomain in discovered]
                })
        except Exception as e:
            results.append({
                "plugin": source_name,
                "issues": [{
                    "severity": "LOW",
                    "title": f"{source_name} failed: {str(e)}",
                    "cve": None
                }]
            })

    subdomains = sorted(collected_subdomains)

    probe_targets = _normalize_probe_targets(target, subdomains)

    if enabled_tools["httpx"]:
        try:
            live_endpoints = httpx_scan(probe_targets)
            if live_endpoints:
                httpx_issues = []
                for item in live_endpoints:
                    status_suffix = f" (status {item['status_code']})" if item["status_code"] else ""
                    httpx_issues.append({
                        "severity": "INFO",
                        "title": f"Live endpoint: {item['endpoint']}{status_suffix}",
                        "cve": None
                    })
                results.append({
                    "plugin": "HTTPX Probe",
                    "issues": httpx_issues
                })
        except Exception as e:
            results.append({
                "plugin": "HTTPX Probe",
                "issues": [{
                    "severity": "LOW",
                    "title": f"HTTPX probe failed: {str(e)}",
                    "cve": None
                }]
            })

    if enabled_tools["nuclei"]:
        try:
            nuclei_findings = nuclei_scan(probe_targets)
            if nuclei_findings:
                nuclei_issues = []
                for finding in nuclei_findings:
                    template_suffix = f" [{finding['template_id']}]" if finding["template_id"] else ""
                    target_suffix = f" on {finding['matched_at']}" if finding["matched_at"] else ""
                    nuclei_issues.append({
                        "severity": finding["severity"],
                        "title": f"{finding['name']}{template_suffix}{target_suffix}",
                        "cve": None
                    })
                results.append({
                    "plugin": "Nuclei Scan",
                    "issues": nuclei_issues
                })
        except Exception as e:
            results.append({
                "plugin": "Nuclei Scan",
                "issues": [{
                    "severity": "LOW",
                    "title": f"Nuclei scan failed: {str(e)}",
                    "cve": None
                }]
            })

    for plugin in plugins:
        try:
            findings = plugin.run(target)

            results.append({
                "plugin": plugin.name,
                "issues": findings
            })

        except Exception as e:
            results.append({
                "plugin": plugin.name,
                "issues": [{
                    "severity": "LOW",
                    "title": str(e),
                    "cve": None
                }]
            })

    return {
        "target": target,
        "results": results,
        "open_ports": open_ports,
        "services": services,
        "versions": versions,
        "cves": cves,
        "subdomains": subdomains,
        "live_endpoints": live_endpoints
    }
