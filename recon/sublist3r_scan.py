import ipaddress
from urllib.parse import urlparse

DEFAULT_SUBLIST3R_ENGINES = (
    "baidu,yahoo,google,bing,ask,netcraft,virustotal,threatcrowd,ssl,passivedns"
)


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
    host = _extract_host(target).strip()

    if not host or _is_ip_address(host):
        return []

    try:
        import sublist3r
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "Sublist3r is not installed in the active environment. "
            "Install dependencies before running recon scans."
        ) from exc

    discovered = sublist3r.main(
        host,
        20,
        None,
        ports=None,
        silent=True,
        verbose=False,
        enable_bruteforce=False,
        engines=DEFAULT_SUBLIST3R_ENGINES
    )

    if not discovered:
        return []

    unique_subdomains = sorted({item.strip() for item in discovered if item and item.strip()})
    return unique_subdomains
