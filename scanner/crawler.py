"""Safe depth-limited crawler for passive discovery."""

from __future__ import annotations

import time
from collections import deque
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import requests

from scanner.request_context import build_request_kwargs


def crawl_same_origin(
    target: str,
    auth_context: Optional[Dict[str, Any]] = None,
    max_depth: int = 2,
    max_pages: int = 30,
    timeout: float = 5.0,
    delay: float = 0.15,
) -> Dict[str, object]:
    """Passively crawl same-origin links using GET requests only."""
    start = target if target.startswith(("http://", "https://")) else f"https://{target}"
    origin = urlparse(start).netloc.lower()
    visited: Set[str] = set()
    discovered: List[str] = []
    queue = deque([(start, 0)])

    request_kwargs = build_request_kwargs(auth_context=auth_context, timeout=timeout)

    while queue and len(visited) < max_pages:
        url, depth = queue.popleft()
        if url in visited or depth > max_depth:
            continue
        visited.add(url)
        discovered.append(url)
        try:
            response = requests.get(url, **request_kwargs)
        except requests.RequestException:
            time.sleep(delay)
            continue

        if "text/html" not in response.headers.get("Content-Type", "").lower():
            time.sleep(delay)
            continue

        body = response.text
        for token in body.split("href="):
            if not token:
                continue
            quote = token[0]
            if quote not in {"'", '"'}:
                continue
            end = token.find(quote, 1)
            if end == -1:
                continue
            candidate = token[1:end].strip()
            if not candidate or candidate.startswith(("#", "javascript:", "mailto:")):
                continue
            resolved = urljoin(url, candidate)
            parsed = urlparse(resolved)
            if parsed.scheme not in {"http", "https"}:
                continue
            if parsed.netloc.lower() != origin:
                continue
            normalized = parsed._replace(fragment="").geturl()
            if normalized not in visited:
                queue.append((normalized, depth + 1))
        time.sleep(delay)

    return {"start_url": start, "visited": discovered}

