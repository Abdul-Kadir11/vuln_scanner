"""Helpers for authenticated/passive HTTP request context."""

from __future__ import annotations

from typing import Any, Dict, Optional


def build_request_kwargs(
    auth_context: Optional[Dict[str, Any]] = None,
    timeout: float = 5.0,
) -> Dict[str, Any]:
    """
    Build safe requests kwargs from auth context.

    Supported auth_context keys:
    - headers: dict[str, str]
    - cookies: dict[str, str]
    - bearer_token: str
    - basic_auth: {"username": "...", "password": "..."}
    - verify_tls: bool (default True)
    """
    auth_context = auth_context or {}
    headers = dict(auth_context.get("headers") or {})
    cookies = dict(auth_context.get("cookies") or {})
    bearer = str(auth_context.get("bearer_token") or "").strip()
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"

    kwargs: Dict[str, Any] = {
        "timeout": timeout,
        "allow_redirects": True,
        "headers": headers,
        "cookies": cookies,
        "verify": bool(auth_context.get("verify_tls", True)),
    }

    basic_auth = auth_context.get("basic_auth") or {}
    username = str(basic_auth.get("username") or "")
    password = str(basic_auth.get("password") or "")
    if username:
        kwargs["auth"] = (username, password)

    return kwargs

