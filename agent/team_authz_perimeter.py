"""Browser perimeter and denied-principal media guard.

Mission hermes-team-policy-simplify-20260918 (T1): a teammate runs ordinary
browser execution, connectors and their own supplied local media without a
provenance register. What remains is the private perimeter: credential entry,
machine-information reads, and private/loopback or unverifiable browser
destinations. No filesystem path is trusted or inventoried here.
"""
from __future__ import annotations

import re
from collections.abc import Mapping


def strings(value):
    """Walk keys and values, including nested browser form/interaction payloads."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for key, item in value.items():
            yield str(key)
            yield from strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from strings(item)


def member_browser_restricted() -> bool:
    """A local browser or global private-URL toggle never grants a member host access."""
    from agent import team_authz as authz
    return authz.is_governed() and not authz.resolve_principal().is_owner


def browser_url_denial(url: str):
    from tools.url_safety import is_safe_url
    if member_browser_restricted() and not is_safe_url(url, public_only=True):
        return "I can't open a private or unverifiable browser destination."
    return None


def browser_payload_denial(payload):
    """Classify URLs without relying on an ambient requester context."""
    from tools.url_safety import is_safe_url
    if isinstance(payload, Mapping):
        for key, value in payload.items():
            if str(key).lower() in {"url", "href", "target_url"} and isinstance(value, str):
                url = value if "://" in value else "https://" + value.lstrip("/")
                if not is_safe_url(url, public_only=True):
                    return True
            if browser_payload_denial(value):
                return True
    elif isinstance(payload, (list, tuple)):
        return any(browser_payload_denial(item) for item in payload)
    elif isinstance(payload, str):
        return any(not is_safe_url(url, public_only=True) for url in re.findall(r"(?:https?|wss?)://[^\s<>\"']+", payload, re.I))
    return False


def cache_team_media(data: bytes, ext: str):
    """Kept for ``gateway.platforms.base._write_cache_file`` compatibility.

    T1 removed the requester-scoped media provenance cache: returning ``None``
    leaves that caller on its original cache path, so a teammate's own media
    is ordinary work.
    """
    return None


def media_payload_denial(payload):
    """Refuse media only for a principal the team policy already denied.

    A registered teammate reads and reuses their own supplied local media
    (T1); this stays as a cheap fail-closed check for revoked, unlisted-scope
    or malformed-policy principals before any reader is touched.
    """
    try:
        from agent import team_authz as authz
        if not authz.is_governed():
            return None
        principal = authz.resolve_principal()
        if not principal.denied:
            return None
        return f"I can't load that media. [{principal.deny_reason or 'denied'}]"
    except Exception:
        return "I can't load that media. [policy-error]"
