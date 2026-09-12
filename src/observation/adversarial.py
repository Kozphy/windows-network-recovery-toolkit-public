"""Cheap heuristics for tampered proxy strings and oddly split stacks — hypotheses only.

These codes are observational cues; they are never asserted as forensic proof.
"""

from __future__ import annotations

from ..core.models import LiveNetworkSnapshot


def adversarial_hints(snap: LiveNetworkSnapshot) -> tuple[str, ...]:
    """Emit short ADV_* codes for audit attachment (never asserted as forensic proof)."""
    fv = snap.feature_vector
    raw = snap.parsed_proxy.raw or ""
    notes: list[str] = []

    head = raw.split(";", 1)[0].strip()
    if "@" in head and "://" in head:
        notes.append("ADV_PROXY_URL_CREDENTIAL_PATTERN")

    if snap.parsed_proxy.is_localhost_proxy and fv.tcp_443_ok and not fv.browser_http_ok and fv.nslookup_ok:
        notes.append("ADV_SPLIT_HTTPS_WORTH_LOCAL_PROXY_INTERCEPT_REVIEW")

    if fv.winhttp_proxy_enabled and not fv.proxy_enabled and fv.browser_http_ok is False:
        notes.append("ADV_WININET_WINHTTP_DIVERGENCE_SIGNAL")

    if snap.parsed_proxy.is_malformed and (snap.proxy_registry.proxy_enable == 1):
        notes.append("ADV_MALFORMED_PROXY_SERVER_WHILE_ENABLED")

    return tuple(notes)
