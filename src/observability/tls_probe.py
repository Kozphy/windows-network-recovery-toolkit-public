"""TLS/HTTPS façade using existing curl heuristic from diagnostics."""

from __future__ import annotations

from ..diagnostics.collector import probe_https_google


def curl_https_google_ok() -> tuple[bool, bool]:
    """Reuse collector HTTPS probe tuple ``(https_ok, tls_hint)``."""
    return probe_https_google()
