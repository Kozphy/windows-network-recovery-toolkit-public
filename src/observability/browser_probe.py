"""Browser-path signal derived from automated HTTPS ``curl`` plus proxy state."""

from __future__ import annotations

from ..diagnostics.features import FeatureVector


def browser_path_stress_signal(features: FeatureVector) -> bool:
    """Heuristic: TCP + DNS healthy but curl HTTPS fails with proxy off.

    Real browsers can still fail via separate proxy policy; use with registry context.
    """
    if features.proxy_enabled:
        return False
    return (
        features.tcp_443_ok
        and features.nslookup_ok
        and not features.browser_http_ok
    )
