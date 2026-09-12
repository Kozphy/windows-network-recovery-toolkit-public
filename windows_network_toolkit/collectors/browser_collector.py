"""Browser / HTTPS path probe facade — delegates to src/observability/browser_probe.

Module responsibility:
    Derive browser-path stress signals from a pre-built ``FeatureVector`` and
    return a normalised evidence dict.  When no feature vector is supplied the
    function returns an empty shell so callers can always pattern-match the
    same keys.

System placement:
    Called by the analytics pipeline's signal-collection phase.  The heavy
    lifting (HTTP probes, HTTPS handshake timing) lives in
    ``src/observability/browser_probe``; this module only shapes the output.

Key invariants:
    * Read-only — no outbound probes are opened by this facade itself.
    * Returns a dict with fixed keys (``browser_https_ok``,
      ``browser_path_stress``, ``source``) whether or not a feature vector
      is supplied.

Side effects:
    None in the no-argument path.  With a ``FeatureVector``, delegates to
    ``browser_path_stress_signal`` which may read cached probe results.

Failure modes:
    ``browser_path_stress_signal`` exceptions propagate to the caller; callers
    should handle ``ImportError`` if the ``src.observability`` package is
    absent.
"""

from __future__ import annotations

from typing import Any


def collect_browser_signals(feature_vector: Any | None = None) -> dict[str, Any]:
    """Derive browser-path stress signals from a FeatureVector or return an empty shell.

    Delegates stress-signal computation to ``browser_path_stress_signal`` in
    ``src.observability.browser_probe``.  When ``feature_vector`` is ``None``
    all evidence keys are present but set to ``None``, keeping downstream
    pattern-matching consistent.

    Args:
        feature_vector: Optional pre-built feature vector carrying ``https_ok``
            and ``curl_https_ok`` attributes.  Pass ``None`` (default) when no
            live probe data is available.

    Returns:
        Dict with keys ``browser_https_ok``, ``browser_path_stress``,
        ``curl_https_ok`` (absent when ``feature_vector`` is ``None``), and
        ``source`` (always ``"browser_probe"``).
    """
    if feature_vector is None:
        return {
            "browser_https_ok": None,
            "browser_path_stress": None,
            "source": "browser_probe",
        }
    from src.observability.browser_probe import browser_path_stress_signal

    stress = browser_path_stress_signal(feature_vector)
    return {
        "browser_https_ok": getattr(feature_vector, "https_ok", None),
        "browser_path_stress": stress,
        "curl_https_ok": getattr(feature_vector, "curl_https_ok", None),
        "source": "browser_probe",
    }
