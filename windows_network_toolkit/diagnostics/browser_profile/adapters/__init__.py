"""Browser adapter registry.

Module responsibility:
    Resolve a browser key (``"auto"``, ``"edge"``, ``"chrome"``) to a concrete
    ``BrowserAdapter`` implementation.

System placement:
    Consumed by ``runner.run_browser_diff`` and the other public runner functions
    that need to interrogate browser profiles.

Key invariants:
    * ``"auto"`` prefers Edge if installed, falls back to Chrome, then returns an
      EdgeAdapter even when neither is installed (graceful degradation).
    * Unknown keys raise ``ValueError`` immediately — no silent fallback.
"""

from __future__ import annotations

from windows_network_toolkit.diagnostics.browser_profile.adapters.base import BrowserAdapter
from windows_network_toolkit.diagnostics.browser_profile.adapters.chrome import ChromeAdapter
from windows_network_toolkit.diagnostics.browser_profile.adapters.edge import EdgeAdapter


def get_adapter(browser: str) -> BrowserAdapter:
    """Return the appropriate ``BrowserAdapter`` for a browser key.

    Args:
        browser: Browser selection key.  Accepted values:
            ``"auto"`` — detect Edge then Chrome; fall back to EdgeAdapter.
            ``"edge"`` / ``"msedge"`` — Microsoft Edge adapter.
            ``"chrome"`` / ``"google-chrome"`` — Google Chrome adapter.

    Returns:
        A concrete ``BrowserAdapter`` instance (never ``None``).

    Raises:
        ValueError: If ``browser`` is not a recognised key.
    """
    key = (browser or "auto").lower().strip()
    if key in {"edge", "msedge"}:
        return EdgeAdapter()
    if key in {"chrome", "google-chrome"}:
        return ChromeAdapter()
    if key == "auto":
        edge = EdgeAdapter()
        if edge.detect_installation().get("installed"):
            return edge
        chrome = ChromeAdapter()
        if chrome.detect_installation().get("installed"):
            return chrome
        return edge
    raise ValueError(f"Unsupported browser adapter: {browser}")


__all__ = ["BrowserAdapter", "ChromeAdapter", "EdgeAdapter", "get_adapter"]
