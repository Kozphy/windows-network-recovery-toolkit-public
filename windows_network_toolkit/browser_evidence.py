"""Browser evidence package — schema and helpers for Playwright-captured TLS path data.

Module responsibility:
    Define the ``BrowserEvidencePackage`` Pydantic model that carries screenshot
    paths, HAR archive location, navigation errors, TLS error hints, and proxy
    failure indicators for one browser probe session.  Provide loader and
    summariser helpers that callers can use without importing Playwright.

System placement:
    Shared schema imported by ``collectors/playwright_collector.py`` (which
    produces packages) and by the analytics pipeline / evidence schema
    (which consumes them).  No live probes or file writes happen here —
    only schema definition, fixture loading, and HAR parsing.

Key invariants:
    * ``BrowserEvidencePackage.limitations`` always includes the standard
      boundary statement: "Browser capture is path evidence — not malware or
      MITM confirmation."
    * ``summarize_har`` is soft-fail: parse errors and missing files return
      ``{"entries": 0, "failed": 0}`` (with ``parse_error: True`` on decode
      failure) rather than raising.

Side effects:
    ``load_browser_package_from_fixture`` reads a file from disk.
    All other functions are pure.

Failure modes:
    ``load_browser_package_from_fixture`` raises ``FileNotFoundError`` /
    ``ValidationError`` on missing or malformed fixture data.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class BrowserEvidencePackage(BaseModel):
    """Pydantic model carrying the results of a single Playwright browser probe.

    Attributes:
        url: The URL that was navigated to.
        screenshot_path: Filesystem path to the captured full-page PNG, or
            ``""`` when the screenshot failed or was not requested.
        har_path: Filesystem path to the HAR JSON archive, or ``""`` when
            absent.
        trace_path: Filesystem path to the Playwright trace ZIP, or ``""``
            when tracing was not enabled.
        navigation_error: Raw exception string from ``page.goto()`` when
            navigation failed, or ``None`` on success.
        tls_errors: Hint strings for TLS / certificate-related navigation
            errors (e.g. ``"tls_or_cert_error_during_navigation"``).
        proxy_hints: Hint strings indicating potential proxy connection
            failures (e.g. ``"proxy_connection_failure_suspected"``).
        limitations: Fixed boundary statement carried through to evidence
            consumers.  Default: "Browser capture is path evidence — not
            malware or MITM confirmation."
    """

    url: str
    screenshot_path: str = ""
    har_path: str = ""
    trace_path: str = ""
    navigation_error: str | None = None
    tls_errors: list[str] = Field(default_factory=list)
    proxy_hints: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(
        default_factory=lambda: [
            "Browser capture is path evidence — not malware or MITM confirmation.",
        ]
    )

    def to_raw_snapshot(self) -> dict[str, Any]:
        """Return a raw evidence snapshot dict for the analytics pipeline.

        Returns:
            Dict with ``browser_package`` (full model dump) and ``proxy_state``
            sub-dict carrying ``browser_url``, ``navigation_error``, and
            ``proxy_hints``.
        """
        return {
            "browser_package": self.model_dump(),
            "proxy_state": {
                "browser_url": self.url,
                "navigation_error": self.navigation_error,
                "proxy_hints": self.proxy_hints,
            },
        }


def load_browser_package_from_fixture(fixture_path: Path) -> BrowserEvidencePackage:
    """Load a ``BrowserEvidencePackage`` from a JSON fixture file.

    Args:
        fixture_path: Path to a JSON file whose contents conform to the
            ``BrowserEvidencePackage`` schema.

    Returns:
        Validated ``BrowserEvidencePackage`` instance.

    Raises:
        FileNotFoundError: If ``fixture_path`` does not exist.
        pydantic.ValidationError: If the JSON does not match the schema.
    """
    data = json.loads(fixture_path.read_text(encoding="utf-8"))
    return BrowserEvidencePackage.model_validate(data)


def summarize_har(har_path: Path) -> dict[str, Any]:
    """Parse a HAR archive and return entry / failure counts.

    Soft-fail: returns ``{"entries": 0, "failed": 0}`` when the file is
    absent; adds ``"parse_error": True`` when JSON decoding fails.

    Args:
        har_path: Path to a HAR JSON archive written by Playwright.

    Returns:
        Dict with ``entries`` (total HAR entries) and ``failed`` (entries
        with HTTP status ≥ 400).  Optionally includes ``parse_error: True``
        on decode failure.
    """
    if not har_path.is_file():
        return {"entries": 0, "failed": 0}
    try:
        har = json.loads(har_path.read_text(encoding="utf-8"))
        entries = har.get("log", {}).get("entries", [])
        failed = sum(1 for e in entries if e.get("response", {}).get("status", 0) >= 400)
        return {"entries": len(entries), "failed": failed}
    except (json.JSONDecodeError, OSError):
        return {"entries": 0, "failed": 0, "parse_error": True}
