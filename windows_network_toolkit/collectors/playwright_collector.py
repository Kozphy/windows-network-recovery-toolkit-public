"""Playwright browser evidence collector — optional ``playwright`` extra required.

Module responsibility:
    Drive a headless Chromium session against a target URL, capture a full-page
    screenshot and HAR network archive, and return a ``BrowserEvidencePackage``
    populated with navigation errors, TLS error hints, and proxy-failure
    indicators.

System placement:
    Called explicitly from CLI commands or integration tests that opt into
    live browser evidence collection.  Not used during routine analytics
    pipeline runs (the pipeline uses ``browser_collector.py`` with a
    ``FeatureVector`` instead).  Requires ``pip install '.[browser]'`` and
    ``playwright install chromium``.

Key invariants:
    * Navigation errors and proxy/TLS hints are soft-captured — a failed
      ``page.goto()`` still produces a partial package rather than raising.
    * Screenshot failures are silently downgraded (empty path); they do not
      abort evidence collection.
    * The ``build_fixture_package`` helper returns a synthetic package with
      hard-coded fixture paths for CI pipelines that lack a live browser.

Side effects:
    Launches a Chromium subprocess via Playwright; writes screenshot and HAR
    archive to ``out_dir``.  Network traffic is contained to the single
    ``page.goto()`` call.

Failure modes:
    Raises ``RuntimeError`` if the ``playwright`` package is not installed.
    Other navigation exceptions are caught and recorded in
    ``BrowserEvidencePackage.navigation_error``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from windows_network_toolkit.browser_evidence import BrowserEvidencePackage, summarize_har


def collect_browser_evidence(
    url: str,
    out_dir: Path,
    *,
    headless: bool = True,
    timeout_ms: int = 30_000,
) -> BrowserEvidencePackage:
    """Capture a screenshot and HAR archive for ``url`` via Playwright Chromium.

    Navigates to ``url`` in a headless (by default) Chromium context, saves a
    full-page screenshot and a HAR network archive, and returns a
    ``BrowserEvidencePackage`` describing the outcome.  Navigation errors,
    TLS/cert issues, and HTTP-proxy failure hints are recorded in the package
    rather than raised.

    Args:
        url: Target URL to navigate to (e.g. ``"https://example.com"``).
        out_dir: Output directory for ``screenshot.png``, ``network.har``, and
            ``trace.zip``.  Created if it does not exist.
        headless: Run Chromium headlessly (default ``True``).  Set ``False``
            for interactive debugging only.
        timeout_ms: Navigation timeout in milliseconds (default 30 000).

    Returns:
        ``BrowserEvidencePackage`` with paths, error strings, and hint lists.
        ``navigation_error`` is ``None`` on a clean load.

    Raises:
        RuntimeError: If the ``playwright`` package is not installed.

    Side effects:
        Spawns Chromium; writes files to ``out_dir``.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    screenshot = out_dir / "screenshot.png"
    har_path = out_dir / "network.har"
    trace_path = out_dir / "trace.zip"

    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError(
            "playwright not installed — pip install '.[browser]' && playwright install chromium"
        ) from exc

    navigation_error: str | None = None
    tls_errors: list[str] = []
    proxy_hints: list[str] = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        context = browser.new_context(record_har_path=str(har_path))
        page = context.new_page()
        try:
            response = page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
            if response and response.status >= 400:
                proxy_hints.append(f"http_status_{response.status}")
        except Exception as exc:
            navigation_error = str(exc)[:500]
            if "ERR_PROXY" in navigation_error.upper() or "PROXY" in navigation_error.upper():
                proxy_hints.append("proxy_connection_failure_suspected")
            if "SSL" in navigation_error.upper() or "CERT" in navigation_error.upper():
                tls_errors.append("tls_or_cert_error_during_navigation")
        try:
            page.screenshot(path=str(screenshot), full_page=True)
        except Exception:
            screenshot = Path("")
        context.close()
        browser.close()

    har_summary = summarize_har(har_path)
    if har_summary.get("failed", 0) > 0:
        proxy_hints.append("har_http_failures_present")

    return BrowserEvidencePackage(
        url=url,
        screenshot_path=str(screenshot) if screenshot else "",
        har_path=str(har_path),
        trace_path=str(trace_path) if trace_path.is_file() else "",
        navigation_error=navigation_error,
        tls_errors=tls_errors,
        proxy_hints=proxy_hints,
    )


def build_fixture_package(url: str = "https://example.com") -> dict[str, Any]:
    """Return a synthetic ``BrowserEvidencePackage`` dict for CI without a live browser.

    Constructs a package that references deterministic fixture files under
    ``tests/fixtures/browser_evidence/`` and pre-populates a
    ``proxy_connection_failure_suspected`` hint so downstream classifiers
    can exercise the browser-evidence path.

    Args:
        url: URL recorded in the package (not fetched).

    Returns:
        Plain dict from ``BrowserEvidencePackage.model_dump()`` with fixture
        paths and a synthetic ``navigation_error``.
    """
    pkg = BrowserEvidencePackage(
        url=url,
        screenshot_path="tests/fixtures/browser_evidence/screenshot.png",
        har_path="tests/fixtures/browser_evidence/sample.har.json",
        navigation_error="ERR_PROXY_CONNECTION_FAILED",
        proxy_hints=["proxy_connection_failure_suspected"],
    )
    return pkg.model_dump()
