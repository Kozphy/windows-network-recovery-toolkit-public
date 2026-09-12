"""Facade for the dead-proxy guardian — auto-remediation of stale localhost WinINET proxy.

Module responsibility:
    Wraps ``src.proxy_drift.guardian.run_dead_proxy_guardian_once`` and normalises its
    output to the legacy classification labels expected by ``windows_network_toolkit``
    consumers (e.g. ``DEAD_PROXY_CONFIG`` instead of ``STALE_LOCALHOST_PROXY``).
    All remediation actions remain policy-gated and require an explicit typed confirmation
    token; ``dry_run=True`` (the default) only previews what would happen.

System placement:
    Called by the ``agent`` CLI command and any operator script that wants a
    single-shot guardian cycle.  Imports ``src.proxy_drift.guardian`` at runtime;
    not available on non-Windows platforms (returns an ``unsupported_platform`` dict).

Key invariants:
    No registry mutation occurs unless ``dry_run=False`` *and* the correct
    ``CONFIRM_CLEAR_DEAD`` token is supplied.  The ``dry_run=True`` path is always
    safe — it produces a preview result without touching Windows state.

Side effects:
    Non-dry-run path: may write to HKCU WinINET registry keys to clear the stale
    proxy server value.  Dry-run path: read-only registry probe only.

Failure modes:
    Raises ``ImportError`` if ``src.proxy_drift.guardian`` is not importable (e.g.
    incomplete install).  Non-Windows calls return early with ``action_taken: "none"``.

Audit Notes:
    Any ``action_taken: "remediated"`` result represents an actual registry mutation.
    The result dict includes the confirmation token used, enabling post-hoc audit
    verification against the canonical custody chain.
"""

from __future__ import annotations

import platform
from typing import Any

from src.proxy_drift.guardian import CONFIRM_CLEAR_DEAD
from src.proxy_drift.guardian import run_dead_proxy_guardian_once as _run_once
from src.proxy_guard.remediation import CONFIRMATION_PHRASE

_LEGACY_DEAD = frozenset({"STALE_LOCALHOST_PROXY", "STALE_PROXY_AFTER_PROCESS_EXIT"})


def _map_legacy(result: dict[str, Any]) -> dict[str, Any]:
    """Normalise upstream guardian labels to legacy ``windows_network_toolkit`` label names.

    Args:
        result: Raw result dict from ``src.proxy_drift.guardian``.

    Returns:
        A shallow-copied dict with ``classification`` and ``action_taken`` fields
        normalised to the values expected by toolkit consumers.  Fields not
        requiring normalisation are passed through unchanged.

    Side effects:
        None — copies only on mutation; does not modify the input dict in place.
    """
    cls = str(result.get("classification") or "")
    if cls in _LEGACY_DEAD:
        result = dict(result)
        result["classification"] = "DEAD_PROXY_CONFIG"
    if result.get("dead_localhost_proxy") and result.get("action_taken") == "preview_only":
        result = dict(result)
        result["action_taken"] = "would_remediate"
    return result


def run_proxy_guardian_once(*, dry_run: bool = False) -> dict[str, Any]:
    """Check proxy state and clear a dead localhost WinINET proxy when safe to do so.

    Delegates to ``src.proxy_drift.guardian`` for evidence collection and policy
    evaluation, then normalises the result for legacy consumers.  On non-Windows
    hosts the function returns immediately without performing any OS calls.

    Args:
        dry_run: When ``True`` (default ``False``), the guardian collects evidence
            and reports what it *would* do but does not modify any registry keys.
            Pass ``False`` only when explicit operator confirmation is intended;
            the underlying confirmation token is supplied automatically.

    Returns:
        A dict with at minimum:

        - ``action_taken`` (str): ``"none"``, ``"would_remediate"``, or
          ``"remediated"``.
        - ``dead_localhost_proxy`` (bool): Whether the dead-proxy condition was
          observed.
        - ``classification`` (str): Normalised label (e.g. ``"DEAD_PROXY_CONFIG"``).
        - ``reason`` (str): Human-readable description of the outcome.
        - ``unsupported_platform`` (bool): Present and ``True`` on non-Windows only.

    Side effects:
        Non-dry-run on Windows: clears the HKCU WinINET ``ProxyServer`` registry
        value when the dead-proxy condition is confirmed.  All other paths are
        read-only.

    Audit Notes:
        ``action_taken: "remediated"`` entries must be correlated with the
        canonical custody chain (``audit verify .audit/canonical_custody.jsonl``)
        to confirm the registry mutation was authorised and logged.
    """
    if platform.system() != "Windows":
        return {
            "unsupported_platform": True,
            "platform": platform.system(),
            "action_taken": "none",
        }

    confirm = CONFIRM_CLEAR_DEAD if not dry_run else ""
    result = _run_once(dry_run=dry_run, confirm=confirm)
    mapped = _map_legacy(result)

    if mapped.get("action_taken") == "remediated":
        mapped["reason"] = mapped.get("reason") or "Dead localhost proxy cleared automatically."
    elif mapped.get("dead_localhost_proxy") and dry_run:
        mapped["action_taken"] = "would_remediate"
        mapped["reason"] = "Dead localhost proxy detected; dry-run preview only."

    # Backward compat: nested remediation shape expected by some scripts
    if mapped.get("action_taken") == "remediated" and "remediation" not in mapped:
        mapped["remediation"] = {"action_allowed": True, "confirm": CONFIRMATION_PHRASE}

    return mapped
