"""Rollback-to-last-known-good WinINET proxy state preview facade.

Module responsibility:
    Returns a structured preview dict describing the action that would restore
    HKCU WinINET registry fields from a last-known-good (LKG) snapshot.  No
    registry write occurs from this module.

System placement:
    Imported via ``remediation.__init__`` and consumed by the ``remediation``
    CLI command group.  Actual restore execution is handled by
    ``src.proxy_guard.remediation`` behind its policy gate.

Key invariants:
    ``snapshot_path`` is descriptive — this module does not read or validate
    the snapshot file.  Path validation and restore execution are the
    responsibility of the calling policy layer.

Side effects:
    Read-only metadata lookup from ``src.proxy_guard.remediation``; no
    registry writes.
"""

from __future__ import annotations

from typing import Any


def preview_rollback(*, snapshot_path: str | None = None, dry_run: bool = True) -> dict[str, Any]:
    """Return a preview dict describing the WinINET proxy rollback action.

    Args:
        snapshot_path: Optional path to the last-known-good snapshot file that
            would be used as the restore source.  Included in the output for
            display purposes; not read or validated by this function.
        dry_run: Passed through to the ``dry_run`` field in the returned dict;
            does not affect behaviour since no registry write occurs.

    Returns:
        A dict with:

        - ``action_id`` (str): ``"restore_wininet_proxy_from_lkg"``.
        - ``dry_run`` (bool): Reflects the ``dry_run`` argument.
        - ``snapshot_path`` (str | None): The provided snapshot path, or ``None``.
        - ``risk_level`` (str): Risk classification from the action metadata.
        - ``required_confirmation`` (str): Typed token required for live execution.
        - ``reversible`` (bool): Rollback reversibility per action metadata.
        - ``rollback_plan`` (str): Human-readable summary of the restore intent.

    Side effects:
        Read-only metadata lookup from ``src.proxy_guard.remediation``; no
        registry writes or file reads.
    """
    from src.proxy_guard.remediation import get_remediation_action

    action = get_remediation_action("restore_wininet_proxy_from_lkg")
    return {
        "action_id": action.action_id,
        "dry_run": dry_run,
        "snapshot_path": snapshot_path,
        "risk_level": action.risk_level,
        "required_confirmation": action.required_confirmation,
        "reversible": action.reversible,
        "rollback_plan": "Restore HKCU WinINET fields from last-known-good snapshot.",
    }
