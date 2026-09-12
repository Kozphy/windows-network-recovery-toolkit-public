"""DNS cache-flush remediation preview — informational only; no execution from this module.

Module responsibility:
    Returns a structured preview dict describing the ``ipconfig /flushdns``
    action without executing it.  The preview includes risk level, required
    confirmation token, and a non-reversible flag so callers can present an
    accurate pre-flight summary to the operator.

System placement:
    Imported via ``remediation.__init__`` and consumed by the ``remediation``
    CLI command group.

Key invariants:
    This module never invokes a subprocess.  ``argv_preview`` is descriptive
    only — it must not be passed directly to ``subprocess.run`` from this layer.

Side effects:
    None.
"""

from __future__ import annotations

from typing import Any


def preview_dns_flush(*, dry_run: bool = True) -> dict[str, Any]:
    """Return a preview dict describing the DNS cache-flush action.

    Args:
        dry_run: Passed through to the ``dry_run`` field in the returned dict;
            does not affect behaviour since no action is executed.

    Returns:
        A dict with:

        - ``action_id`` (str): ``"dns_flush"``.
        - ``dry_run`` (bool): Reflects the ``dry_run`` argument.
        - ``risk_level`` (str): ``"medium"`` — cache flush can briefly affect
          name resolution for all processes on the host.
        - ``required_confirmation`` (str): Token the operator must supply to
          permit execution (``"FLUSH_DNS_CACHE"``).
        - ``description`` (str): Human-readable summary.
        - ``argv_preview`` (list[str]): Command that *would* be run.
        - ``reversible`` (bool): ``False`` — the cache cannot be restored
          after a flush.

    Side effects:
        None.
    """
    return {
        "action_id": "dns_flush",
        "dry_run": dry_run,
        "risk_level": "medium",
        "required_confirmation": "FLUSH_DNS_CACHE",
        "description": "Flush DNS resolver cache (ipconfig /flushdns). Preview only.",
        "argv_preview": ["ipconfig", "/flushdns"],
        "reversible": False,
    }
