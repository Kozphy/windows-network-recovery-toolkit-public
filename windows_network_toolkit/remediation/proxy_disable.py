"""WinINET proxy-disable remediation preview.

Module responsibility:
    Returns a structured preview dict describing the registry mutations that
    would disable the WinINET proxy (clearing ``ProxyEnable`` and optionally
    ``ProxyServer`` in HKCU).  No registry write occurs from this module.

System placement:
    Imported via ``remediation.__init__`` and consumed by the ``remediation``
    CLI command group and operator scripts that display a pre-flight summary
    before requesting operator confirmation.

Key invariants:
    ``build_user_proxy_disable_mutations`` is called for its descriptive output
    only; the returned mutation objects are never executed here.  Actual
    execution requires a separate confirmation-gated code path in
    ``src.proxy_guard.remediation``.

Side effects:
    Reads the ``disable_wininet_proxy`` action metadata from
    ``src.proxy_guard.remediation`` (read-only metadata lookup, no OS writes).

Audit Notes:
    This preview function is separate from the execution path by design.
    Any code that attempts to execute ``argv`` values from the returned
    ``mutations`` list without going through the policy gate violates the
    safety contract.
"""

from __future__ import annotations

from typing import Any


def preview_proxy_disable(*, dry_run: bool = True) -> dict[str, Any]:
    """Return a preview dict describing the WinINET proxy-disable registry mutations.

    Calls ``build_user_proxy_disable_mutations`` in description-only mode and
    serialises each mutation to ``{"argv": [...], "human": "..."}`` for display.

    Args:
        dry_run: Passed through to the ``dry_run`` field in the returned dict;
            does not affect behaviour since no registry write occurs.

    Returns:
        A dict with:

        - ``action_id`` (str): Canonical action identifier from the remediation registry.
        - ``dry_run`` (bool): Reflects the ``dry_run`` argument.
        - ``risk_level`` (str): Risk classification from the action metadata.
        - ``required_confirmation`` (str): Typed token required for live execution.
        - ``mutations`` (list[dict]): Each mutation as ``{"argv": list, "human": str}``.
        - ``reversible`` (bool): Whether the action can be rolled back via snapshot.

    Side effects:
        Read-only metadata lookup from ``src.proxy_guard.remediation``; no
        registry writes or subprocesses.

    Audit Notes:
        The ``mutations`` list describes what *would* happen; it is not an
        authorisation record.  Live execution must go through the policy gate
        with a matching confirmation token.
    """
    from src.proxy_guard.remediation import (
        build_user_proxy_disable_mutations,
        get_remediation_action,
    )

    action = get_remediation_action("disable_wininet_proxy")
    mutations, _warnings = build_user_proxy_disable_mutations(clear_proxy_server_value=True)
    mutation_preview = [{"argv": list(m.argv), "human": m.human} for m in mutations]
    return {
        "action_id": action.action_id,
        "dry_run": dry_run,
        "risk_level": action.risk_level,
        "required_confirmation": action.required_confirmation,
        "mutations": mutation_preview,
        "reversible": action.reversible,
    }
