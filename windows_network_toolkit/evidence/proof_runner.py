"""Read-only proof verification facade over ``proxy_reasoning``.

Module responsibility:
    Thin adapter that converts a flat signal dict into ``ProxySignal`` objects,
    delegates verification to ``proxy_reasoning.verification``, and returns a
    normalised list of check-result dicts for the decision layer.

System placement:
    Called by the ``decision`` and ``pipeline`` layers when a proof step is
    requested.  Depends only on ``proxy_reasoning`` (the deterministic
    reasoning library) — no Windows API, registry, or network I/O.

Key invariants:
    * This module is strictly read-only: it performs no remediation, registry
      writes, or network changes.
    * Verification results carry ``status`` and ``detail`` fields only;
      callers must not interpret ``status == "pass"`` as proof of absence —
      absence of evidence is not evidence of absence.

Side effects:
    None — delegated verification is deterministic over the supplied signals.

Failure modes:
    Exceptions from ``proxy_reasoning`` propagate to the caller; partial
    results are not returned on error.
"""

from __future__ import annotations

from typing import Any

from proxy_reasoning.models import ProxySignal
from proxy_reasoning.verification import run_verification_checks


def run_proof_checks(signals: dict[str, Any]) -> list[dict[str, Any]]:
    """Run ``proxy_reasoning`` verification checks against a normalised signal dict.

    Converts each entry in ``signals`` into a ``ProxySignal`` and delegates to
    ``proxy_reasoning.verification.run_verification_checks``.  Results are
    projected to a stable dict shape regardless of the upstream model version.

    Args:
        signals: Flat mapping of signal name → observed value.  Keys and values
            are passed verbatim to ``ProxySignal``; no normalisation is applied
            here.

    Returns:
        List of dicts, each with keys:

        * ``check_id`` — identifier of the verification check.
        * ``status``   — result status string (e.g. ``"pass"``, ``"fail"``).
        * ``detail``   — human-readable explanation of the result.

    Note:
        A ``status`` of ``"pass"`` indicates the check did not find a
        discrepancy; it does not constitute forensic proof.
    """
    proxy_signals = [ProxySignal(name=k, value=v) for k, v in signals.items()]
    results = run_verification_checks(proxy_signals)
    out: list[dict[str, Any]] = []
    for r in results:
        out.append(
            {
                "check_id": getattr(r, "check_id", ""),
                "status": getattr(r, "status", ""),
                "detail": getattr(r, "detail", ""),
            }
        )
    return out
