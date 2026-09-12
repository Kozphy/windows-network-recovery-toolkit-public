"""Human-readable summaries for localhost diagnose.

Module responsibility:
    Convert a structured ``localhost-diagnose`` report dict into a concise
    operator-facing text summary suitable for terminal or log output.  Does
    not re-classify or add evidence; purely a formatting/rendering concern.

System placement:
    Called by ``localhost/runner.py``'s ``render_localhost_diagnose`` when
    ``--json`` is not requested.  Also exported from ``localhost/__init__.py``
    for direct CLI use.

Key invariants:
    * Never overclaims — proxy-interference line uses "possible" language and
      marks preview-only when flagged.
    * Relations flagged as ``unrelated`` are reported as "not supported by
      current evidence" to avoid false-positive proxy suggestions.
    * At most 3 ``limitations[]`` items are rendered to keep output scannable.

Side effects:
    None.  Pure function; does not write files or modify the input dict.

Failure modes:
    Tolerant of missing or ``None`` keys in *report*; uses ``or {}`` / ``or []``
    guards throughout.  Never raises.
"""

from __future__ import annotations

from typing import Any


def format_localhost_diagnose_human(report: dict[str, Any]) -> str:
    """Render *report* as a concise operator summary; avoids firewall/malware overclaims.

    Produces a fixed-order, newline-separated block: target URL, TCP result,
    listener summary, proxy interference status, classification code, proof
    tier, recommended action, and up to 3 limitation notices.

    Args:
        report: Full output dict from ``run_localhost_diagnose``; missing keys
            are tolerated with empty fallbacks.

    Returns:
        A multi-line string ending with ``"\\n"`` suitable for ``print()`` or
        direct log emission.  Never includes raw stack traces or secrets.
    """

    target = report.get("target") or {}
    classification = report.get("classification") or {}
    tcp = report.get("tcp_probes") or []
    listeners = (report.get("listeners") or {}).get("listeners") or []
    proxy_cmp = report.get("proxy_comparison") or {}
    proxy_ev = report.get("proxy_evidence") or {}

    tcp_bits: list[str] = []
    for p in tcp:
        if p.get("connect_success"):
            tcp_bits.append(f"connected {p.get('address')}")
        else:
            tcp_bits.append(
                f"{str(p.get('error_category') or 'failed').lower()} on {p.get('address')}"
            )
    tcp_line = ", ".join(tcp_bits) if tcp_bits else "no probes"

    if listeners:
        listener_line = ", ".join(
            f"{r.get('local_address')}:{r.get('local_port')} pid={r.get('pid')}"
            for r in listeners[:5]
        )
    else:
        listener_line = f"none found on port {target.get('port')}"

    relation = (
        proxy_ev.get("relation_to_incident") or proxy_cmp.get("interpretation") or "not assessed"
    )
    if relation in {"proxy_unrelated_to_incident", "unrelated_or_both_paths_failed"}:
        proxy_line = "not supported by current evidence"
    elif relation == "possible_proxy_interference":
        proxy_line = "possible (direct vs proxy-aware differ) — preview only"
    else:
        proxy_line = str(relation)

    lines = [
        f"Target: {target.get('url')}",
        f"TCP: {tcp_line}",
        f"Listener: {listener_line}",
        f"Proxy interference: {proxy_line}",
        f"Classification: {classification.get('code')}",
        f"Proof: {classification.get('proof_tier')}",
        f"Recommended action: {classification.get('recommended_next_action')}",
    ]
    for lim in (classification.get("limitations") or [])[:3]:
        lines.append(f"Limitation: {lim}")
    return "\n".join(lines) + "\n"
