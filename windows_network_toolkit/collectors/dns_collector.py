"""DNS reachability probe facade — delegates to src/observability/dns_probe.

Module responsibility:
    Run a lightweight DNS lookup (``nslookup google.com``) and return a
    normalised evidence dict.  Accepts an injected ``dns_ok`` result so unit
    tests never open real sockets.

System placement:
    Called by the analytics pipeline's signal-collection phase.  The actual
    nslookup execution lives in ``src.observability.dns_probe``; this module
    only shapes the output and provides the injection seam.

Key invariants:
    * No real DNS query is made when ``dns_ok`` is provided.
    * Returns a dict with fixed keys (``dns_ok``, ``probe``, ``source``)
      regardless of the resolution path.

Side effects:
    When ``dns_ok`` is ``None``, invokes ``nslookup_google_ok`` which spawns
    a subprocess.  No side effects otherwise.

Failure modes:
    ``nslookup_google_ok`` exceptions propagate to the caller.  A
    ``False`` result means the probe ran but resolution failed — not an
    exception.
"""

from __future__ import annotations

from typing import Any


def collect_dns_signals(
    *,
    dns_ok: bool | None = None,
) -> dict[str, Any]:
    """Run a lightweight DNS reachability probe, or accept an injected result.

    Args:
        dns_ok: Pre-computed DNS result for deterministic tests.  When
            ``None`` (default) the live ``nslookup_google_ok`` probe runs.

    Returns:
        Dict with keys ``dns_ok`` (bool), ``probe`` (probe description
        string), and ``source`` (``"dns_probe"``).
    """
    if dns_ok is None:
        from src.observability.dns_probe import nslookup_google_ok

        ok, _label = nslookup_google_ok()
    else:
        ok = dns_ok
    return {"dns_ok": ok, "probe": "nslookup google.com", "source": "dns_probe"}
