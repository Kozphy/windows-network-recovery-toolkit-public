"""Netstat / TCP listener collector facade — delegates to src/observability/tcp_table.

Module responsibility:
    Capture local TCP listener ports and raw connection counts via
    ``netstat -ano`` and return a normalised evidence dict.  Accepts an
    injectable ``run`` callable for deterministic tests.

System placement:
    Called by the analytics pipeline's signal-collection phase.  The actual
    ``netstat`` invocation and port parsing live in
    ``src.observability.tcp_table``; this module only dispatches and shapes
    the output.

Key invariants:
    * ``localhost_listen_ports`` is only evaluated when the ``netstat`` exit
      code is 0.
    * Returns a dict with fixed keys (``exit_code``, ``localhost_listen_ports``,
      ``raw_line_count``, ``source``) regardless of outcome.

Side effects:
    Spawns ``netstat.exe -ano`` as a subprocess when called without an
    injectable ``run`` override.

Failure modes:
    A non-zero ``exit_code`` in the result dict indicates ``netstat`` failed;
    ``localhost_listen_ports`` will be an empty list in that case.  Exceptions
    from the subprocess or parser propagate to the caller.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def collect_netstat_signals(
    *,
    run: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Capture localhost TCP listener ports via netstat -ano.

    Args:
        run: Optional subprocess runner forwarded to ``capture_netstat_ano``.
            Pass a fixture callable in tests to avoid spawning a real process.

    Returns:
        Dict with keys ``exit_code`` (int), ``localhost_listen_ports``
        (list[int], empty on non-zero exit), ``raw_line_count`` (int), and
        ``source`` (``"netstat_ano"``).
    """
    from src.observability.tcp_table import capture_netstat_ano, localhost_listen_ports

    kwargs: dict[str, Any] = {}
    if run is not None:
        kwargs["run"] = run
    code, text = capture_netstat_ano(**kwargs)
    listen_ports = list(localhost_listen_ports(text)) if code == 0 else []
    return {
        "exit_code": code,
        "localhost_listen_ports": listen_ports,
        "raw_line_count": len(text.splitlines()) if text else 0,
        "source": "netstat_ano",
    }
