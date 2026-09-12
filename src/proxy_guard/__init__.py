"""Proxy Guard package re-export for stable ``parse_proxy_server`` consumption.

Module responsibility:
    Exposes ``parse_proxy_server`` for lightweight imports while the CLI and service layer pull
    richer modules (for example ``guard``, ``watcher``) directly from subpackages.

System placement:
    Lives under ``src/proxy_guard`` beside policy, rollback, attribution, and audit helpers invoked
    from ``python -m src proxy-guard`` entry points.

Key invariants:
    * Parsing helpers are pure string utilities—no registry side effects at import time.

How other modules use it:
    Downstream code imports ``parse_proxy_server`` when normalizing ``ProxyServer`` registry strings
    without loading the full guard loop.

Engineering Notes:
    Prefer explicit submodule imports for orchestration-heavy paths to keep dependency graphs clear.
"""

from .parser import parse_proxy_server

__all__ = ["parse_proxy_server"]
