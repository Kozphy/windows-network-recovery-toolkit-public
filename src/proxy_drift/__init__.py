"""Targeted proxy drift detection — startup inventory, boot trace, guardian, safe search."""

from __future__ import annotations

from src.proxy_drift.boot_trace import run_boot_trace_loop
from src.proxy_drift.classify import classify_proxy_drift
from src.proxy_drift.guardian import run_dead_proxy_guardian_loop, run_dead_proxy_guardian_once
from src.proxy_drift.proxy_fix import apply_proxy_fix
from src.proxy_drift.safe_search import safe_search
from src.proxy_drift.startup_inventory import collect_startup_inventory

__all__ = [
    "apply_proxy_fix",
    "classify_proxy_drift",
    "collect_startup_inventory",
    "run_boot_trace_loop",
    "run_dead_proxy_guardian_loop",
    "run_dead_proxy_guardian_once",
    "safe_search",
]
