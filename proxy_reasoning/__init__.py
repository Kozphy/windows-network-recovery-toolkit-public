"""Proxy attribute and evidence reasoning (Observation ≠ Inference ≠ Proof).

Package responsibility:
    Model proxy-specific signals, rank canonical scenarios, run verification checks,
    evaluate conservative policy for requested actions, and emit replayable audit rows.

System placement:
    Standalone Python package at repo root; complements ``src.proxy_guard`` collectors and
    ``platform_core`` fleet reasoning without replacing either.

Public API:
    ``run_proxy_reasoning``, ``append_proxy_reasoning_run``, ``replay_proxy_reasoning_record``,
    builders ``build_proxy_entity`` / ``signals_from_dict``, and scenario constants.

Safety:
    Policy blocks kill/cert/firewall-reset tokens; localhost dev proxies are not labeled malicious
    without proof-tier evidence.

See:
    ``docs/proxy_reasoning.md`` for pipeline vocabulary and audit sink paths.
"""

from proxy_reasoning.audit import (
    append_proxy_reasoning_run,
    default_audit_path,
    iter_proxy_reasoning_records,
    replay_proxy_reasoning_record,
    to_audit_record,
)
from proxy_reasoning.builders import build_proxy_entity, signals_from_dict
from proxy_reasoning.constants import (
    CASE_BROWSER_PROXY_PATH_ISSUE,
    CASE_ELECTRON_APP_PROXY_FIREWALL_INTERACTION,
    CASE_LOCALHOST_PROXY_LISTENER,
    CASE_WININET_PROXY_DRIFT,
)
from proxy_reasoning.diagnosis_text import render_proxy_diagnosis
from proxy_reasoning.models import ProxyEntity, ProxyReasoningRun, ProxySignal
from proxy_reasoning.pipeline import run_proxy_reasoning

__all__ = [
    "CASE_BROWSER_PROXY_PATH_ISSUE",
    "CASE_ELECTRON_APP_PROXY_FIREWALL_INTERACTION",
    "CASE_LOCALHOST_PROXY_LISTENER",
    "CASE_WININET_PROXY_DRIFT",
    "ProxyEntity",
    "ProxyReasoningRun",
    "ProxySignal",
    "append_proxy_reasoning_run",
    "build_proxy_entity",
    "default_audit_path",
    "iter_proxy_reasoning_records",
    "render_proxy_diagnosis",
    "replay_proxy_reasoning_record",
    "run_proxy_reasoning",
    "signals_from_dict",
    "to_audit_record",
]
