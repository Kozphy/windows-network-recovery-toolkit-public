"""App-path reliability scenarios (diagnose-first, audit-backed, preview-gated remediation).

Module responsibility:
    Public exports for ChatGPT app-path scenario models and ``run_scenario_diagnosis``.

System placement:
    Imported by tests and optional downstream tooling; CLI uses ``cli_handlers`` directly.

Key invariants:
    * No side effects on import.
"""

from .engine import run_scenario_diagnosis
from .models import (
    CASE_CHATGPT_APP_FIREWALL_FILTERING_INTERACTION,
    SCENARIO_CHATGPT_APP_FIREWALL,
    AuditRecord,
    DiagnosisResult,
    OrdinalConfidence,
    PolicyOutcome,
    SignalBundle,
)

__all__ = [
    "CASE_CHATGPT_APP_FIREWALL_FILTERING_INTERACTION",
    "SCENARIO_CHATGPT_APP_FIREWALL",
    "AuditRecord",
    "DiagnosisResult",
    "OrdinalConfidence",
    "PolicyOutcome",
    "SignalBundle",
    "run_scenario_diagnosis",
]
