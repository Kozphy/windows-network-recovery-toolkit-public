"""Technology Risk Decision Platform — business/control layer above evidence pipeline."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .asset import Asset, asset_for_fixture
from .business_objective import BusinessObjective, objective_for_fixture
from .control import ControlObjective, controls_for_fixture
from .control_test import ControlTest, ControlTestResult, run_control_tests
from .finding import Finding, findings_from_fixture
from .risk_rating import RiskRating, rate_risk
from .threat import ThreatScenario, threat_for_fixture

if TYPE_CHECKING:
    from .governance_report import GovernanceDecision

_LAZY_EXPORTS = {
    "GovernanceDecision",
    "assess_risk",
    "build_governance_report",
    "load_fixture",
}


def __getattr__(name: str):
    if name in _LAZY_EXPORTS:
        from . import governance_report as _gr

        return getattr(_gr, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "Asset",
    "BusinessObjective",
    "ControlObjective",
    "ControlTest",
    "ControlTestResult",
    "Finding",
    "GovernanceDecision",
    "RiskRating",
    "ThreatScenario",
    "assess_risk",
    "asset_for_fixture",
    "build_governance_report",
    "controls_for_fixture",
    "findings_from_fixture",
    "load_fixture",
    "objective_for_fixture",
    "rate_risk",
    "run_control_tests",
    "threat_for_fixture",
]