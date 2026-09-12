"""Tests for technology risk scoring engine."""

from __future__ import annotations

from windows_network_toolkit.risk_scoring_engine import (
    ControlAggregate,
    RiskScoringInput,
    aggregate_control_result,
    score_risk,
    score_risk_from_incident,
)


def test_score_risk_dead_proxy_high() -> None:
    result = score_risk(
        RiskScoringInput(
            incident_class="DEAD_PROXY_CONFIG",
            evidence_quality=0.8,
            proof_level="T1",
            business_impact="high",
            recurrence_count=1,
            control_test_result=ControlAggregate.FAIL.value,
        )
    )
    assert result.risk_level == "HIGH"
    assert result.likelihood in ("high", "medium")
    assert result.impact == "high"
    assert result.risk_score >= 40
    assert result.human_review_recommended is True
    assert len(result.limitations) >= 3


def test_score_risk_no_proxy_low() -> None:
    result = score_risk(
        RiskScoringInput(
            incident_class="NO_PROXY",
            evidence_quality=0.9,
            proof_level="T2",
            business_impact="low",
            recurrence_count=0,
            control_test_result=ControlAggregate.PASS.value,
        )
    )
    assert result.risk_level == "LOW"
    assert result.risk_score < 40


def test_aggregate_control_result_worst_case() -> None:
    assert aggregate_control_result(["PASS", "FAIL", "PARTIAL"]) == "FAIL"
    assert aggregate_control_result(["PASS", "NOT_TESTED"]) == "NOT_TESTED"


def test_score_risk_from_incident_dict() -> None:
    incident = {
        "incident_id": "INC-test",
        "incident_class": "REVERTER_SUSPECTED",
        "confidence": 0.7,
        "risk_level": "HIGH",
    }
    controls = [
        {"control_id": "PROXY_REVERTER_DETECTION", "test_result": "FAIL"},
        {"control_id": "SAFE_REMEDIATION_POLICY", "test_result": "PASS"},
    ]
    result = score_risk_from_incident(incident, control_tests=controls)
    assert result.incident_class == "REVERTER_SUSPECTED"
    assert result.risk_level in ("HIGH", "MEDIUM")


def test_limitations_include_governance() -> None:
    result = score_risk(
        RiskScoringInput(
            incident_class="UNKNOWN",
            evidence_quality=0.3,
            proof_level="T0",
            business_impact="medium",
            control_test_result=ControlAggregate.NOT_TESTED.value,
        )
    )
    joined = " ".join(result.limitations).lower()
    assert "not proof" in joined or "ordinal" in joined
    assert "not_tested" in joined.lower() or "not tested" in joined.lower()
