"""Provider-neutral structured LLM diagnosis adapter.

The adapter can reason, but it cannot execute remediation. Invalid or out-of-taxonomy
responses fail closed to human review so model integration cannot bypass existing policy.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

from pydantic import ValidationError

from windows_network_toolkit.decision.decision_model import DecisionResult, IncidentType

from .models import AgentDiagnosis


class StructuredModelClient(Protocol):
    """Minimal provider-neutral client contract for structured model output."""

    def complete(self, payload: Mapping[str, Any]) -> Mapping[str, Any]: ...


class StructuredLLMDiagnosisAgent:
    """Translate deterministic evidence into a strictly validated model diagnosis.

    The model receives no execution tool and no authority signal. It only proposes a typed
    diagnosis. Malformed output, unsupported incident labels, or client errors fail closed.
    """

    def __init__(self, client: StructuredModelClient) -> None:
        self._client = client

    def diagnose(self, decision: DecisionResult) -> AgentDiagnosis:
        payload: dict[str, Any] = {
            "task": "classify_windows_network_incident",
            "allowed_incident_types": [item.value for item in IncidentType],
            "decision": {
                "decision_id": decision.decision_id,
                "incident_id": decision.incident_id,
                "incident_type_baseline": decision.incident_type.value,
                "confidence_baseline": decision.confidence,
                "reasoning": decision.reasoning,
                "evidence_refs": list(decision.evidence_refs),
                "risk_level": decision.risk_level,
            },
            "required_output": {
                "incident_type": "one allowed_incident_type",
                "confidence": "number from 0 to 1",
                "hypothesis": "concise evidence-grounded hypothesis",
                "evidence_refs": "subset of supplied evidence_refs",
                "limitations": "list of uncertainty statements",
                "human_review_required": "boolean",
            },
            "safety": {
                "execution_authority": False,
                "must_not_invent_evidence": True,
                "must_preserve_uncertainty": True,
            },
        }

        try:
            raw = dict(self._client.complete(payload))
            diagnosis = AgentDiagnosis.model_validate(raw)
        except (Exception, ValidationError) as exc:
            return self._fail_closed(decision, type(exc).__name__)

        supplied = set(decision.evidence_refs)
        if any(ref not in supplied for ref in diagnosis.evidence_refs):
            return self._fail_closed(decision, "invented_evidence_reference")

        if diagnosis.confidence > decision.confidence + 0.25 and not diagnosis.limitations:
            return self._fail_closed(decision, "unsupported_confidence_increase")

        return diagnosis

    @staticmethod
    def _fail_closed(decision: DecisionResult, reason: str) -> AgentDiagnosis:
        return AgentDiagnosis(
            incident_type=decision.incident_type,
            confidence=min(decision.confidence, 0.49),
            hypothesis=(
                "Model diagnosis was rejected; preserve the deterministic baseline and "
                "require human review."
            ),
            evidence_refs=list(decision.evidence_refs),
            limitations=[f"llm_adapter_failure:{reason}"],
            human_review_required=True,
        )
