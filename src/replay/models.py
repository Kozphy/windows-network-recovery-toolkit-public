"""Timeline replay models — Step 4."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class ProxyTimelineEventType(StrEnum):
    """Represent proxy timeline event type data used by the toolkit.
    
    Attributes:
        PROCESS_CREATED: Field or variant describing p r o c e s s c r e a t e d evidence or state.
        REGISTRY_VALUE_SET: Field or variant describing r e g i s t r y v a l u e s e t evidence or state.
        PROXY_STATE_CHANGED: Field or variant describing p r o x y s t a t e c h a n g e d evidence or state.
        LOCALHOST_LISTENER_OBSERVED: Field or variant describing l o c a l h o s t l i s t e n e r o b s e r v e d evidence or state.
        NETWORK_FAILURE_OBSERVED: Field or variant describing n e t w o r k f a i l u r e o b s e r v e d evidence or state.
        CLASSIFICATION_ASSIGNED: Field or variant describing c l a s s i f i c a t i o n a s s i g n e d evidence or state.
        POLICY_DECISION_CREATED: Field or variant describing p o l i c y d e c i s i o n c r e a t e d evidence or state.
        REMEDIATION_PREVIEWED: Field or variant describing r e m e d i a t i o n p r e v i e w e d evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    PROCESS_CREATED = "PROCESS_CREATED"
    REGISTRY_VALUE_SET = "REGISTRY_VALUE_SET"
    PROXY_STATE_CHANGED = "PROXY_STATE_CHANGED"
    LOCALHOST_LISTENER_OBSERVED = "LOCALHOST_LISTENER_OBSERVED"
    NETWORK_FAILURE_OBSERVED = "NETWORK_FAILURE_OBSERVED"
    CLASSIFICATION_ASSIGNED = "CLASSIFICATION_ASSIGNED"
    POLICY_DECISION_CREATED = "POLICY_DECISION_CREATED"
    REMEDIATION_PREVIEWED = "REMEDIATION_PREVIEWED"
    USER_CONFIRMATION_REQUIRED = "USER_CONFIRMATION_REQUIRED"
    PROXY_DISABLED_CONFIRMED = "PROXY_DISABLED_CONFIRMED"
    UNKNOWN = "UNKNOWN"


_KIND_ORDER: dict[str, int] = {
    ProxyTimelineEventType.PROCESS_CREATED.value: 10,
    ProxyTimelineEventType.REGISTRY_VALUE_SET.value: 20,
    ProxyTimelineEventType.LOCALHOST_LISTENER_OBSERVED.value: 30,
    ProxyTimelineEventType.PROXY_STATE_CHANGED.value: 40,
    ProxyTimelineEventType.CLASSIFICATION_ASSIGNED.value: 50,
    ProxyTimelineEventType.POLICY_DECISION_CREATED.value: 60,
    ProxyTimelineEventType.NETWORK_FAILURE_OBSERVED.value: 70,
    ProxyTimelineEventType.REMEDIATION_PREVIEWED.value: 80,
    ProxyTimelineEventType.USER_CONFIRMATION_REQUIRED.value: 90,
    ProxyTimelineEventType.PROXY_DISABLED_CONFIRMED.value: 100,
    ProxyTimelineEventType.UNKNOWN.value: 99,
}


@dataclass
class ProxyTimelineEvent:
    """Represent proxy timeline event data used by the toolkit.
    
    Attributes:
        timestamp_utc: Field or variant describing timestamp utc evidence or state.
        event_type: Field or variant describing event type evidence or state.
        source: Field or variant describing source evidence or state.
        title: Field or variant describing title evidence or state.
        details: Field or variant describing details evidence or state.
        process_guid: Field or variant describing process guid evidence or state.
        process_id: Field or variant describing process id evidence or state.
        confidence: Field or variant describing confidence evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    timestamp_utc: str
    event_type: ProxyTimelineEventType
    source: str
    title: str
    details: str = ""
    process_guid: str | None = None
    process_id: int | None = None
    confidence: float = 0.0
    raw_reference: dict[str, Any] | None = None
    incident_id: str | None = None

    def sort_key(self) -> tuple[str, int, str]:
        """Sort key.
        
        Args:
            None.
        
        Returns:
            The tuple[str, int, str] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return (self.timestamp_utc or "", _KIND_ORDER.get(self.event_type.value, 99), self.event_type.value)

    def to_dict(self) -> dict[str, Any]:
        """To dict.
        
        Args:
            None.
        
        Returns:
            The dict[str, Any] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return {
            "timestamp_utc": self.timestamp_utc,
            "event_type": self.event_type.value,
            "source": self.source,
            "title": self.title,
            "details": self.details,
            "process_guid": self.process_guid,
            "process_id": self.process_id,
            "confidence": self.confidence,
            "raw_reference": self.raw_reference,
            "incident_id": self.incident_id,
        }


# Backward alias
TimelineEvent = ProxyTimelineEvent
