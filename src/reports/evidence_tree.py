"""Dashboard evidence tree — Step 5."""

from __future__ import annotations

import json
from typing import Any

from src.classification.models import ProcessClassificationResult
from src.policy.models import ProxyPolicyDecision

from .models import EvidenceNode


def build_evidence_tree(
    *,
    transition_row: dict[str, Any],
    causation: dict[str, Any],
    classification: ProcessClassificationResult | dict[str, Any],
    policy: ProxyPolicyDecision | dict[str, Any],
) -> EvidenceNode:
    """Build hierarchical evidence tree for dashboard/API."""
    ts = str(transition_row.get("timestamp") or "")
    diff = transition_row.get("diff") or {}
    after = diff.get("after") or {}
    before = diff.get("before") or {}
    attrib = transition_row.get("attribution") or {}
    suspect = attrib.get("primary_suspect") if isinstance(attrib, dict) else None

    cls = classification.to_dict() if isinstance(classification, ProcessClassificationResult) else classification
    pol = policy.to_dict() if isinstance(policy, ProxyPolicyDecision) else policy
    level = str(causation.get("causation_level") or "UNKNOWN")

    observation = EvidenceNode(
        id="observation",
        parent_id=None,
        node_type="observation",
        title="Observation",
        summary=f"Proxy drift detected at {ts}",
        timestamp_utc=ts,
        source="proxy-watch",
        confidence=0.95,
        raw_event_reference={"diff": diff},
    )

    state_change = EvidenceNode(
        id="proxy_state_change",
        parent_id="observation",
        node_type="proxy_state_change",
        title="Proxy State Change",
        summary=f"Before {before} -> After {after}",
        timestamp_utc=ts,
        source="proxy-watch",
        confidence=0.95,
        raw_event_reference=diff,
    )
    observation.children.append(state_change)

    registry_proof = EvidenceNode(
        id="registry_writer_proof",
        parent_id="proxy_state_change",
        node_type="registry_writer_proof",
        title="Registry Writer Proof",
        summary=str(causation.get("explanation") or "No registry writer proof"),
        timestamp_utc=ts,
        source="sysmon/eid13",
        confidence=float(causation.get("confidence") or 0.0),
        severity="HIGH" if level == "FINAL_CAUSATION" else "MEDIUM",
        raw_event_reference={
            "causation_level": level,
            "target": causation.get("matched_registry_target"),
            "details": causation.get("matched_registry_details"),
        },
    )
    state_change.children.append(registry_proof)

    lineage = EvidenceNode(
        id="process_lineage",
        parent_id="registry_writer_proof",
        node_type="process_lineage",
        title="Process Lineage",
        summary=f"Writer: {causation.get('writer_process')} | Parent: {causation.get('parent_process')}",
        timestamp_utc=ts,
        source="sysmon/eid1",
        confidence=float(causation.get("confidence") or 0.3),
        raw_event_reference={"process_tree": causation.get("process_tree")},
    )
    registry_proof.children.append(lineage)

    listener = EvidenceNode(
        id="listener_evidence",
        parent_id="process_lineage",
        node_type="listener_evidence",
        title="Listener Evidence",
        summary=(
            f"Candidate: {suspect.get('name')} pid={suspect.get('pid')}"
            if isinstance(suspect, dict)
            else "No listener correlation"
        ),
        timestamp_utc=ts,
        source="proxy-watch/inventory",
        confidence=float(attrib.get("confidence") or 0.45) if suspect else 0.2,
        raw_event_reference={"primary_suspect": suspect},
    )
    lineage.children.append(listener)

    classify_node = EvidenceNode(
        id="classification",
        parent_id="listener_evidence",
        node_type="classification",
        title="Classification",
        summary=str(cls.get("summary") or cls.get("explanation") or cls.get("classification")),
        timestamp_utc=ts,
        source="process_classifier",
        confidence=float(cls.get("confidence") or 0.5),
        raw_event_reference=cls,
    )
    listener.children.append(classify_node)

    policy_node = EvidenceNode(
        id="policy_decision",
        parent_id="classification",
        node_type="policy_decision",
        title="Policy Decision",
        summary=str(pol.get("reason") or pol.get("decision")),
        timestamp_utc=ts,
        source="proxy_policy_engine",
        confidence=float(pol.get("confidence") or 0.5),
        severity=str(pol.get("severity") or "MEDIUM"),
        raw_event_reference=pol,
    )
    classify_node.children.append(policy_node)

    action = EvidenceNode(
        id="recommended_action",
        parent_id="policy_decision",
        node_type="recommended_action",
        title="Recommended Action",
        summary=_action_summary(pol),
        timestamp_utc=ts,
        source="policy",
        confidence=float(pol.get("confidence") or 0.5),
        severity=str(pol.get("severity") or "MEDIUM"),
        raw_event_reference={"next_safe_steps": pol.get("next_safe_steps")},
    )
    policy_node.children.append(action)

    return observation


def _action_summary(pol: dict[str, Any]) -> str:
    dec = str(pol.get("decision") or pol.get("action") or "OBSERVE")
    mapping = {
        "ALLOW": "Allow — log only.",
        "OBSERVE": "Observe — continue proxy-watch.",
        "ALERT": "Alert — human review recommended.",
        "PREVIEW_DISABLE": "Preview disable only — no mutation until confirmed.",
        "BLOCK_RECOMMENDED": "Block recommended — no automatic kill.",
        "ESCALATE_REVIEW": "Escalate for human review.",
        "CORRELATION_ONLY_ALERT": "Correlation only — registry writer proof unavailable.",
    }
    return mapping.get(dec, dec)


def render_evidence_tree_json(root: EvidenceNode) -> str:
    """Render evidence tree json.
    
    Args:
        root: Repository root used to resolve fixtures, reports, or local state.
    
    Returns:
        The str result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    return json.dumps(root.to_dict(), indent=2)


def render_evidence_tree_markdown(root: EvidenceNode, *, indent: int = 0) -> str:
    """Render evidence tree markdown.
    
    Args:
        root: Repository root used to resolve fixtures, reports, or local state.
        indent: The indent value supplied by the caller.
    
    Returns:
        The str result produced by the operation.
    
    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
    """
    prefix = "  " * indent
    lines = [f"{prefix}- **{root.title}** ({root.source})"]
    if root.summary:
        lines.append(f"{prefix}  - {root.summary}")
    for child in root.children:
        lines.append(render_evidence_tree_markdown(child, indent=indent + 1))
    return "\n".join(lines)


def render_evidence_tree_text(root: EvidenceNode, *, indent: int = 0) -> str:
    """Render evidence tree text.
    
    Args:
        root: Repository root used to resolve fixtures, reports, or local state.
        indent: The indent value supplied by the caller.
    
    Returns:
        The str result produced by the operation.
    
    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
    """
    prefix = "  " * indent
    lines = [f"{prefix}{root.title} [{root.node_type}] conf={root.confidence:.2f}"]
    if root.summary:
        lines.append(f"{prefix}  {root.summary}")
    for child in root.children:
        lines.append(render_evidence_tree_text(child, indent=indent + 1))
    return "\n".join(lines)
