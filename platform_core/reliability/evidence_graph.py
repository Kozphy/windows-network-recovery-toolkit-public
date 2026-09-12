"""Causal evidence graph for endpoint reliability reasoning."""

from __future__ import annotations

from typing import Any, Literal

from .models import (
    EvidenceGraphEdge,
    EvidenceGraphNode,
    NormalizedPlatformEvent,
    PlatformStateTransition,
)


class EvidenceGraph:
    """In-memory directed graph supporting causal reasoning queries."""

    def __init__(self) -> None:
        """Initialize the EvidenceGraph instance.

        Returns:
            None.

        Side effects:
            Initializes instance state only.
        """
        self.nodes: dict[str, EvidenceGraphNode] = {}
        self.edges: list[EvidenceGraphEdge] = []

    def add_node(self, node: EvidenceGraphNode) -> EvidenceGraphNode:
        """Provide add node behavior for toolkit workflows.

        Args:
            node: Value supplied by the caller for node.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        self.nodes[node.node_id] = node
        return node

    def link(
        self,
        from_id: str,
        to_id: str,
        *,
        relation: Literal["supports", "contradicts", "caused_by", "correlates_with"] = "supports",
        weight: float = 0.5,
    ) -> EvidenceGraphEdge:
        """Provide link behavior for toolkit workflows.

        Args:
            from_id: Value supplied by the caller for from id.
            to_id: Value supplied by the caller for to id.
            relation: Value supplied by the caller for relation.
            weight: Value supplied by the caller for weight.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        edge = EvidenceGraphEdge(
            from_node_id=from_id,
            to_node_id=to_id,
            relation=relation,
            weight=weight,
        )
        self.edges.append(edge)
        return edge

    def to_jsonable(self) -> dict[str, Any]:
        """Return a serialized to jsonable representation.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        return {
            "nodes": [n.model_dump(mode="json") for n in self.nodes.values()],
            "edges": [e.model_dump(mode="json") for e in self.edges],
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
        }

    def nodes_for_hypothesis(self, node_ids: list[str]) -> list[EvidenceGraphNode]:
        """Provide nodes for hypothesis behavior for toolkit workflows.

        Args:
            node_ids: Value supplied by the caller for node ids.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        return [self.nodes[nid] for nid in node_ids if nid in self.nodes]


def build_evidence_graph(
    events: list[NormalizedPlatformEvent],
    transitions: list[PlatformStateTransition],
    *,
    process_snapshot: dict[str, Any] | None = None,
) -> EvidenceGraph:
    """Build graph from normalized events and state transitions."""
    graph = EvidenceGraph()
    obs_nodes: dict[str, str] = {}

    for ev in events:
        kind = "observation"
        strength = "weak"
        if ev.evidence_tier == "TIER_3_CAUSAL_PROOF":
            strength = "proof"
            kind = "registry_write" if ev.source_kind in ("sysmon", "registry") else "observation"
        elif ev.evidence_tier == "TIER_1_CORRELATED_SIGNAL":
            strength = "medium"
        if "listener" in ev.signal_name or "tcp" in ev.signal_name:
            kind = "listener"
        if ev.source_kind == "network_telemetry":
            kind = "network_flow"

        node = EvidenceGraphNode(
            kind=kind,  # type: ignore[arg-type]
            label=f"{ev.signal_name}={ev.signal_value!r}",
            strength=strength,  # type: ignore[arg-type]
            timestamp_utc=ev.timestamp_utc,
            event_ids=[ev.event_id],
            detail={"source_kind": ev.source_kind, "tier": ev.evidence_tier},
            limitations=list(ev.limitations),
        )
        graph.add_node(node)
        obs_nodes[ev.event_id] = node.node_id

    if process_snapshot:
        proc = EvidenceGraphNode(
            kind="process",
            label=str(process_snapshot.get("process_name") or "unknown"),
            strength="medium",
            detail=process_snapshot,
            limitations=["Process correlation is not registry writer proof."],
        )
        graph.add_node(proc)
        for _eid, nid in list(obs_nodes.items())[:1]:
            graph.link(nid, proc.node_id, relation="correlates_with", weight=0.6)

    prev_trans_node: str | None = None
    for trans in transitions:
        tnode = EvidenceGraphNode(
            kind="policy_decision",
            label=f"{trans.from_state} → {trans.to_state}",
            strength="strong",
            event_ids=list(trans.triggering_event_ids),
            detail={"rule_id": trans.rule_id, "confidence": trans.confidence},
        )
        graph.add_node(tnode)
        if prev_trans_node:
            graph.link(
                prev_trans_node, tnode.node_id, relation="caused_by", weight=trans.confidence
            )
        prev_trans_node = tnode.node_id
        for eid in trans.triggering_event_ids:
            if eid in obs_nodes:
                graph.link(obs_nodes[eid], tnode.node_id, relation="supports", weight=0.7)

    return graph
