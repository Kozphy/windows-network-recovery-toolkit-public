"""Reasoning-pipeline Prometheus metrics (Observation → Event → … → Audit → Metrics)."""

from __future__ import annotations

import re
from typing import Any

from backend.prometheus_exporter import inc_labeled
from platform_core.privacy import stable_endpoint_hash
from platform_core.storage import iter_jsonl, platform_data_dir

_SAFE_LABEL = re.compile(r"[^a-zA-Z0-9_:-]")


def sanitize_label(value: object, *, default: str = "unknown", max_len: int = 64) -> str:
    """Sanitize label.
    
    Args:
        value: The value value supplied by the caller.
        default: The default value supplied by the caller.
        max_len: The max len value supplied by the caller.
    
    Returns:
        The str result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    text = str(value or default).strip() or default
    text = _SAFE_LABEL.sub("_", text.lower())[:max_len]
    return text or default


def hostname_label(endpoint_id: str | None = None, hostname_hint: str | None = None) -> str:
    """Stable hashed hostname label — not a raw hostname (privacy-safe)."""
    hint = (endpoint_id or hostname_hint or "local").strip()
    if len(hint) == 32 and all(c in "0123456789abcdef" for c in hint.lower()):
        return hint[:16]
    digest = stable_endpoint_hash(hint, "observability", None)
    return digest[:16]


def confidence_label(score: float) -> str:
    """Confidence label.
    
    Args:
        score: The score value supplied by the caller.
    
    Returns:
        The str result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    if score >= 0.9:
        return "very_high"
    if score >= 0.6:
        return "high"
    if score >= 0.3:
        return "medium"
    return "low"


def policy_label(outcome: str) -> str:
    """Policy label.
    
    Args:
        outcome: The outcome value supplied by the caller.
    
    Returns:
        The str result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    
    Audit Notes:
        Preserves observation, policy, and audit boundaries established by the caller.
    """
    normalized = str(outcome or "PREVIEW").upper()
    if normalized == "ALLOW":
        return "allow"
    if normalized == "BLOCK":
        return "block"
    return "preview"


def _labels(
    *,
    endpoint_id: str = "local",
    policy_outcome: str = "PREVIEW",
    hypothesis: str = "unknown",
    confidence: float = 0.0,
) -> dict[str, str]:
    return {
        "hostname": hostname_label(endpoint_id),
        "policy": policy_label(policy_outcome),
        "hypothesis": sanitize_label(hypothesis or "unknown"),
        "confidence": confidence_label(confidence),
    }


def record_proxy_change(
    *,
    endpoint_id: str,
    policy_outcome: str,
    hypothesis: str,
    confidence: float,
) -> None:
    """Record proxy change.
    
    Args:
        endpoint_id: The endpoint id value supplied by the caller.
        policy_outcome: The policy outcome value supplied by the caller.
        hypothesis: The hypothesis value supplied by the caller.
        confidence: The confidence value supplied by the caller.
    
    Returns:
        None.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    inc_labeled(
        "proxy_change_total",
        _labels(
            endpoint_id=endpoint_id,
            policy_outcome=policy_outcome,
            hypothesis=hypothesis,
            confidence=confidence,
        ),
    )


def record_hypothesis_generated(
    *,
    endpoint_id: str,
    hypothesis: str,
    confidence: float,
    policy_outcome: str = "PREVIEW",
) -> None:
    """Record hypothesis generated.
    
    Args:
        endpoint_id: The endpoint id value supplied by the caller.
        hypothesis: The hypothesis value supplied by the caller.
        confidence: The confidence value supplied by the caller.
        policy_outcome: The policy outcome value supplied by the caller.
    
    Returns:
        None.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    inc_labeled(
        "hypothesis_generated_total",
        _labels(
            endpoint_id=endpoint_id,
            policy_outcome=policy_outcome,
            hypothesis=hypothesis,
            confidence=confidence,
        ),
    )


def record_hypothesis_confirmed(
    *,
    endpoint_id: str,
    hypothesis: str,
    confidence: float,
    policy_outcome: str = "PREVIEW",
) -> None:
    """Record hypothesis confirmed.
    
    Args:
        endpoint_id: The endpoint id value supplied by the caller.
        hypothesis: The hypothesis value supplied by the caller.
        confidence: The confidence value supplied by the caller.
        policy_outcome: The policy outcome value supplied by the caller.
    
    Returns:
        None.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    inc_labeled(
        "hypothesis_confirmed_total",
        _labels(
            endpoint_id=endpoint_id,
            policy_outcome=policy_outcome,
            hypothesis=hypothesis,
            confidence=confidence,
        ),
    )


def record_policy_decision(
    *,
    endpoint_id: str,
    policy_outcome: str,
    hypothesis: str,
    confidence: float,
) -> None:
    """Record policy decision.
    
    Args:
        endpoint_id: The endpoint id value supplied by the caller.
        policy_outcome: The policy outcome value supplied by the caller.
        hypothesis: The hypothesis value supplied by the caller.
        confidence: The confidence value supplied by the caller.
    
    Returns:
        None.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    
    Audit Notes:
        Preserves observation, policy, and audit boundaries established by the caller.
    """
    labels = _labels(
        endpoint_id=endpoint_id,
        policy_outcome=policy_outcome,
        hypothesis=hypothesis,
        confidence=confidence,
    )
    tri = policy_label(policy_outcome)
    if tri == "allow":
        inc_labeled("policy_allow_total", labels)
    elif tri == "block":
        inc_labeled("policy_block_total", labels)
    else:
        inc_labeled("policy_preview_total", labels)


def record_proof_result(
    *,
    endpoint_id: str,
    hypothesis: str,
    confidence: float,
    policy_outcome: str,
    proof_status: str,
) -> None:
    """Record proof result.
    
    Args:
        endpoint_id: The endpoint id value supplied by the caller.
        hypothesis: The hypothesis value supplied by the caller.
        confidence: The confidence value supplied by the caller.
        policy_outcome: The policy outcome value supplied by the caller.
        proof_status: The proof status value supplied by the caller.
    
    Returns:
        None.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    labels = _labels(
        endpoint_id=endpoint_id,
        policy_outcome=policy_outcome,
        hypothesis=hypothesis,
        confidence=confidence,
    )
    status = str(proof_status or "NOT_RUN").upper()
    if status == "CONFIRMED":
        inc_labeled("proof_success_total", labels)
        record_hypothesis_confirmed(
            endpoint_id=endpoint_id,
            hypothesis=hypothesis,
            confidence=confidence,
            policy_outcome=policy_outcome,
        )
    elif status in {"REJECTED", "INCONCLUSIVE"}:
        inc_labeled("proof_failure_total", labels)


def record_reasoning_pipeline(
    *,
    endpoint_id: str,
    correlation: dict[str, Any],
    proxy_change_detected: bool = False,
) -> None:
    """Emit full pipeline counters from a correlation / reasoning JSON payload."""
    hypothesis = str(correlation.get("accepted_hypothesis") or "unknown")
    confidence = float(correlation.get("confidence_score") or 0.0)
    policy = correlation.get("policy_decision") or {}
    outcome = str(policy.get("outcome") or "PREVIEW")
    proof = correlation.get("proof_result") or {}
    proof_status = str(proof.get("status") or "NOT_RUN")

    record_hypothesis_generated(
        endpoint_id=endpoint_id,
        hypothesis=hypothesis,
        confidence=confidence,
        policy_outcome=outcome,
    )
    ranking = correlation.get("hypothesis_ranking") or []
    for row in ranking[1:3]:
        if isinstance(row, dict) and row.get("hypothesis"):
            record_hypothesis_generated(
                endpoint_id=endpoint_id,
                hypothesis=str(row["hypothesis"]),
                confidence=float(row.get("score") or 0.0),
                policy_outcome=outcome,
            )

    record_policy_decision(
        endpoint_id=endpoint_id,
        policy_outcome=outcome,
        hypothesis=hypothesis,
        confidence=confidence,
    )
    record_proof_result(
        endpoint_id=endpoint_id,
        hypothesis=hypothesis,
        confidence=confidence,
        policy_outcome=outcome,
        proof_status=proof_status,
    )
    if proxy_change_detected or _signals_proxy_change(correlation):
        record_proxy_change(
            endpoint_id=endpoint_id,
            policy_outcome=outcome,
            hypothesis=hypothesis,
            confidence=confidence,
        )


def _signals_proxy_change(correlation: dict[str, Any]) -> bool:
    for obs in correlation.get("observations") or []:
        if not isinstance(obs, dict):
            continue
        name = str(obs.get("signal_name") or "")
        if name in {"proxy_enable", "proxy_server", "wininet_proxy_state"}:
            val = obs.get("value")
            if val in (True, 1, "1", "true") or (isinstance(val, str) and val.strip()):
                return True
    for ev in correlation.get("events") or []:
        if isinstance(ev, dict) and "proxy" in str(ev.get("name") or ev.get("event_type") or "").lower():
            return True
    return False


def bootstrap_labeled_metrics_from_storage() -> int:
    """Load historical audit/signal rows into counters once at process start."""
    loaded = 0
    root = platform_data_dir()
    for row in iter_jsonl(root / "platform_signals.jsonl"):
        kind = str(row.get("kind") or row.get("signal") or "")
        if kind not in ("proxy_registry_change", "proxy_change", "proxy_enable_transition"):
            continue
        endpoint = str(row.get("endpoint_id") or row.get("endpoint_id_hash") or "local")
        record_proxy_change(
            endpoint_id=endpoint,
            policy_outcome="PREVIEW",
            hypothesis="proxy_registry_change",
            confidence=0.5,
        )
        loaded += 1

    for row in iter_jsonl(root / "audit.jsonl"):
        endpoint = str(row.get("endpoint_id") or "local")
        hypothesis_list = row.get("hypothesis") or []
        hypothesis = str(hypothesis_list[0]) if hypothesis_list else "unknown"
        confidence = float(row.get("confidence") or 0.0)
        decision = str(row.get("policy_decision") or "preview_only")
        if decision == "blocked":
            outcome = "BLOCK"
        elif decision == "allow":
            outcome = "ALLOW"
        else:
            outcome = "PREVIEW"
        record_policy_decision(
            endpoint_id=endpoint,
            policy_outcome=outcome,
            hypothesis=hypothesis,
            confidence=confidence,
        )
        record_hypothesis_generated(
            endpoint_id=endpoint,
            hypothesis=hypothesis,
            confidence=confidence,
            policy_outcome=outcome,
        )
        loaded += 1
    return loaded
