"""Proxy policy decision engine — Step 3."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.classification.models import ProcessClassificationKind, ProcessClassificationResult

from .models import (
    PolicyDecisionKind,
    PolicySeverity,
    ProxyPolicyDecision,
    ProxyPolicyInput,
    ProxyPolicyUserConfig,
)

_BLOCKED = ["kill_process", "reset_firewall", "disable_adapter", "registry_mutation_without_confirmation"]
_SAFE_OBSERVE = ["observe", "log", "export_report", "proxy_timeline", "proxy_forensics"]


def load_proxy_policy_config(repo_root: Path | None = None) -> ProxyPolicyUserConfig:
    """Load user policy from repo config or bundled default."""
    root = repo_root or Path.cwd()
    for rel in ("config/proxy_policy.json", "config/proxy_policy.example.json"):
        path = root / rel
        if path.is_file():
            try:
                blob = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(blob, dict):
                    return ProxyPolicyUserConfig.from_dict(blob)
            except (OSError, json.JSONDecodeError):
                pass
    default_yaml = Path(__file__).with_name("default_policy.yaml")
    if default_yaml.is_file():
        try:
            return _parse_minimal_policy_yaml(default_yaml.read_text(encoding="utf-8"))
        except OSError:
            pass
    return ProxyPolicyUserConfig()


def _parse_minimal_policy_yaml(text: str) -> ProxyPolicyUserConfig:
    raw: dict[str, Any] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, _, val = line.partition(":")
        raw[key.strip()] = val.strip()
    return ProxyPolicyUserConfig.from_dict(raw)


def _cls_label(inp: ProxyPolicyInput) -> str:
    cr = inp.classification_result
    if isinstance(cr, ProcessClassificationResult):
        return cr.classification.value
    if isinstance(cr, dict):
        return str(cr.get("classification") or cr.get("label") or "UNKNOWN")
    return str(cr)


def _external_proxy(state: dict[str, Any]) -> bool:
    srv = str(state.get("proxy_server") or "").strip().lower()
    if not srv:
        return False
    return not (srv.startswith("127.") or srv.startswith("localhost") or srv.startswith("[::1]"))


def _base_decision(
    decision: PolicyDecisionKind,
    severity: PolicySeverity,
    *,
    reason: str,
    explanation: list[str],
    requires_confirmation: bool = False,
    allowed: list[str] | None = None,
    next_steps: list[str] | None = None,
) -> ProxyPolicyDecision:
    return ProxyPolicyDecision(
        decision=decision,
        severity=severity,
        allowed_actions=allowed or list(_SAFE_OBSERVE),
        blocked_actions=list(_BLOCKED),
        requires_confirmation=requires_confirmation,
        reason=reason,
        explanation=explanation,
        next_safe_steps=next_steps
        or [
            "python -m src proxy-forensics --latest",
            "python -m src proxy-timeline --since-minutes 60",
            "python -m src proxy-disable  # preview only by default",
        ],
    )


def evaluate_proxy_policy_input(inp: ProxyPolicyInput) -> ProxyPolicyDecision:
    """Evaluate policy from structured input."""
    cfg = inp.user_config or ProxyPolicyUserConfig()
    label = _cls_label(inp)
    level = str(inp.causation_level or "UNKNOWN")
    fields = {str(f) for f in inp.changed_fields}

    if level in ("CORRELATION_ONLY", "UNKNOWN") or label == ProcessClassificationKind.CORRELATION_ONLY.value:
        return _base_decision(
            PolicyDecisionKind.CORRELATION_ONLY_ALERT,
            PolicySeverity.MEDIUM if str(inp.risk_level or "").lower() != "high" else PolicySeverity.HIGH,
            reason="correlation_only_no_registry_writer_proof",
            explanation=[
                "Registry writer proof unavailable.",
                "Listener correlation does not prove which process wrote HKCU proxy keys.",
            ],
            next_steps=[
                "Enable Sysmon Event ID 13 on Internet Settings keys.",
                "python -m src proxy-forensics --watch-integrated",
            ],
        )

    if "AutoConfigURL" in fields:
        return _base_decision(
            PolicyDecisionKind.ALERT,
            PolicySeverity.HIGH,
            reason="autoconfigurl_unexpected_change",
            explanation=["Unexpected AutoConfigURL change — policy violation."],
            requires_confirmation=True,
            allowed=["observe", "preview_disable", "export_report"],
        )

    if label == ProcessClassificationKind.POSSIBLE_MITM_RISK.value:
        return _base_decision(
            PolicyDecisionKind.ESCALATE_REVIEW,
            PolicySeverity.CRITICAL,
            reason="possible_mitm_risk",
            explanation=["Possible MITM risk — escalate for human review."],
            requires_confirmation=True,
        )

    if _external_proxy(inp.proxy_after):
        sev = PolicySeverity.HIGH
        dec = PolicyDecisionKind.BLOCK_RECOMMENDED if str(inp.risk_level or "").lower() == "high" else PolicyDecisionKind.ALERT
        return _base_decision(
            dec,
            sev,
            reason="external_proxy_destination",
            explanation=["Non-localhost proxy destination detected."],
            requires_confirmation=True,
        )

    if label == ProcessClassificationKind.SUSPICIOUS_PROXY.value:
        return _base_decision(
            PolicyDecisionKind.BLOCK_RECOMMENDED,
            PolicySeverity.CRITICAL,
            reason="suspicious_proxy_writer",
            explanation=["Suspicious proxy writer — block recommended; no automatic process kill."],
            requires_confirmation=True,
        )

    if label in (ProcessClassificationKind.UNKNOWN_LOCAL_PROXY.value, ProcessClassificationKind.REGISTRY_WRITER_CONFIRMED.value):
        return _base_decision(
            PolicyDecisionKind.ALERT,
            PolicySeverity.HIGH,
            reason=f"classification_{label.lower()}",
            explanation=[f"Classification {label} — alert; preview disable only with confirmation."],
            requires_confirmation=True,
            allowed=["observe", "preview_disable", "export_report", "proxy_forensics"],
        )

    if label == ProcessClassificationKind.KNOWN_CURSOR_PROXY.value:
        action = PolicyDecisionKind.OBSERVE if cfg.allow_known_cursor else PolicyDecisionKind.ALERT
        if cfg.cursor_action == "ALLOW":
            action = PolicyDecisionKind.ALLOW
        return _base_decision(
            action,
            PolicySeverity.LOW,
            reason="known_cursor_proxy",
            explanation=["Known Cursor proxy pattern — observe per policy."],
        )

    if label == ProcessClassificationKind.KNOWN_VSCODE_EXTENSION.value:
        dec = PolicyDecisionKind(cfg.vscode_action) if cfg.vscode_action in PolicyDecisionKind._value2member_map_ else PolicyDecisionKind.OBSERVE
        return _base_decision(
            dec,
            PolicySeverity.LOW,
            reason="known_vscode_extension",
            explanation=["VS Code extension proxy — observe."],
        )

    if label == ProcessClassificationKind.KNOWN_DEV_PROXY.value:
        dec = PolicyDecisionKind.OBSERVE if cfg.active_dev_session else PolicyDecisionKind.ALERT
        if cfg.dev_proxy_action in PolicyDecisionKind._value2member_map_:
            dec = PolicyDecisionKind(cfg.dev_proxy_action)
        return _base_decision(
            dec,
            PolicySeverity.MEDIUM,
            reason="known_dev_proxy",
            explanation=["Known dev proxy during active dev session."],
        )

    if label == ProcessClassificationKind.KNOWN_SECURITY_TOOL.value:
        return _base_decision(
            PolicyDecisionKind.OBSERVE,
            PolicySeverity.LOW,
            reason="known_security_tool",
            explanation=["Known security/debug proxy tool."],
        )

    if label == ProcessClassificationKind.BENIGN_SYSTEM_CHANGE.value:
        return _base_decision(
            PolicyDecisionKind.ALLOW,
            PolicySeverity.LOW,
            reason="benign_system_change",
            explanation=["Benign system registry change."],
        )

    return _base_decision(
        PolicyDecisionKind.OBSERVE,
        PolicySeverity.MEDIUM,
        reason="default_observe",
        explanation=["No elevated policy rule matched — default observe."],
    )


def evaluate_proxy_policy(
    *,
    causation_level: str,
    classification: ProcessClassificationResult | dict[str, Any] | str,
    current_proxy_state: dict[str, Any],
    risk_score: float | None = None,
    risk_level: str | None = None,
    changed_fields: list[str] | None = None,
    config: ProxyPolicyUserConfig | None = None,
    proxy_before: dict[str, Any] | None = None,
    registry_writer: str | None = None,
    registry_target: str | None = None,
    registry_details: str | None = None,
    localhost_port: int | None = None,
    timestamp_utc: str = "",
) -> ProxyPolicyDecision:
    """Backward-compatible wrapper around :func:`evaluate_proxy_policy_input`."""
    _ = risk_score
    if isinstance(classification, str):
        cr: ProcessClassificationResult | dict[str, Any] = {"classification": classification, "label": classification}
    else:
        cr = classification
    inp = ProxyPolicyInput(
        causation_level=causation_level,
        classification_result=cr,
        proxy_before=proxy_before or {},
        proxy_after=current_proxy_state,
        registry_writer=registry_writer,
        registry_target=registry_target,
        registry_details=registry_details,
        localhost_port=localhost_port,
        user_config=config,
        timestamp_utc=timestamp_utc,
        changed_fields=list(changed_fields or []),
        risk_level=risk_level,
    )
    return evaluate_proxy_policy_input(inp)
