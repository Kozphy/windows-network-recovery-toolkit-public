"""Process classification engine — Step 2 orchestrator."""

from __future__ import annotations

from pathlib import Path

from src.proxy_guard.proxy_allowlist import ProxyAllowlist, load_proxy_allowlist
from src.telemetry.registry_targets import proxy_registry_value_name

from . import rules
from .models import (
    ProcessClassificationInput,
    ProcessClassificationKind,
    ProcessClassificationResult,
)

# Backward-compatible aliases
ProcessLabel = ProcessClassificationKind
ProcessClassification = ProcessClassificationResult


def classify_process(
    inp: ProcessClassificationInput,
    *,
    allowlist: ProxyAllowlist | None = None,
    repo_root: Path | None = None,
) -> ProcessClassificationResult:
    """Classify a registry writer or correlated process (never labels malware)."""
    al = allowlist or load_proxy_allowlist(repo_root)
    reasons: list[str] = []
    risk: list[str] = []
    trust: list[str] = []

    if not inp.registry_value_name and inp.registry_target:
        inp.registry_value_name = proxy_registry_value_name(inp.registry_target) or ""

    if inp.has_listener_only or inp.causation_level in ("CORRELATION_ONLY", "UNKNOWN"):
        reasons.append("listener_or_partial_telemetry_without_registry_writer_proof")
        return ProcessClassificationResult(
            classification=ProcessClassificationKind.CORRELATION_ONLY,
            confidence=0.45,
            reasons=reasons,
            risk_factors=["registry_writer_proof_unavailable"],
            summary="Correlation only — registry writer proof unavailable; requires human review.",
            recommended_review=True,
        )

    if rules.nvidia_python_false_positive(inp):
        reasons.append("python_nvidia_context_without_registry_write_proof")
        risk.append("possible_false_attribution")
        return ProcessClassificationResult(
            classification=ProcessClassificationKind.UNKNOWN,
            confidence=0.22,
            reasons=reasons,
            risk_factors=risk,
            summary="python.exe near NVIDIA context without registry write proof — LOW confidence.",
            recommended_review=True,
        )

    if rules.system_writer(inp):
        trust.append("system_or_admin_utility_writer")
        return ProcessClassificationResult(
            classification=ProcessClassificationKind.BENIGN_SYSTEM_CHANGE,
            confidence=0.7,
            reasons=reasons + ["system_binary_registry_write"],
            trust_factors=trust,
            summary="System utility wrote proxy registry key — likely benign system change.",
        )

    if rules.obfuscated_command(inp.parent_command_line) and rules.suspicious_launch_path(inp):
        reasons.append("obfuscated_powershell_suspicious_path")
        risk.extend(["obfuscated_command", "writable_user_path"])
        return ProcessClassificationResult(
            classification=ProcessClassificationKind.SUSPICIOUS_PROXY,
            confidence=0.88,
            reasons=reasons,
            risk_factors=risk,
            summary="Suspicious: PowerShell launched node.exe from Temp/AppData with obfuscated command.",
            recommended_review=True,
        )

    if rules.is_external_proxy(inp.proxy_server_after):
        reasons.append("external_proxy_destination")
        risk.append("possible_mitm_risk")
        return ProcessClassificationResult(
            classification=ProcessClassificationKind.POSSIBLE_MITM_RISK,
            confidence=0.9,
            reasons=reasons,
            risk_factors=risk,
            summary="Possible MITM risk: non-localhost proxy destination — requires human review.",
            recommended_review=True,
        )

    if rules.autoconfig_changed(inp):
        reasons.append("autoconfigurl_changed")
        risk.append("policy_violation")
        return ProcessClassificationResult(
            classification=ProcessClassificationKind.SUSPICIOUS_PROXY,
            confidence=0.86,
            reasons=reasons,
            risk_factors=risk,
            summary="Unexpected AutoConfigURL change — policy violation; requires human review.",
            recommended_review=True,
        )

    if (
        inp.has_registry_writer_proof
        and "proxyserver" in (inp.registry_value_name or inp.registry_target).lower()
        and rules.is_unsigned(inp.signature_status)
        and rules.basename(inp.image_path) not in ("node.exe", "code.exe", "cursor.exe")
        and not rules.is_localhost_proxy(inp.proxy_server_after)
    ):
        reasons.append("unsigned_writer_proxyserver")
        risk.append("unsigned_binary")
        return ProcessClassificationResult(
            classification=ProcessClassificationKind.POSSIBLE_MITM_RISK,
            confidence=0.84,
            reasons=reasons,
            risk_factors=risk,
            summary="Unsigned unknown binary wrote ProxyServer — possible MITM risk.",
            recommended_review=True,
        )

    cap = 0.85
    lineage_confirmed = bool(inp.parent_image_path and inp.has_registry_writer_proof)

    if rules.basename(inp.image_path) == "node.exe" and rules.cursor_context(inp, al):
        trust.append("cursor_lineage")
        conf = 0.82 if lineage_confirmed else 0.72
        conf = min(conf, cap)
        return ProcessClassificationResult(
            classification=ProcessClassificationKind.KNOWN_CURSOR_PROXY,
            confidence=conf,
            reasons=reasons + ["cursor_launched_node"],
            trust_factors=trust,
            summary="Known Cursor proxy pattern — node.exe from trusted Cursor context.",
        )

    if rules.basename(inp.image_path) == "node.exe" and rules.dev_proxy_context(inp):
        if rules.suspicious_launch_path(inp):
            risk.append("dev_keywords_but_suspicious_path")
            return ProcessClassificationResult(
                classification=ProcessClassificationKind.SUSPICIOUS_PROXY,
                confidence=0.8,
                reasons=reasons + ["dev_keywords_but_suspicious_path"],
                risk_factors=risk,
                summary="Suspicious: dev-server indicators but launched from suspicious path.",
                recommended_review=True,
            )
        trust.append("dev_server_command_line")
        return ProcessClassificationResult(
            classification=ProcessClassificationKind.KNOWN_DEV_PROXY,
            confidence=min(0.83, cap),
            reasons=reasons + ["dev_proxy_keywords"],
            trust_factors=trust,
            summary="Known dev proxy — npm/vite/next style localhost dev server.",
        )

    if rules.basename(inp.image_path) == "node.exe" and rules.vscode_context(inp, al):
        trust.append("vscode_extension_host")
        conf = min(0.8 if lineage_confirmed else 0.7, cap)
        return ProcessClassificationResult(
            classification=ProcessClassificationKind.KNOWN_VSCODE_EXTENSION,
            confidence=conf,
            reasons=reasons + ["vscode_launched_node"],
            trust_factors=trust,
            summary="Known VS Code extension proxy — observed dev tooling.",
        )

    if rules.basename(inp.image_path) in rules._SECURITY_TOOLS:
        trust.append("known_security_tool")
        return ProcessClassificationResult(
            classification=ProcessClassificationKind.KNOWN_SECURITY_TOOL,
            confidence=0.85,
            reasons=reasons + ["security_tool_image"],
            trust_factors=trust,
            summary="Known security/debug proxy tool.",
        )

    if rules.basename(inp.image_path) in rules._BROWSER_NAMES:
        return ProcessClassificationResult(
            classification=ProcessClassificationKind.KNOWN_BROWSER_PROXY,
            confidence=0.75,
            reasons=reasons + ["browser_process"],
            trust_factors=["browser_proxy_stack"],
            summary="Browser-related proxy writer — known browser proxy pattern.",
        )

    if inp.has_registry_writer_proof and rules.is_localhost_proxy(inp.proxy_server_after):
        reasons.append("confirmed_writer_localhost")
        return ProcessClassificationResult(
            classification=ProcessClassificationKind.UNKNOWN_LOCAL_PROXY,
            confidence=0.78,
            reasons=reasons,
            risk_factors=["unknown_localhost_writer"],
            summary="Unknown local proxy — registry writer confirmed on 127.0.0.1; requires human review.",
            recommended_review=True,
        )

    if inp.has_registry_writer_proof:
        return ProcessClassificationResult(
            classification=ProcessClassificationKind.REGISTRY_WRITER_CONFIRMED,
            confidence=0.72,
            reasons=reasons + ["registry_writer_confirmed"],
            summary="Registry writer confirmed — process category unknown.",
            recommended_review=True,
        )

    return ProcessClassificationResult(
        classification=ProcessClassificationKind.UNKNOWN,
        confidence=0.35,
        reasons=reasons + ["insufficient_telemetry"],
        summary="Unknown — insufficient telemetry for classification.",
        recommended_review=True,
    )
