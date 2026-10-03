"""Proxy risk classification for read-only investigation bundles.

Uses posture language — sensitive localhost proxy posture, not compromise claims.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
RiskCategory = Literal[
    "NO_PROXY",
    "MANUAL_LOCALHOST_PROXY",
    "KNOWN_DEV_PROXY",
    "TRUSTED_ALLOWLIST_MATCH",
    "SENSITIVE_LOCALHOST_PROXY",
    "UNKNOWN_LOCAL_PROXY",
    "EXTERNAL_PROXY",
    "POSSIBLE_MITM_RISK",
    "REMEDIATION_NOT_STICKY",
]
PolicyAction = Literal[
    "OBSERVE_ONLY",
    "EXPORT_EVIDENCE",
    "DISABLE_WININET_PROXY",
    "TERMINATE_PROXY_LISTENER",
    "TERMINATE_PROXY_REVERTER",
    "NO_ACTION",
]

_DEV_PROCESS_NAMES = frozenset({"node.exe", "python.exe", "electron.exe", "npm.cmd", "pnpm.exe"})
_DEV_PARENT_NAMES = frozenset({"powershell.exe", "pwsh.exe", "cmd.exe", "cursor.exe", "code.exe"})
_SECURITY_TOOL_NAMES = frozenset({"fiddler.exe", "charles.exe", "mitmproxy.exe", "proxifier.exe"})
_PROXY_CMDLINE_TERMS = (
    "proxy",
    "tunnel",
    "socks",
    "http-proxy",
    "mitm",
    "mcp",
    "dev server",
    "dev-server",
)
_USER_WRITABLE_MARKERS = ("\\appdata\\", "\\temp\\", "\\users\\", "\\downloads\\")


@dataclass(frozen=True)
class InvestigationRisk:
    """Risk classification with policy recommendation (preview only)."""

    category: RiskCategory
    risk_level: RiskLevel
    confidence: float
    evidence: tuple[str, ...]
    limitations: tuple[str, ...]
    recommended_policy_action: PolicyAction
    recommended_next_step: str
    posture_label: str

    def to_jsonable(self) -> dict[str, Any]:
        """To jsonable.

        Args:
            None.

        Returns:
            The dict[str, Any] result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return {
            "category": self.category,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
            "limitations": list(self.limitations),
            "recommended_policy_action": self.recommended_policy_action,
            "recommended_next_step": self.recommended_next_step,
            "posture_label": self.posture_label,
        }


def _norm_name(name: str | None) -> str:
    return (name or "").strip().lower()


def _path_user_writable(path: str | None) -> bool:
    if not path or not path.strip():
        return False
    norm = path.strip().strip('"').lower().replace("/", "\\")
    return any(marker in norm for marker in _USER_WRITABLE_MARKERS)


def _cmdline_has_proxy_terms(cmdline: str | None) -> bool:
    if not cmdline:
        return False
    low = cmdline.lower()
    return any(term in low for term in _PROXY_CMDLINE_TERMS)


def classify_investigation_risk(
    *,
    proxy_enable: int | None,
    parsed: dict[str, Any],
    port_owner: dict[str, Any] | None,
    before_snapshot: dict[str, Any] | None,
    registry_writer_proof: bool = False,
    allowlist_match: bool = False,
    attribution_level: str | None = None,
) -> InvestigationRisk:
    """Classify localhost proxy posture using observable signals only."""

    limitations = (
        "Sensitive localhost proxy posture does not imply compromise or malware.",
        "Listener correlation is not registry writer proof.",
    )
    enabled = proxy_enable == 1
    is_localhost = bool(parsed.get("is_localhost_proxy"))
    is_external = enabled and not is_localhost and bool(parsed.get("proxy_server"))
    port = parsed.get("localhost_port")

    if not enabled:
        return InvestigationRisk(
            category="NO_PROXY",
            risk_level="LOW",
            confidence=0.95,
            evidence=("WinINET ProxyEnable is off.",),
            limitations=limitations,
            recommended_policy_action="OBSERVE_ONLY",
            recommended_next_step="No WinINET remediation required; monitor with proxy-watch if drift recurs.",
            posture_label="normal",
        )

    if enabled and not is_localhost and not parsed.get("proxy_server"):
        return InvestigationRisk(
            category="NO_PROXY",
            risk_level="LOW",
            confidence=0.7,
            evidence=("ProxyEnable is on but ProxyServer is empty or non-localhost.",),
            limitations=limitations,
            recommended_policy_action="OBSERVE_ONLY",
            recommended_next_step="Review proxy-status and PAC/AutoConfigURL before remediation.",
            posture_label="normal",
        )

    if is_external:
        return InvestigationRisk(
            category="EXTERNAL_PROXY",
            risk_level="CRITICAL",
            confidence=0.8,
            evidence=(
                f"ProxyServer points to non-localhost destination: {parsed.get('proxy_server')!r}.",
            ),
            limitations=limitations,
            recommended_policy_action="EXPORT_EVIDENCE",
            recommended_next_step="Export Sysmon/Procmon proof and review external proxy destination before changes.",
            posture_label="external proxy destination",
        )

    evidence: list[str] = []
    if enabled:
        evidence.append("WinINET proxy is enabled.")
    if is_localhost and port:
        evidence.append(
            f"ProxyServer points to localhost port {port} (sensitive localhost proxy posture)."
        )

    sticky = False
    if before_snapshot is not None:
        prev_enable = before_snapshot.get("proxy_enable")
        prev_server = before_snapshot.get("proxy_server")
        if prev_enable == 0 and enabled:
            sticky = True
            evidence.append(
                "ProxyEnable flipped from disabled to enabled since last known-good snapshot."
            )
        if prev_server and parsed.get("proxy_server") and prev_server != parsed.get("proxy_server"):
            evidence.append("ProxyServer changed since last known-good snapshot.")

    owner = port_owner or {}
    proc_name = _norm_name(owner.get("process_name"))
    parent_name = _norm_name(owner.get("parent_name"))
    exe_path = owner.get("executable_path")
    cmdline = owner.get("command_line")
    path_missing = not bool(exe_path)
    path_writable = _path_user_writable(str(exe_path) if exe_path else None)
    listener_match = bool(owner.get("listener_on_proxy_port"))

    if path_missing:
        evidence.append("Executable path for port owner is unresolved_path.")
    if path_writable:
        evidence.append("Executable path appears user-writable.")
    if _cmdline_has_proxy_terms(str(cmdline) if cmdline else None):
        evidence.append("Command line mentions proxy/tunnel/dev-server related terms.")
    if parent_name in _DEV_PARENT_NAMES:
        evidence.append(f"Parent process is {parent_name}.")

    category: RiskCategory = "SENSITIVE_LOCALHOST_PROXY"
    risk_level: RiskLevel = "MEDIUM"
    confidence = 0.55
    policy: PolicyAction = "DISABLE_WININET_PROXY"
    next_step = (
        "Preview proxy-disable after review. Use proxy-stop-listener / proxy-stop-reverter only "
        "with typed Admin confirmation."
    )
    posture = "sensitive localhost proxy posture"

    if allowlist_match:
        category = "TRUSTED_ALLOWLIST_MATCH"
        risk_level = "LOW"
        confidence = 0.7
        policy = "OBSERVE_ONLY"
        evidence.append("Process matched config/proxy_allowlist.yaml (event still logged).")
        next_step = (
            "Monitor with proxy-watch; export Sysmon/Procmon if registry writer proof is required."
        )
        posture = "trusted-tool localhost proxy posture"

    elif proc_name in _SECURITY_TOOL_NAMES:
        category = "KNOWN_DEV_PROXY"
        risk_level = "MEDIUM"
        confidence = 0.6
        policy = "OBSERVE_ONLY"
        next_step = "Confirm intentional security tooling before disabling proxy."

    elif proc_name in _DEV_PROCESS_NAMES or parent_name in {
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
    }:
        category = "SENSITIVE_LOCALHOST_PROXY"
        risk_level = "MEDIUM" if listener_match else "MEDIUM"
        confidence = 0.65 if listener_match else 0.5

    elif proc_name in {"cursor.exe", "code.exe"}:
        category = "SENSITIVE_LOCALHOST_PROXY"
        risk_level = "MEDIUM"
        confidence = 0.45
        evidence.append("IDE-adjacent process correlated — not registry writer proof.")

    elif path_missing or path_writable:
        category = "UNKNOWN_LOCAL_PROXY"
        risk_level = "HIGH"
        confidence = 0.6
        posture = "sensitive localhost proxy posture (unknown owner path)"

    elif enabled and is_localhost and listener_match:
        category = "UNKNOWN_LOCAL_PROXY"
        risk_level = "HIGH"
        confidence = 0.6

    if sticky:
        category = "REMEDIATION_NOT_STICKY"
        risk_level = "HIGH"
        confidence = max(confidence, 0.7)
        policy = "TERMINATE_PROXY_REVERTER"
        next_step = (
            "Proxy re-enabled after prior disable. Stop attributed reverter parent "
            "(STOP_PROXY_REVERTER) then listener (STOP_PROXY_LISTENER), then proxy-disable with soak."
        )
        posture = "sensitive localhost proxy posture (sticky re-enable)"

    if registry_writer_proof or attribution_level == "PROVEN_REGISTRY_WRITER":
        category = "POSSIBLE_MITM_RISK"
        risk_level = "CRITICAL"
        confidence = 0.85
        evidence.append(
            "Event-level registry write proof present (review source and authorization)."
        )
        posture = "proven registry writer on proxy keys"

    return InvestigationRisk(
        category=category,
        risk_level=risk_level,
        confidence=round(min(max(confidence, 0.0), 1.0), 2),
        evidence=tuple(evidence),
        limitations=limitations,
        recommended_policy_action=policy,
        recommended_next_step=next_step,
        posture_label=posture,
    )
