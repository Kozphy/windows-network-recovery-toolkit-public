"""Conservative trust/risk classification for proxy entities.

Module responsibility:
    Derive ``TrustRiskAttributes`` from entity fields without malware overclaims.

Audit Notes:
    * Localhost listeners map to dev-proxy candidates, not confirmed threats.
"""

from __future__ import annotations

from proxy_reasoning.constants import ATTRIBUTION_LIMITATION, MALWARE_CLAIM_FORBIDDEN
from proxy_reasoning.models import ProcessAttributionAttributes, ProxyEntity, TrustRiskAttributes

KNOWN_DEV_NAMES = frozenset(
    {"node.exe", "python.exe", "mitmproxy.exe", "fiddler.exe", "charles.exe", "proxyman.exe"},
)
KNOWN_SECURITY_NAMES = frozenset(
    {
        "zscaler.exe",
        "zsatunnel.exe",
        "netskope.exe",
        "crowdstrike.exe",
        "csfalconservice.exe",
    },
)
DEV_PATH_HINTS = ("\\program files\\nodejs\\", "\\mitmproxy", "\\fiddler", "\\charles")
SECURITY_PATH_HINTS = ("\\zscaler\\", "\\netskope\\", "\\crowdstrike\\")


def _path_contains(path: str | None, hints: tuple[str, ...]) -> bool:
    lower = (path or "").lower()
    return bool(lower and any(h in lower for h in hints))


def classify_trust_risk(
    entity: ProxyEntity,
    *,
    suspicious_cert_observed: bool = False,
    unexpected_persistence: bool = False,
) -> TrustRiskAttributes:
    """Assign bounded classification without overclaiming MITM or malware."""
    cfg = entity.configuration_attributes
    net = entity.network_attributes
    proc = entity.process_attribution_attributes
    limitations = [ATTRIBUTION_LIMITATION, MALWARE_CLAIM_FORBIDDEN]

    if not cfg.proxy_enable:
        return TrustRiskAttributes(
            classification="NO_PROXY",
            risk_level="low",
            rationale=["ProxyEnable is off or proxy is not actively configured."],
            limitations=limitations,
        )

    name = (proc.process_name or "").lower()
    path = proc.executable_path

    if name in KNOWN_DEV_NAMES or _path_contains(path, DEV_PATH_HINTS):
        return TrustRiskAttributes(
            classification="KNOWN_DEV_PROXY",
            risk_level="low",
            rationale=[
                f"Listener or attribution points to common developer tooling ({name or 'unknown'}).",
                "Localhost proxy alone is not treated as compromise.",
            ],
            limitations=limitations,
        )

    if name in KNOWN_SECURITY_NAMES or _path_contains(path, SECURITY_PATH_HINTS):
        return TrustRiskAttributes(
            classification="KNOWN_SECURITY_TOOL",
            risk_level="low",
            rationale=["Process metadata resembles enterprise security or VPN proxy tooling."],
            limitations=limitations,
        )

    if net.is_loopback and not suspicious_cert_observed:
        return TrustRiskAttributes(
            classification="UNKNOWN_LOCAL_PROXY",
            risk_level="medium",
            rationale=[
                "Loopback proxy endpoint observed.",
                "No TLS/certificate proof tier present — not classified as MITM.",
            ],
            limitations=limitations
            + ["node.exe or unknown local listeners are not labeled malicious."],
        )

    if suspicious_cert_observed and unexpected_persistence:
        return TrustRiskAttributes(
            classification="POSSIBLE_MITM_RISK",
            risk_level="high",
            rationale=[
                "Suspicious certificate signals and persistence indicators require analyst validation.",
            ],
            limitations=limitations
            + ["Classification is provisional until certificate and writer proof are validated."],
        )

    if suspicious_cert_observed:
        return TrustRiskAttributes(
            classification="SUSPICIOUS_PROXY",
            risk_level="high",
            rationale=["Certificate or trust-store anomalies observed — validate before action."],
            limitations=limitations,
        )

    if unexpected_persistence:
        return TrustRiskAttributes(
            classification="SUSPICIOUS_PROXY",
            risk_level="medium",
            rationale=["Unexpected persistence surfaces reference proxy-related paths."],
            limitations=limitations,
        )

    return TrustRiskAttributes(
        classification="UNKNOWN_LOCAL_PROXY" if net.is_loopback else "SUSPICIOUS_PROXY",
        risk_level="medium",
        rationale=["Proxy enabled without strong trust context."],
        limitations=limitations,
    )


def apply_attribution_limitations(
    proc: ProcessAttributionAttributes,
) -> ProcessAttributionAttributes:
    """Ensure process attribution carries mandatory limitations."""
    lims = list(proc.attribution_limitations)
    if ATTRIBUTION_LIMITATION not in lims:
        lims.append(ATTRIBUTION_LIMITATION)
    return proc.model_copy(update={"attribution_limitations": lims})
