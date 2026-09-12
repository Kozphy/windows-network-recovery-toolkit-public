"""Business-facing impact language for technology risk forums."""

from __future__ import annotations

from pydantic import BaseModel, Field

_DEFAULT_LIMITATIONS = [
    "Forum mapping supports triage narratives — not regulatory attestation.",
    "Classification is not accusation.",
]


class BusinessImpactMapping(BaseModel):
    """Represent the business impact mapping type.

    Key fields:
        classification: Structured value carried by this type.
        user_impact: Structured value carried by this type.
        operational_risk: Structured value carried by this type.
        security_risk: Structured value carried by this type.
        audit_risk: Structured value carried by this type.
        suggested_forum: Structured value carried by this type.
        limitations: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    classification: str
    user_impact: str = ""
    operational_risk: str = ""
    security_risk: str = ""
    audit_risk: str = ""
    suggested_forum: str = "Technology risk review"
    limitations: list[str] = Field(default_factory=lambda: list(_DEFAULT_LIMITATIONS))


_MAPPING: dict[str, dict[str, str]] = {
    "DEAD_PROXY_CONFIG": {
        "user_impact": "Browser and business app connectivity failure while basic network checks may succeed",
        "operational_risk": "Increased support handling time and repeated manual proxy resets",
        "security_risk": "Possible false escalation if treated as compromise without proof tier upgrade",
        "audit_risk": "Weak reconstruction if remediation occurs without decision logs",
        "suggested_forum": "IT support / Technology risk review",
    },
    "WININET_WINHTTP_MISMATCH": {
        "user_impact": "Applications using different proxy stacks may behave inconsistently",
        "operational_risk": "Difficult troubleshooting because ping/DNS may appear healthy",
        "security_risk": "May be misclassified as network or endpoint compromise",
        "audit_risk": "Inconsistent evidence trail if tools inspect only one proxy layer",
        "suggested_forum": "Endpoint reliability / Platform governance",
    },
    "LOCAL_PROXY_ACTIVE": {
        "user_impact": "Traffic routed through localhost proxy; may be intended dev tooling",
        "operational_risk": "Unexpected proxy behavior when dev tools exit without cleanup",
        "security_risk": "Unknown listener requires review — not automatic malware verdict",
        "audit_risk": "Listener correlation without writer proof weakens audit narrative",
        "suggested_forum": "Endpoint reliability / Developer platform review",
    },
    "LOCAL_PROXY_ENABLED": {
        "user_impact": "Browser traffic uses configured localhost proxy",
        "operational_risk": "Support burden when proxy owner is unclear",
        "security_risk": "Triage only — confirm intent before security escalation",
        "audit_risk": "Remediation without attribution leaves gaps in decision record",
        "suggested_forum": "IT support / Technology risk review",
    },
    "PAC_CONFIGURED": {
        "user_impact": "PAC-driven routing may affect only subset of applications",
        "operational_risk": "PAC misconfiguration causes intermittent failures",
        "security_risk": "PAC changes require change-management review, not malware assumption",
        "audit_risk": "PAC URL and fetch history may be missing from audit trail",
        "suggested_forum": "Platform governance / Change advisory",
    },
    "UNKNOWN_LOCAL_PROXY": {
        "user_impact": "Unattributed localhost proxy may disrupt business applications",
        "operational_risk": "Extended investigation cycles without writer attribution",
        "security_risk": "High false-positive risk if labeled compromise without proof",
        "audit_risk": "Human review required before remediation narrative is defensible",
        "suggested_forum": "Cyber risk triage / Technology risk review",
    },
    "REVERTER_SUSPECTED": {
        "user_impact": "Proxy settings may flip back after remediation attempts",
        "operational_risk": "Repeated manual fixes; remediation may not stick",
        "security_risk": "Active reverter requires attribution — not automatic malicious verdict",
        "audit_risk": "Without proxy-watch logs, flip-flop timeline may be incomplete",
        "suggested_forum": "Endpoint reliability / Security operations review",
    },
    "POSSIBLE_MITM_RISK": {
        "user_impact": "Potential TLS or certificate path inconsistency under proxy",
        "operational_risk": "Requires TLS proof workflow before escalation",
        "security_risk": "Triage label only — not confirmed MITM or compromise",
        "audit_risk": "Over-claiming MITM without tls-proof weakens governance credibility",
        "suggested_forum": "Cyber risk review",
    },
    "NO_PROXY": {
        "user_impact": "No proxy misconfiguration detected in scope",
        "operational_risk": "Low for proxy drift; investigate other failure domains",
        "security_risk": "Nominal proxy path — does not prove endpoint safety",
        "audit_risk": "Standard monitoring sufficient",
        "suggested_forum": "Routine operations",
    },
}


def map_business_impact(classification: str) -> BusinessImpactMapping:
    """Translate technical classification into business-facing impact language."""
    key = (classification or "").upper()
    data = _MAPPING.get(
        key,
        {
            "user_impact": "Endpoint reliability incident requires structured evidence review",
            "operational_risk": "Impact depends on classification proof tier and control posture",
            "security_risk": "Avoid compromise language without proof tier T3+ and independent validation",
            "audit_risk": "Ensure decision record and audit chain before remediation",
            "suggested_forum": "Technology risk review",
        },
    )
    return BusinessImpactMapping(
        classification=key or "UNCLASSIFIED",
        user_impact=data["user_impact"],
        operational_risk=data["operational_risk"],
        security_risk=data["security_risk"],
        audit_risk=data["audit_risk"],
        suggested_forum=data["suggested_forum"],
    )
