"""Stable identifiers and vocabulary for proxy attribute reasoning.

Module responsibility:
    Export scenario ids, schema version, policy/evidence literals, and limitation strings
    shared across classification, scenarios, policy, and audit serializers.
"""

from __future__ import annotations

from typing import Literal

# Canonical failure scenarios (proxy-specific)
CASE_WININET_PROXY_DRIFT = "CASE_WININET_PROXY_DRIFT"
CASE_LOCALHOST_PROXY_LISTENER = "CASE_LOCALHOST_PROXY_LISTENER"
CASE_BROWSER_PROXY_PATH_ISSUE = "CASE_BROWSER_PROXY_PATH_ISSUE"
CASE_ELECTRON_APP_PROXY_FIREWALL_INTERACTION = "CASE_ELECTRON_APP_PROXY_FIREWALL_INTERACTION"

PROXY_CASE_IDS = (
    CASE_WININET_PROXY_DRIFT,
    CASE_LOCALHOST_PROXY_LISTENER,
    CASE_BROWSER_PROXY_PATH_ISSUE,
    CASE_ELECTRON_APP_PROXY_FIREWALL_INTERACTION,
)

ProxyClassification = Literal[
    "NO_PROXY",
    "KNOWN_DEV_PROXY",
    "KNOWN_SECURITY_TOOL",
    "UNKNOWN_LOCAL_PROXY",
    "SUSPICIOUS_PROXY",
    "POSSIBLE_MITM_RISK",
]

RiskLevel = Literal["low", "medium", "high"]
ConfidenceRank = Literal["low", "medium", "high"]
VerificationStatus = Literal["UNVERIFIED", "INCONCLUSIVE", "CONFIRMED", "REJECTED"]
PolicyOutcome = Literal["ALLOW", "PREVIEW", "BLOCK"]
EvidenceLevel = Literal["observed", "inferred", "validated", "proof", "rejected"]
ConclusionStrength = Literal["weak", "moderate", "strong"]

ATTRIBUTION_LIMITATION = (
    "Process attribution is listener correlation only; it does not prove registry "
    "writer identity or malicious intent."
)

MALWARE_CLAIM_FORBIDDEN = (
    "Do not label processes or proxies as malware without explicit proof-tier evidence."
)

SCHEMA_VERSION = "proxy_reasoning.v1"
ENGINE_VERSION = "2026.05"
DEFAULT_AUDIT_FILE = "logs/proxy_reasoning_audit.jsonl"
