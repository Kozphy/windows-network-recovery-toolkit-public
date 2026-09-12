"""Shared governance report sections — AI transparency and non-claims."""

from __future__ import annotations

AI_TRANSPARENCY_SECTION = {
    "title": "AI usage transparency",
    "ai_assists_with": [
        "Explanation and narrative summarization",
        "Report drafting and interview-ready case study structure",
        "Risk hypothesis framing with explicit limitations",
    ],
    "ai_does_not_authorize": [
        "Registry changes or proxy remediation apply",
        "Process termination",
        "Firewall reset",
        "Network adapter disable",
        "Malware verdicts or compromise confirmation",
        "MITM confirmation or control effectiveness attestation",
    ],
    "human_review_required": (
        "Final decisions require evidence, policy gates, typed confirmation where applicable, "
        "and human review for high-impact or accusatory-adjacent classifications."
    ),
}

NON_CLAIMS = [
    "This platform does not provide antivirus, EDR, XDR, or intrusion detection.",
    "Classification labels are triage hypotheses — not accusations.",
    "Proof tiers describe evidence strength — not certainty of malicious intent.",
    "Policy permission to preview remediation is not an operational safety guarantee.",
    "Recommendations are not execution authority without explicit human approval.",
]

GOVERNANCE_PRINCIPLES = [
    "Observation is not proof.",
    "Correlation is not causation.",
    "Confidence is not certainty.",
    "Classification is not accusation.",
    "Policy permission is not a safety guarantee.",
    "Stakeholder assignment is not approval.",
    "A valid maintenance window is not execution authorization.",
    "Recommendation is not execution authority.",
]
