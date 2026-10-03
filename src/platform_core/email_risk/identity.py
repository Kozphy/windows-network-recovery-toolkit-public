"""Identity and impersonation signals.

Signals:
    ``display_name_impersonation``, ``executive_impersonation``,
    ``finance_team_impersonation``, ``vendor_impersonation``,
    ``lookalike_domain``, ``domain_typosquatting``.

Key invariants:
    * A role title alone is not impersonation. Role claims fire only when the
      sender is *not* internal **and** the claim is implausible for that
      sender: consumer mailbox, lookalike domain, org-name claim, or a
      configured executive name arriving from outside the org.
    * A partner's CEO writing from the partner's own corporate domain does not
      trigger ``executive_impersonation``.
    * When organization context is missing and the sender is not free-mail,
      the relationship is ``unknown`` and role-based signals are not emitted;
      the engine records that as a limitation.

Side effects:
    None.
"""

from __future__ import annotations

import re

from .domains import (
    is_free_mail,
    lookalike_match,
    registrable_domain,
    same_or_subdomain,
    sender_relationship,
)
from .lexicon import (
    EXEC_LOCAL_TOKENS,
    EXEC_ROLE,
    FINANCE_LOCAL_TOKENS,
    FINANCE_ROLE,
    SELF_CLAIM,
)
from .models import EmailAddress, EmailRiskConfig, EmailRiskEvidence, EvidenceSource, ParsedEmail
from .normalization import EmailText, clip, first_match, normalize_text
from .privacy import mask_address
from .scoring import build_evidence

_EMBEDDED_ADDRESS = re.compile(r"[\w.+\-]+@([\w\-]+(?:\.[\w\-]+)+)")


def _local_tokens(address: EmailAddress) -> set[str]:
    return {t for t in re.split(r"[._+\-\d]+", address.local_part) if t}


def _contains_name(haystack: str, name: str) -> bool:
    tokens = [t for t in normalize_text(name).lower().split() if t]
    text = normalize_text(haystack).lower()
    return bool(tokens) and all(t in text for t in tokens)


def _claims_org(display: str, config: EmailRiskConfig) -> str:
    for name in config.organization_names:
        if name.strip() and _contains_name(display, name):
            return name
    return ""


def _display_name_embedded_address(
    sender: EmailAddress, config: EmailRiskConfig
) -> EmailRiskEvidence | None:
    match = _EMBEDDED_ADDRESS.search(sender.display_name)
    if not match:
        return None
    shown = match.group(1).lower()
    if registrable_domain(shown) == registrable_domain(sender.domain):
        return None
    return build_evidence(
        "display_name_impersonation",
        observed=f"display shows @{shown}, actual {registrable_domain(sender.domain)}",
        source=EvidenceSource.DISPLAY_NAME,
        detail="Display name contains an address on a different domain than the real sender.",
        config=config,
    )


def _display_name_brand_claim(
    sender: EmailAddress, config: EmailRiskConfig, relationship: str
) -> EmailRiskEvidence | None:
    if relationship == "internal":
        return None
    org = _claims_org(sender.display_name, config)
    if org:
        return build_evidence(
            "display_name_impersonation",
            observed=f"display claims '{clip(org, 40)}' via {registrable_domain(sender.domain)}",
            source=EvidenceSource.DISPLAY_NAME,
            detail="Display name claims the organization but the sender domain is external.",
            config=config,
        )
    return None


def role_claim_implausible(sender: EmailAddress, config: EmailRiskConfig) -> tuple[bool, str]:
    """Return (implausible, reason) for a role claim from a non-internal sender."""
    if is_free_mail(sender.domain, config):
        return True, f"consumer mailbox ({registrable_domain(sender.domain)})"
    look = lookalike_match(sender.domain, config)
    if look:
        return True, f"domain resembles {look[1]}"
    org = _claims_org(sender.display_name, config)
    if org:
        return True, f"claims '{org}' from an external domain"
    return False, ""


def _executive_signal(
    sender: EmailAddress, text: EmailText, config: EmailRiskConfig, relationship: str
) -> EmailRiskEvidence | None:
    if relationship == "internal":
        return None
    domain = registrable_domain(sender.domain)
    for name in config.executive_names:
        if (
            name.strip()
            and _contains_name(sender.display_name, name)
            and relationship == "external"
        ):
            return build_evidence(
                "executive_impersonation",
                observed=f"display name matches executive '{clip(name, 40)}' via {domain}",
                source=EvidenceSource.DISPLAY_NAME,
                detail="A configured executive name is used by a sender outside the organization.",
                config=config,
            )
    implausible, why = role_claim_implausible(sender, config)
    if not implausible:
        return None
    role = EXEC_ROLE.search(sender.display_name)
    if role:
        return build_evidence(
            "executive_impersonation",
            observed=f"display_name role '{role.group(0)}' via {domain}",
            source=EvidenceSource.DISPLAY_NAME,
            detail=f"Executive title in display name, but the sender is a {why}.",
            config=config,
        )
    token = sorted(_local_tokens(sender) & EXEC_LOCAL_TOKENS)
    if token:
        return build_evidence(
            "executive_impersonation",
            observed=f"mailbox token '{token[0]}' via {domain}",
            source=EvidenceSource.HEADER_FROM,
            detail=f"Executive title in the mailbox name, but the sender is a {why}.",
            config=config,
        )
    claim = first_match(SELF_CLAIM, text.active())
    if claim:
        segment, match = claim
        return build_evidence(
            "executive_impersonation",
            observed=clip(match.group(0)),
            source=segment.source,
            detail=f"Message claims an executive identity, but the sender is a {why}.",
            config=config,
        )
    return None


def _finance_signal(
    sender: EmailAddress, config: EmailRiskConfig, relationship: str
) -> EmailRiskEvidence | None:
    if relationship == "internal":
        return None
    implausible, why = role_claim_implausible(sender, config)
    if not implausible:
        return None
    role = FINANCE_ROLE.search(sender.display_name)
    token = sorted(_local_tokens(sender) & FINANCE_LOCAL_TOKENS)
    if not role and not token:
        return None
    observed = f"'{role.group(0)}'" if role else f"mailbox token '{token[0]}'"
    return build_evidence(
        "finance_team_impersonation",
        observed=f"{observed} via {registrable_domain(sender.domain)}",
        source=EvidenceSource.DISPLAY_NAME if role else EvidenceSource.HEADER_FROM,
        detail=f"Presents as a finance/accounting function, but the sender is a {why}.",
        config=config,
    )


def _vendor_signal(
    sender: EmailAddress, config: EmailRiskConfig, relationship: str
) -> EmailRiskEvidence | None:
    if relationship == "internal":
        return None
    for vendor in config.vendors:
        legit = any(same_or_subdomain(sender.domain, d) for d in vendor.domains)
        if legit:
            continue
        if vendor.name.strip() and _contains_name(sender.display_name, vendor.name):
            return build_evidence(
                "vendor_impersonation",
                observed=f"display claims '{clip(vendor.name, 40)}' via "
                f"{registrable_domain(sender.domain)}",
                source=EvidenceSource.DISPLAY_NAME,
                detail="Display name names a known vendor but the domain is not one of its domains.",
                config=config,
            )
        look = lookalike_match(sender.domain, config)
        if look and any(registrable_domain(d) == look[1] for d in vendor.domains):
            return build_evidence(
                "vendor_impersonation",
                observed=f"{registrable_domain(sender.domain)} resembles vendor {look[1]}",
                source=EvidenceSource.HEADER_FROM,
                detail=f"Sender domain imitates the domain of known vendor '{vendor.name}'.",
                config=config,
            )
    return None


def _domain_resemblance(email: ParsedEmail, config: EmailRiskConfig) -> EmailRiskEvidence | None:
    checks: list[tuple[str, EvidenceSource]] = []
    if email.from_address:
        checks.append((email.from_address.domain, EvidenceSource.HEADER_FROM))
    checks.extend((r.domain, EvidenceSource.HEADER_REPLY_TO) for r in email.reply_to)
    for domain, source in checks:
        match = lookalike_match(domain, config)
        if match:
            signal, protected, reason = match
            return build_evidence(
                signal,
                observed=f"{registrable_domain(domain)} ~ {protected}",
                source=source,
                detail=reason,
                config=config,
            )
    return None


def detect_identity_signals(
    email: ParsedEmail, text: EmailText, config: EmailRiskConfig
) -> list[EmailRiskEvidence]:
    """Return impersonation / lookalike evidence for ``email``."""
    out: list[EmailRiskEvidence] = []
    resemblance = _domain_resemblance(email, config)
    if resemblance:
        out.append(resemblance)
    sender = email.from_address
    if sender is None:
        return out
    relationship = sender_relationship(sender.domain, config)
    display = _display_name_embedded_address(sender, config) or _display_name_brand_claim(
        sender, config, relationship
    )
    for item in (
        display,
        _executive_signal(sender, text, config, relationship),
        _finance_signal(sender, config, relationship),
        _vendor_signal(sender, config, relationship),
    ):
        if item is not None:
            out.append(item)
    return out


def describe_sender(sender: EmailAddress | None, *, show_identifiers: bool) -> str:
    """Render a sender for summaries (local part masked by default)."""
    if sender is None:
        return ""
    address = sender.address if show_identifiers else mask_address(sender.address)
    name = sender.display_name.replace('"', "")
    return f'"{clip(name, 60)}" <{address}>' if name else f"<{address}>"
