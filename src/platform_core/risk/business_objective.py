"""Business objective models for technology risk decisions."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class BusinessObjective(BaseModel):
    """Represent the business objective type.

    Key fields:
        objective_id: Structured value carried by this type.
        name: Structured value carried by this type.
        description: Structured value carried by this type.
        owner: Structured value carried by this type.
        priority: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    objective_id: str
    name: str
    description: str
    owner: str = "IT Operations"
    priority: str = "high"


def objective_for_fixture(fixture: dict[str, Any]) -> BusinessObjective:
    """Return objective for fixture.

    Args:
        fixture: fixture supplied by the caller.

    Returns:
        The computed `BusinessObjective` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    override = fixture.get("business_objective")
    if override:
        return BusinessObjective.model_validate(override)
    return BusinessObjective(
        objective_id="OBJ_BROWSER_ACCESS",
        name="Maintain reliable and secure browser/network access",
        description=(
            "Ensure corporate endpoints can reach business web applications "
            "without misconfigured proxy state or unaudited configuration drift."
        ),
        owner="IT Operations / Endpoint Engineering",
        priority="high",
    )
