"""Compatibility shims for serializing Pydantic models to plain dicts.

Module responsibility:
    Centralizes :func:`dump_model` so legacy call sites avoid scattering ``model_dump`` variants.

System placement:
    Thin helper above :mod:`platform_core.models`; routers may call Pydantic directly—this module is
    optional glue.

Side effects:
    None.

Engineering Notes:
    Prefer direct ``model_dump(mode="json")`` on hot paths when discriminating JSON-only types;
    this helper mirrors v1-era habits.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


def dump_model(model: BaseModel) -> dict[str, Any]:
    """Return :meth:`pydantic.BaseModel.model_dump` without mode overrides.

    Args:
        model: Any Pydantic v2 model instance.

    Returns:
        Python-native dict (not necessarily JSON-safe unless caller post-processes).

    Side effects:
        None.
    """
    return model.model_dump()
