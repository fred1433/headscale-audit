"""All controls, registered in import order."""

from __future__ import annotations

from ..model import Check
from . import fleet, keys, nodes, policy, server  # noqa: F401  (registers them)
from .registry import CATEGORIES, CHECKS


def all_checks() -> list[Check]:
    """Every control, in stable id order."""
    return sorted(CHECKS, key=lambda check: check.id)


__all__ = ["all_checks", "CATEGORIES", "CHECKS"]
