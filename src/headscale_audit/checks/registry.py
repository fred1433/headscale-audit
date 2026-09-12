"""Check registry: every control declares what it reads before it runs."""

from __future__ import annotations

from typing import Callable, Iterable

from ..model import Check, Finding, Inventory

CHECKS: list[Check] = []

CATEGORIES = {
    "server": "Server configuration",
    "policy": "Access control policy",
    "nodes": "Nodes, routes and users",
    "keys": "Pre-auth keys and API keys",
    "fleet": "Fleet coverage",
}

DOC = "https://headscale.net/0.29.3"
REPO = "https://github.com/juanfont/headscale/blob/v0.29.3"
TS_KB = "https://tailscale.com/kb"


def register(
    check_id: str,
    title: str,
    category: str,
    doc: str,
    needs: tuple[str, ...],
    expected: str,
) -> Callable[[Callable[[Inventory], Iterable[Finding]]], Callable]:
    """Declare a control.

    ``needs`` gates it: a missing section means the control is not evaluated.
    ``expected`` is the condition it asserts, printed next to its status so a
    PASS says something.
    """

    def decorator(func: Callable[[Inventory], Iterable[Finding]]):
        if any(existing.id == check_id for existing in CHECKS):
            raise RuntimeError(f"duplicate check id {check_id}")
        if category not in CATEGORIES:
            raise RuntimeError(f"unknown category {category}")
        CHECKS.append(
            Check(
                id=check_id,
                title=title,
                category=category,
                doc=doc,
                needs=needs,
                expected=expected,
                func=func,
            )
        )
        return func

    return decorator
