#!/usr/bin/env python3
"""Regenerate docs/checks.md from the registry, so the table cannot drift."""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from headscale_audit.checks import CATEGORIES, all_checks  # noqa: E402
from headscale_audit.report import HEADSCALE_BASELINE  # noqa: E402

HEADER = f"""# Controls

Every control asserts one condition against Headscale {HEADSCALE_BASELINE}. A
control that cannot read what it needs is reported as NOT_EVALUATED, never as a
pass; one that does not apply to the deployment is NOT_APPLICABLE; one that
cannot conclude on its own is UNKNOWN, with the question it wants answered.

Regenerate this file with `python scripts/gen_checks_doc.py`.
"""


def render() -> str:
    out = [HEADER]
    for category, label in CATEGORIES.items():
        checks = [check for check in all_checks() if check.category == category]
        if not checks:
            continue
        out.append(f"## {label}\n")
        out.append("| Id | Control | Asserts | Reference |")
        out.append("| --- | --- | --- | --- |")
        for check in checks:
            out.append(
                f"| `{check.id}` | {check.title} | {check.expected} | "
                f"[doc]({check.doc}) |"
            )
        out.append("")
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    target = pathlib.Path(__file__).resolve().parent.parent / "docs" / "checks.md"
    target.write_text(render(), encoding="utf-8")
    print(f"wrote {target}")
