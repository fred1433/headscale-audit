"""Run the controls against an inventory.

A control ends as PASS, FAIL, UNKNOWN, NOT_APPLICABLE, NOT_EVALUATED or ERROR.
The distinction is the point: a report with no FAIL and twenty NOT_EVALUATED is
not a clean audit, and the summary says so.
"""

from __future__ import annotations

import traceback
from typing import Sequence

from .checks import all_checks
from .model import Check, CheckResult, Inventory, NotApplicable, SkipCheck

SECTION_LABEL = {
    "config": "no config.yaml provided",
    "policy": "no policy loaded",
    "policy_raw": "no policy document read",
    "nodes": "no node inventory provided",
    "users": "no user list provided",
    "preauthkeys": "no pre-auth key list provided",
    "apikeys": "no API key list provided",
    "gce_instances": "no GCE instance inventory provided",
}


def run(
    inventory: Inventory, checks: Sequence[Check] | None = None
) -> list[CheckResult]:
    results: list[CheckResult] = []
    for check in checks if checks is not None else all_checks():
        missing = [section for section in check.needs if not inventory.has(section)]
        if missing:
            results.append(
                CheckResult(
                    check=check,
                    status="not_evaluated",
                    reason=", ".join(
                        SECTION_LABEL.get(section, f"no {section}")
                        for section in missing
                    ),
                )
            )
            continue
        try:
            findings = list(check.func(inventory))
        except SkipCheck as skip:
            results.append(
                CheckResult(check=check, status="not_evaluated", reason=str(skip))
            )
            continue
        except NotApplicable as reason:
            results.append(
                CheckResult(check=check, status="not_applicable", reason=str(reason))
            )
            continue
        except Exception as exc:  # pragma: no cover - defensive
            results.append(
                CheckResult(
                    check=check,
                    status="error",
                    reason=f"{type(exc).__name__}: {exc}",
                )
            )
            inventory.collection_errors.append(
                f"{check.id} raised {type(exc).__name__}: {exc}\n"
                + "".join(traceback.format_exception_only(type(exc), exc))
            )
            continue
        if not findings:
            results.append(CheckResult(check=check, status="pass"))
        elif all(finding.severity == "review" for finding in findings):
            results.append(
                CheckResult(
                    check=check,
                    status="unknown",
                    findings=findings,
                    reason="needs a human answer, see the finding",
                )
            )
        else:
            results.append(CheckResult(check=check, status="fail", findings=findings))
    return results
