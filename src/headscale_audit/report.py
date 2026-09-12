"""Render an audit as Markdown or JSON."""

from __future__ import annotations

import json
from typing import Any, Sequence

from . import __version__
from .checks.registry import CATEGORIES
from .model import (
    SEVERITY_LABEL,
    SEVERITY_ORDER,
    STATUS_LABEL,
    STATUS_ORDER,
    CheckResult,
    Inventory,
    iter_findings,
    severity_counts,
    status_counts,
)

HEADSCALE_BASELINE = "0.29.3"

SCOPE_NOTE = (
    "Scope: this audit reads what it was given. It does not scan the network, "
    "does not connect to nodes, and never writes to the server. Headscale also "
    "reads HEADSCALE_* environment variables, which override the file and are "
    "invisible from here."
)


def _sorted_findings(results: Sequence[CheckResult]):
    order = {severity: index for index, severity in enumerate(SEVERITY_ORDER)}
    return sorted(
        iter_findings(results),
        key=lambda finding: (order[finding.severity], finding.check_id),
    )


def _expected_of(results: Sequence[CheckResult]) -> dict[str, str]:
    return {result.check.id: result.check.expected for result in results}


def summary(results: Sequence[CheckResult], inventory: Inventory) -> dict[str, Any]:
    findings = list(iter_findings(results))
    return {
        "tool": {"name": "headscale-audit", "version": __version__},
        "generated_at": inventory.now.replace(microsecond=0).isoformat(),
        "headscale_baseline": HEADSCALE_BASELINE,
        "server_version": inventory.server_version,
        "source": inventory.source,
        "inputs": {
            "config": inventory.config_path or None,
            "policy": inventory.policy_source or None,
            "policy_mode": inventory.policy_mode,
            "nodes": len(inventory.nodes) if inventory.nodes is not None else None,
            "users": len(inventory.users) if inventory.users is not None else None,
            "preauthkeys": (
                len(inventory.preauthkeys)
                if inventory.preauthkeys is not None
                else None
            ),
            "apikeys": (
                len(inventory.apikeys) if inventory.apikeys is not None else None
            ),
        },
        "status": {STATUS_LABEL[k]: v for k, v in status_counts(results).items()},
        "findings": {**severity_counts(findings), "total": len(findings)},
    }


def to_json(results: Sequence[CheckResult], inventory: Inventory) -> str:
    payload = {
        **summary(results, inventory),
        "scope": SCOPE_NOTE,
        "notes": inventory.notes,
        "collection_errors": inventory.collection_errors,
        "checks": [result.as_dict() for result in results],
    }
    return json.dumps(payload, indent=2, sort_keys=False) + "\n"


def _inputs_line(inputs: dict[str, Any]) -> str:
    parts = []
    if inputs["config"]:
        parts.append(f"config `{inputs['config']}`")
    if inputs["policy"]:
        parts.append(f"policy `{inputs['policy']}`")
    for section in ("nodes", "users", "preauthkeys", "apikeys"):
        if inputs[section] is not None:
            label = {"preauthkeys": "pre-auth keys", "apikeys": "API keys"}.get(
                section, section
            )
            parts.append(f"{inputs[section]} {label}")
    return ", ".join(parts) if parts else "nothing"


def to_markdown(results: Sequence[CheckResult], inventory: Inventory) -> str:
    meta = summary(results, inventory)
    counts = meta["findings"]
    statuses = meta["status"]
    lines: list[str] = []
    add = lines.append

    add("# Headscale audit report")
    add("")
    add(f"- Generated: {meta['generated_at']}")
    add(f"- Source: {inventory.source}")
    add(f"- Read: {_inputs_line(meta['inputs'])}")
    add(
        f"- Tool: headscale-audit {__version__}; controls written against "
        f"Headscale {HEADSCALE_BASELINE}"
        + (
            f"; server reports {inventory.server_version}"
            if inventory.server_version
            else ""
        )
    )
    if inventory.policy_mode:
        add(
            f"- Policy mode: {inventory.policy_mode}"
            + (
                " (the file on disk, which is what a reload would load, not "
                "proof of what the running server holds in memory)"
                if inventory.policy_mode == "file"
                else ""
            )
        )
    add("")
    add(SCOPE_NOTE)
    add("")

    add("## Result")
    add("")
    add("| Status | Controls |")
    add("| --- | --- |")
    for status in STATUS_ORDER:
        add(f"| {STATUS_LABEL[status]} | {statuses[STATUS_LABEL[status]]} |")
    add("")
    add(
        f"{counts['total']} finding(s): {counts['high']} high, "
        f"{counts['medium']} medium, {counts['low']} low, "
        f"{counts['review']} to verify. A control that is NOT_EVALUATED is not "
        "a pass: it had nothing to read."
    )
    add("")
    for note in inventory.notes:
        add(f"> Note: {note}")
    for error in inventory.collection_errors:
        add(f"> Collection error: {error.splitlines()[0]}")
    if inventory.notes or inventory.collection_errors:
        add("")

    findings = _sorted_findings(results)
    expected = _expected_of(results)
    if findings:
        add("## Findings")
        add("")
        add("| Severity | Id | Finding |")
        add("| --- | --- | --- |")
        for finding in findings:
            title = finding.title
            if finding.subject:
                title = f"{title} ({finding.subject})"
            add(
                f"| {SEVERITY_LABEL[finding.severity]} | {finding.check_id} | "
                f"{title} |"
            )
        add("")
        for finding in findings:
            add(
                f"### {finding.check_id} [{SEVERITY_LABEL[finding.severity]}] "
                f"{finding.title}"
            )
            add("")
            add(f"- **Expected**: {expected.get(finding.check_id, '')}")
            add(f"- **Read**: {finding.evidence}")
            add(f"- **Why it matters**: {finding.why}")
            add(f"- **Fix**: {finding.fix}")
            add(f"- **Reference**: {finding.doc}")
            add("")
    else:
        add("## Findings")
        add("")
        add("None.")
        add("")

    for status, heading, blurb in (
        (
            "not_evaluated",
            "Not evaluated",
            "These controls had nothing to read. They are not passes.",
        ),
        (
            "not_applicable",
            "Not applicable",
            "These controls do not apply to this deployment.",
        ),
        ("error", "Errors", "These controls failed to run."),
    ):
        rows = [result for result in results if result.status == status]
        if not rows:
            continue
        add(f"## {heading}")
        add("")
        add(blurb)
        add("")
        add("| Id | Control | Reason |")
        add("| --- | --- | --- |")
        for result in rows:
            add(f"| {result.check.id} | {result.check.title} | {result.reason} |")
        add("")

    passed = [result for result in results if result.status == "pass"]
    if passed:
        add("## Passed")
        add("")
        by_category: dict[str, list[str]] = {}
        for result in passed:
            by_category.setdefault(result.check.category, []).append(result.check.id)
        for category, ids in by_category.items():
            add(f"- {CATEGORIES.get(category, category)}: {', '.join(sorted(ids))}")
        add("")
        add("<details><summary>What each passing control asserts</summary>")
        add("")
        add("| Id | Asserted |")
        add("| --- | --- |")
        for result in passed:
            add(f"| {result.check.id} | {result.check.expected} |")
        add("")
        add("</details>")
        add("")

    add("---")
    add("")
    add(
        "Read-only output: headscale-audit issues HTTP GET only, runs no "
        "command against the server, and prints no key material."
    )
    add("")
    return "\n".join(lines)


def exit_code(results: Sequence[CheckResult], fail_on: str) -> int:
    if fail_on == "never":
        return 0
    counts = severity_counts(iter_findings(results))
    thresholds = {
        "high": ("high",),
        "medium": ("high", "medium"),
        "low": ("high", "medium", "low"),
        "any": SEVERITY_ORDER,
    }
    for severity in thresholds.get(fail_on, ()):
        if counts[severity]:
            return 1
    return 0
