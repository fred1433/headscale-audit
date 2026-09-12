"""Core data model: findings, checks and the inventory a check reads from."""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Iterator, Sequence

SEVERITY_ORDER = ("high", "medium", "low", "review")

SEVERITY_LABEL = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "review": "to verify",
}

# A control ends in exactly one of these states. "unknown" and "not_applicable"
# exist so that a quiet report cannot be mistaken for a clean one.
STATUS_ORDER = ("fail", "unknown", "pass", "not_applicable", "not_evaluated", "error")

STATUS_LABEL = {
    "fail": "FAIL",
    "unknown": "UNKNOWN",
    "pass": "PASS",
    "not_applicable": "NOT_APPLICABLE",
    "not_evaluated": "NOT_EVALUATED",
    "error": "ERROR",
}


class SkipCheck(Exception):
    """The control could not read what it needs; it is *not evaluated*."""


class NotApplicable(Exception):
    """The control does not apply to this deployment, with the reason why."""


@dataclass(frozen=True)
class Finding:
    """One problem found by one check.

    ``evidence`` must contain the value that was actually read, never a
    paraphrase: an auditor has to be able to grep for it in the source data.
    A finding of severity ``review`` is an open question, not a verdict.
    """

    check_id: str
    title: str
    severity: str
    evidence: str
    why: str
    fix: str
    doc: str
    subject: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_ORDER:
            raise ValueError(f"unknown severity {self.severity!r}")

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.check_id,
            "title": self.title,
            "severity": self.severity,
            "subject": self.subject,
            "observed": self.evidence,
            "why": self.why,
            "fix": self.fix,
            "doc": self.doc,
        }


@dataclass(frozen=True)
class Check:
    """A single audit control.

    ``expected`` states the condition the control asserts, so that a reader can
    tell what a PASS actually means. ``needs`` lists the inventory sections the
    control reads: when one is absent the control is reported as *not
    evaluated* rather than as passed.
    """

    id: str
    title: str
    category: str
    doc: str
    needs: tuple[str, ...]
    expected: str
    func: Callable[[Inventory], Iterable[Finding]]


@dataclass
class CheckResult:
    check: Check
    status: str
    findings: list[Finding] = field(default_factory=list)
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.check.id,
            "title": self.check.title,
            "area": self.check.category,
            "status": STATUS_LABEL[self.status],
            "expected": self.check.expected,
            "reason": self.reason,
            "doc": self.check.doc,
            "findings": [finding.as_dict() for finding in self.findings],
        }


@dataclass
class Inventory:
    """Everything the audit was able to read, and where it came from."""

    source: str = "unknown"
    config: dict[str, Any] | None = None
    config_path: str | None = None
    policy: dict[str, Any] | None = None
    policy_raw: str | None = None
    policy_source: str | None = None
    policy_mode: str | None = None
    policy_error: str | None = None
    nodes: list[dict[str, Any]] | None = None
    users: list[dict[str, Any]] | None = None
    preauthkeys: list[dict[str, Any]] | None = None
    apikeys: list[dict[str, Any]] | None = None
    server_version: str | None = None
    gce_instances: list[dict[str, Any]] | None = None
    now: _dt.datetime = field(
        default_factory=lambda: _dt.datetime.now(tz=_dt.timezone.utc)
    )
    notes: list[str] = field(default_factory=list)
    collection_errors: list[str] = field(default_factory=list)
    headscale_binary: str | None = None
    # Options a control may read.
    stale_node_days: int = 90
    max_key_lifetime_days: int = 30
    max_api_key_lifetime_days: int = 90

    def has(self, section: str) -> bool:
        return getattr(self, section, None) is not None

    # -- config helpers ---------------------------------------------------
    def cfg(self, dotted: str, default: Any = None) -> Any:
        """Read a dotted key from config.yaml, e.g. ``derp.server.enabled``."""
        node: Any = self.config or {}
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def cfg_is_set(self, dotted: str) -> bool:
        sentinel = object()
        return self.cfg(dotted, sentinel) is not sentinel


def iter_findings(results: Sequence[CheckResult]) -> Iterator[Finding]:
    for result in results:
        yield from result.findings


def severity_counts(findings: Iterable[Finding]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def status_counts(results: Sequence[CheckResult]) -> dict[str, int]:
    counts = {status: 0 for status in STATUS_ORDER}
    for result in results:
        counts[result.status] += 1
    return counts
