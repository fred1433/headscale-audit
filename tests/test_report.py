"""The two fixtures, and what the report is allowed to print."""

from __future__ import annotations

import json

from headscale_audit.engine import run
from headscale_audit.model import Inventory, iter_findings, severity_counts
from headscale_audit.report import exit_code, to_json, to_markdown

# Same gate as the CI job.
MIN_INSECURE_FINDINGS = 8
MIN_INSECURE_HIGH = 3


def test_insecure_fixture_raises_enough(insecure: Inventory) -> None:
    results = run(insecure)
    counts = severity_counts(iter_findings(results))
    total = sum(counts[severity] for severity in ("high", "medium", "low", "review"))
    assert total >= MIN_INSECURE_FINDINGS
    assert counts["high"] >= MIN_INSECURE_HIGH


def test_hardened_fixture_raises_no_high(hardened: Inventory) -> None:
    counts = severity_counts(iter_findings(run(hardened)))
    assert counts["high"] == 0


def test_hardened_fixture_is_not_quiet_by_omission(hardened: Inventory) -> None:
    """A clean report must come from controls that ran, not from missing data."""
    results = run(hardened)
    evaluated = [r for r in results if r.status in {"pass", "fail", "unknown"}]
    assert len(evaluated) >= len(results) - 6


def test_report_never_prints_key_material(insecure: Inventory) -> None:
    markdown = to_markdown(run(insecure), insecure)
    payload = to_json(run(insecure), insecure)
    for secret in (
        "GOCSPX-not-a-real-secret-value",  # oidc.client_secret in the fixture
        "REDACTED-IN-FIXTURE",  # the pre-auth key material
        "nodekey:redacted01",
        "mkey:redacted01",
    ):
        assert secret not in markdown
        assert secret not in payload


def test_json_report_is_machine_readable(insecure: Inventory) -> None:
    payload = json.loads(to_json(run(insecure), insecure))
    assert payload["headscale_baseline"] == "0.29.3"
    assert payload["status"]["FAIL"] > 0
    ids = {check["id"] for check in payload["checks"]}
    assert {"HS-001", "HS-032", "HS-060"} <= ids
    for check in payload["checks"]:
        assert check["expected"]
        for finding in check["findings"]:
            assert finding["observed"] and finding["why"] and finding["fix"]
            assert finding["doc"].startswith("https://")


def test_markdown_declares_what_was_not_evaluated(hardened: Inventory) -> None:
    markdown = to_markdown(run(hardened), hardened)
    assert "NOT_EVALUATED" in markdown
    assert "They are not passes." in markdown


def test_exit_code_thresholds(insecure: Inventory, hardened: Inventory) -> None:
    bad = run(insecure)
    good = run(hardened)
    assert exit_code(bad, "never") == 0
    assert exit_code(bad, "high") == 1
    assert exit_code(good, "high") == 0
    assert exit_code(good, "any") == 0


def test_checks_doc_is_up_to_date() -> None:
    """docs/checks.md is generated; a new control must be documented."""
    import pathlib
    import subprocess
    import sys

    root = pathlib.Path(__file__).resolve().parent.parent
    generator = root / "scripts" / "gen_checks_doc.py"
    current = (root / "docs" / "checks.md").read_text()
    rendered = subprocess.run(
        [sys.executable, "-c", f"import runpy,sys;sys.argv=['x'];"
         f"m=runpy.run_path('{generator}');print(m['render'](),end='')"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert current == rendered, "run python scripts/gen_checks_doc.py"
