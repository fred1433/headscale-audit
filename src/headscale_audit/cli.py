"""Command line entry point."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Sequence

from . import __version__
from .checks import CATEGORIES, all_checks
from .engine import run
from .loaders import LoadError, from_api, from_directory, load_config, load_policy_text
from .model import Inventory
from .report import exit_code, to_json, to_markdown
from .hujson import HuJSONError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="headscale-audit",
        description=(
            "Read-only audit of a Headscale control plane: configuration, "
            "policy, nodes, routes and keys. Never writes anything."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  headscale-audit --config /etc/headscale/config.yaml\n"
            "  HEADSCALE_API_KEY=... headscale-audit --config "
            "/etc/headscale/config.yaml \\\n"
            "      --api-url https://headscale.example.com\n"
            "  headscale-audit --offline-dir ./export --format both "
            "--output report.md --json-output report.json\n"
        ),
    )
    parser.add_argument("--version", action="version", version=__version__)
    source = parser.add_argument_group("what to read")
    source.add_argument("--config", metavar="PATH", help="path to config.yaml")
    source.add_argument(
        "--policy",
        metavar="PATH",
        help="path to the policy file (huJSON); defaults to policy.path from "
        "the configuration",
    )
    source.add_argument(
        "--offline-dir",
        metavar="DIR",
        help="directory holding config.yaml, policy.hujson, nodes.json, "
        "users.json, preauthkeys.json, apikeys.json",
    )
    source.add_argument(
        "--api-url",
        metavar="URL",
        help="base URL of the Headscale REST API, e.g. "
        "https://headscale.example.com",
    )
    source.add_argument(
        "--api-key",
        metavar="KEY",
        help="API key; prefer the HEADSCALE_API_KEY environment variable, a "
        "command line is visible to every local process",
    )
    source.add_argument(
        "--headscale-binary",
        metavar="PATH",
        help="path to the headscale binary; when given, the policy is also "
        "validated by the server's own parser (headscale policy check)",
    )
    source.add_argument(
        "--gce-inventory",
        metavar="FILE",
        help="gcloud compute instances list --format=json export, to compare "
        "the fleet with what is actually enrolled",
    )
    source.add_argument(
        "--api-timeout", type=float, default=15.0, metavar="SECONDS", help=argparse.SUPPRESS
    )
    for section in ("nodes", "users", "preauthkeys", "apikeys"):
        source.add_argument(
            f"--{section}",
            metavar="FILE",
            help=f"JSON export of {section} (headscale {section} list --output json)",
        )

    tuning = parser.add_argument_group("thresholds")
    tuning.add_argument(
        "--stale-days",
        type=int,
        default=90,
        help="a node quiet for longer is reported (default: 90)",
    )
    tuning.add_argument(
        "--max-key-days",
        type=int,
        default=30,
        help="longest acceptable lifetime for a reusable pre-auth key "
        "(default: 30)",
    )
    tuning.add_argument(
        "--max-api-key-days",
        type=int,
        default=90,
        help="longest acceptable lifetime for an API key (default: 90)",
    )

    out = parser.add_argument_group("output")
    out.add_argument(
        "--format",
        choices=("md", "json", "both"),
        default="md",
        help="report format (default: md)",
    )
    out.add_argument("--output", metavar="PATH", help="write the Markdown report here")
    out.add_argument(
        "--json-output", metavar="PATH", help="write the JSON report here"
    )
    out.add_argument(
        "--fail-on",
        choices=("never", "high", "medium", "low", "any"),
        default="never",
        help="exit with status 1 when a finding of this severity or above is "
        "present (default: never)",
    )
    out.add_argument(
        "--list-checks",
        action="store_true",
        help="print the table of controls and exit",
    )
    return parser


def _list_checks() -> str:
    lines = ["| Id | Control | Area |", "| --- | --- | --- |"]
    for check in all_checks():
        lines.append(
            f"| {check.id} | {check.title} | {CATEGORIES[check.category]} |"
        )
    return "\n".join(lines) + "\n"


def build_inventory(args: argparse.Namespace) -> Inventory:
    inventory = Inventory()
    if args.offline_dir:
        inventory = from_directory(args.offline_dir, inventory)

    if args.config:
        inventory.config = load_config(args.config)
        inventory.config_path = args.config
        inventory.policy_mode = str(
            inventory.cfg("policy.mode", "file") or "file"
        ).lower()
        inventory.source = f"config {args.config}"

    policy_path = args.policy
    if policy_path is None and args.config and inventory.config:
        declared = str(inventory.cfg("policy.path", "") or "").strip()
        mode = str(inventory.cfg("policy.mode", "file") or "file").lower()
        if declared and mode == "file" and os.path.exists(declared):
            policy_path = declared
    if policy_path:
        with open(policy_path, "r", encoding="utf-8") as handle:
            inventory.policy_raw = handle.read()
        inventory.policy_source = policy_path
        try:
            inventory.policy = load_policy_text(inventory.policy_raw)
        except HuJSONError as exc:
            inventory.policy = None
            inventory.policy_error = str(exc)

    for section in ("nodes", "users", "preauthkeys", "apikeys"):
        path = getattr(args, section, None)
        if path:
            from .loaders import _as_list  # local import: internal helper

            with open(path, "r", encoding="utf-8") as handle:
                setattr(inventory, section, _as_list(json.load(handle), section))

    if args.gce_inventory:
        with open(args.gce_inventory, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if isinstance(payload, dict):
            payload = payload.get("items") or []
        if not isinstance(payload, list):
            raise LoadError(
                f"{args.gce_inventory}: expected the JSON array printed by "
                "gcloud compute instances list --format=json"
            )
        inventory.gce_instances = [item for item in payload if isinstance(item, dict)]

    inventory.headscale_binary = args.headscale_binary

    if args.api_url:
        api_key = args.api_key or os.environ.get("HEADSCALE_API_KEY", "")
        if not api_key:
            raise LoadError(
                "--api-url needs an API key: set HEADSCALE_API_KEY or pass "
                "--api-key (headscale apikeys create)"
            )
        if args.api_key:
            inventory.notes.append(
                "API key passed on the command line; prefer HEADSCALE_API_KEY."
            )
        inventory = from_api(
            args.api_url, api_key, inventory, timeout=args.api_timeout
        )
        if args.config:
            inventory.source = f"config {args.config} + API {args.api_url}"

    inventory.stale_node_days = args.stale_days
    inventory.max_key_lifetime_days = args.max_key_days
    inventory.max_api_key_lifetime_days = args.max_api_key_days
    return inventory


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_checks:
        sys.stdout.write(_list_checks())
        return 0

    if not any(
        [args.config, args.offline_dir, args.api_url, args.nodes, args.gce_inventory]
    ):
        parser.error(
            "nothing to audit: pass --config, --offline-dir, --api-url or an "
            "export such as --nodes"
        )

    try:
        inventory = build_inventory(args)
    except (LoadError, OSError) as exc:
        sys.stderr.write(f"headscale-audit: {exc}\n")
        return 2

    results = run(inventory)

    markdown = to_markdown(results, inventory)
    payload = to_json(results, inventory)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(markdown)
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as handle:
            handle.write(payload)

    if args.format in ("md", "both") and not args.output:
        sys.stdout.write(markdown)
    if args.format in ("json", "both") and not args.json_output:
        sys.stdout.write(payload)

    return exit_code(results, args.fail_on)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
