"""One minimal mutation per control.

The baseline is ``lab/hardened``: a deployment where every control is quiet.
Each case below changes exactly one thing and asserts that the matching
control fires. The reverse direction (the fix silences it) is asserted once,
by ``test_baseline_is_quiet``: the baseline is the fixed version of every
mutation in this file.
"""

from __future__ import annotations

import datetime as _dt
from typing import Callable

import pytest

from headscale_audit.engine import run
from headscale_audit.model import Inventory

Mutator = Callable[[Inventory], None]


def failing_ids(inventory: Inventory) -> set[str]:
    return {
        result.check.id
        for result in run(inventory)
        if result.status in {"fail", "unknown"}
    }


def set_cfg(inventory: Inventory, dotted: str, value) -> None:
    node = inventory.config
    parts = dotted.split(".")
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value


def rule(**kwargs) -> dict:
    return kwargs


def _days(inventory: Inventory, delta: int) -> str:
    return (inventory.now + _dt.timedelta(days=delta)).strftime("%Y-%m-%dT%H:%M:%SZ")


CASES: list[tuple[str, Mutator]] = [
    ("HS-001", lambda inv: set_cfg(inv, "server_url", "http://headscale.example.com")),
    ("HS-002", lambda inv: set_cfg(inv, "metrics_listen_addr", "0.0.0.0:9090")),
    ("HS-003", lambda inv: set_cfg(inv, "grpc_allow_insecure", True)),
    ("HS-004", lambda inv: set_cfg(inv, "tls_letsencrypt_hostname", "")),
    ("HS-005", lambda inv: set_cfg(inv, "tls_letsencrypt_hostname", "vpn.example.com")),
    ("HS-006", lambda inv: set_cfg(inv, "tls_cert_path", "/etc/ssl/hs.pem")),
    ("HS-007", lambda inv: set_cfg(inv, "noise.private_key_path", "")),
    ("HS-009", lambda inv: set_cfg(inv, "server_url", "http://headscale.example.com")),
    ("HS-010", lambda inv: set_cfg(inv, "derp.server.verify_clients", False)),
    ("HS-011", lambda inv: set_cfg(inv, "derp.server.stun_listen_addr", "")),
    (
        "HS-012",
        lambda inv: (
            set_cfg(inv, "derp.server.enabled", False),
            set_cfg(
                inv,
                "derp.urls",
                ["https://controlplane.tailscale.com/derpmap/default"],
            ),
        ),
    ),
    ("HS-013", lambda inv: set_cfg(inv, "dns.base_domain", "headscale.example.com")),
    ("HS-014", lambda inv: set_cfg(inv, "dns.override_local_dns", True)),
    (
        "HS-015",
        lambda inv: (
            set_cfg(inv, "dns.override_local_dns", True),
            set_cfg(inv, "dns.nameservers.global", ["1.1.1.1"]),
        ),
    ),
    ("HS-016", lambda inv: set_cfg(inv, "acl_policy_path", "/etc/headscale/acl.hujson")),
    (
        "HS-017",
        lambda inv: set_cfg(inv, "node.ephemeral.inactivity_timeout", "30s"),
    ),
    ("HS-018", lambda inv: set_cfg(inv, "unix_socket_permission", "0777")),
    ("HS-019", lambda inv: set_cfg(inv, "trusted_proxies", ["0.0.0.0/0"])),
    ("HS-020", lambda inv: set_cfg(inv, "logtail.enabled", True)),
    ("HS-021", lambda inv: set_cfg(inv, "database.sqlite.write_ahead_log", False)),
    ("HS-022", lambda inv: set_cfg(inv, "oidc.allowed_domains", [])),
    ("HS-023", lambda inv: set_cfg(inv, "oidc.client_secret", "GOCSPX-example")),
    ("HS-024", lambda inv: set_cfg(inv, "oidc.pkce.enabled", False)),
    ("HS-025", lambda inv: set_cfg(inv, "oidc.email_verified_required", False)),
    ("HS-026", lambda inv: setattr(inv, "server_version", "0.28.1")),
    (
        "HS-030",
        lambda inv: (
            setattr(inv, "policy", None),
            set_cfg(inv, "policy.path", ""),
        ),
    ),
    ("HS-031", lambda inv: setattr(inv, "policy", {"tagOwners": {}})),
    (
        "HS-032",
        lambda inv: inv.policy["grants"].append(
            rule(src=["*"], dst=["*"], ip=["*"])
        ),
    ),
    (
        "HS-033",
        lambda inv: inv.policy["grants"].append(
            rule(src=["*"], dst=["tag:web"], ip=["443"])
        ),
    ),
    (
        "HS-034",
        lambda inv: inv.policy["grants"].append(
            rule(src=["autogroup:danger-all"], dst=["tag:web"], ip=["443"])
        ),
    ),
    (
        "HS-035",
        lambda inv: inv.policy["grants"].append(
            rule(src=["group:ops"], dst=["tag:unowned"], ip=["443"])
        ),
    ),
    (
        "HS-036",
        lambda inv: inv.policy["ssh"].append(
            rule(action="accept", src=["*"], dst=["*"], users=["root"])
        ),
    ),
    ("HS-037", lambda inv: inv.policy.pop("tests")),
    (
        "HS-038",
        lambda inv: inv.policy["hosts"].update({"old-dc": "10.9.0.0/16"}),
    ),
    ("HS-039", lambda inv: inv.policy["groups"].update({"group:interns": []})),
    (
        "HS-040",
        lambda inv: inv.policy["autoApprovers"]["routes"].update(
            {"0.0.0.0/0": ["tag:router"]}
        ),
    ),
    (
        "HS-042",
        lambda inv: inv.policy.update({"ipsets": {"ipset:office": ["192.0.2.0/24"]}}),
    ),
    (
        "HS-041",
        lambda inv: (
            setattr(inv, "policy_raw", "{ not json"),
            setattr(inv, "policy_error", "invalid huJSON: line 1"),
        ),
    ),
    (
        "HS-050",
        lambda inv: inv.nodes.append(
            {"id": "9", "given_name": "laptop-sam", "tags": [], "online": True}
        ),
    ),
    (
        "HS-051",
        lambda inv: inv.nodes.append(
            {
                "id": "9",
                "given_name": "laptop-sam",
                "tags": [],
                "expiry": _days(inv, -3),
                "online": False,
                "last_seen": _days(inv, -3),
            }
        ),
    ),
    (
        "HS-052",
        lambda inv: inv.nodes.append(
            {
                "id": "9",
                "given_name": "old-builder",
                "tags": ["tag:web"],
                "online": False,
                "last_seen": _days(inv, -200),
            }
        ),
    ),
    (
        "HS-053",
        lambda inv: inv.nodes.append(
            {
                "id": "9",
                "given_name": "shadow-router",
                "tags": [],
                "expiry": _days(inv, 30),
                "online": True,
                "last_seen": _days(inv, 0),
                "available_routes": ["192.168.7.0/24"],
                "approved_routes": ["192.168.7.0/24"],
            }
        ),
    ),
    (
        "HS-054",
        lambda inv: inv.nodes.append(
            {
                "id": "9",
                "given_name": "gce-web-01",
                "tags": ["tag:web"],
                "online": True,
                "last_seen": _days(inv, 0),
            }
        ),
    ),
    (
        "HS-055",
        lambda inv: inv.nodes[1].update({"approved_routes": []}),
    ),
    (
        "HS-056",
        lambda inv: [
            inv.policy.__setitem__(
                "grants",
                [
                    grant
                    for grant in inv.policy["grants"]
                    if "autogroup:internet" not in grant.get("dst", [])
                ],
            )
        ],
    ),
    (
        "HS-057",
        lambda inv: inv.users.append({"id": "9", "name": "leaver"}),
    ),
    (
        "HS-060",
        lambda inv: inv.preauthkeys.append(
            {
                "id": "9",
                "user": {"name": "ops"},
                "reusable": True,
                "used": False,
                "acl_tags": ["tag:web"],
            }
        ),
    ),
    (
        "HS-061",
        lambda inv: inv.preauthkeys.append(
            {
                "id": "9",
                "user": {"name": "ops"},
                "reusable": True,
                "used": True,
                "expiration": _days(inv, 365),
                "acl_tags": ["tag:web"],
            }
        ),
    ),
    (
        "HS-062",
        lambda inv: inv.preauthkeys.append(
            {
                "id": "9",
                "user": {"name": "ops"},
                "reusable": False,
                "used": False,
                "expiration": _days(inv, 5),
                "acl_tags": ["tag:not-in-policy"],
            }
        ),
    ),
    (
        "HS-063",
        lambda inv: inv.apikeys.append(
            {"id": "9", "prefix": "abcdefgh", "expiration": _days(inv, 3650)}
        ),
    ),
    (
        "HS-070",
        lambda inv: inv.gce_instances.append(
            {"name": "gce-batch-09", "zone": "z/europe-north1-c", "status": "RUNNING"}
        ),
    ),
    (
        "HS-071",
        lambda inv: inv.nodes.append(
            {
                "id": "9",
                "given_name": "gce-ghost-01",
                "tags": ["tag:web"],
                "online": True,
                "last_seen": _days(inv, 0),
            }
        ),
    ),
    (
        "HS-072",
        lambda inv: (
            inv.gce_instances.append(
                {"name": "gce-quiet-01", "zone": "z/europe-north1-a", "status": "RUNNING"}
            ),
            inv.nodes.append(
                {
                    "id": "9",
                    "given_name": "gce-quiet-01",
                    "tags": ["tag:web"],
                    "online": False,
                }
            ),
        ),
    ),
    (
        "HS-064",
        lambda inv: inv.preauthkeys.append(
            {
                "id": "9",
                "user": {"name": "ops"},
                "reusable": False,
                "used": True,
                "expiration": _days(inv, -5),
            }
        ),
    ),
]


def test_baseline_is_quiet(base: Inventory) -> None:
    results = run(base)
    noisy = [
        (result.check.id, [finding.evidence for finding in result.findings])
        for result in results
        if result.status in {"fail", "unknown", "error"}
    ]
    assert noisy == []


@pytest.mark.parametrize("check_id,mutate", CASES, ids=[case[0] for case in CASES])
def test_mutation_triggers_control(
    base: Inventory, check_id: str, mutate: Mutator
) -> None:
    mutate(base)
    assert check_id in failing_ids(base)


def test_every_control_has_a_case() -> None:
    from headscale_audit.checks import all_checks

    covered = {case[0] for case in CASES}
    # HS-008 (file permissions) and HS-043 (headscale binary) need the host,
    # they have their own tests.
    covered |= {"HS-008", "HS-043"}
    missing = sorted(check.id for check in all_checks() if check.id not in covered)
    assert missing == []


def test_a_terminated_instance_is_not_a_missing_node(base: Inventory) -> None:
    """An instance that is not running has nothing to enrol yet."""
    base.gce_instances.append(
        {"name": "gce-old-09", "zone": "z/europe-north1-a", "status": "TERMINATED"}
    )
    assert "HS-070" not in failing_ids(base)


def test_an_untagged_node_is_not_a_fleet_orphan(base: Inventory) -> None:
    """A laptop is not expected to appear in an instance inventory."""
    base.nodes.append(
        {"id": "9", "given_name": "laptop-sam", "tags": [], "online": True,
         "expiry": _days(base, 90)}
    )
    assert "HS-071" not in failing_ids(base)


def test_oidc_private_issuer_is_a_question_not_a_verdict(base: Inventory) -> None:
    """An empty allow list is only a finding when the issuer is multi-tenant."""
    set_cfg(base, "oidc.issuer", "https://sso.example.com/realms/corp")
    set_cfg(base, "oidc.allowed_domains", [])
    results = {result.check.id: result for result in run(base)}
    assert results["HS-022"].status == "unknown"
    assert results["HS-022"].findings[0].severity == "review"


def test_base_domain_suffix_and_equality(base: Inventory) -> None:
    for base_domain, expected in (
        ("headscale.example.com", True),  # equal to the server host
        ("example.com", True),  # server host is under it
        ("vpn.internal.example", False),  # independent domain
    ):
        set_cfg(base, "dns.base_domain", base_domain)
        assert (("HS-013" in failing_ids(base)) is expected), base_domain
