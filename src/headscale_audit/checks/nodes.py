"""Controls that read the node, route and user inventory."""

from __future__ import annotations

import datetime as _dt
from collections import defaultdict
from typing import Any, Iterator

from ..loaders import parse_time
from ..model import Finding, Inventory, SkipCheck
from .common import is_exit_route, node_name, node_tags, quote
from .registry import DOC, register

NODES_DOC = f"{DOC}/ref/registration/"
ROUTES_DOC = f"{DOC}/ref/routes/"
TAGS_DOC = f"{DOC}/ref/tags/"
CFG_DOC = f"{DOC}/ref/configuration/"


def _user_of(node: dict[str, Any]) -> str:
    user = node.get("user")
    if isinstance(user, dict):
        return str(user.get("name") or user.get("id") or "")
    return str(user or "")


def _routes(node: dict[str, Any], field: str) -> list[str]:
    return [str(route) for route in node.get(field) or []]


@register(
    "HS-050",
    "Node key never expires",
    "nodes",
    CFG_DOC,
    ("nodes",),
    expected="untagged nodes have a key expiry",
)
def hs050(inv: Inventory) -> Iterator[Finding]:
    offenders = []
    for node in inv.nodes or []:
        if node_tags(node):
            continue  # tagged nodes are exempt from expiry by design
        if parse_time(node.get("expiry")) is None:
            offenders.append(node_name(node))
    if offenders:
        yield Finding(
            "HS-050",
            "Node key never expires",
            "medium",
            f"{len(offenders)} untagged node(s) with no expiry: "
            f"{quote(sorted(offenders)[:10])}"
            + (" ..." if len(offenders) > 10 else ""),
            "A personal device keeps its access for as long as the key lives, "
            "so a laptop that is lost or leaves with its owner stays a member "
            "of the tailnet until someone remembers to delete it.",
            "Set node.expiry in config.yaml (Tailscale's hosted service uses "
            "180d) so new registrations expire, and run headscale nodes expire "
            "-i <id> on the devices that should go now.",
            CFG_DOC,
        )


@register(
    "HS-051",
    "Expired node still registered",
    "nodes",
    NODES_DOC,
    ("nodes",),
    expected="no expired node is left registered",
)
def hs051(inv: Inventory) -> Iterator[Finding]:
    expired = []
    for node in inv.nodes or []:
        expiry = parse_time(node.get("expiry"))
        if expiry and expiry < inv.now:
            expired.append(f"{node_name(node)} (expired {expiry:%Y-%m-%d})")
    if expired:
        yield Finding(
            "HS-051",
            "Expired node still registered",
            "low",
            f"{len(expired)} node(s): {quote(sorted(expired)[:10])}"
            + (" ..." if len(expired) > 10 else ""),
            "The node cannot connect but still holds its name and its address, "
            "which keeps stale entries in MagicDNS and in any list built from "
            "the inventory.",
            "Delete what will not come back: headscale nodes delete -i <id>.",
            NODES_DOC,
        )


@register(
    "HS-052",
    "Node not seen for a long time",
    "nodes",
    NODES_DOC,
    ("nodes",),
    expected="every registered node has been seen recently",
)
def hs052(inv: Inventory) -> Iterator[Finding]:
    cutoff = inv.now - _dt.timedelta(days=inv.stale_node_days)
    stale = []
    for node in inv.nodes or []:
        if node.get("online"):
            continue
        last_seen = parse_time(node.get("last_seen"))
        if last_seen is None:
            created = parse_time(node.get("created_at"))
            if created and created < cutoff:
                stale.append(f"{node_name(node)} (never seen)")
            continue
        if last_seen < cutoff:
            stale.append(f"{node_name(node)} (last seen {last_seen:%Y-%m-%d})")
    if stale:
        yield Finding(
            "HS-052",
            "Node not seen for a long time",
            "low",
            f"{len(stale)} node(s) quiet for more than {inv.stale_node_days} "
            f"days: {quote(sorted(stale)[:10])}"
            + (" ..." if len(stale) > 10 else ""),
            "Each of these still counts as a member of the tailnet, and the "
            "longer one sits unused the less likely anyone notices when it "
            "comes back with someone else's hands on it.",
            "Confirm the machine is gone, then headscale nodes delete -i <id>; "
            "for instances that come and go, enrol them with an ephemeral key "
            "so they clean themselves up.",
            NODES_DOC,
        )


@register(
    "HS-053",
    "Subnet router or exit node has no tag",
    "nodes",
    TAGS_DOC,
    ("nodes",),
    expected="nodes that carry routes are tagged",
)
def hs053(inv: Inventory) -> Iterator[Finding]:
    for node in inv.nodes or []:
        if node_tags(node):
            continue
        advertised = set(_routes(node, "available_routes")) | set(
            _routes(node, "approved_routes")
        )
        if not advertised:
            continue
        yield Finding(
            "HS-053",
            "Subnet router or exit node has no tag",
            "medium",
            f"{node_name(node)} advertises {quote(sorted(advertised))} and "
            f"carries no tag (owner: {_user_of(node) or 'unknown'})",
            "An untagged node belongs to a person: its access follows that "
            "user's identity and its key expires with them, which is the wrong "
            "lifecycle for a machine that routes a subnet, and no policy rule "
            "or autoApprover can select it by role.",
            "Give it a role tag (headscale nodes tag -i <id> -t tag:router) "
            "and enrol its replacements with a tagged pre-auth key.",
            TAGS_DOC,
        )


@register(
    "HS-054",
    "Several nodes share one hostname",
    "nodes",
    NODES_DOC,
    ("nodes",),
    expected="node names are unique",
)
def hs054(inv: Inventory) -> Iterator[Finding]:
    by_name: dict[str, list[str]] = defaultdict(list)
    for node in inv.nodes or []:
        name = str(node.get("given_name") or node.get("name") or "").lower()
        if name:
            by_name[name].append(str(node.get("id", "?")))
    for name, ids in sorted(by_name.items()):
        if len(ids) > 1:
            yield Finding(
                "HS-054",
                "Several nodes share one hostname",
                "low",
                f"{name}: node ids {quote(ids)}",
                "Headscale renames the duplicates for MagicDNS, so the name an "
                "operator types no longer points where they expect; this is "
                "the usual trace of a machine re-enrolled instead of being "
                "cleaned up.",
                "Delete the dead entries, and pass --hostname explicitly when "
                "enrolling so names stay predictable.",
                NODES_DOC,
            )


@register(
    "HS-055",
    "Advertised route waiting for approval",
    "nodes",
    ROUTES_DOC,
    ("nodes",),
    expected="advertised routes are either approved or not advertised",
)
def hs055(inv: Inventory) -> Iterator[Finding]:
    for node in inv.nodes or []:
        available = set(_routes(node, "available_routes"))
        approved = set(_routes(node, "approved_routes"))
        pending = sorted(available - approved)
        if pending:
            yield Finding(
                "HS-055",
                "Advertised route waiting for approval",
                "review",
                f"{node_name(node)} advertises {quote(pending)}, approved "
                f"{quote(sorted(approved)) if approved else '[]'}",
                "Routes need the second opt-in on the control plane, so this "
                "subnet is not reachable through the tailnet yet: the usual "
                "symptom is a rollout that looks complete but where half the "
                "estate cannot be reached.",
                f"Approve what is intended: headscale nodes approve-routes -i "
                f"{node.get('id', '<id>')} -r {','.join(pending)}.",
                ROUTES_DOC,
            )


@register(
    "HS-056",
    "Exit node approved for the whole tailnet",
    "nodes",
    ROUTES_DOC,
    ("nodes",),
    expected="an approved exit node is paired with a policy that says who may use it",
)
def hs056(inv: Inventory) -> Iterator[Finding]:
    if inv.policy is None and any(
        is_exit_route(route)
        for node in inv.nodes or []
        for route in _routes(node, "approved_routes")
    ):
        raise SkipCheck(
            "an exit node is approved but no policy was read, so who may use "
            "it cannot be established"
        )
    policy = inv.policy or {}
    has_internet_rule = "autogroup:internet" in str(
        policy.get("acls", "")
    ) or "autogroup:internet" in str(policy.get("grants", ""))
    for node in inv.nodes or []:
        exits = [route for route in _routes(node, "approved_routes") if is_exit_route(route)]
        if not exits:
            continue
        if has_internet_rule:
            continue
        yield Finding(
            "HS-056",
            "Exit node approved for the whole tailnet",
            "medium",
            f"{node_name(node)} has {quote(exits)} approved and no policy rule "
            "mentions autogroup:internet",
            "Without a policy, every node may route its internet traffic "
            "through this machine, which puts its address and its bandwidth "
            "behind anything a colleague does.",
            "Grant autogroup:internet to the group that needs it and deny the "
            "rest, or unapprove the default route.",
            ROUTES_DOC,
        )


@register(
    "HS-057",
    "User account with no node",
    "nodes",
    NODES_DOC,
    ("users", "nodes"),
    expected="every user account owns at least one node",
)
def hs057(inv: Inventory) -> Iterator[Finding]:
    owners = set()
    for node in inv.nodes or []:
        user = node.get("user")
        if isinstance(user, dict):
            owners.add(str(user.get("name") or ""))
            owners.add(str(user.get("id") or ""))
        elif user:
            owners.add(str(user))
    # A user can legitimately own no device: the account that owns the tags and
    # issues the rollout keys is exactly that. Only accounts with no device and
    # no role are reported.
    tag_owners: set[str] = set()
    for owner_list in ((inv.policy or {}).get("tagOwners") or {}).values():
        for owner in owner_list if isinstance(owner_list, list) else []:
            tag_owners.add(str(owner).rstrip("@"))
    key_issuers: set[str] = set()
    for key in inv.preauthkeys or []:
        user = key.get("user")
        if isinstance(user, dict):
            key_issuers.add(str(user.get("name") or ""))
        elif user:
            key_issuers.add(str(user))

    orphans = []
    for user in inv.users or []:
        name = str(user.get("name") or "")
        if name == "tagged-devices":
            continue
        if name in owners or str(user.get("id") or "") in owners:
            continue
        if name in tag_owners or name in key_issuers:
            continue
        orphans.append(name or str(user.get("id")))
    if orphans:
        yield Finding(
            "HS-057",
            "User account with no node",
            "low",
            f"{len(orphans)} user(s): {quote(sorted(orphans)[:10])}"
            + (" ..." if len(orphans) > 10 else ""),
            "An account with no device, no tag to own and no key to its "
            "name is usually someone who left, and it can still be used to "
            "register nodes.",
            "Delete it (headscale users destroy --name <user>) once its keys "
            "and tag ownership have been moved.",
            NODES_DOC,
        )
