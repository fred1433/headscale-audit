"""Controls that compare the cloud inventory with the tailnet."""

from __future__ import annotations

from typing import Iterator

from .. import fleet
from ..loaders import parse_time
from ..model import Finding, Inventory
from .common import node_name, node_tags, quote
from .registry import DOC, register

ROLLOUT_DOC = f"{DOC}/ref/registration/"


@register(
    "HS-070",
    "Instances missing from the tailnet",
    "fleet",
    ROLLOUT_DOC,
    ("gce_instances", "nodes"),
    expected="every running instance of the inventory is a node in headscale",
)
def hs070(inv: Inventory) -> Iterator[Finding]:
    missing = [
        row
        for row in fleet.rows(inv)
        if not row.enrolled and row.status.upper() == "RUNNING"
    ]
    if not missing:
        return
    names = [f"{row.name} ({row.zone})" for row in missing]
    yield Finding(
        "HS-070",
        "Instances missing from the tailnet",
        "medium",
        f"{len(missing)} running instance(s) with no node in headscale: "
        f"{quote(sorted(names)[:15])}" + (" ..." if len(names) > 15 else ""),
        "These are the machines the rollout has not reached: they are running "
        "and they are not in the tailnet, which is the gap between what was "
        "deployed and what was intended.",
        "Run rollout/probe.sh on one of them to find out which step fails, "
        "then rollout/enroll.sh once the cause is fixed.",
        ROLLOUT_DOC,
    )


@register(
    "HS-071",
    "Tagged node with no matching instance",
    "fleet",
    ROLLOUT_DOC,
    ("gce_instances", "nodes"),
    expected="every tagged node corresponds to an instance of the inventory",
)
def hs071(inv: Inventory) -> Iterator[Finding]:
    known = {fleet.node_key(fleet.instance_name(i)) for i in inv.gce_instances or []}
    # Untagged nodes are personal devices: a laptop is not expected to be an
    # instance. Only service nodes are compared.
    orphans = [
        node_name(node)
        for node in inv.nodes or []
        if node_tags(node)
        and fleet.node_key(node_name(node)) not in known
    ]
    if not orphans:
        return
    yield Finding(
        "HS-071",
        "Tagged node with no matching instance",
        "review",
        f"{len(orphans)} tagged node(s) absent from the instance inventory: "
        f"{quote(sorted(orphans)[:15])}" + (" ..." if len(orphans) > 15 else ""),
        "Either they live somewhere the inventory does not cover (another "
        "project, another cloud, on premises), or they are machines that were "
        "deleted without being removed from the tailnet.",
        "Widen the inventory, or delete the nodes that no longer exist: "
        "headscale nodes delete -i <id>.",
        ROLLOUT_DOC,
    )


@register(
    "HS-072",
    "Instance enrolled but not connecting",
    "fleet",
    ROLLOUT_DOC,
    ("gce_instances", "nodes"),
    expected="every enrolled instance is online or was seen recently",
)
def hs072(inv: Inventory) -> Iterator[Finding]:
    index = fleet.node_index(inv)
    never: list[str] = []
    for row in fleet.rows(inv):
        if not row.enrolled or row.status.upper() != "RUNNING":
            continue
        node = index[fleet.node_key(row.name)]
        if node.get("online"):
            continue
        if parse_time(node.get("last_seen")) is None:
            never.append(row.name)
    if never:
        yield Finding(
            "HS-072",
            "Instance enrolled but not connecting",
            "medium",
            f"{len(never)} running instance(s) registered but never seen: "
            f"{quote(sorted(never)[:15])}",
            "Registration succeeded and the connection never did: the usual "
            "causes are a daemon that does not start at boot, outbound "
            "filtering towards the control server, or a clock that is off.",
            "Run rollout/probe.sh on the machine: it tests name resolution, "
            "the control port, TLS, the clock and the peer paths in that "
            "order.",
            ROLLOUT_DOC,
        )
