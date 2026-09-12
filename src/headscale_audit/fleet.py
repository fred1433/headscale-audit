"""Compare a cloud instance inventory with what is actually enrolled.

The input is what ``gcloud compute instances list --format=json`` prints. The
question it answers is the one a stalled rollout actually asks: which machines
are not in the tailnet, and what is the next thing to look at for each.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from typing import Any

from .loaders import parse_time
from .model import Inventory


@dataclass(frozen=True)
class FleetRow:
    name: str
    zone: str
    status: str
    enrolled: bool
    tags: list[str]
    last_seen: str
    blocker: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "instance": self.name,
            "zone": self.zone,
            "instance_status": self.status,
            "enrolled": self.enrolled,
            "tags": self.tags,
            "last_seen": self.last_seen,
            "next_step": self.blocker,
        }


def zone_of(instance: dict[str, Any]) -> str:
    zone = str(instance.get("zone") or "")
    return zone.rsplit("/", 1)[-1] if zone else ""


def instance_name(instance: dict[str, Any]) -> str:
    return str(instance.get("name") or "")


def node_key(name: str) -> str:
    """A hostname as both sides would write it: lower case, no domain."""
    return (name or "").strip().lower().split(".")[0]


def node_index(inventory: Inventory) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for node in inventory.nodes or []:
        for candidate in (node.get("given_name"), node.get("name")):
            key = node_key(str(candidate or ""))
            if key:
                index.setdefault(key, node)
    return index


def rows(inventory: Inventory) -> list[FleetRow]:
    index = node_index(inventory)
    out: list[FleetRow] = []
    for instance in inventory.gce_instances or []:
        name = instance_name(instance)
        status = str(instance.get("status") or "UNKNOWN")
        node = index.get(node_key(name))
        if node is None:
            blocker = (
                "not running, nothing to enrol yet"
                if status != "RUNNING"
                else "never registered: run rollout/probe.sh on it"
            )
            out.append(
                FleetRow(name, zone_of(instance), status, False, [], "never", blocker)
            )
            continue
        last_seen = parse_time(node.get("last_seen"))
        tags = [str(tag) for tag in node.get("tags") or []]
        if node.get("online"):
            seen = "online"
            blocker = ""
        elif last_seen is None:
            seen = "never"
            blocker = "registered but never connected: check the daemon and UDP 41641"
        else:
            seen = last_seen.strftime("%Y-%m-%d")
            age = (inventory.now - last_seen).days
            blocker = (
                f"last seen {age} days ago"
                if age >= inventory.stale_node_days
                else ""
            )
        if not blocker and not tags:
            blocker = "enrolled without a tag: no policy rule can select it"
        out.append(
            FleetRow(name, zone_of(instance), status, True, tags, seen, blocker)
        )
    return out


def summary(inventory: Inventory) -> dict[str, Any]:
    table = rows(inventory)
    return {
        "instances": len(table),
        "enrolled": sum(1 for row in table if row.enrolled),
        "missing": sum(1 for row in table if not row.enrolled),
        "blocked": sum(1 for row in table if row.blocker),
        "rows": [row.as_dict() for row in table],
    }


def stale_cutoff(inventory: Inventory) -> _dt.datetime:
    return inventory.now - _dt.timedelta(days=inventory.stale_node_days)
