"""Helpers shared by the controls."""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Iterable
from urllib.parse import urlparse

WILDCARDS = {"*", "0.0.0.0/0", "::/0", "autogroup:danger-all"}
PORT_SPEC = re.compile(r"^(\*|\d[\d,\-]*)$")


def host_of(url: str) -> str:
    """Hostname of a URL, without port. Empty string when unparseable."""
    if not url:
        return ""
    parsed = urlparse(url if "//" in url else f"//{url}")
    return (parsed.hostname or "").lower()


def split_host_port(addr: str) -> tuple[str, str]:
    """Split ``host:port`` shapes, including ``[::1]:8080`` and ``:8080``."""
    addr = (addr or "").strip()
    if not addr:
        return "", ""
    if addr.startswith("["):
        host, _, port = addr.partition("]")
        return host[1:], port.lstrip(":")
    if addr.count(":") > 1:  # bare IPv6 without brackets
        return addr, ""
    host, _, port = addr.rpartition(":")
    if not host and port and not port.isdigit():
        return port, ""
    return host, port


def exposure(addr: str) -> str:
    """Classify a listen address: loopback, wildcard, routable or unknown."""
    host, _ = split_host_port(addr)
    if host == "":
        return "wildcard"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if host in {"localhost", "ip6-localhost"}:
            return "loopback"
        return "unknown"
    if ip.is_unspecified:
        return "wildcard"
    if ip.is_loopback:
        return "loopback"
    return "routable"


def is_wildcard(value: str) -> bool:
    return value.strip() in WILDCARDS


def parse_target(entry: str) -> tuple[str, str]:
    """Split an ACL destination ``target:ports`` into its two halves.

    ``tag:web:80,443`` -> ``("tag:web", "80,443")`` and ``100.64.0.1`` ->
    ``("100.64.0.1", "")``.
    """
    text = (entry or "").strip()
    if ":" not in text:
        return text, ""
    head, _, tail = text.rpartition(":")
    if head and PORT_SPEC.match(tail):
        return head, tail
    return text, ""


def as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def tags_in(values: Iterable[str]) -> set[str]:
    found: set[str] = set()
    for value in values:
        target, _ = parse_target(str(value))
        if target.startswith("tag:"):
            found.add(target)
    return found


def quote(value: Any) -> str:
    """Render a configuration value the way it would appear in YAML."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(quote(item) for item in value) + "]"
    return str(value)


def node_name(node: dict[str, Any]) -> str:
    for key in ("given_name", "name", "id"):
        value = node.get(key)
        if value:
            return str(value)
    return "<unnamed node>"


def node_tags(node: dict[str, Any]) -> list[str]:
    return [str(tag) for tag in node.get("tags") or []]


def is_exit_route(route: str) -> bool:
    return route.strip() in {"0.0.0.0/0", "::/0"}


def plural(count: int, singular: str, many: str | None = None) -> str:
    return singular if count == 1 else (many or f"{singular}s")
