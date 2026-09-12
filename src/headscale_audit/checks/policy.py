"""Controls that read the access control policy (huJSON, ACLs and grants)."""

from __future__ import annotations

import os
import subprocess
from typing import Any, Iterator

from ..model import Finding, Inventory, NotApplicable, SkipCheck
from .common import as_list, is_wildcard, parse_target, quote
from .registry import DOC, TS_KB, register

POLICY_DOC = f"{DOC}/ref/policy/"
TAGS_DOC = f"{DOC}/ref/tags/"
ROUTES_DOC = f"{DOC}/ref/routes/"
SSH_DOC = f"{TS_KB}/1193/tailscale-ssh"


def _rules(policy: dict[str, Any]) -> list[tuple[str, int, dict[str, Any]]]:
    """Return ``(kind, index, rule)`` for every acl and grant entry."""
    out: list[tuple[str, int, dict[str, Any]]] = []
    for kind in ("acls", "grants"):
        entries = policy.get(kind) or []
        if isinstance(entries, list):
            for index, rule in enumerate(entries):
                if isinstance(rule, dict):
                    out.append((kind, index, rule))
    return out


def _dst_targets(rule: dict[str, Any]) -> list[tuple[str, str]]:
    return [parse_target(entry) for entry in as_list(rule.get("dst"))]


def _ports_of(kind: str, rule: dict[str, Any], dst_ports: str) -> str:
    if kind == "grants":
        return ",".join(as_list(rule.get("ip"))) or "(no ip field)"
    return dst_ports or "(none)"


def _all_ports(kind: str, rule: dict[str, Any], dst_ports: str) -> bool:
    if kind == "grants":
        return any(is_wildcard(port) for port in as_list(rule.get("ip")))
    return dst_ports.strip() == "*"


def _collect_referenced(policy: dict[str, Any]) -> set[str]:
    """Every selector the policy points at, ports stripped."""
    seen: set[str] = set()
    for _, _, rule in _rules(policy):
        for field in ("src", "dst", "via"):
            for entry in as_list(rule.get(field)):
                seen.add(parse_target(entry)[0])
    for rule in policy.get("ssh") or []:
        if isinstance(rule, dict):
            for field in ("src", "dst"):
                for entry in as_list(rule.get(field)):
                    seen.add(parse_target(entry)[0])
    approvers = policy.get("autoApprovers") or {}
    if isinstance(approvers, dict):
        for owners in (approvers.get("routes") or {}).values():
            seen.update(as_list(owners))
        seen.update(as_list(approvers.get("exitNode")))
    for owners in (policy.get("tagOwners") or {}).values():
        seen.update(as_list(owners))
    for entry in policy.get("nodeAttrs") or []:
        if isinstance(entry, dict):
            seen.update(parse_target(t)[0] for t in as_list(entry.get("target")))
    return seen


@register(
    "HS-030",
    "No access control policy loaded",
    "policy",
    POLICY_DOC,
    ("config",),
    expected="a policy is loaded",
)
def hs030(inv: Inventory) -> Iterator[Finding]:
    if inv.policy is not None:
        return
    mode = str(inv.cfg("policy.mode", "file") or "file").lower()
    path = str(inv.cfg("policy.path", "") or "").strip()
    if mode != "file":
        raise SkipCheck(
            f"policy.mode is {mode}: read the policy with --api-url or "
            "headscale policy get, this file does not hold it"
        )
    if path:
        raise SkipCheck(
            f"policy.path is {path} but the file was not provided; pass "
            "--policy to audit it"
        )
    if mode == "file" and not path:
        yield Finding(
            "HS-030",
            "No access control policy loaded",
            "high",
            "policy.mode: file, policy.path: (empty)",
            "With no policy loaded headscale allows all traffic between nodes, "
            "so every device in the tailnet can reach every port of every "
            "other device.",
            "Write a policy file, point policy.path at it, and reload "
            "headscale (SIGHUP or systemctl reload).",
            POLICY_DOC,
        )


@register(
    "HS-031",
    "Policy loaded but grants no rule at all",
    "policy",
    POLICY_DOC,
    ("policy",),
    expected="the policy declares acls or grants",
)
def hs031(inv: Inventory) -> Iterator[Finding]:
    policy = inv.policy or {}
    if "acls" in policy or "grants" in policy:
        return
    yield Finding(
        "HS-031",
        "Policy loaded but grants no rule at all",
        "high",
        f"policy keys: {quote(sorted(policy)) if policy else '{}'}",
        "A policy that omits both acls and grants is the documented allow all "
        "default: loading it changes nothing about who can reach what.",
        'Add a grants section; an empty one ("grants": []) denies everything '
        "and is the right starting point to open access rule by rule.",
        POLICY_DOC,
    )


@register(
    "HS-032",
    "Rule opens every source to every destination",
    "policy",
    POLICY_DOC,
    ("policy",),
    expected="no rule pairs an unrestricted source with an unrestricted destination",
)
def hs032(inv: Inventory) -> Iterator[Finding]:
    for kind, index, rule in _rules(inv.policy or {}):
        if str(rule.get("action", "accept")).lower() not in ("accept", ""):
            continue
        srcs = as_list(rule.get("src"))
        if not any(is_wildcard(src) for src in srcs):
            continue
        for target, ports in _dst_targets(rule):
            if is_wildcard(target) and _all_ports(kind, rule, ports):
                yield Finding(
                    "HS-032",
                    "Rule opens every source to every destination",
                    "high",
                    f"{kind}[{index}]: src {quote(srcs)} -> dst {quote(target)} "
                    f"ports {_ports_of(kind, rule, ports)}",
                    "This single rule makes the rest of the policy decorative: "
                    "any device, tagged or not, reaches every port of every "
                    "other device.",
                    "Replace it with rules that name the source (a user, a "
                    "group or a tag) and the destination ports.",
                    POLICY_DOC,
                )
                break


@register(
    "HS-033",
    "Rule source is not scoped to a user, group or tag",
    "policy",
    POLICY_DOC,
    ("policy",),
    expected="every accepting rule names its source",
)
def hs033(inv: Inventory) -> Iterator[Finding]:
    for kind, index, rule in _rules(inv.policy or {}):
        if str(rule.get("action", "accept")).lower() not in ("accept", ""):
            continue
        srcs = as_list(rule.get("src"))
        wildcard_src = [src for src in srcs if is_wildcard(src)]
        if not wildcard_src:
            continue
        targets = _dst_targets(rule)
        if any(
            is_wildcard(target) and _all_ports(kind, rule, ports)
            for target, ports in targets
        ):
            continue  # already reported by HS-032
        dst = ", ".join(f"{t}:{p}" if p else t for t, p in targets) or "(none)"
        yield Finding(
            "HS-033",
            "Rule source is not scoped to a user, group or tag",
            "medium",
            f"{kind}[{index}]: src {quote(wildcard_src)} -> dst {dst}",
            "Any device that joins the tailnet inherits this access, including "
            "one enrolled with a leaked pre-auth key, so the destination is "
            "only as protected as the weakest key.",
            "Name the source: a user (alice@), a group (group:ops) or a tag "
            "(tag:ci).",
            POLICY_DOC,
        )


@register(
    "HS-034",
    "Policy source includes addresses outside the tailnet",
    "policy",
    POLICY_DOC,
    ("policy",),
    expected="no rule takes autogroup:danger-all as its source",
)
def hs034(inv: Inventory) -> Iterator[Finding]:
    for kind, index, rule in _rules(inv.policy or {}):
        srcs = as_list(rule.get("src"))
        if any(src.strip() == "autogroup:danger-all" for src in srcs):
            targets = _dst_targets(rule)
            dst = ", ".join(f"{t}:{p}" if p else t for t, p in targets) or "(none)"
            yield Finding(
                "HS-034",
                "Policy source includes addresses outside the tailnet",
                "high",
                f"{kind}[{index}]: src {quote(srcs)} -> dst {dst}",
                "autogroup:danger-all resolves to 0.0.0.0/0 and ::/0, so the "
                "rule also accepts traffic that arrives from outside the "
                "tailnet through a subnet router or an exit node.",
                "Replace it with the tailnet selectors that actually need the "
                "access, or with the specific external prefixes.",
                POLICY_DOC,
            )


@register(
    "HS-035",
    "Tag used in the policy has no owner",
    "policy",
    TAGS_DOC,
    ("policy",),
    expected="every tag the policy uses has an owner in tagOwners",
)
def hs035(inv: Inventory) -> Iterator[Finding]:
    policy = inv.policy or {}
    owners = policy.get("tagOwners") or {}
    declared = {str(tag) for tag in owners}
    used = {
        target
        for target in _collect_referenced(policy)
        if target.startswith("tag:")
    }
    for tag in sorted(used - declared):
        yield Finding(
            "HS-035",
            "Tag used in the policy has no owner",
            "high",
            f"{tag} appears in the policy but not in tagOwners "
            f"(declared: {quote(sorted(declared)) if declared else '[]'})",
            "Nobody is allowed to assign this tag, so every enrolment that "
            "requests it is refused and the rules written for it never apply.",
            f'Add "{tag}": ["<owner>@"] to tagOwners, with the user or group '
            "that may register such nodes.",
            TAGS_DOC,
        )
    for tag, value in owners.items():
        if not as_list(value):
            yield Finding(
                "HS-035",
                "Tag used in the policy has no owner",
                "high",
                f'tagOwners["{tag}"]: []',
                "An empty owner list means no user can register a node with "
                "this tag, which blocks the rollout that relies on it.",
                f'Give "{tag}" at least one owner, for example the user whose '
                "pre-auth keys carry it.",
                TAGS_DOC,
            )


@register(
    "HS-036",
    "Tailscale SSH rule is too broad",
    "policy",
    SSH_DOC,
    ("policy",),
    expected="SSH rules name their source, their destination and their login users",
)
def hs036(inv: Inventory) -> Iterator[Finding]:
    rules = (inv.policy or {}).get("ssh") or []
    if not rules:
        raise NotApplicable("the policy declares no ssh section")
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        action = str(rule.get("action", "")).lower()
        if action not in {"accept", "check"}:
            continue
        srcs = as_list(rule.get("src"))
        dsts = as_list(rule.get("dst"))
        users = as_list(rule.get("users"))
        problems = []
        if any(is_wildcard(src) for src in srcs):
            problems.append("any source")
        if any(is_wildcard(dst) for dst in dsts):
            problems.append("any destination")
        if any(user.strip() in {"root", "*"} for user in users):
            problems.append("login as root")
        if not problems:
            continue
        severity = "high" if len(problems) >= 2 or action == "accept" else "medium"
        yield Finding(
            "HS-036",
            "Tailscale SSH rule is too broad",
            severity,
            f"ssh[{index}]: action {action}, src {quote(srcs)}, dst "
            f"{quote(dsts)}, users {quote(users)} ({', '.join(problems)})",
            "Tailscale SSH bypasses the host's own authorized_keys, so this "
            "rule is the real access list for shell access to those machines.",
            'Scope src and dst to tags or groups, prefer "action": "check" for '
            "human access, and use autogroup:nonroot instead of root.",
            SSH_DOC,
        )


@register(
    "HS-037",
    "Policy has no tests section",
    "policy",
    POLICY_DOC,
    ("policy",),
    expected="the policy carries tests",
)
def hs037(inv: Inventory) -> Iterator[Finding]:
    policy = inv.policy or {}
    if policy.get("tests") or policy.get("sshTests"):
        return
    yield Finding(
        "HS-037",
        "Policy has no tests section",
        "low",
        "no tests and no sshTests entry in the policy",
        "Nothing catches a rule that silently stops matching after an edit; "
        "with tests, headscale policy check refuses the change instead.",
        'Add a tests section asserting the access you rely on, then run '
        "headscale policy check -f policy.hujson before reloading.",
        POLICY_DOC,
    )


@register(
    "HS-038",
    "Host declared in the policy but never used",
    "policy",
    POLICY_DOC,
    ("policy",),
    expected="every declared host is used by a rule",
)
def hs038(inv: Inventory) -> Iterator[Finding]:
    policy = inv.policy or {}
    hosts = policy.get("hosts") or {}
    if not isinstance(hosts, dict) or not hosts:
        raise NotApplicable("the policy declares no hosts")
    referenced = _collect_referenced(policy)
    unused = sorted(str(name) for name in hosts if str(name) not in referenced)
    if unused:
        yield Finding(
            "HS-038",
            "Host declared in the policy but never used",
            "low",
            f"hosts declared and unreferenced: {quote(unused)}",
            "A host alias that no rule mentions is either a leftover from a "
            "rule that was deleted, or a rule that was never written.",
            "Delete the alias, or write the rule it was meant for.",
            POLICY_DOC,
        )


@register(
    "HS-039",
    "Group empty or never used",
    "policy",
    POLICY_DOC,
    ("policy",),
    expected="every declared group has members and is used by a rule",
)
def hs039(inv: Inventory) -> Iterator[Finding]:
    policy = inv.policy or {}
    groups = policy.get("groups") or {}
    if not isinstance(groups, dict) or not groups:
        raise NotApplicable("the policy declares no groups")
    referenced = _collect_referenced(policy)
    for name, members in groups.items():
        label = str(name)
        if not as_list(members):
            yield Finding(
                "HS-039",
                "Group empty or never used",
                "low",
                f'groups["{label}"]: []',
                "An empty group silently matches nobody, so the rules written "
                "for it grant nothing.",
                f"Add the members of {label}, or delete the group and the "
                "rules that use it.",
                POLICY_DOC,
            )
        elif label not in referenced:
            yield Finding(
                "HS-039",
                "Group empty or never used",
                "low",
                f'groups["{label}"]: {quote(as_list(members))} (never '
                "referenced)",
                "The group is defined but no rule selects it, which usually "
                "means the access it was created for is granted some other "
                "way.",
                f"Use {label} in the rules it belongs to, or delete it.",
                POLICY_DOC,
            )


@register(
    "HS-040",
    "Auto-approved routes are too broad",
    "policy",
    ROUTES_DOC,
    ("policy",),
    expected="auto-approval covers specific prefixes owned by specific tags",
)
def hs040(inv: Inventory) -> Iterator[Finding]:
    approvers = (inv.policy or {}).get("autoApprovers") or {}
    if not isinstance(approvers, dict) or not approvers:
        raise NotApplicable("the policy declares no autoApprovers")
    routes = approvers.get("routes") or {}
    if isinstance(routes, dict):
        for prefix, owners in routes.items():
            owner_list = as_list(owners)
            broad_prefix = str(prefix).strip() in {"0.0.0.0/0", "::/0"}
            broad_owner = any(is_wildcard(owner) for owner in owner_list)
            if broad_prefix or broad_owner:
                yield Finding(
                    "HS-040",
                    "Auto-approved routes are too broad",
                    "high" if broad_prefix else "medium",
                    f'autoApprovers.routes["{prefix}"]: {quote(owner_list)}',
                    "Approval of a route is the tailnet's second opt-in; "
                    "auto-approving a default route, or approving for any "
                    "owner, hands that decision to whoever can enrol a node.",
                    "Auto-approve the specific prefixes a role serves, owned "
                    "by the tag that role carries, and approve the rest by "
                    "hand with headscale nodes approve-routes.",
                    ROUTES_DOC,
                )
    exit_owners = as_list(approvers.get("exitNode"))
    if exit_owners:
        yield Finding(
            "HS-040",
            "Auto-approved routes are too broad",
            "medium",
            f"autoApprovers.exitNode: {quote(exit_owners)}",
            "Any node these owners enrol becomes an exit node without review, "
            "so a single compromised key adds a route for all internet "
            "traffic of anyone who selects it.",
            "Keep exit nodes on manual approval, or restrict the owner to a "
            "tag used by nothing else.",
            ROUTES_DOC,
        )


@register(
    "HS-041",
    "Policy does not parse",
    "policy",
    POLICY_DOC,
    ("policy_raw",),
    expected="the policy document parses as huJSON",
)
def hs041(inv: Inventory) -> Iterator[Finding]:
    if not inv.policy_error:
        return
    yield Finding(
        "HS-041",
        "Policy does not parse",
        "high",
        f"{inv.policy_source or 'policy'}: {inv.policy_error}",
        "Headscale keeps serving the last policy it managed to load, so the "
        "file being edited and the rules being enforced have drifted apart.",
        "Run headscale policy check -f <file> until it is quiet, then reload "
        "the server and confirm in the logs.",
        POLICY_DOC,
    )


# Sections this tool understands. Anything else is reported, because a policy
# with an unread section has not been fully audited.
KNOWN_SECTIONS = {
    "acls",
    "grants",
    "ssh",
    "tagOwners",
    "groups",
    "hosts",
    "autoApprovers",
    "tests",
    "sshTests",
    "nodeAttrs",
    "randomizeClientPort",
    "postures",
    "defaultSrcPosture",
    "derpMap",
    "extraDNSRecords",
}


@register(
    "HS-042",
    "Policy contains sections this audit does not read",
    "policy",
    POLICY_DOC,
    ("policy",),
    expected="every section of the policy is one this tool analyses",
)
def hs042(inv: Inventory) -> Iterator[Finding]:
    unknown = sorted(
        str(key) for key in (inv.policy or {}) if str(key) not in KNOWN_SECTIONS
    )
    if not unknown:
        return
    yield Finding(
        "HS-042",
        "Policy contains sections this audit does not read",
        "review",
        f"unread policy sections: {quote(unknown)}",
        "The analysis above is incomplete: these sections can widen access in "
        "ways none of the controls looked at.",
        "Read them by hand, and treat the policy verdict as partial until "
        "they are covered.",
        POLICY_DOC,
    )


@register(
    "HS-043",
    "Policy rejected by the headscale binary",
    "policy",
    POLICY_DOC,
    ("policy_raw",),
    expected="headscale policy check accepts the policy file",
)
def hs043(inv: Inventory) -> Iterator[Finding]:
    """Ask headscale itself, rather than trusting a second implementation."""
    binary = inv.headscale_binary
    if not binary:
        raise SkipCheck(
            "no headscale binary given; pass --headscale-binary to have the "
            "server's own parser validate the policy"
        )
    source = inv.policy_source or ""
    if not source or not os.path.exists(source):
        raise SkipCheck(
            "the policy was not read from a file, so it cannot be handed to "
            "headscale policy check"
        )
    argv = [binary, "policy", "check", "--file", source]
    if inv.config_path:
        # headscale finds its socket through the configuration file.
        argv += ["-c", inv.config_path]
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            argv,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SkipCheck(f"could not run {binary} policy check: {exc}") from exc
    if completed.returncode == 0:
        return
    output = (completed.stderr or completed.stdout or "").strip().splitlines()
    detail = output[-1] if output else f"exit code {completed.returncode}"
    if "connecting to headscale" in detail or "connection refused" in detail:
        # The command is a frontend for a gRPC call: without a running server
        # it says nothing about the policy itself.
        raise SkipCheck(
            "headscale policy check needs the running server it belongs to "
            f"({detail})"
        )
    yield Finding(
        "HS-043",
        "Policy rejected by the headscale binary",
        "high",
        f"headscale policy check --file {source} exited "
        f"{completed.returncode}: {detail}",
        "The server's own parser refuses this document, so a reload keeps the "
        "previous rules and the file being edited is not the policy in force.",
        "Fix what the command reports, re-run it until it is quiet, then "
        "reload headscale and confirm in the logs.",
        POLICY_DOC,
    )
