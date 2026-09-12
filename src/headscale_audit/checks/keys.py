"""Controls that read pre-auth keys and API keys.

No control ever prints key material: evidence names the key by id, user and
flags only.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any, Iterator

from ..loaders import parse_time
from ..model import Finding, Inventory
from .common import as_list, quote
from .registry import DOC, TS_KB, register

KEYS_DOC = f"{DOC}/ref/registration/"
API_DOC = f"{DOC}/ref/api/"
TAGS_DOC = f"{DOC}/ref/tags/"
TS_KEYS_DOC = f"{TS_KB}/1085/auth-keys"


def _label(key: dict[str, Any]) -> str:
    user = key.get("user")
    if isinstance(user, dict):
        owner = str(user.get("name") or user.get("id") or "?")
    else:
        owner = str(user or "?")
    return f"key id {key.get('id', '?')} (user {owner})"


def _usable(key: dict[str, Any], now: _dt.datetime) -> bool:
    """A key that can still register a node."""
    expiration = parse_time(key.get("expiration"))
    if expiration is not None and expiration < now:
        return False
    if not key.get("reusable") and key.get("used"):
        return False
    return True


@register(
    "HS-060",
    "Pre-auth key without expiry",
    "keys",
    TS_KEYS_DOC,
    ("preauthkeys",),
    expected="every usable pre-auth key has an expiry",
)
def hs060(inv: Inventory) -> Iterator[Finding]:
    for key in inv.preauthkeys or []:
        if parse_time(key.get("expiration")) is not None:
            continue
        if not _usable(key, inv.now):
            continue
        reusable = bool(key.get("reusable"))
        yield Finding(
            "HS-060",
            "Pre-auth key without expiry",
            "high" if reusable else "medium",
            f"{_label(key)}: expiration unset, reusable "
            f"{quote(reusable)}, ephemeral {quote(bool(key.get('ephemeral')))}, "
            f"tags {quote(as_list(key.get('acl_tags')))}",
            "The key is a standing credential to join the tailnet: wherever it "
            "was copied (an image, a startup script, a CI variable, a chat "
            "thread) it still works, and nothing reveals that it was used.",
            "Expire it (headscale preauthkeys expire -i <id>) and issue "
            "rollout keys with a short --expiration, tagged, and --ephemeral "
            "for instances that come and go.",
            TS_KEYS_DOC,
        )


@register(
    "HS-061",
    "Reusable pre-auth key valid for a long time",
    "keys",
    TS_KEYS_DOC,
    ("preauthkeys",),
    expected="reusable pre-auth keys are short lived",
)
def hs061(inv: Inventory) -> Iterator[Finding]:
    horizon = inv.now + _dt.timedelta(days=inv.max_key_lifetime_days)
    for key in inv.preauthkeys or []:
        expiration = parse_time(key.get("expiration"))
        if expiration is None or not key.get("reusable"):
            continue
        if expiration <= horizon:
            continue
        days = (expiration - inv.now).days
        yield Finding(
            "HS-061",
            "Reusable pre-auth key valid for a long time",
            "medium",
            f"{_label(key)}: reusable, expires {expiration:%Y-%m-%d} "
            f"({days} days from now), tags "
            f"{quote(as_list(key.get('acl_tags')))}",
            "A reusable key is a password for the network, and the window "
            "during which a leaked copy still enrols machines is exactly this "
            "long.",
            f"Keep reusable keys under {inv.max_key_lifetime_days} days and "
            "rotate them from the automation that consumes them.",
            TS_KEYS_DOC,
        )


@register(
    "HS-062",
    "Pre-auth key carries a tag the policy does not own",
    "keys",
    TAGS_DOC,
    ("preauthkeys", "policy"),
    expected="the tags carried by pre-auth keys exist in tagOwners",
)
def hs062(inv: Inventory) -> Iterator[Finding]:
    owners = (inv.policy or {}).get("tagOwners") or {}
    declared = {str(tag) for tag in owners}
    for key in inv.preauthkeys or []:
        tags = as_list(key.get("acl_tags"))
        missing = sorted(tag for tag in tags if tag not in declared)
        if not missing or not _usable(key, inv.now):
            continue
        yield Finding(
            "HS-062",
            "Pre-auth key carries a tag the policy does not own",
            "high",
            f"{_label(key)}: tags {quote(tags)}, tagOwners declares "
            f"{quote(sorted(declared)) if declared else '[]'}",
            "Registration with this key fails because the owner of the key is "
            "not allowed to apply the tag; this is the most common reason a "
            "fleet rollout stops with 'requested tags are invalid or not "
            "permitted'.",
            f"Add {', '.join(missing)} to tagOwners with the key's user as "
            "owner, reload the policy, then re-run the enrolment.",
            TAGS_DOC,
        )


@register(
    "HS-063",
    "API key long-lived or without expiry",
    "keys",
    API_DOC,
    ("apikeys",),
    expected="API keys expire within the upstream default window",
)
def hs063(inv: Inventory) -> Iterator[Finding]:
    horizon = inv.now + _dt.timedelta(days=inv.max_api_key_lifetime_days)
    for key in inv.apikeys or []:
        expiration = parse_time(key.get("expiration"))
        prefix = str(key.get("prefix") or key.get("id") or "?")
        if expiration is None:
            yield Finding(
                "HS-063",
                "API key long-lived or without expiry",
                "medium",
                f"API key {prefix}: no expiration",
                "An API key is full administrative access to the control "
                "plane over HTTP, and one that never expires outlives the "
                "integration it was made for.",
                "Expire it (headscale apikeys expire --prefix <prefix>) and "
                "reissue with the default 90 day window.",
                API_DOC,
            )
            continue
        if expiration < inv.now:
            continue
        if expiration > horizon:
            days = (expiration - inv.now).days
            yield Finding(
                "HS-063",
                "API key long-lived or without expiry",
                "medium",
                f"API key {prefix}: expires {expiration:%Y-%m-%d} ({days} days "
                "from now)",
                "An API key is full administrative access to the control "
                "plane, so its lifetime is the time a leaked copy stays "
                "useful.",
                f"Keep API keys at or under {inv.max_api_key_lifetime_days} "
                "days, the upstream default, and rotate them.",
                API_DOC,
            )


@register(
    "HS-064",
    "Expired credential left in place",
    "keys",
    KEYS_DOC,
    ("preauthkeys",),
    expected="expired credentials are deleted",
)
def hs064(inv: Inventory) -> Iterator[Finding]:
    stale_keys = [
        _label(key)
        for key in inv.preauthkeys or []
        if (parse_time(key.get("expiration")) or inv.now) < inv.now
    ]
    stale_api = [
        str(key.get("prefix") or key.get("id"))
        for key in inv.apikeys or []
        if (parse_time(key.get("expiration")) or inv.now) < inv.now
    ]
    if not stale_keys and not stale_api:
        return
    parts = []
    if stale_keys:
        parts.append(f"{len(stale_keys)} pre-auth key(s): {quote(stale_keys[:5])}")
    if stale_api:
        parts.append(f"{len(stale_api)} API key(s): {quote(stale_api[:5])}")
    yield Finding(
        "HS-064",
        "Expired credential left in place",
        "low",
        "; ".join(parts),
        "Expired credentials are inert, but they hide the live ones in every "
        "listing and make it harder to answer what is actually valid today.",
        "Delete them: headscale preauthkeys delete -i <id>, headscale apikeys "
        "delete --prefix <prefix>.",
        KEYS_DOC,
    )
