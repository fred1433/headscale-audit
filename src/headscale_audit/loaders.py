"""Read the material an audit needs, from files or from the Headscale API.

Two shapes of JSON reach this module and they are not the same:

* the ``headscale`` CLI (``--output json``) marshals the protobuf structs with
  Go's ``encoding/json``, which keeps the proto field names: ``snake_case``,
  numeric ids, and timestamps as ``{"seconds": ..., "nanos": ...}``;
* the REST gateway marshals the same structs with protojson: ``camelCase``,
  ids as strings, timestamps as RFC 3339.

Everything below is normalised to snake_case keys and ``datetime`` objects so
that a control never has to care which door the data came through.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
import urllib.error
import urllib.request
from typing import Any

import yaml

from . import hujson
from .model import Inventory

_CAMEL_RE = re.compile(r"(?<!^)(?=[A-Z])")

LIST_KEYS = {
    "nodes": ("nodes",),
    "users": ("users",),
    "preauthkeys": ("pre_auth_keys", "preAuthKeys"),
    "apikeys": ("api_keys", "apiKeys"),
}


class LoadError(RuntimeError):
    pass


def snake(name: str) -> str:
    return _CAMEL_RE.sub("_", name).lower()


def normalise(value: Any) -> Any:
    """Recursively rewrite mapping keys to snake_case."""
    if isinstance(value, dict):
        return {snake(str(k)): normalise(v) for k, v in value.items()}
    if isinstance(value, list):
        return [normalise(v) for v in value]
    return value


def parse_time(value: Any) -> _dt.datetime | None:
    """Accept RFC 3339 strings and protobuf ``{seconds, nanos}`` objects."""
    if value in (None, "", {}):
        return None
    if isinstance(value, dict):
        seconds = value.get("seconds")
        if seconds in (None, 0):
            return None
        return _dt.datetime.fromtimestamp(int(seconds), tz=_dt.timezone.utc)
    if isinstance(value, (int, float)):
        return _dt.datetime.fromtimestamp(float(value), tz=_dt.timezone.utc)
    if isinstance(value, str):
        text = value.replace("Z", "+00:00")
        try:
            parsed = _dt.datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=_dt.timezone.utc)
        # protojson renders an unset timestamp as year 1.
        if parsed.year <= 1:
            return None
        return parsed
    return None


def _as_list(payload: Any, section: str) -> list[dict[str, Any]]:
    # headscale prints "null" for an empty list: Go marshals a nil slice that
    # way. It means zero items, not a broken export.
    if payload is None:
        return []
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict):
        items = None
        for key in LIST_KEYS[section]:
            if key in payload:
                items = payload[key]
                break
        if items is None:
            # A single-object response, e.g. {"node": {...}}.
            raise LoadError(
                f"{section}: expected a list or a key in {LIST_KEYS[section]}, "
                f"got keys {sorted(payload)}"
            )
    else:
        raise LoadError(f"{section}: unexpected JSON type {type(payload).__name__}")
    if items is None:
        items = []
    return [normalise(item) for item in items if isinstance(item, dict)]


def load_config(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise LoadError(f"{path}: expected a YAML mapping")
    return data


def load_policy_text(text: str) -> dict[str, Any]:
    parsed = hujson.loads(text)
    if not isinstance(parsed, dict):
        raise hujson.HuJSONError("policy must be a JSON object")
    return parsed


def from_directory(path: str, inventory: Inventory | None = None) -> Inventory:
    """Load an offline export produced by ``lab/export.sh`` or by hand.

    Recognised file names (all optional):
    ``config.yaml``, ``policy.hujson`` / ``policy.json``, ``nodes.json``,
    ``users.json``, ``preauthkeys.json``, ``apikeys.json``.
    """
    inv = inventory or Inventory()
    inv.source = f"directory {path}"

    config_path = _first_existing(path, ["config.yaml", "config.yml", "config.json"])
    if config_path:
        inv.config = load_config(config_path)
        inv.config_path = config_path
        inv.policy_mode = str(inv.cfg("policy.mode", "file") or "file").lower()

    policy_path = _first_existing(
        path, ["policy.hujson", "policy.json", "acl.hujson", "acl.json"]
    )
    if policy_path is None and inv.config:
        declared = inv.cfg("policy.path") or ""
        if declared:
            candidate = declared
            if not os.path.isabs(candidate):
                candidate = os.path.join(path, candidate)
            if os.path.exists(candidate):
                policy_path = candidate
    if policy_path:
        with open(policy_path, "r", encoding="utf-8") as handle:
            inv.policy_raw = handle.read()
        inv.policy_source = policy_path
        try:
            inv.policy = load_policy_text(inv.policy_raw)
        except hujson.HuJSONError as exc:
            inv.policy_error = str(exc)

    for section in ("nodes", "users", "preauthkeys", "apikeys"):
        file_path = _first_existing(path, [f"{section}.json"])
        if file_path:
            with open(file_path, "r", encoding="utf-8") as handle:
                setattr(inv, section, _as_list(json.load(handle), section))
    return inv


def _first_existing(directory: str, names: list[str]) -> str | None:
    for name in names:
        candidate = os.path.join(directory, name)
        if os.path.exists(candidate):
            return candidate
    return None


class HeadscaleAPI:
    """Strictly read-only client.

    The only method that touches the network is :meth:`get`, and it hard-codes
    ``method="GET"``. A Headscale API key is administrative (there is no
    read-only scope), so the tool is built so that it cannot change anything
    even if it wanted to; ``tests/test_api_readonly.py`` asserts it.
    """

    def __init__(self, base_url: str, api_key: str, timeout: float = 15.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def get(self, path: str) -> Any:
        url = f"{self.base_url}{path}"
        request = urllib.request.Request(url, method="GET")
        request.add_header("Authorization", f"Bearer {self.api_key}")
        request.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise LoadError(f"GET {path} returned HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise LoadError(f"GET {path} failed: {exc.reason}") from exc


def from_api(
    base_url: str,
    api_key: str,
    inventory: Inventory | None = None,
    timeout: float = 15.0,
) -> Inventory:
    """Collect nodes, users, keys and the policy over the REST API."""
    inv = inventory or Inventory()
    inv.source = f"API {base_url.rstrip('/')}"
    api = HeadscaleAPI(base_url, api_key, timeout=timeout)

    try:
        payload = api.get("/version")
    except LoadError as exc:
        inv.notes.append(f"Server version not read: {exc}")
    else:
        if isinstance(payload, dict):
            inv.server_version = str(payload.get("version") or "") or None

    inv.nodes = _as_list(api.get("/api/v1/node"), "nodes")
    inv.users = _as_list(api.get("/api/v1/user"), "users")
    inv.preauthkeys = _as_list(api.get("/api/v1/preauthkey"), "preauthkeys")
    try:
        inv.apikeys = _as_list(api.get("/api/v1/apikey"), "apikeys")
    except LoadError as exc:
        inv.collection_errors.append(f"API keys not read: {exc}")

    try:
        payload = api.get("/api/v1/policy")
    except LoadError as exc:
        # A file-based policy returns an error here; that is not a failure.
        inv.notes.append(
            f"Policy not available over the API ({exc}); with policy.mode: "
            "file the document lives on the server's filesystem."
        )
    else:
        raw = payload.get("policy") if isinstance(payload, dict) else None
        if raw and inv.policy is not None:
            # A policy file was passed explicitly: keep it as the source of
            # truth (it can be handed to headscale policy check) and only note
            # that the server serves one too.
            inv.notes.append(
                "The API also returns a policy; the file given on the command "
                "line is the one audited."
            )
        elif raw:
            inv.policy_raw = raw
            inv.policy_source = f"{base_url.rstrip('/')}/api/v1/policy"
            try:
                inv.policy = load_policy_text(raw)
            except hujson.HuJSONError as exc:
                inv.policy_error = str(exc)
    return inv
