"""Controls that read the Headscale server configuration (``config.yaml``).

Every field name below exists in the configuration of the pinned version:
https://github.com/juanfont/headscale/blob/v0.29.3/config-example.yaml
"""

from __future__ import annotations

import os
import stat
from typing import Iterator

from ..model import Finding, Inventory, NotApplicable, SkipCheck
from .common import exposure, host_of, quote
from .registry import DOC, REPO, register

CFG_DOC = f"{DOC}/ref/configuration/"
TLS_DOC = f"{DOC}/ref/tls/"
DNS_DOC = f"{DOC}/ref/dns/"
DERP_DOC = f"{DOC}/ref/derp/"
OIDC_DOC = f"{DOC}/ref/oidc/"
API_DOC = f"{DOC}/ref/api/"
EXAMPLE = f"{REPO}/config-example.yaml"

# Issuers that authenticate accounts well beyond one organisation. Anything
# else (a private realm, a tenant specific issuer) may already be restricted on
# the provider side, so the control asks instead of concluding.
MULTI_TENANT_ISSUERS = {
    "accounts.google.com",
    "github.com",
    "gitlab.com",
}


def _resolve(inv: Inventory, path: str) -> str:
    """Resolve a config path the way headscale does: relative to config.yaml."""
    if not path:
        return path
    if os.path.isabs(path):
        return path
    base = os.path.dirname(inv.config_path or "")
    return os.path.normpath(os.path.join(base, path))


@register(
    "HS-001",
    "Control plane served over plain HTTP",
    "server",
    TLS_DOC,
    ("config",),
    expected="server_url uses https://",
)
def hs001(inv: Inventory) -> Iterator[Finding]:
    url = str(inv.cfg("server_url", "") or "")
    if url and not url.lower().startswith("https://"):
        yield Finding(
            "HS-001",
            "Control plane served over plain HTTP",
            "high",
            f"server_url: {url}",
            "Clients fetch the control plane's Noise public key from "
            "server_url/key over this scheme, so anyone in path can answer "
            "instead of the server, and the embedded DERP relay cannot be "
            "enabled without TLS.",
            "Put headscale behind TLS (tls_letsencrypt_hostname, or "
            "tls_cert_path/tls_key_path, or a reverse proxy) and set "
            "server_url to the https:// URL.",
            TLS_DOC,
        )


@register(
    "HS-002",
    "Metrics and debug listener reachable off-host",
    "server",
    CFG_DOC,
    ("config",),
    expected="metrics_listen_addr is empty or bound to a loopback address",
)
def hs002(inv: Inventory) -> Iterator[Finding]:
    addr = inv.cfg("metrics_listen_addr")
    if addr in (None, ""):
        return
    level = exposure(str(addr))
    if level in {"wildcard", "routable"}:
        yield Finding(
            "HS-002",
            "Metrics and debug listener reachable off-host",
            "medium",
            f"metrics_listen_addr: {addr}",
            "This listener serves /metrics and /debug, which expose the "
            "deployment's internals; upstream documents it as an endpoint to "
            "keep on a private network.",
            "Bind it to 127.0.0.1 (or an empty value to disable it) and scrape "
            "it through the tailnet or an SSH tunnel.",
            EXAMPLE,
        )


@register(
    "HS-003",
    "gRPC admin interface allowed to run unencrypted",
    "server",
    API_DOC,
    ("config",),
    expected="grpc_allow_insecure is false",
)
def hs003(inv: Inventory) -> Iterator[Finding]:
    if not inv.cfg("grpc_allow_insecure", False):
        return
    addr = str(inv.cfg("grpc_listen_addr", "") or "")
    level = exposure(addr)
    severity = "high" if level in {"wildcard", "routable"} else "medium"
    yield Finding(
        "HS-003",
        "gRPC admin interface allowed to run unencrypted",
        severity,
        f"grpc_allow_insecure: true, grpc_listen_addr: {addr or '(unset)'}",
        "The gRPC interface drives the whole control plane and carries the API "
        "key in clear text when TLS is disabled, so anyone who can read the "
        "traffic to this port becomes an administrator.",
        "Set grpc_allow_insecure: false and serve gRPC over TLS, or keep the "
        "port on 127.0.0.1 and reach it through SSH.",
        API_DOC,
    )


@register(
    "HS-004",
    "HTTPS advertised but no certificate configured",
    "server",
    TLS_DOC,
    ("config",),
    expected="an https server_url comes with a certificate source headscale itself can use",
)
def hs004(inv: Inventory) -> Iterator[Finding]:
    url = str(inv.cfg("server_url", "") or "")
    if not url.lower().startswith("https://"):
        raise NotApplicable(f"server_url is not https ({url or 'unset'})")
    has_tls = bool(
        inv.cfg("tls_cert_path")
        or inv.cfg("tls_key_path")
        or inv.cfg("tls_letsencrypt_hostname")
    )
    if not has_tls:
        yield Finding(
            "HS-004",
            "HTTPS advertised but no certificate configured",
            "review",
            f"server_url: {url}; tls_cert_path, tls_key_path and "
            "tls_letsencrypt_hostname are all empty",
            "Either a reverse proxy terminates TLS in front of headscale, "
            "which is a supported setup, or clients are being pointed at an "
            "endpoint that cannot complete a TLS handshake.",
            "Confirm which component terminates TLS; if it is a proxy, check "
            "that it forwards to listen_addr and that trusted_proxies names it.",
            TLS_DOC,
        )


@register(
    "HS-005",
    "Let's Encrypt hostname does not match server_url",
    "server",
    TLS_DOC,
    ("config",),
    expected="tls_letsencrypt_hostname is the host in server_url",
)
def hs005(inv: Inventory) -> Iterator[Finding]:
    hostname = str(inv.cfg("tls_letsencrypt_hostname", "") or "").strip()
    if not hostname:
        raise NotApplicable("tls_letsencrypt_hostname is empty, ACME is not used")
    server_host = host_of(str(inv.cfg("server_url", "") or ""))
    if server_host and hostname.lower() != server_host:
        yield Finding(
            "HS-005",
            "Let's Encrypt hostname does not match server_url",
            "high",
            f"tls_letsencrypt_hostname: {hostname} vs server_url host: "
            f"{server_host}",
            "The certificate is issued for a name clients never ask for, so "
            "every client fails the TLS handshake with a name mismatch.",
            "Set tls_letsencrypt_hostname to the host in server_url, and make "
            "that name resolve to this server.",
            TLS_DOC,
        )


@register(
    "HS-006",
    "Two TLS sources configured at once",
    "server",
    TLS_DOC,
    ("config",),
    expected="TLS comes from Let's Encrypt or from a certificate file, not both",
)
def hs006(inv: Inventory) -> Iterator[Finding]:
    letsencrypt = str(inv.cfg("tls_letsencrypt_hostname", "") or "").strip()
    cert = str(inv.cfg("tls_cert_path", "") or "").strip()
    key = str(inv.cfg("tls_key_path", "") or "").strip()
    if letsencrypt and (cert or key):
        yield Finding(
            "HS-006",
            "Two TLS sources configured at once",
            "high",
            f"tls_letsencrypt_hostname: {letsencrypt}, tls_cert_path: "
            f"{cert or '(empty)'}, tls_key_path: {key or '(empty)'}",
            "Headscale 0.29 refuses to start with both set: 'set either "
            "tls_letsencrypt_hostname or tls_cert_path/tls_key_path, not both'.",
            "Keep one source and empty the other.",
            TLS_DOC,
        )


@register(
    "HS-007",
    "Noise private key path missing",
    "server",
    CFG_DOC,
    ("config",),
    expected="noise.private_key_path is set",
)
def hs007(inv: Inventory) -> Iterator[Finding]:
    if not str(inv.cfg("noise.private_key_path", "") or "").strip():
        yield Finding(
            "HS-007",
            "Noise private key path missing",
            "high",
            "noise.private_key_path: (unset)",
            "Headscale refuses to start without it: the key encrypts every "
            "control connection with the Tailscale v2 protocol.",
            "Set noise.private_key_path, for example "
            "/var/lib/headscale/noise_private.key; the file is generated on "
            "first start if absent.",
            EXAMPLE,
        )


@register(
    "HS-008",
    "Server secrets readable by other local users",
    "server",
    CFG_DOC,
    ("config",),
    expected="the Noise key, the DERP key and the database are mode 0600 or tighter",
)
def hs008(inv: Inventory) -> Iterator[Finding]:
    candidates = {
        "noise.private_key_path": inv.cfg("noise.private_key_path"),
        "derp.server.private_key_path": inv.cfg("derp.server.private_key_path"),
        "database.sqlite.path": inv.cfg("database.sqlite.path"),
    }
    seen: list[tuple[str, str, int]] = []
    unreadable: list[str] = []
    for field, raw in candidates.items():
        if not raw:
            continue
        path = _resolve(inv, str(raw))
        try:
            mode = os.stat(path).st_mode
        except OSError:
            unreadable.append(f"{field} -> {path}")
            continue
        seen.append((field, path, stat.S_IMODE(mode)))
    if not seen:
        raise SkipCheck(
            "file permissions can only be read on the headscale host; "
            + (
                "none of these paths exist here: " + ", ".join(unreadable)
                if unreadable
                else "no key or database path is configured"
            )
        )
    for field, path, mode in seen:
        if mode & 0o077:
            yield Finding(
                "HS-008",
                "Server secrets readable by other local users",
                "high",
                f"{field}: {path} has mode {mode:04o}",
                "The Noise key impersonates the control plane and the SQLite "
                "database holds node keys and API key hashes, so any local "
                "account that can read them owns the tailnet.",
                f"chmod 600 {path} and keep /var/lib/headscale owned by the "
                "headscale user.",
                EXAMPLE,
            )


@register(
    "HS-009",
    "Embedded DERP enabled without TLS",
    "server",
    DERP_DOC,
    ("config",),
    expected="the embedded DERP runs only with an https server_url",
)
def hs009(inv: Inventory) -> Iterator[Finding]:
    if not inv.cfg("derp.server.enabled", False):
        raise NotApplicable("derp.server.enabled is false")
    url = str(inv.cfg("server_url", "") or "")
    if not url.lower().startswith("https://"):
        yield Finding(
            "HS-009",
            "Embedded DERP enabled without TLS",
            "high",
            f"derp.server.enabled: true with server_url: {url}",
            "The configuration states that the embedded DERP requires TLS: "
            "with a plain HTTP server_url the relay clients are handed cannot "
            "be reached, so traffic that needs a relay simply fails.",
            "Terminate TLS and set an https:// server_url, or disable the "
            "embedded DERP and point derp.paths / derp.urls at a relay that "
            "has TLS.",
            DERP_DOC,
        )


@register(
    "HS-010",
    "Embedded DERP relays for any client",
    "server",
    DERP_DOC,
    ("config",),
    expected="derp.server.verify_clients is true",
)
def hs010(inv: Inventory) -> Iterator[Finding]:
    if not inv.cfg("derp.server.enabled", False):
        raise NotApplicable("derp.server.enabled is false")
    if inv.cfg("derp.server.verify_clients", True) is False:
        yield Finding(
            "HS-010",
            "Embedded DERP relays for any client",
            "high",
            "derp.server.enabled: true, derp.server.verify_clients: false",
            "With client verification off the relay forwards traffic for nodes "
            "that belong to no tailnet of yours, which turns the server into "
            "open bandwidth for anyone who finds the port.",
            "Set derp.server.verify_clients: true.",
            f"{REPO}/config-example.yaml",
        )


@register(
    "HS-011",
    "Embedded DERP without a STUN listener",
    "server",
    DERP_DOC,
    ("config",),
    expected="derp.server.stun_listen_addr is set when the embedded DERP is on",
)
def hs011(inv: Inventory) -> Iterator[Finding]:
    if not inv.cfg("derp.server.enabled", False):
        raise NotApplicable("derp.server.enabled is false")
    if not str(inv.cfg("derp.server.stun_listen_addr", "") or "").strip():
        yield Finding(
            "HS-011",
            "Embedded DERP without a STUN listener",
            "medium",
            "derp.server.enabled: true, derp.server.stun_listen_addr: (empty)",
            "The configuration requires stun_listen_addr when the embedded "
            "DERP is on; without STUN, nodes behind NAT never learn their "
            "public endpoint and stay on the relay instead of going direct.",
            "Set derp.server.stun_listen_addr (for example 0.0.0.0:3478) and "
            "open UDP 3478.",
            EXAMPLE,
        )


@register(
    "HS-012",
    "Relayed traffic falls back to the public DERP map",
    "server",
    DERP_DOC,
    ("config",),
    expected="relayed traffic uses a DERP you operate",
)
def hs012(inv: Inventory) -> Iterator[Finding]:
    if inv.cfg("derp.server.enabled", False):
        raise NotApplicable("the embedded DERP server is enabled")
    urls = [str(u) for u in (inv.cfg("derp.urls") or [])]
    paths = inv.cfg("derp.paths") or []
    public = [u for u in urls if "controlplane.tailscale.com" in u]
    if public and not paths:
        yield Finding(
            "HS-012",
            "Relayed traffic falls back to the public DERP map",
            "low",
            f"derp.urls: {quote(urls)}, derp.paths: {quote(list(paths))}, "
            "derp.server.enabled: false",
            "Nodes that cannot reach each other directly relay through "
            "Tailscale's own servers; the payload stays end to end encrypted, "
            "but availability and timing metadata leave the estate.",
            "Either accept this on purpose, or run the embedded DERP (with "
            "TLS) or a self-hosted derper and list it in derp.paths.",
            DERP_DOC,
        )


@register(
    "HS-013",
    "MagicDNS base domain collides with server_url",
    "server",
    DNS_DOC,
    ("config",),
    expected="dns.base_domain is neither equal to nor a suffix of the server_url host",
)
def hs013(inv: Inventory) -> Iterator[Finding]:
    base = str(inv.cfg("dns.base_domain", "") or "").strip().lower()
    if not base:
        raise NotApplicable("dns.base_domain is not set")
    server_host = host_of(str(inv.cfg("server_url", "") or ""))
    if not server_host:
        return
    same = server_host == base
    server_parts = server_host.split(".")
    base_parts = base.split(".")
    suffix = len(server_parts) > len(base_parts) and server_parts[
        -len(base_parts) :
    ] == base_parts
    if same or suffix:
        yield Finding(
            "HS-013",
            "MagicDNS base domain collides with server_url",
            "low",
            f"dns.base_domain: {base}, server_url host: {server_host}",
            "MagicDNS takes over the base domain on every node, so the "
            "control plane and DERP names under it stop resolving; headscale "
            "refuses to start in this state, which means a running server is "
            "not using this file.",
            "Give MagicDNS its own domain, for example base_domain: "
            "internal.example.net while the server lives on "
            "headscale.example.com.",
            DNS_DOC,
        )


@register(
    "HS-014",
    "override_local_dns without global nameservers",
    "server",
    DNS_DOC,
    ("config",),
    expected="dns.nameservers.global is populated when dns.override_local_dns is true",
)
def hs014(inv: Inventory) -> Iterator[Finding]:
    if not inv.cfg("dns.override_local_dns", False):
        raise NotApplicable("dns.override_local_dns is false")
    if not (inv.cfg("dns.nameservers.global") or []):
        yield Finding(
            "HS-014",
            "override_local_dns without global nameservers",
            "high",
            "dns.override_local_dns: true, dns.nameservers.global: []",
            "Headscale refuses to start with this combination, and a node that "
            "did receive it would have no resolver at all.",
            "List at least one resolver under dns.nameservers.global, or set "
            "dns.override_local_dns: false.",
            DNS_DOC,
        )


@register(
    "HS-015",
    "Node resolvers replaced tailnet-wide",
    "server",
    DNS_DOC,
    ("config",),
    expected="nodes keep a resolver that answers for their local names",
)
def hs015(inv: Inventory) -> Iterator[Finding]:
    if not inv.cfg("dns.override_local_dns", False):
        raise NotApplicable("dns.override_local_dns is false")
    servers = [str(s) for s in (inv.cfg("dns.nameservers.global") or [])]
    if not servers:
        raise NotApplicable("no global nameserver is pushed, see HS-014")
    split = inv.cfg("dns.nameservers.split") or {}
    yield Finding(
        "HS-015",
        "Node resolvers replaced tailnet-wide",
        "review",
        f"dns.override_local_dns: true, dns.nameservers.global: "
        f"{quote(servers)}, dns.nameservers.split keys: "
        f"{quote(sorted(split)) if split else '[]'}",
        "Every node that accepts DNS drops its own resolver for this list, "
        "which breaks names a cloud instance resolves locally (internal zones "
        "such as *.internal, or a metadata resolver) unless a split entry "
        "covers them.",
        "Add the internal zones under dns.nameservers.split, or enrol server "
        "instances with --accept-dns=false so they keep their local resolver.",
        DNS_DOC,
    )


# (removed key, replacement, "if_new_unset" | "always")
# "if_new_unset" mirrors headscale's fatalIfNewKeyIsNotUsed: fatal when the old
# key is present and the new one is not, deprecated-but-ignored when both are.
# "always" mirrors fatal / fatalIfSet: the key alone stops the server.
REMOVED_KEYS: tuple[tuple[str, str, str], ...] = (
    ("acl_policy_path", "policy.path", "if_new_unset"),
    ("dns_config.magic_dns", "dns.magic_dns", "if_new_unset"),
    ("dns_config.base_domain", "dns.base_domain", "if_new_unset"),
    ("dns_config.override_local_dns", "dns.override_local_dns", "if_new_unset"),
    ("dns_config.nameservers", "dns.nameservers.global", "if_new_unset"),
    ("dns_config.restricted_nameservers", "dns.nameservers.split", "if_new_unset"),
    ("dns_config.domains", "dns.search_domains", "if_new_unset"),
    ("dns_config.extra_records", "dns.extra_records", "if_new_unset"),
    ("dns.use_username_in_magic_dns", "", "always"),
    ("dns_config.use_username_in_magic_dns", "", "always"),
    ("oidc.strip_email_domain", "", "always"),
    ("oidc.map_legacy_users", "", "always"),
    ("randomize_client_port", 'the policy key "randomizeClientPort"', "always"),
    ("oidc.expiry", "node.expiry", "always"),
)

WARNED_KEYS: tuple[tuple[str, str], ...] = (
    ("ephemeral_node_inactivity_timeout", "node.ephemeral.inactivity_timeout"),
)


@register(
    "HS-016",
    "Configuration keys removed in this version",
    "server",
    CFG_DOC,
    ("config",),
    expected="the file carries no configuration key that 0.29 has removed",
)
def hs016(inv: Inventory) -> Iterator[Finding]:
    for old, new, mode in REMOVED_KEYS:
        if not inv.cfg_is_set(old):
            continue
        replaced = mode == "if_new_unset" and inv.cfg_is_set(new)
        severity = "medium" if replaced else "high"
        why = (
            "The key is dead in 0.29: it is read by nothing, so the setting it "
            "carries is silently not applied."
            if replaced
            else "Headscale 0.29 stops at startup when this key is present "
            "without its replacement, so the service will not come back after "
            "the next restart or upgrade."
        )
        yield Finding(
            "HS-016",
            "Configuration keys removed in this version",
            severity,
            f"{old}: {quote(inv.cfg(old))}"
            + (f" (replacement {new} is set)" if replaced else ""),
            why,
            f"Delete {old}" + (f" and use {new}." if new else "."),
            f"{REPO}/CHANGELOG.md",
        )
    for old, new in WARNED_KEYS:
        if inv.cfg_is_set(old) and not inv.cfg_is_set(new):
            yield Finding(
                "HS-016",
                "Configuration keys removed in this version",
                "low",
                f"{old}: {quote(inv.cfg(old))}",
                "The key still works but is deprecated and logs a warning at "
                "every start.",
                f"Move the value to {new}.",
                f"{REPO}/CHANGELOG.md",
            )


@register(
    "HS-017",
    "Ephemeral node timeout below the supported floor",
    "server",
    CFG_DOC,
    ("config",),
    expected="node.ephemeral.inactivity_timeout is above 65s",
)
def hs017(inv: Inventory) -> Iterator[Finding]:
    raw = inv.cfg("node.ephemeral.inactivity_timeout")
    if raw is None:
        raw = inv.cfg("ephemeral_node_inactivity_timeout")
    if raw is None:
        raise NotApplicable("not set, the 30m default applies")
    seconds = _duration_seconds(str(raw))
    if seconds is None:
        return
    if seconds <= 65:
        yield Finding(
            "HS-017",
            "Ephemeral node timeout below the supported floor",
            "high",
            f"node.ephemeral.inactivity_timeout: {raw}",
            "Headscale refuses to start below 65 seconds, the client keepalive "
            "window: shorter values delete nodes that are merely quiet.",
            "Raise it above 65s; the shipped default is 30m.",
            EXAMPLE,
        )


def _duration_seconds(text: str) -> float | None:
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    value = text.strip()
    if not value:
        return None
    if value.isdigit():
        return float(value)
    total = 0.0
    number = ""
    for char in value:
        if char.isdigit() or char == ".":
            number += char
        elif char in units and number:
            total += float(number) * units[char]
            number = ""
        else:
            return None
    return total if not number else None


@register(
    "HS-018",
    "CLI socket open to every local account",
    "server",
    CFG_DOC,
    ("config",),
    expected="unix_socket_permission grants nothing to other users",
)
def hs018(inv: Inventory) -> Iterator[Finding]:
    raw = inv.cfg("unix_socket_permission")
    if raw in (None, ""):
        return
    try:
        mode = int(str(raw), 8)
    except ValueError:
        return
    if mode & 0o007:
        yield Finding(
            "HS-018",
            "CLI socket open to every local account",
            "high",
            f"unix_socket_permission: {quote(raw)} "
            f"(socket {inv.cfg('unix_socket', '(default)')})",
            "The socket is the door the CLI uses without any authentication, "
            "so any local account that can open it can create users, keys and "
            "API keys.",
            'Set unix_socket_permission: "0770" and put the operators in the '
            "socket's group.",
            EXAMPLE,
        )


@register(
    "HS-019",
    "Proxy headers trusted from everywhere",
    "server",
    CFG_DOC,
    ("config",),
    expected="trusted_proxies lists the reverse proxies, not the whole internet",
)
def hs019(inv: Inventory) -> Iterator[Finding]:
    proxies = [str(p) for p in (inv.cfg("trusted_proxies") or [])]
    broad = [p for p in proxies if p.strip() in {"0.0.0.0/0", "::/0", "*"}]
    if broad:
        yield Finding(
            "HS-019",
            "Proxy headers trusted from everywhere",
            "medium",
            f"trusted_proxies: {quote(proxies)}",
            "Headscale then honours True-Client-IP, X-Real-IP and "
            "X-Forwarded-For from any source, so a client picks the address "
            "that lands in the logs and in anything built on them.",
            "List only the addresses of your reverse proxies, for example "
            "[127.0.0.1/32].",
            EXAMPLE,
        )


@register(
    "HS-020",
    "Client logs shipped to Tailscale",
    "server",
    CFG_DOC,
    ("config",),
    expected="logtail.enabled is false",
)
def hs020(inv: Inventory) -> Iterator[Finding]:
    if inv.cfg("logtail.enabled", False):
        yield Finding(
            "HS-020",
            "Client logs shipped to Tailscale",
            "medium",
            "logtail.enabled: true",
            "The configuration is explicit that enabling this makes your "
            "clients send their logs to Tailscale Inc, which is rarely what a "
            "self-hosted control plane is for.",
            "Set logtail.enabled: false.",
            EXAMPLE,
        )


@register(
    "HS-021",
    "SQLite write-ahead log disabled",
    "server",
    CFG_DOC,
    ("config",),
    expected="database.sqlite.write_ahead_log is true",
)
def hs021(inv: Inventory) -> Iterator[Finding]:
    engine = str(inv.cfg("database.type", "sqlite")).lower()
    if engine != "sqlite":
        raise NotApplicable(f"database.type is {engine}")
    if not inv.cfg_is_set("database.sqlite.write_ahead_log"):
        return  # unset means the recommended default (true) applies
    if inv.cfg("database.sqlite.write_ahead_log") is False:
        yield Finding(
            "HS-021",
            "SQLite write-ahead log disabled",
            "low",
            "database.sqlite.write_ahead_log: false",
            "WAL is the documented recommendation for production; without it "
            "writers block readers and a crash is more likely to leave the "
            "database in a state that needs recovery.",
            "Set database.sqlite.write_ahead_log: true, and back up the "
            "database file with a scheduled copy (sqlite3 .backup).",
            EXAMPLE,
        )


@register(
    "HS-022",
    "OIDC accepts every account of the provider",
    "server",
    OIDC_DOC,
    ("config",),
    expected="OIDC registration is restricted to accounts you control",
)
def hs022(inv: Inventory) -> Iterator[Finding]:
    issuer = str(inv.cfg("oidc.issuer", "") or "").strip()
    if not issuer:
        raise NotApplicable("oidc.issuer is not set")
    allow = {
        "oidc.allowed_domains": inv.cfg("oidc.allowed_domains") or [],
        "oidc.allowed_users": inv.cfg("oidc.allowed_users") or [],
        "oidc.allowed_groups": inv.cfg("oidc.allowed_groups") or [],
    }
    if any(allow.values()):
        return
    host = host_of(issuer)
    multi_tenant = host in MULTI_TENANT_ISSUERS or (
        host == "login.microsoftonline.com"
        and ("/common" in issuer or "/consumers" in issuer)
    )
    if multi_tenant:
        yield Finding(
            "HS-022",
            "OIDC accepts every account of the provider",
            "high",
            f"oidc.issuer: {issuer}; oidc.allowed_domains, allowed_users and "
            "allowed_groups are all empty",
            "This issuer authenticates accounts far beyond your organisation, "
            "so registration succeeds for anyone who can sign in there, not "
            "for your staff.",
            "Set oidc.allowed_domains to your mail domains, or pin "
            "oidc.allowed_groups to a group that exists in the provider.",
            OIDC_DOC,
        )
        return
    yield Finding(
        "HS-022",
        "OIDC accepts every account of the provider",
        "review",
        f"oidc.issuer: {issuer}; oidc.allowed_domains, allowed_users and "
        "allowed_groups are all empty",
        "Headscale applies no restriction of its own here: whoever the "
        "identity provider authenticates may register a node, which is safe "
        "only if the provider itself is limited to your people.",
        "Answer one question: can an account outside the organisation sign in "
        "to this issuer? If yes, add oidc.allowed_domains or "
        "oidc.allowed_groups; if the restriction lives in the provider (an "
        "app assignment, a dedicated realm), record where.",
        OIDC_DOC,
    )


@register(
    "HS-023",
    "OIDC client secret stored in the configuration file",
    "server",
    OIDC_DOC,
    ("config",),
    expected="the OIDC client secret is read from a file, not stored in config.yaml",
)
def hs023(inv: Inventory) -> Iterator[Finding]:
    if not str(inv.cfg("oidc.issuer", "") or "").strip():
        raise NotApplicable("oidc.issuer is not set")
    secret = str(inv.cfg("oidc.client_secret", "") or "").strip()
    if not secret:
        return
    yield Finding(
        "HS-023",
        "OIDC client secret stored in the configuration file",
        "medium",
        "oidc.client_secret is set inline (value not shown)",
        "config.yaml is the file most likely to be copied into a repository, "
        "a backup or a support ticket, and this value lets its holder "
        "impersonate the login flow.",
        "Move it to oidc.client_secret_path, which also resolves environment "
        "variables such as ${CREDENTIALS_DIRECTORY}/oidc_client_secret.",
        OIDC_DOC,
    )


@register(
    "HS-024",
    "OIDC without PKCE",
    "server",
    OIDC_DOC,
    ("config",),
    expected="oidc.pkce.enabled is true with method S256",
)
def hs024(inv: Inventory) -> Iterator[Finding]:
    if not str(inv.cfg("oidc.issuer", "") or "").strip():
        raise NotApplicable("oidc.issuer is not set")
    enabled = bool(inv.cfg("oidc.pkce.enabled", False))
    method = str(inv.cfg("oidc.pkce.method", "S256") or "S256")
    if enabled and method.upper() == "S256":
        return
    yield Finding(
        "HS-024",
        "OIDC without PKCE",
        "low" if not enabled else "medium",
        f"oidc.pkce.enabled: {quote(enabled)}, oidc.pkce.method: {method}",
        "PKCE is what stops an intercepted authorization code from being "
        "exchanged by someone else; without it the login flow leans entirely "
        "on the redirect being private.",
        "Set oidc.pkce.enabled: true and oidc.pkce.method: S256, then confirm "
        "the provider accepts it.",
        OIDC_DOC,
    )


@register(
    "HS-025",
    "OIDC accepts unverified email addresses",
    "server",
    OIDC_DOC,
    ("config",),
    expected="oidc.email_verified_required stays true",
)
def hs025(inv: Inventory) -> Iterator[Finding]:
    if not str(inv.cfg("oidc.issuer", "") or "").strip():
        raise NotApplicable("oidc.issuer is not set")
    if inv.cfg("oidc.email_verified_required", True) is not False:
        return
    yield Finding(
        "HS-025",
        "OIDC accepts unverified email addresses",
        "medium",
        "oidc.email_verified_required: false",
        "The email claim is what maps an identity to a headscale user and to "
        "oidc.allowed_domains; accepting it unverified lets a provider that "
        "does not check ownership decide who you are.",
        "Set oidc.email_verified_required: true, and fix the provider if it "
        "does not send email_verified.",
        OIDC_DOC,
    )


@register(
    "HS-026",
    "Server version outside the audited baseline",
    "server",
    f"{REPO}/CHANGELOG.md",
    ("server_version",),
    expected="the server runs the 0.29.x line these controls were written for",
)
def hs026(inv: Inventory) -> Iterator[Finding]:
    version = (inv.server_version or "").strip()
    if not version:
        raise SkipCheck("the server did not report a version")
    normalised = version.lstrip("v")
    if normalised.startswith("0.29."):
        return
    yield Finding(
        "HS-026",
        "Server version outside the audited baseline",
        "review",
        f"server reports version {version}; controls were written against "
        "0.29.3",
        "Headscale moves configuration keys and policy semantics between "
        "minor versions, so a control can be right about 0.29 and wrong about "
        "the version actually running here.",
        "Re-read the findings against the CHANGELOG of the running version, "
        "or run the audit from a release of this tool that targets it.",
        f"{REPO}/CHANGELOG.md",
    )
