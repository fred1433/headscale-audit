# Headscale audit report

- Generated: 2026-09-12T13:16:09+00:00
- Source: config /Users/frederic/ProjetsDev/headscale-audit/lab/.run/config.yaml + API http://127.0.0.1:18080
- Read: config `/Users/frederic/ProjetsDev/headscale-audit/lab/.run/config.yaml`, policy `/Users/frederic/ProjetsDev/headscale-audit/lab/.run/policy.hujson`, 3 nodes, 1 users, 3 pre-auth keys, 3 API keys
- Tool: headscale-audit 0.1.0; controls written against Headscale 0.29.3; server reports v0.29.3
- Policy mode: file (the file on disk, which is what a reload would load, not proof of what the running server holds in memory)

Scope: this audit reads what it was given. It does not scan the network, does not connect to nodes, and never writes to the server. Headscale also reads HEADSCALE_* environment variables, which override the file and are invisible from here.

## Result

| Status | Controls |
| --- | --- |
| FAIL | 2 |
| UNKNOWN | 0 |
| PASS | 36 |
| NOT_APPLICABLE | 15 |
| NOT_EVALUATED | 0 |
| ERROR | 0 |

2 finding(s): 2 high, 0 medium, 0 low, 0 to verify. A control that is NOT_EVALUATED is not a pass: it had nothing to read.

> Note: The API also returns a policy; the file given on the command line is the one audited.

## Findings

| Severity | Id | Finding |
| --- | --- | --- |
| high | HS-001 | Control plane served over plain HTTP |
| high | HS-008 | Server secrets readable by other local users |

### HS-001 [high] Control plane served over plain HTTP

- **Expected**: server_url uses https://
- **Read**: server_url: http://127.0.0.1:18080
- **Why it matters**: Clients fetch the control plane's Noise public key from server_url/key over this scheme, so anyone in path can answer instead of the server, and the embedded DERP relay cannot be enabled without TLS.
- **Fix**: Put headscale behind TLS (tls_letsencrypt_hostname, or tls_cert_path/tls_key_path, or a reverse proxy) and set server_url to the https:// URL.
- **Reference**: https://headscale.net/0.29.3/ref/tls/

### HS-008 [high] Server secrets readable by other local users

- **Expected**: the Noise key, the DERP key and the database are mode 0600 or tighter
- **Read**: database.sqlite.path: /Users/frederic/ProjetsDev/headscale-audit/lab/.run/db.sqlite has mode 0644
- **Why it matters**: The Noise key impersonates the control plane and the SQLite database holds node keys and API key hashes, so any local account that can read them owns the tailnet.
- **Fix**: chmod 600 /Users/frederic/ProjetsDev/headscale-audit/lab/.run/db.sqlite and keep /var/lib/headscale owned by the headscale user.
- **Reference**: https://github.com/juanfont/headscale/blob/v0.29.3/config-example.yaml

## Not applicable

These controls do not apply to this deployment.

| Id | Control | Reason |
| --- | --- | --- |
| HS-004 | HTTPS advertised but no certificate configured | server_url is not https (http://127.0.0.1:18080) |
| HS-005 | Let's Encrypt hostname does not match server_url | tls_letsencrypt_hostname is empty, ACME is not used |
| HS-009 | Embedded DERP enabled without TLS | derp.server.enabled is false |
| HS-010 | Embedded DERP relays for any client | derp.server.enabled is false |
| HS-011 | Embedded DERP without a STUN listener | derp.server.enabled is false |
| HS-014 | override_local_dns without global nameservers | dns.override_local_dns is false |
| HS-015 | Node resolvers replaced tailnet-wide | dns.override_local_dns is false |
| HS-022 | OIDC accepts every account of the provider | oidc.issuer is not set |
| HS-023 | OIDC client secret stored in the configuration file | oidc.issuer is not set |
| HS-024 | OIDC without PKCE | oidc.issuer is not set |
| HS-025 | OIDC accepts unverified email addresses | oidc.issuer is not set |
| HS-036 | Tailscale SSH rule is too broad | the policy declares no ssh section |
| HS-038 | Host declared in the policy but never used | the policy declares no hosts |
| HS-039 | Group empty or never used | the policy declares no groups |
| HS-040 | Auto-approved routes are too broad | the policy declares no autoApprovers |

## Passed

- Server configuration: HS-002, HS-003, HS-006, HS-007, HS-012, HS-013, HS-016, HS-017, HS-018, HS-019, HS-020, HS-021, HS-026
- Access control policy: HS-030, HS-031, HS-032, HS-033, HS-034, HS-035, HS-037, HS-041, HS-042, HS-043
- Nodes, routes and users: HS-050, HS-051, HS-052, HS-053, HS-054, HS-055, HS-056, HS-057
- Pre-auth keys and API keys: HS-060, HS-061, HS-062, HS-063, HS-064

<details><summary>What each passing control asserts</summary>

| Id | Asserted |
| --- | --- |
| HS-002 | metrics_listen_addr is empty or bound to a loopback address |
| HS-003 | grpc_allow_insecure is false |
| HS-006 | TLS comes from Let's Encrypt or from a certificate file, not both |
| HS-007 | noise.private_key_path is set |
| HS-012 | relayed traffic uses a DERP you operate |
| HS-013 | dns.base_domain is neither equal to nor a suffix of the server_url host |
| HS-016 | the file carries no configuration key that 0.29 has removed |
| HS-017 | node.ephemeral.inactivity_timeout is above 65s |
| HS-018 | unix_socket_permission grants nothing to other users |
| HS-019 | trusted_proxies lists the reverse proxies, not the whole internet |
| HS-020 | logtail.enabled is false |
| HS-021 | database.sqlite.write_ahead_log is true |
| HS-026 | the server runs the 0.29.x line these controls were written for |
| HS-030 | a policy is loaded |
| HS-031 | the policy declares acls or grants |
| HS-032 | no rule pairs an unrestricted source with an unrestricted destination |
| HS-033 | every accepting rule names its source |
| HS-034 | no rule takes autogroup:danger-all as its source |
| HS-035 | every tag the policy uses has an owner in tagOwners |
| HS-037 | the policy carries tests |
| HS-041 | the policy document parses as huJSON |
| HS-042 | every section of the policy is one this tool analyses |
| HS-043 | headscale policy check accepts the policy file |
| HS-050 | untagged nodes have a key expiry |
| HS-051 | no expired node is left registered |
| HS-052 | every registered node has been seen recently |
| HS-053 | nodes that carry routes are tagged |
| HS-054 | node names are unique |
| HS-055 | advertised routes are either approved or not advertised |
| HS-056 | an approved exit node is paired with a policy that says who may use it |
| HS-057 | every user account owns at least one node |
| HS-060 | every usable pre-auth key has an expiry |
| HS-061 | reusable pre-auth keys are short lived |
| HS-062 | the tags carried by pre-auth keys exist in tagOwners |
| HS-063 | API keys expire within the upstream default window |
| HS-064 | expired credentials are deleted |

</details>

---

Read-only output: headscale-audit issues HTTP GET only, runs no command against the server, and prints no key material.
