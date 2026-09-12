# Controls

Every control asserts one condition against Headscale 0.29.3. A
control that cannot read what it needs is reported as NOT_EVALUATED, never as a
pass; one that does not apply to the deployment is NOT_APPLICABLE; one that
cannot conclude on its own is UNKNOWN, with the question it wants answered.

Regenerate this file with `python scripts/gen_checks_doc.py`.

## Server configuration

| Id | Control | Asserts | Reference |
| --- | --- | --- | --- |
| `HS-001` | Control plane served over plain HTTP | server_url uses https:// | [doc](https://headscale.net/0.29.3/ref/tls/) |
| `HS-002` | Metrics and debug listener reachable off-host | metrics_listen_addr is empty or bound to a loopback address | [doc](https://headscale.net/0.29.3/ref/configuration/) |
| `HS-003` | gRPC admin interface allowed to run unencrypted | grpc_allow_insecure is false | [doc](https://headscale.net/0.29.3/ref/api/) |
| `HS-004` | HTTPS advertised but no certificate configured | an https server_url comes with a certificate source headscale itself can use | [doc](https://headscale.net/0.29.3/ref/tls/) |
| `HS-005` | Let's Encrypt hostname does not match server_url | tls_letsencrypt_hostname is the host in server_url | [doc](https://headscale.net/0.29.3/ref/tls/) |
| `HS-006` | Two TLS sources configured at once | TLS comes from Let's Encrypt or from a certificate file, not both | [doc](https://headscale.net/0.29.3/ref/tls/) |
| `HS-007` | Noise private key path missing | noise.private_key_path is set | [doc](https://headscale.net/0.29.3/ref/configuration/) |
| `HS-008` | Server secrets readable by other local users | the Noise key, the DERP key and the database are mode 0600 or tighter | [doc](https://headscale.net/0.29.3/ref/configuration/) |
| `HS-009` | Embedded DERP enabled without TLS | the embedded DERP runs only with an https server_url | [doc](https://headscale.net/0.29.3/ref/derp/) |
| `HS-010` | Embedded DERP relays for any client | derp.server.verify_clients is true | [doc](https://headscale.net/0.29.3/ref/derp/) |
| `HS-011` | Embedded DERP without a STUN listener | derp.server.stun_listen_addr is set when the embedded DERP is on | [doc](https://headscale.net/0.29.3/ref/derp/) |
| `HS-012` | Relayed traffic falls back to the public DERP map | relayed traffic uses a DERP you operate | [doc](https://headscale.net/0.29.3/ref/derp/) |
| `HS-013` | MagicDNS base domain collides with server_url | dns.base_domain is neither equal to nor a suffix of the server_url host | [doc](https://headscale.net/0.29.3/ref/dns/) |
| `HS-014` | override_local_dns without global nameservers | dns.nameservers.global is populated when dns.override_local_dns is true | [doc](https://headscale.net/0.29.3/ref/dns/) |
| `HS-015` | Node resolvers replaced tailnet-wide | nodes keep a resolver that answers for their local names | [doc](https://headscale.net/0.29.3/ref/dns/) |
| `HS-016` | Configuration keys removed in this version | the file carries no configuration key that 0.29 has removed | [doc](https://headscale.net/0.29.3/ref/configuration/) |
| `HS-017` | Ephemeral node timeout below the supported floor | node.ephemeral.inactivity_timeout is above 65s | [doc](https://headscale.net/0.29.3/ref/configuration/) |
| `HS-018` | CLI socket open to every local account | unix_socket_permission grants nothing to other users | [doc](https://headscale.net/0.29.3/ref/configuration/) |
| `HS-019` | Proxy headers trusted from everywhere | trusted_proxies lists the reverse proxies, not the whole internet | [doc](https://headscale.net/0.29.3/ref/configuration/) |
| `HS-020` | Client logs shipped to Tailscale | logtail.enabled is false | [doc](https://headscale.net/0.29.3/ref/configuration/) |
| `HS-021` | SQLite write-ahead log disabled | database.sqlite.write_ahead_log is true | [doc](https://headscale.net/0.29.3/ref/configuration/) |
| `HS-022` | OIDC accepts every account of the provider | OIDC registration is restricted to accounts you control | [doc](https://headscale.net/0.29.3/ref/oidc/) |
| `HS-023` | OIDC client secret stored in the configuration file | the OIDC client secret is read from a file, not stored in config.yaml | [doc](https://headscale.net/0.29.3/ref/oidc/) |
| `HS-024` | OIDC without PKCE | oidc.pkce.enabled is true with method S256 | [doc](https://headscale.net/0.29.3/ref/oidc/) |
| `HS-025` | OIDC accepts unverified email addresses | oidc.email_verified_required stays true | [doc](https://headscale.net/0.29.3/ref/oidc/) |
| `HS-026` | Server version outside the audited baseline | the server runs the 0.29.x line these controls were written for | [doc](https://github.com/juanfont/headscale/blob/v0.29.3/CHANGELOG.md) |

## Access control policy

| Id | Control | Asserts | Reference |
| --- | --- | --- | --- |
| `HS-030` | No access control policy loaded | a policy is loaded | [doc](https://headscale.net/0.29.3/ref/policy/) |
| `HS-031` | Policy loaded but grants no rule at all | the policy declares acls or grants | [doc](https://headscale.net/0.29.3/ref/policy/) |
| `HS-032` | Rule opens every source to every destination | no rule pairs an unrestricted source with an unrestricted destination | [doc](https://headscale.net/0.29.3/ref/policy/) |
| `HS-033` | Rule source is not scoped to a user, group or tag | every accepting rule names its source | [doc](https://headscale.net/0.29.3/ref/policy/) |
| `HS-034` | Policy source includes addresses outside the tailnet | no rule takes autogroup:danger-all as its source | [doc](https://headscale.net/0.29.3/ref/policy/) |
| `HS-035` | Tag used in the policy has no owner | every tag the policy uses has an owner in tagOwners | [doc](https://headscale.net/0.29.3/ref/tags/) |
| `HS-036` | Tailscale SSH rule is too broad | SSH rules name their source, their destination and their login users | [doc](https://tailscale.com/kb/1193/tailscale-ssh) |
| `HS-037` | Policy has no tests section | the policy carries tests | [doc](https://headscale.net/0.29.3/ref/policy/) |
| `HS-038` | Host declared in the policy but never used | every declared host is used by a rule | [doc](https://headscale.net/0.29.3/ref/policy/) |
| `HS-039` | Group empty or never used | every declared group has members and is used by a rule | [doc](https://headscale.net/0.29.3/ref/policy/) |
| `HS-040` | Auto-approved routes are too broad | auto-approval covers specific prefixes owned by specific tags | [doc](https://headscale.net/0.29.3/ref/routes/) |
| `HS-041` | Policy does not parse | the policy document parses as huJSON | [doc](https://headscale.net/0.29.3/ref/policy/) |
| `HS-042` | Policy contains sections this audit does not read | every section of the policy is one this tool analyses | [doc](https://headscale.net/0.29.3/ref/policy/) |
| `HS-043` | Policy rejected by the headscale binary | headscale policy check accepts the policy file | [doc](https://headscale.net/0.29.3/ref/policy/) |

## Nodes, routes and users

| Id | Control | Asserts | Reference |
| --- | --- | --- | --- |
| `HS-050` | Node key never expires | untagged nodes have a key expiry | [doc](https://headscale.net/0.29.3/ref/configuration/) |
| `HS-051` | Expired node still registered | no expired node is left registered | [doc](https://headscale.net/0.29.3/ref/registration/) |
| `HS-052` | Node not seen for a long time | every registered node has been seen recently | [doc](https://headscale.net/0.29.3/ref/registration/) |
| `HS-053` | Subnet router or exit node has no tag | nodes that carry routes are tagged | [doc](https://headscale.net/0.29.3/ref/tags/) |
| `HS-054` | Several nodes share one hostname | node names are unique | [doc](https://headscale.net/0.29.3/ref/registration/) |
| `HS-055` | Advertised route waiting for approval | advertised routes are either approved or not advertised | [doc](https://headscale.net/0.29.3/ref/routes/) |
| `HS-056` | Exit node approved for the whole tailnet | an approved exit node is paired with a policy that says who may use it | [doc](https://headscale.net/0.29.3/ref/routes/) |
| `HS-057` | User account with no node | every user account owns at least one node | [doc](https://headscale.net/0.29.3/ref/registration/) |

## Pre-auth keys and API keys

| Id | Control | Asserts | Reference |
| --- | --- | --- | --- |
| `HS-060` | Pre-auth key without expiry | every usable pre-auth key has an expiry | [doc](https://tailscale.com/kb/1085/auth-keys) |
| `HS-061` | Reusable pre-auth key valid for a long time | reusable pre-auth keys are short lived | [doc](https://tailscale.com/kb/1085/auth-keys) |
| `HS-062` | Pre-auth key carries a tag the policy does not own | the tags carried by pre-auth keys exist in tagOwners | [doc](https://headscale.net/0.29.3/ref/tags/) |
| `HS-063` | API key long-lived or without expiry | API keys expire within the upstream default window | [doc](https://headscale.net/0.29.3/ref/api/) |
| `HS-064` | Expired credential left in place | expired credentials are deleted | [doc](https://headscale.net/0.29.3/ref/registration/) |

## Fleet coverage

| Id | Control | Asserts | Reference |
| --- | --- | --- | --- |
| `HS-070` | Instances missing from the tailnet | every running instance of the inventory is a node in headscale | [doc](https://headscale.net/0.29.3/ref/registration/) |
| `HS-071` | Tagged node with no matching instance | every tagged node corresponds to an instance of the inventory | [doc](https://headscale.net/0.29.3/ref/registration/) |
| `HS-072` | Instance enrolled but not connecting | every enrolled instance is online or was seen recently | [doc](https://headscale.net/0.29.3/ref/registration/) |

