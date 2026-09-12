# Rolling Tailscale clients out to a fleet

Three ways in, one implementation: `enroll.sh`. The Ansible role copies it and
runs it, the GCE startup script downloads it and runs it, and an operator on a
box runs it by hand. Nothing else knows how to register a node.

```
enroll.sh                 idempotent enrolment of one machine
probe.sh                  run it ON a machine that will not join
gce-startup-script.sh     first boot enrolment, key from Secret Manager
ansible/                  role, example GCE inventory, playbook
```

`enroll.sh` is exercised on the laboratory by `lab/rollout_test.sh`: a blank
node enrols, a second run changes nothing, the daemon restarts and keeps its
identity, an expired key fails with an explanation, and pointing an enrolled
node at another control server is refused. Same file as the one you ship.

## Six reasons a rollout stops, and where each one is visible

| Symptom on the machine | Cause | Where it is caught |
| --- | --- | --- |
| `backend error: authkey expired` | the key ran out, or a single use key was used twice | `enroll.sh` exits 3 with that line; `headscale-audit` reports keys with no expiry as **HS-060** and expired ones as **HS-064** |
| `requested tags [tag:x] are invalid or not permitted` | the user that owns the key does not own the tag in the policy | **HS-062** (key tag not in `tagOwners`) and **HS-035** (tag used with no owner), before anyone tries |
| the same message, with a key that is fine | `tailscale up` was given `--advertise-tags` **and** a pre-auth key: headscale 0.28+ takes the tags from the key and rejects the pair | `enroll.sh` never passes `--advertise-tags`; put the tags on the key |
| `tailscale up` hangs, then times out | the control server is not reachable from that subnet, or TLS fails there | `probe.sh` checks 1 to 3: name resolution, tcp port, `/health`, certificate dates |
| enrolled, but every peer is relayed and slow | inbound **UDP 41641** is closed, so no direct path is ever established | `probe.sh` check 7 prints `direct=` and `relayed=` counts; **HS-011** catches a DERP with no STUN, **HS-012** a deployment leaning on the public relays |
| key looks expired although it was just issued, or the certificate is rejected | the clock drifted | `probe.sh` check 4 compares the machine's clock with the server's `Date` header |

Two more, specific to a fleet that already exists:

- **`requires mentioning all non-default flags`**: the machine has settings from
  an earlier attempt. `enroll.sh` exits 6 and prints them rather than resetting
  them behind your back; re-run with `ALLOW_RESET=1` once you have read them.
- **already registered to another control server**: `enroll.sh` exits 5.
  Migrating changes the node's identity and address, so it takes
  `ALLOW_MIGRATE=1`.

Two that break DNS rather than enrolment, and that the audit catches from the
server side: **HS-013** (MagicDNS `base_domain` equal to, or a parent of, the
`server_url` host: headscale refuses to start) and **HS-015** (`override_local_dns`
replacing the resolver of every node, which on GCE takes `*.internal` and the
metadata resolver with it).

## Keys

Two strategies, both supported by `enroll.sh`:

1. **One key per machine**, issued by whatever orchestrates the rollout, with a
   short expiry. Best audit trail, needs a control machine that can reach the
   headscale API.
2. **One reusable key per role**, short lived (hours, not months), one per tag.
   Simpler for a startup script; rotate it from the pipeline that consumes it.

For instance groups that scale in and out, add `--ephemeral`: the node removes
itself when it goes away instead of accumulating as an offline entry.

```shell
headscale preauthkeys create --user <USER_ID> --tags tag:web --expiration 1h
headscale preauthkeys create --user <USER_ID> --tags tag:ci --ephemeral --expiration 1h
```

The key never travels as an argument. `enroll.sh` hands it to tailscale as
`--auth-key=file:<path>` (Tailscale 1.80+), so it stays out of the process
list, out of shell traces and out of `journalctl`. On GCE it lives in Secret
Manager and is read at boot by the instance's own service account: not in the
image, not in the instance metadata, not in the Terraform state.

## Firewall

| Direction | Port | Why |
| --- | --- | --- |
| out, from every node | tcp 443 (or 80) to the control server | registration and the control connection |
| in, to every node | **udp 41641** | direct peer to peer; without it everything falls back to a relay |
| out, from every node | udp 3478 to your STUN/DERP | NAT traversal, when you run the embedded DERP |
| out, from every node | tcp 443 to the DERP servers in your map | the relay path itself |
| in, to the DERP host | tcp 443 and udp 3478 | only if you host the relay |

On GCE the inbound rule is a VPC firewall rule on the network tag of the
instances, not an OS level rule.

## What this does not cover

`enroll.sh` assumes a Linux machine with systemd and one of the package
managers the official installer supports. It does not build images, does not
manage the lifetime of the instance, and does not touch an existing startup
script: on a fleet that already exists, call it from whatever configuration
management is already in place.
