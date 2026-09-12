# headscale-audit

[![ci](https://github.com/fred1433/headscale-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/fred1433/headscale-audit/actions/workflows/ci.yml)

A versioned configuration audit for a self-hosted [Headscale](https://headscale.net)
control plane, and a reproducible enrolment harness for the machines that have
to join it. Read only: it issues HTTP GET and nothing else, calls no AI service,
needs no key of its own, and prints no key material.

Point it at a `config.yaml`, a policy file and an export of the nodes; get back
a Markdown and JSON report where every finding carries what was read, why it
matters, and the fix.

## Install and run

```shell
pipx install .           # or: uv run headscale-audit --help

# offline, on the headscale host, nothing leaves the machine
headscale-audit --config /etc/headscale/config.yaml \
                --policy /etc/headscale/policy.hujson

# with the inventory, from a CLI export
headscale nodes list --output json > nodes.json     # same for users,
headscale-audit --config /etc/headscale/config.yaml --nodes nodes.json

# or through the REST API, with a short lived key
HEADSCALE_API_KEY=... headscale-audit --api-url https://headscale.example.com \
                --config /etc/headscale/config.yaml --format both \
                --output report.md --json-output report.json
```

`REPORT.md` is the real output of the laboratory below, not an illustration.

## The controls

56 controls over five areas: server configuration (26), access control policy
(14), nodes, routes and users (8), pre-auth and API keys (5), fleet coverage
(3). The full table,
with the exact condition each one asserts, is in
[`docs/checks.md`](docs/checks.md); `headscale-audit --list-checks` prints it too.

A few that matter in practice: a policy that is absent or wide open (HS-030 to
HS-034), a tag used by a key that no `tagOwners` entry grants, which is the
usual reason a fleet rollout stops (HS-062), the CLI socket left world writable
(HS-018), OIDC with no allow list on a multi-tenant issuer (HS-022), keys that
never expire (HS-060), and configuration keys removed in 0.29 that stop the
server at its next restart (HS-016).

Every control ends in one of PASS, FAIL, UNKNOWN, NOT_APPLICABLE,
NOT_EVALUATED or ERROR, and the report counts them. A control that could not
read what it needs is never reported as a pass, and a control that is not sure
says so instead of raising a false alarm.

## Fleet coverage

Pass an instance inventory and the report gains a coverage table: one line per
machine, saying whether it is in the tailnet, which tags it carries, when it
was last seen and what to look at next.

```shell
gcloud compute instances list --format=json > instances.json
headscale-audit --config /etc/headscale/config.yaml --nodes nodes.json \
                --gce-inventory instances.json
```

Machines that never appear in headscale are the ones the rollout never
reached; `rollout/probe.sh` says which step fails on one of them.

## The laboratory

`lab/up.sh` builds a real tailnet on one machine: the official Headscale
**0.29.3** binary and three **Tailscale 1.102.3** clients in userspace
networking, no Docker, no root, no TUN device. `lab/verify.sh` then proves,
against those processes:

- each node sees the other two;
- the tags the server applied are the tags the pre-auth keys carried;
- with a restrictive policy, `lab-a` reaches `lab-b` on the port a grant opens,
  `lab-c` does not, and `lab-c` loses the peers from its netmap;
- adding one grant flips that, removing it flips it back;
- the final policy carries tests that `headscale policy check` evaluates.

Connections are made through each node's own SOCKS5 proxy, never from the host:
in userspace networking there is no interface to test from.

The same scenario runs in CI on `ubuntu-latest` with the official
`headscale/headscale` and `tailscale/tailscale` images, pinned by digest, in
`TS_USERSPACE` mode. The badge above is that run.

## The rollout half

`rollout/enroll.sh` enrols one machine and converges on a declared state:
already enrolled is a no-op, settings that differ are reported instead of
reset, a node registered against another control server is refused, and an
expired key produces an explanation. The key reaches tailscale as
`--auth-key=file:<path>`, so it stays out of the process list and the logs.
Tags come from the key, never from `--advertise-tags`: since Headscale 0.28 a
pre-auth key registration that also advertises tags is rejected outright.

The same script is driven by `rollout/ansible/` and by
`rollout/gce-startup-script.sh` (key read at boot from Secret Manager).
`rollout/probe.sh` runs on a machine that will not join and tests the six
things that usually explain it: name resolution, the control port, TLS, the
clock, the package source and the peer paths.
[`rollout/README.md`](rollout/README.md) maps each symptom to the control that
catches it.

`lab/rollout_test.sh` runs that exact script against the laboratory: blank node
enrols, second run is a no-op, restart keeps the identity, expired key exits 3,
foreign control server exits 5.

## Development

```shell
uv run --extra dev pytest -q       # the suite, no install step needed
python scripts/gen_checks_doc.py   # regenerate docs/checks.md
./lab/up.sh && ./lab/audit.sh && ./lab/down.sh
```

## What it does not do

- No network scan, no connection to your nodes, no write of any kind.
- Headscale API keys are administrative, there is no read-only scope: prefer
  the offline export, and use a short lived key for a connected run.
- A userspace laboratory proves the control plane and the policy, not systemd
  units, TUN interfaces or Linux firewall rules; nothing here has been run
  against a live GCE project.
- Headscale also reads `HEADSCALE_*` environment variables, which override the
  file and are invisible to an audit of that file.
- The controls are written against 0.29.3. On another version the tool says so
  (HS-026) rather than pretending.

MIT licensed. Frederic de Lavenne de Choulot, The AI Pipe.
