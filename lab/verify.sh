#!/usr/bin/env bash
# Prove the lab is a real tailnet, not three daemons that merely started.
#
#   1. every node sees the other two while the policy is open
#   2. the tags the server applied are the tags the pre-auth keys carried
#   3. once the policy is tightened, an allowed packet arrives and a denied one
#      does not, and the netmap itself shrinks
#   4. adding one grant flips that answer, removing it flips it back
#   5. the final policy carries tests, which headscale evaluates on reload
#
# In userspace networking there is no utun interface, so nothing is tested from
# the host directly: every connection is made through the SOCKS5 proxy of the
# node that is supposed to be making it.
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_DIR="$LAB_DIR/.run"
BIN_DIR="$RUN_DIR/bin"
WITNESS_PORT="${WITNESS_PORT:-8081}"
WITNESS_TOKEN="lab-db-witness"

NODES="a b c"
node_index() { case "$1" in a) echo 0;; b) echo 1;; c) echo 2;; esac; }
node_socks() { echo $((11081 + $(node_index "$1"))); }

say()  { printf '\n== %s\n' "$*"; }
ok()   { printf '   ok   %s\n' "$*"; }
fail() { printf '   FAIL %s\n' "$*" >&2; FAILED=1; }
FAILED=0

hs() { "$BIN_DIR/headscale" -c "$RUN_DIR/config.yaml" "$@"; }
ts() { local n="$1"; shift; "$BIN_DIR/tailscale" --socket "$RUN_DIR/$n/tailscaled.sock" "$@"; }

node_ip() { ts "$1" status --json | python3 -c \
  "import json,sys;print(json.load(sys.stdin)['Self']['TailscaleIPs'][0])"; }

peers_of() { ts "$1" status --json | python3 -c \
  "import json,sys
peers=json.load(sys.stdin).get('Peer') or {}
print(' '.join(sorted(p['HostName'] for p in peers.values())))"; }

start_witness() {
  local dir="$RUN_DIR/b"
  if [ -f "$dir/witness.pid" ] && kill -0 "$(cat "$dir/witness.pid")" 2>/dev/null; then
    return 0
  fi
  ( python3 -c "
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'${WITNESS_TOKEN}\n'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args): pass
socketserver.TCPServer.allow_reuse_address = True
socketserver.TCPServer(('127.0.0.1', ${WITNESS_PORT}), H).serve_forever()
" >"$RUN_DIR/logs/witness-b.log" 2>&1 &
    echo $! > "$dir/witness.pid" )
  for _ in $(seq 1 40); do
    curl -fsS --max-time 2 "http://127.0.0.1:${WITNESS_PORT}/" >/dev/null 2>&1 && return 0
    sleep 0.25
  done
  fail "the witness service on 127.0.0.1:${WITNESS_PORT} did not start"
  return 1
}

reaches() { # reaches <from-node> <target-ip>: one attempt
  curl -fsS --max-time 6 \
    --socks5-hostname "127.0.0.1:$(node_socks "$1")" \
    "http://$2:${WITNESS_PORT}/" 2>/dev/null | grep -q "$WITNESS_TOKEN"
}

waits_until_reaches() { # same, but gives the peer connection time to come up
  local node="$1" ip="$2"
  for _ in $(seq 1 12); do
    reaches "$node" "$ip" && return 0
    sleep 2
  done
  return 1
}

warm_path() { # a denial must not be confused with a path that is not up yet
  ts "$1" ping -c 1 --timeout 10s "$2" >/dev/null 2>&1 || true
}

reload_policy() { # reload_policy <file>
  cp "$1" "$RUN_DIR/policy.hujson"
  kill -HUP "$(cat "$RUN_DIR/headscale.pid")"
  sleep 4
}

main() {
  say "1. every node sees the other two (policy is open)"
  for node in $NODES; do
    peers=""
    for _ in $(seq 1 15); do
      peers="$(peers_of "$node")"
      [ "$(printf '%s' "$peers" | wc -w | tr -d ' ')" = "2" ] && break
      sleep 1
    done
    if [ "$(printf '%s' "$peers" | wc -w | tr -d ' ')" = "2" ]; then
      ok "lab-$node sees: $peers"
    else
      fail "lab-$node sees [$peers], expected the two other nodes"
    fi
  done

  say "2. the tags the server applied"
  hs nodes list --output json | python3 -c "
import json,sys
nodes = json.load(sys.stdin)
want = {'lab-a': 'tag:web', 'lab-b': 'tag:db', 'lab-c': 'tag:ci'}
bad = 0
for node in nodes:
    name = node.get('given_name') or node.get('name')
    tags = node.get('tags') or []
    expected = want.get(name)
    if expected is None:
        continue
    if tags == [expected]:
        print(f'   ok   {name} carries {tags} (read back from headscale)')
    else:
        print(f'   FAIL {name} carries {tags}, expected [{expected}]')
        bad += 1
sys.exit(1 if bad else 0)
" || fail "the effective tags are not the ones the pre-auth keys carried"

  ip_b="$(node_ip b)"
  start_witness || true
  warm_path a "$ip_b"
  warm_path c "$ip_b"

  say "3. the policy decides who arrives"
  reload_policy "$LAB_DIR/policy.lab.hujson"
  if waits_until_reaches a "$ip_b"; then
    ok "lab-a reaches lab-b ($ip_b:${WITNESS_PORT}), which the policy allows"
  else
    fail "lab-a cannot reach lab-b, although the policy allows it"
  fi
  if reaches c "$ip_b"; then
    fail "lab-c reached lab-b, although no rule allows it"
  else
    ok "lab-c does not reach lab-b, which no rule allows"
  fi
  if [ -z "$(peers_of c)" ]; then
    ok "lab-c no longer sees any peer: the policy shrank its netmap too"
  else
    fail "lab-c still sees [$(peers_of c)] with no rule allowing it"
  fi

  say "4. changing the policy changes the answer"
  reload_policy "$LAB_DIR/policy.lab.open.hujson"
  if waits_until_reaches c "$ip_b"; then
    ok "after adding one grant, lab-c reaches lab-b"
  else
    fail "lab-c still cannot reach lab-b after the grant was added"
  fi
  reload_policy "$LAB_DIR/policy.lab.hujson"
  if reaches c "$ip_b"; then
    fail "lab-c still reaches lab-b after the grant was removed"
  else
    ok "with the grant removed, lab-c is blocked again"
  fi

  say "5. the final policy carries tests that headscale evaluates"
  reload_policy "$LAB_DIR/policy.lab.tested.hujson"
  if hs policy check --file "$RUN_DIR/policy.hujson" >/dev/null 2>&1; then
    ok "headscale policy check accepts the policy, tests included"
  else
    fail "headscale policy check rejected the final policy"
  fi
  if waits_until_reaches a "$ip_b" && ! reaches c "$ip_b"; then
    ok "final state: lab-a reaches lab-b, lab-c does not"
  else
    fail "the final policy does not behave like the one it replaced"
  fi

  if [ "$FAILED" = "0" ]; then
    say "lab verified"
  else
    say "lab verification FAILED"
    exit 1
  fi
}

main "$@"
