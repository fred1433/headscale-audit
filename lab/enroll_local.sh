#!/usr/bin/env bash
# Enrol the three lab nodes. Idempotent: running it twice changes nothing and
# says so. This is the local twin of rollout/enroll.sh, which does the same on
# a real VM.
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_DIR="$LAB_DIR/.run"
BIN_DIR="$RUN_DIR/bin"
LOG_DIR="$RUN_DIR/logs"
HS_PORT="${HS_PORT:-18080}"
SERVER_URL="http://127.0.0.1:${HS_PORT}"
LAB_USER="${LAB_USER:-lab}"

NODES="a b c"
node_tag() { case "$1" in a) echo "tag:web";; b) echo "tag:db";; c) echo "tag:ci";; esac; }
node_index() { case "$1" in a) echo 0;; b) echo 1;; c) echo 2;; esac; }
node_port()  { echo $((41651 + $(node_index "$1"))); }
node_socks() { echo $((11081 + $(node_index "$1"))); }

say() { printf '\n== %s\n' "$*"; }
die() { printf 'enrol: %s\n' "$*" >&2; exit 1; }
hs()  { "$BIN_DIR/headscale" -c "$RUN_DIR/config.yaml" "$@"; }
ts()  { local n="$1"; shift; "$BIN_DIR/tailscale" --socket "$RUN_DIR/$n/tailscaled.sock" "$@"; }

wait_for() {
  local deadline=$(( $(date +%s) + $1 )); local what="$2"; shift 2
  until "$@" >/dev/null 2>&1; do
    [ "$(date +%s)" -lt "$deadline" ] || die "timed out waiting for $what"
    sleep 0.3
  done
}

ensure_user() {
  if ! hs users list --output json | grep -q "\"name\": *\"${LAB_USER}\""; then
    hs users create "$LAB_USER" >/dev/null
  fi
  hs users list --output json \
    | python3 -c "import json,sys;print([u['id'] for u in json.load(sys.stdin) if u['name']=='${LAB_USER}'][0])"
}

start_daemon() { # start_daemon <node>
  local node="$1" dir="$RUN_DIR/$1"
  mkdir -p "$dir"
  if [ -f "$dir/tailscaled.pid" ] && kill -0 "$(cat "$dir/tailscaled.pid")" 2>/dev/null; then
    return 0
  fi
  rm -f "$dir/tailscaled.sock"
  ( "$BIN_DIR/tailscaled" \
      --tun=userspace-networking \
      --statedir="$dir" \
      --socket="$dir/tailscaled.sock" \
      --port="$(node_port "$node")" \
      --socks5-server="127.0.0.1:$(node_socks "$node")" \
      --no-logs-no-support \
      >"$LOG_DIR/tailscaled-$node.log" 2>&1 &
    echo $! > "$dir/tailscaled.pid" )
  wait_for 30 "tailscaled $node" ts "$node" status --json
}

backend_state() { ts "$1" status --json 2>/dev/null | python3 -c \
  "import json,sys
try: print(json.load(sys.stdin).get('BackendState',''))
except Exception: print('')"; }

enrol() { # enrol <node> <user-id>
  local node="$1" user_id="$2" tag dir key_file
  tag="$(node_tag "$node")"
  dir="$RUN_DIR/$node"
  if [ "$(backend_state "$node")" = "Running" ]; then
    printf 'lab-%s: already enrolled, nothing to do\n' "$node"
    return 0
  fi
  key_file="$dir/authkey"
  # The key is written to a file with restrictive permissions and handed to
  # tailscale as file:<path>: it never appears in a command line or in a log.
  ( umask 077
    hs preauthkeys create --user "$user_id" --expiration 1h --tags "$tag" \
      --output json \
      | python3 -c "import json,sys;print(json.load(sys.stdin)['key'])" > "$key_file" )
  # No --advertise-tags here on purpose: headscale 0.29 rejects a pre-auth key
  # registration that also advertises tags, with "requested tags [...] are
  # invalid or not permitted". The tags come from the key.
  ts "$node" up \
    --login-server "$SERVER_URL" \
    --auth-key "file:$key_file" \
    --hostname "lab-$node" \
    --accept-dns=false \
    --accept-routes=false
  rm -f "$key_file"
  wait_for 30 "lab-$node to reach Running" \
    sh -c "[ \"\$($BIN_DIR/tailscale --socket $dir/tailscaled.sock status --json | python3 -c 'import json,sys;print(json.load(sys.stdin)[\"BackendState\"])')\" = Running ]"
  printf 'lab-%s: enrolled with %s\n' "$node" "$tag"
}

main() {
  local user_id
  user_id="$(ensure_user)"
  say "enrolling three nodes as user ${LAB_USER} (id ${user_id})"
  for node in $NODES; do
    start_daemon "$node"
    enrol "$node" "$user_id"
  done
}

main "$@"
