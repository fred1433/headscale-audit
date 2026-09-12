#!/usr/bin/env bash
# Run rollout/enroll.sh, the script meant for a real VM, against the running
# laboratory. It is the same file, not a copy: what passes here is what ships.
#
#   1. a blank node enrols
#   2. running the script again changes nothing (idempotent)
#   3. the daemon restarts and the node keeps its identity
#   4. an expired key fails with an explanation, not a stack trace
#   5. pointing an enrolled node at another control server is refused
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$LAB_DIR/.." && pwd)"
RUN_DIR="$LAB_DIR/.run"
BIN_DIR="$RUN_DIR/bin"
LOG_DIR="$RUN_DIR/logs"
HS_PORT="${HS_PORT:-18080}"
SERVER_URL="http://127.0.0.1:${HS_PORT}"
ENROLL="$ROOT_DIR/rollout/enroll.sh"

say()  { printf '\n== %s\n' "$*"; }
ok()   { printf '   ok   %s\n' "$*"; }
fail() { printf '   FAIL %s\n' "$*" >&2; FAILED=1; }
FAILED=0

hs() { "$BIN_DIR/headscale" -c "$RUN_DIR/config.yaml" "$@"; }

start_daemon() { # start_daemon <name> <udp-port>
  local name="$1" port="$2" dir="$RUN_DIR/$1"
  mkdir -p "$dir"
  if [ -f "$dir/tailscaled.pid" ] && kill -0 "$(cat "$dir/tailscaled.pid")" 2>/dev/null; then
    return 0
  fi
  rm -f "$dir/tailscaled.sock"
  ( "$BIN_DIR/tailscaled" --tun=userspace-networking \
      --statedir="$dir" --socket="$dir/tailscaled.sock" --port="$port" \
      --no-logs-no-support >"$LOG_DIR/tailscaled-$name.log" 2>&1 &
    echo $! > "$dir/tailscaled.pid" )
  for _ in $(seq 1 40); do
    "$BIN_DIR/tailscale" --socket "$dir/tailscaled.sock" status --json >/dev/null 2>&1 && return 0
    sleep 0.3
  done
  fail "tailscaled $name did not start"
}

stop_daemon() {
  local dir="$RUN_DIR/$1"
  [ -f "$dir/tailscaled.pid" ] || return 0
  kill "$(cat "$dir/tailscaled.pid")" 2>/dev/null || true
  rm -f "$dir/tailscaled.pid" "$dir/tailscaled.sock"
  sleep 1
}

new_key() { # new_key <user-id> <tag> <expiration>
  ( umask 077
    hs preauthkeys create --user "$1" --tags "$2" --expiration "$3" --output json \
      | python3 -c "import json,sys;print(json.load(sys.stdin)['key'])" )
}

node_id_of() { # node_id_of <hostname>
  hs nodes list --output json | python3 -c "
import json,sys
name='$1'
print(next((str(n['id']) for n in json.load(sys.stdin)
            if (n.get('given_name') or n.get('name')) == name), ''))"
}

user_id() {
  hs users list --output json | python3 -c \
    "import json,sys;print([u['id'] for u in json.load(sys.stdin) if u['name']=='lab'][0])"
}

run_enroll() { # run_enroll <node-dir> <hostname> [extra env assignments]
  local dir="$RUN_DIR/$1" name="$2"; shift 2
  # The caller's assignments come last so that a test can override a default.
  env \
    TS="$BIN_DIR/tailscale" \
    TS_ARGS="--socket=$dir/tailscaled.sock" \
    HEADSCALE_URL="$SERVER_URL" \
    HOSTNAME_OVERRIDE="$name" \
    AUTHKEY_FILE="$dir/authkey" \
    "$@" \
    bash "$ENROLL"
}

reset_node() { # reset_node <name> <hostname>: start from a machine that never joined
  stop_daemon "$1"
  rm -rf "${RUN_DIR:?}/$1"
  local id; id="$(node_id_of "$2")"
  [ -n "$id" ] && hs nodes delete --identifier "$id" --force >/dev/null 2>&1
  return 0
}

main() {
  local uid; uid="$(user_id)"
  reset_node d lab-d
  reset_node e lab-e

  say "1. a blank node enrols with rollout/enroll.sh"
  start_daemon d 41660
  ( umask 077; new_key "$uid" "tag:web" 10m > "$RUN_DIR/d/authkey" )
  if run_enroll d lab-d > "$LOG_DIR/enroll-d-1.log" 2>&1; then
    ok "$(grep -m1 'enrolled as' "$LOG_DIR/enroll-d-1.log" || echo enrolled)"
  else
    cat "$LOG_DIR/enroll-d-1.log" >&2; fail "enrolment failed"
  fi
  id_before="$(node_id_of lab-d)"
  [ -n "$id_before" ] && ok "the server knows lab-d as node $id_before" \
    || fail "lab-d is not in headscale nodes list"

  say "2. running it again is a no-op"
  if run_enroll d lab-d > "$LOG_DIR/enroll-d-2.log" 2>&1 \
     && grep -q "nothing to do" "$LOG_DIR/enroll-d-2.log"; then
    ok "second run: $(grep -m1 'nothing to do' "$LOG_DIR/enroll-d-2.log")"
  else
    cat "$LOG_DIR/enroll-d-2.log" >&2; fail "the second run was not a no-op"
  fi

  say "3. the daemon restarts and the identity survives"
  stop_daemon d
  start_daemon d 41660
  for _ in $(seq 1 20); do
    state="$("$BIN_DIR/tailscale" --socket "$RUN_DIR/d/tailscaled.sock" status --json \
      | python3 -c "import json,sys;print(json.load(sys.stdin)['BackendState'])")"
    [ "$state" = "Running" ] && break
    sleep 1
  done
  id_after="$(node_id_of lab-d)"
  if [ "$state" = "Running" ] && [ "$id_after" = "$id_before" ]; then
    ok "after a restart lab-d is still node $id_after, no second registration"
  else
    fail "after a restart lab-d is in state $state as node '$id_after' (was $id_before)"
  fi

  say "4. an expired key fails with an explanation"
  start_daemon e 41661
  ( umask 077; new_key "$uid" "tag:web" 1s > "$RUN_DIR/e/authkey" )
  sleep 3
  set +e
  run_enroll e lab-e > "$LOG_DIR/enroll-e.log" 2>&1
  code=$?
  set -e
  if [ $code -ne 0 ] && grep -qi "key was refused\|expired\|invalid" "$LOG_DIR/enroll-e.log"; then
    ok "exit $code with: $(grep -m1 -i 'refused\|expired\|invalid' "$LOG_DIR/enroll-e.log" | cut -c1-90)"
  else
    cat "$LOG_DIR/enroll-e.log" >&2
    fail "an expired key should fail with an explanation (exit was $code)"
  fi

  say "5. an enrolled node is not silently moved to another server"
  set +e
  run_enroll d lab-d HEADSCALE_URL="http://127.0.0.1:19999" \
    > "$LOG_DIR/enroll-d-3.log" 2>&1
  code=$?
  set -e
  if [ $code -eq 5 ] && grep -q "already registered to" "$LOG_DIR/enroll-d-3.log"; then
    ok "exit 5: $(grep -m1 'already registered to' "$LOG_DIR/enroll-d-3.log" | cut -c1-90)"
  else
    cat "$LOG_DIR/enroll-d-3.log" >&2
    fail "moving control servers should be refused (exit was $code)"
  fi

  if [ "$FAILED" = "0" ]; then
    say "rollout/enroll.sh verified on the lab"
  else
    say "rollout test FAILED"
    exit 1
  fi
}

main "$@"
