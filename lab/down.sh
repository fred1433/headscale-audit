#!/usr/bin/env bash
# Stop everything lab/up.sh started, and nothing else: only the pids this lab
# wrote down are signalled.
set -uo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_DIR="$LAB_DIR/.run"

stop() { # stop <pidfile> <label>
  local file="$1" label="$2" pid
  [ -f "$file" ] || return 0
  pid="$(cat "$file")"
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.3
    done
    kill -9 "$pid" 2>/dev/null
    printf 'stopped %s (pid %s)\n' "$label" "$pid"
  fi
  rm -f "$file"
}

for node in a b c; do
  stop "$RUN_DIR/$node/tailscaled.pid" "tailscaled lab-$node"
  stop "$RUN_DIR/$node/witness.pid" "witness lab-$node"
  rm -f "$RUN_DIR/$node/tailscaled.sock"
done
stop "$RUN_DIR/headscale.pid" "headscale"
rm -f "$RUN_DIR/headscale.sock"
printf 'lab is down. State is kept in lab/.run (delete it for a clean slate).\n'
