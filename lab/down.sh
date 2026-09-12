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

# Every node directory this lab created, including the ones lab/rollout_test.sh
# adds, and nothing else: only pids written by these scripts are signalled.
for pidfile in "$RUN_DIR"/*/tailscaled.pid; do
  [ -e "$pidfile" ] || continue
  node="$(basename "$(dirname "$pidfile")")"
  stop "$pidfile" "tailscaled lab-$node"
  stop "$RUN_DIR/$node/witness.pid" "witness lab-$node"
  rm -f "$RUN_DIR/$node/tailscaled.sock"
done
stop "$RUN_DIR/headscale.pid" "headscale"
rm -f "$RUN_DIR/headscale.sock"
# A daemon whose pid file was lost (an interrupted run) is reported, never
# killed blind: the pid is printed so a human decides.
if command -v pgrep >/dev/null 2>&1; then
  orphans="$(pgrep -f "$RUN_DIR/bin/tailscaled" 2>/dev/null || true)"
  if [ -n "$orphans" ]; then
    printf 'still running from an earlier run, with no pid file: %s\n' \
      "$(printf '%s' "$orphans" | tr '\n' ' ')"
    printf 'stop them with: kill %s\n' "$(printf '%s' "$orphans" | tr '\n' ' ')"
  fi
fi

printf 'lab is down. State is kept in lab/.run (delete it for a clean slate).\n'
