#!/usr/bin/env bash
# Enrol one machine into a Headscale tailnet, idempotently.
#
# The script converges towards one declared state and refuses, loudly, when it
# cannot get there without destroying something:
#
#   not installed            -> install, then register
#   installed, not running   -> start the daemon, then register
#   installed, not registered-> register
#   registered, same server  -> nothing to do (exit 0)
#   registered, other server -> refuse, unless ALLOW_MIGRATE=1
#   local settings differ    -> refuse, unless ALLOW_RESET=1
#   key expired or rejected  -> explain what the server said, exit 3
#
# Usage:
#   HEADSCALE_URL=https://headscale.example.com \
#   AUTHKEY_FILE=/run/secrets/ts-authkey \
#   ./enroll.sh
#
# Environment:
#   HEADSCALE_URL   (required) the control server, https:// in production
#   AUTHKEY_FILE    path to a file holding the pre-auth key (preferred)
#   AUTHKEY         the key itself; written to a 0600 temporary file and never
#                   passed on a command line
#   HOSTNAME_OVERRIDE  node name to register (default: this machine's hostname)
#   ACCEPT_DNS      true|false (default false: a server keeps its own resolver)
#   ACCEPT_ROUTES   true|false (default false)
#   EXTRA_ARGS      further tailscale up flags, e.g. --advertise-routes=...
#   ALLOW_MIGRATE   1 to allow moving a node from another control server
#   ALLOW_RESET     1 to allow tailscale up --reset when settings differ
#   TS              path to the tailscale CLI (default: tailscale on PATH)
#   TS_ARGS         extra CLI arguments, e.g. --socket=... when several daemons
#                   run on one host (used by the laboratory)
#
# Tags are NOT passed here on purpose. Since headscale 0.28 a pre-auth key
# carries its own tags and a registration that also advertises tags is
# rejected with "requested tags [...] are invalid or not permitted". Create the
# key with them instead:
#   headscale preauthkeys create --user <ID> --tags tag:web --expiration 1h
set -euo pipefail

log()  { printf '[enroll] %s\n' "$*"; }
die()  { printf '[enroll] %s\n' "$*" >&2; exit "${2:-1}"; }
have() { command -v "$1" >/dev/null 2>&1; }

: "${HEADSCALE_URL:?set HEADSCALE_URL to the control server URL}"
HOSTNAME_OVERRIDE="${HOSTNAME_OVERRIDE:-$(hostname -s 2>/dev/null || hostname)}"
ACCEPT_DNS="${ACCEPT_DNS:-false}"
ACCEPT_ROUTES="${ACCEPT_ROUTES:-false}"
EXTRA_ARGS="${EXTRA_ARGS:-}"
TS="${TS:-tailscale}"
# TS_ARGS lets a test harness point the CLI at one daemon among several
# (--socket=...). It is empty on a real machine.
TS_ARGS="${TS_ARGS:-}"

case "$HEADSCALE_URL" in
  https://*) ;;
  http://127.0.0.1*|http://localhost*) log "warning: plain http, acceptable only for a local lab" ;;
  http://*) log "warning: HEADSCALE_URL is plain http; the control connection is exposed to anyone on the path" ;;
esac

# ---------------------------------------------------------------- install ---
install_tailscale() {
  have "$TS" && return 0
  [ -x "$TS" ] && return 0
  log "tailscale is not installed"
  if [ "$(id -u)" != "0" ] && ! have sudo; then
    die "cannot install without root; run as root or install tailscale first"
  fi
  local sudo=""
  [ "$(id -u)" = "0" ] || sudo="sudo"
  if have apt-get; then
    log "installing with the official apt repository"
    $sudo sh -c 'curl -fsSL https://tailscale.com/install.sh | sh'
  elif have dnf || have yum || have zypper || have pacman || have apk; then
    log "installing with the official install script"
    $sudo sh -c 'curl -fsSL https://tailscale.com/install.sh | sh'
  else
    die "no supported package manager found; install tailscale by hand, then re-run" 4
  fi
  have "$TS" || die "installation finished but tailscale is still not on PATH" 4
}

start_daemon() {
  $TS $TS_ARGS status >/dev/null 2>&1 && return 0
  if have systemctl; then
    local sudo=""; [ "$(id -u)" = "0" ] || sudo="sudo"
    log "starting tailscaled"
    $sudo systemctl enable --now tailscaled
    for _ in $(seq 1 30); do
      $TS $TS_ARGS status >/dev/null 2>&1 && return 0
      sleep 1
    done
  fi
  # status exits non-zero when the node is not registered yet, which is fine:
  # what matters is that the daemon answers at all.
  $TS $TS_ARGS status --json >/dev/null 2>&1 || die "tailscaled is not answering" 4
}

# ------------------------------------------------------------------ state ---
json_field() { # json_field <jq-ish path via python> ; reads stdin
  python3 -c "import json,sys
data = json.load(sys.stdin)
value = data
for part in '$1'.split('.'):
    value = (value or {}).get(part) if isinstance(value, dict) else None
print('' if value is None else value)" 2>/dev/null || true
}

current_state() { $TS $TS_ARGS status --json 2>/dev/null | json_field "BackendState"; }
current_server() { $TS $TS_ARGS status --json 2>/dev/null | json_field "CurrentTailnet.Name"; }
current_control() {
  # The control URL lives in the preferences, not in the status payload.
  $TS $TS_ARGS debug prefs 2>/dev/null | json_field "ControlURL"
}
self_name() { $TS $TS_ARGS status --json 2>/dev/null | json_field "Self.HostName"; }
self_tags() {
  $TS $TS_ARGS status --json 2>/dev/null | python3 -c "import json,sys
try:
    print(','.join(json.load(sys.stdin)['Self'].get('Tags') or []))
except Exception:
    print('')" 2>/dev/null || true
}

# -------------------------------------------------------------- authkey ----
authkey_path() {
  if [ -n "${AUTHKEY_FILE:-}" ]; then
    [ -r "$AUTHKEY_FILE" ] || die "AUTHKEY_FILE $AUTHKEY_FILE is not readable" 3
    printf '%s' "$AUTHKEY_FILE"
    return 0
  fi
  [ -n "${AUTHKEY:-}" ] || die "no key: set AUTHKEY_FILE or AUTHKEY" 3
  local tmp
  tmp="$(mktemp)"
  chmod 600 "$tmp"
  printf '%s' "$AUTHKEY" > "$tmp"
  CLEANUP_KEY="$tmp"
  printf '%s' "$tmp"
}

cleanup() {
  # The last command of an EXIT trap sets the exit status of the whole script,
  # so this one ends on a success no matter what.
  if [ -n "${CLEANUP_KEY:-}" ]; then rm -f "$CLEANUP_KEY"; fi
  return 0
}
trap cleanup EXIT

# --------------------------------------------------------------- enrol -----
main() {
  install_tailscale
  start_daemon

  local state control
  state="$(current_state)"
  control="$(current_control)"

  if [ "$state" = "Running" ]; then
    if [ -n "$control" ] && [ "${control%/}" != "${HEADSCALE_URL%/}" ]; then
      [ "${ALLOW_MIGRATE:-0}" = "1" ] || die \
        "already registered to ${control}, not ${HEADSCALE_URL}. Moving a node
between control servers changes its identity and its address: re-run with
ALLOW_MIGRATE=1 if that is what you want." 5
      log "migrating from ${control} to ${HEADSCALE_URL} (ALLOW_MIGRATE=1)"
    else
      log "already enrolled as $(self_name) with tags [$(self_tags)], nothing to do"
      exit 0
    fi
  fi

  local key_file
  key_file="$(authkey_path)"

  set +e
  # The key is handed over as file:<path>: it never appears in this command
  # line, in the process list, or in a shell trace.
  # shellcheck disable=SC2086
  output="$($TS $TS_ARGS up \
    --login-server="$HEADSCALE_URL" \
    --auth-key="file:${key_file}" \
    --hostname="$HOSTNAME_OVERRIDE" \
    --accept-dns="$ACCEPT_DNS" \
    --accept-routes="$ACCEPT_ROUTES" \
    $EXTRA_ARGS 2>&1)"
  status=$?
  set -e

  if [ $status -ne 0 ]; then
    printf '%s\n' "$output" >&2
    case "$output" in
      *"requires mentioning all non-default flags"*)
        [ "${ALLOW_RESET:-0}" = "1" ] || die \
          "this machine already has tailscale settings that differ from the ones
requested. tailscale refuses to change them silently. Review the flags it
printed above, then either re-run with the same flags, or with ALLOW_RESET=1
to drop the local settings." 6
        log "re-running with --reset (ALLOW_RESET=1)"
        # shellcheck disable=SC2086
        $TS $TS_ARGS up --reset \
          --login-server="$HEADSCALE_URL" \
          --auth-key="file:${key_file}" \
          --hostname="$HOSTNAME_OVERRIDE" \
          --accept-dns="$ACCEPT_DNS" \
          --accept-routes="$ACCEPT_ROUTES" \
          $EXTRA_ARGS
        ;;
      *"requested tags"*)
        die "the server refused the tags carried by this key. The user that owns
the key must own the tag in the policy (tagOwners). Ask for:
  headscale preauthkeys create --user <ID> --tags <tag> --expiration 1h
and check that tagOwners lists that user. headscale-audit reports this as
HS-062." 3
        ;;
      *"authkey"*|*"auth key"*|*"expired"*|*"invalid key"*|*"Unauthorized"*)
        die "the pre-auth key was refused (expired, already used, or not valid
for this server). Issue a fresh one and re-run. headscale-audit reports keys
without expiry as HS-060." 3
        ;;
      *)
        die "tailscale up failed, see the output above" 3
        ;;
    esac
  fi

  for _ in $(seq 1 30); do
    [ "$(current_state)" = "Running" ] && break
    sleep 1
  done
  [ "$(current_state)" = "Running" ] || die "registration did not complete" 3

  log "enrolled as $(self_name) with tags [$(self_tags)]"
  log "verify on the server: headscale nodes list | grep $(self_name)"
}

main "$@"
