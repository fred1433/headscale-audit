#!/usr/bin/env bash
# Run this ON the machine that will not join, before blaming the control plane.
#
# Each check prints one line: what was tested, and what came back. Nothing is
# changed on the machine. Exit status is the number of failed checks.
#
#   HEADSCALE_URL=https://headscale.example.com ./probe.sh
set -uo pipefail

: "${HEADSCALE_URL:?set HEADSCALE_URL to the control server URL}"
HOST="$(printf '%s' "$HEADSCALE_URL" | sed -E 's#^[a-z]+://##; s#[:/].*$##')"
PORT="$(printf '%s' "$HEADSCALE_URL" | sed -nE 's#^[a-z]+://[^:/]+:([0-9]+).*#\1#p')"
case "$HEADSCALE_URL" in https://*) SCHEME=https; PORT="${PORT:-443}";; *) SCHEME=http; PORT="${PORT:-80}";; esac
FAILED=0
ok()   { printf '  ok    %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; FAILED=$((FAILED+1)); }
note() { printf '  note  %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

printf '\n== control server %s (%s port %s)\n' "$HEADSCALE_URL" "$HOST" "$PORT"

# 1. Name resolution. A VM that resolves nothing usually lost its resolver to a
#    pushed DNS configuration (headscale-audit HS-015).
if have getent; then
  addr="$(getent hosts "$HOST" | awk '{print $1}' | head -1)"
elif have dig; then
  addr="$(dig +short "$HOST" | head -1)"
else
  addr="$(python3 -c "import socket,sys;print(socket.gethostbyname('$HOST'))" 2>/dev/null)"
fi
[ -n "${addr:-}" ] && ok "$HOST resolves to $addr" || bad "$HOST does not resolve"

# 2. Reachability of the control port.
if have nc; then
  nc -z -w 5 "$HOST" "$PORT" >/dev/null 2>&1 \
    && ok "tcp/$PORT is open" || bad "tcp/$PORT refused or filtered"
else
  python3 - "$HOST" "$PORT" <<'PY' && ok "tcp port is open" || bad "tcp port refused or filtered"
import socket, sys
s = socket.socket(); s.settimeout(5)
sys.exit(0 if s.connect_ex((sys.argv[1], int(sys.argv[2]))) == 0 else 1)
PY
fi

# 3. The control plane answers, and its certificate is trusted by THIS machine.
health="$(curl -fsS --max-time 10 "${HEADSCALE_URL%/}/health" 2>&1)"
if [ $? -eq 0 ]; then
  ok "/health answered: $(printf '%s' "$health" | head -c 60)"
else
  bad "/health failed: $(printf '%s' "$health" | head -c 120)"
fi
if [ "$SCHEME" = "https" ] && have openssl; then
  dates="$(printf '' | openssl s_client -servername "$HOST" -connect "$HOST:$PORT" 2>/dev/null \
    | openssl x509 -noout -dates 2>/dev/null | tr '\n' ' ')"
  [ -n "$dates" ] && ok "certificate: $dates" || bad "no usable certificate on $HOST:$PORT"
fi

# 4. Clock. An expired-looking key and a rejected certificate are the usual
#    symptoms of a VM whose clock drifted.
remote_date="$(curl -fsSI --max-time 10 "${HEADSCALE_URL%/}/health" 2>/dev/null \
  | awk 'BEGIN{IGNORECASE=1}/^date:/{sub(/^[Dd]ate: /,""); print}' | tr -d '\r')"
if [ -n "$remote_date" ]; then
  skew="$(python3 - "$remote_date" <<'PY'
import email.utils, sys, time
try:
    remote = email.utils.parsedate_to_datetime(sys.argv[1]).timestamp()
    print(int(abs(remote - time.time())))
except Exception:
    print(-1)
PY
)"
  if [ "$skew" -lt 0 ]; then note "could not compare clocks"
  elif [ "$skew" -lt 60 ]; then ok "clock within ${skew}s of the server"
  else bad "clock is ${skew}s away from the server; fix NTP first"
  fi
fi

# 5. Package source, only when tailscale is not installed yet.
if have tailscale; then
  ok "tailscale $(tailscale version | head -1) is installed"
else
  curl -fsS --max-time 10 -o /dev/null https://pkgs.tailscale.com/stable/ \
    && ok "pkgs.tailscale.com is reachable" \
    || bad "pkgs.tailscale.com unreachable: the install step will fail"
fi

# 6. The secret, if one was pointed at.
if [ -n "${AUTHKEY_FILE:-}" ]; then
  if [ -r "$AUTHKEY_FILE" ] && [ -s "$AUTHKEY_FILE" ]; then
    ok "the key file is readable and not empty (contents not shown)"
  else
    bad "AUTHKEY_FILE=$AUTHKEY_FILE is missing, empty or unreadable"
  fi
elif [ -n "${SECRET_NAME:-}" ] && have gcloud; then
  gcloud secrets versions access latest --secret="$SECRET_NAME" >/dev/null 2>&1 \
    && ok "Secret Manager returns $SECRET_NAME" \
    || bad "cannot read secret $SECRET_NAME: check the instance service account"
fi

# 7. Registration state and path, when the daemon is there.
if have tailscale; then
  state="$(tailscale status --json 2>/dev/null | python3 -c \
    "import json,sys;print(json.load(sys.stdin).get('BackendState',''))" 2>/dev/null)"
  case "$state" in
    Running) ok "registered, backend state Running" ;;
    NeedsLogin|Stopped|"") bad "not registered, backend state '${state:-unknown}'" ;;
    *) note "backend state $state" ;;
  esac
  if [ "$state" = "Running" ]; then
    relay="$(tailscale status --json | python3 -c \
      "import json,sys
peers=(json.load(sys.stdin).get('Peer') or {}).values()
direct=[p['HostName'] for p in peers if p.get('CurAddr')]
relayed=[p['HostName'] for p in peers if not p.get('CurAddr') and p.get('Relay')]
print(f'direct={len(direct)} relayed={len(relayed)}')" 2>/dev/null)"
    note "peer paths: $relay (all relayed usually means UDP 41641 is blocked inbound)"
  fi
fi

printf '\n%s check(s) failed\n' "$FAILED"
exit "$FAILED"
