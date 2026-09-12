#!/usr/bin/env bash
# The laboratory, in CI: official images, three real clients, one audit.
#
# Same scenario as lab/up.sh on a workstation, expressed with docker compose.
# Every wait is a wait on a condition with a deadline, never a fixed sleep.
set -euo pipefail

CI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$CI_DIR/.." && pwd)"
ROOT_DIR="$(cd "$LAB_DIR/.." && pwd)"
OUT_DIR="${OUT_DIR:-$CI_DIR/out}"
AUDIT="${AUDIT:-headscale-audit}"
COMPOSE="docker compose -f $CI_DIR/docker-compose.yml --env-file $CI_DIR/.env"

say()  { printf '\n== %s\n' "$*"; }
ok()   { printf '   ok   %s\n' "$*"; }
fail() { printf '   FAIL %s\n' "$*" >&2; FAILED=1; }
FAILED=0

hs()   { $COMPOSE exec -T headscale headscale "$@"; }
tsc()  { local node="$1"; shift; $COMPOSE exec -T "ts-$node" tailscale "$@"; }

wait_for() { # wait_for <seconds> <what> <command...>
  local deadline=$(( $(date +%s) + $1 )) what="$2"; shift 2
  until "$@" >/dev/null 2>&1; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
      printf 'timed out waiting for %s\n' "$what" >&2
      return 1
    fi
    sleep 1
  done
}

node_state() { tsc "$1" status --json 2>/dev/null | python3 -c \
  "import json,sys;print(json.load(sys.stdin).get('BackendState',''))" 2>/dev/null; }

peers_of() { tsc "$1" status --json 2>/dev/null | python3 -c \
  "import json,sys
peers=json.load(sys.stdin).get('Peer') or {}
print(' '.join(sorted(p['HostName'] for p in peers.values())))" 2>/dev/null; }

mkdir -p "$OUT_DIR"
: > "$CI_DIR/.env"

say "starting headscale"
$COMPOSE up -d headscale
wait_for 90 "the headscale API" curl -fsS http://127.0.0.1:8080/health
ok "headscale answers: $(curl -fsS http://127.0.0.1:8080/health)"
hs version | head -1

say "creating the user and three tagged pre-auth keys"
hs users create ci >/dev/null
USER_ID="$(hs users list --output json | python3 -c \
  "import json,sys;print([u['id'] for u in json.load(sys.stdin) if u['name']=='ci'][0])")"
make_key() { hs preauthkeys create --user "$USER_ID" --tags "$1" --expiration 1h --output json \
  | python3 -c "import json,sys;print(json.load(sys.stdin)['key'])"; }
{
  printf 'TS_AUTHKEY_A=%s\n' "$(make_key tag:web)"
  printf 'TS_AUTHKEY_B=%s\n' "$(make_key tag:db)"
  printf 'TS_AUTHKEY_C=%s\n' "$(make_key tag:ci)"
} > "$CI_DIR/.env"
chmod 600 "$CI_DIR/.env"
ok "three keys issued for user ci (id $USER_ID)"

say "starting three tailscale clients (userspace networking)"
$COMPOSE up -d ts-a ts-b ts-c
for node in a b c; do
  wait_for 120 "ci-$node to register" sh -c \
    "[ \"\$($COMPOSE exec -T ts-$node tailscale status --json 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin).get(\"BackendState\",\"\"))')\" = Running ]" \
    || fail "ci-$node never reached Running"
  ok "ci-$node: $(node_state "$node")"
done

say "every node sees the other two"
for node in a b c; do
  peers=""
  deadline=$(( $(date +%s) + 60 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    peers="$(peers_of "$node")"
    [ "$(printf '%s' "$peers" | wc -w | tr -d ' ')" = "2" ] && break
    sleep 2
  done
  if [ "$(printf '%s' "$peers" | wc -w | tr -d ' ')" = "2" ]; then
    ok "ci-$node sees: $peers"
  else
    fail "ci-$node sees [$peers], expected two peers"
  fi
done

say "the tags the server applied"
hs nodes list --output json > "$OUT_DIR/nodes.json"
python3 - "$OUT_DIR/nodes.json" <<'PY' || FAILED=1
import json, sys
want = {"ci-a": "tag:web", "ci-b": "tag:db", "ci-c": "tag:ci"}
nodes = json.load(open(sys.argv[1]))
bad = 0
for node in nodes:
    name = node.get("given_name") or node.get("name")
    if name not in want:
        continue
    tags = node.get("tags") or []
    if tags == [want[name]]:
        print(f"   ok   {name} carries {tags}")
    else:
        print(f"   FAIL {name} carries {tags}, expected [{want[name]}]")
        bad += 1
if len(nodes) != 3:
    print(f"   FAIL expected 3 nodes, found {len(nodes)}")
    bad += 1
sys.exit(1 if bad else 0)
PY

say "tightening the policy shrinks what a node can see"
cp "$LAB_DIR/policy.lab.hujson" "$CI_DIR/policy.hujson"
$COMPOSE kill -s HUP headscale >/dev/null
deadline=$(( $(date +%s) + 60 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  [ -z "$(peers_of c)" ] && break
  sleep 2
done
if [ -z "$(peers_of c)" ]; then
  ok "ci-c (tag:ci) no longer sees any peer, as the policy says"
else
  fail "ci-c still sees [$(peers_of c)] after the policy was tightened"
fi
if [ "$(peers_of a)" = "ci-b" ]; then
  ok "ci-a (tag:web) still sees ci-b, which the policy allows"
else
  fail "ci-a sees [$(peers_of a)], expected ci-b"
fi
cp "$LAB_DIR/policy.lab.openall.hujson" "$CI_DIR/policy.hujson"

say "auditing the live server"
hs users list --output json       > "$OUT_DIR/users.json"
hs preauthkeys list --output json > "$OUT_DIR/preauthkeys.json"
hs apikeys list --output json     > "$OUT_DIR/apikeys.json"
cp "$CI_DIR/config.yaml" "$OUT_DIR/config.yaml"
cp "$CI_DIR/policy.hujson" "$OUT_DIR/policy.hujson"
API_KEY="$(hs apikeys create --expiration 1h | tail -1)"
HEADSCALE_API_KEY="$API_KEY" "$AUDIT" \
  --config "$CI_DIR/config.yaml" \
  --policy "$CI_DIR/policy.hujson" \
  --api-url http://127.0.0.1:8080 \
  --format both \
  --output "$OUT_DIR/report-live.md" \
  --json-output "$OUT_DIR/report-live.json"
unset API_KEY
python3 - "$OUT_DIR/report-live.json" <<'PY' || FAILED=1
import json, sys
payload = json.load(open(sys.argv[1]))
print(f"   ok   audited {payload['inputs']['nodes']} nodes, "
      f"status {payload['status']}")
if payload["inputs"]["nodes"] != 3:
    print("   FAIL the audit did not read the three nodes"); sys.exit(1)
if payload["status"]["ERROR"]:
    print("   FAIL a control raised an error"); sys.exit(1)
PY

say "the two fixtures"
"$AUDIT" --offline-dir "$LAB_DIR/insecure" --format json \
  --json-output "$OUT_DIR/fixture-insecure.json" > /dev/null
"$AUDIT" --offline-dir "$LAB_DIR/hardened" --format json \
  --json-output "$OUT_DIR/fixture-hardened.json" > /dev/null
python3 - "$OUT_DIR/fixture-insecure.json" "$OUT_DIR/fixture-hardened.json" <<'PY' || FAILED=1
import json, sys
bad, good = (json.load(open(path)) for path in sys.argv[1:3])
failed = False
if bad["findings"]["total"] < 8 or bad["findings"]["high"] < 3:
    print(f"   FAIL insecure fixture: {bad['findings']}"); failed = True
else:
    print(f"   ok   insecure fixture: {bad['findings']['total']} findings, "
          f"{bad['findings']['high']} high")
if good["findings"]["high"]:
    print(f"   FAIL hardened fixture has high findings: {good['findings']}"); failed = True
else:
    print(f"   ok   hardened fixture: 0 high findings")
evaluated = good["status"]["PASS"] + good["status"]["FAIL"] + good["status"]["UNKNOWN"]
if evaluated < 40:
    print(f"   FAIL only {evaluated} controls were evaluated on the hardened "
          "fixture: a quiet report must come from controls that ran")
    failed = True
else:
    print(f"   ok   {evaluated} controls actually ran on the hardened fixture")
sys.exit(1 if failed else 0)
PY

if [ "$FAILED" = "0" ]; then
  say "CI laboratory verified"
else
  say "CI laboratory FAILED"
  exit 1
fi
