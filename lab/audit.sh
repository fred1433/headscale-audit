#!/usr/bin/env bash
# Audit the running laboratory, twice: once through the REST API, once from an
# offline export. The two runs must reach the same conclusions.
#
# Writes:
#   lab/.run/export/         nodes, users, keys, config and policy as JSON/YAML
#   lab/.run/report-api.md   audit through the API
#   REPORT.md                the report kept in the repository
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$LAB_DIR/.." && pwd)"
RUN_DIR="$LAB_DIR/.run"
BIN_DIR="$RUN_DIR/bin"
EXPORT_DIR="$RUN_DIR/export"
HS_PORT="${HS_PORT:-18080}"
SERVER_URL="http://127.0.0.1:${HS_PORT}"
AUDIT="${AUDIT:-$ROOT_DIR/.venv/bin/headscale-audit}"

hs() { "$BIN_DIR/headscale" -c "$RUN_DIR/config.yaml" "$@"; }
say() { printf '\n== %s\n' "$*"; }

[ -x "$AUDIT" ] || { printf 'no headscale-audit at %s (pip install -e .)\n' "$AUDIT" >&2; exit 1; }

mkdir -p "$EXPORT_DIR"
# A short lived key, created for this run only. Headscale API keys are
# administrative: there is no read-only scope, which is why the offline export
# is the preferred mode outside a lab.
API_KEY="$(hs apikeys create --expiration 1h | tail -1)"

say "exporting the inventory (headscale ... --output json)"
hs nodes list --output json        > "$EXPORT_DIR/nodes.json"
hs users list --output json        > "$EXPORT_DIR/users.json"
hs preauthkeys list --output json  > "$EXPORT_DIR/preauthkeys.json"
hs apikeys list --output json      > "$EXPORT_DIR/apikeys.json"
cp "$RUN_DIR/config.yaml" "$EXPORT_DIR/config.yaml"
cp "$RUN_DIR/policy.hujson" "$EXPORT_DIR/policy.hujson"
chmod 600 "$EXPORT_DIR"/*.json
printf 'exported %s nodes, %s users, %s pre-auth keys\n' \
  "$(python3 -c "import json;print(len(json.load(open('$EXPORT_DIR/nodes.json'))))")" \
  "$(python3 -c "import json;print(len(json.load(open('$EXPORT_DIR/users.json'))))")" \
  "$(python3 -c "import json;print(len(json.load(open('$EXPORT_DIR/preauthkeys.json'))))")"

say "audit through the REST API"
HEADSCALE_API_KEY="$API_KEY" "$AUDIT" \
  --config "$RUN_DIR/config.yaml" \
  --policy "$RUN_DIR/policy.hujson" \
  --api-url "$SERVER_URL" \
  --headscale-binary "$BIN_DIR/headscale" \
  --format both \
  --output "$RUN_DIR/report-api.md" \
  --json-output "$RUN_DIR/report-api.json"
unset API_KEY
printf 'wrote %s\n' "$RUN_DIR/report-api.md"

say "audit from the offline export"
"$AUDIT" --offline-dir "$EXPORT_DIR" \
  --headscale-binary "$BIN_DIR/headscale" \
  --format both \
  --output "$RUN_DIR/report-offline.md" \
  --json-output "$RUN_DIR/report-offline.json"

python3 - "$RUN_DIR/report-api.json" "$RUN_DIR/report-offline.json" <<'PY'
import json, sys
api, offline = (json.load(open(path)) for path in sys.argv[1:3])
def findings(payload):
    return sorted(
        (finding["id"], finding["severity"])
        for check in payload["checks"] for finding in check["findings"]
    )
same = findings(api) == findings(offline)
print(f"   API run: {api['findings']}")
print(f"   offline: {offline['findings']}")
print("   ok   both routes reach the same findings" if same
      else "   FAIL the two routes disagree")
sys.exit(0 if same else 1)
PY

say "the two fixtures"
"$AUDIT" --offline-dir "$LAB_DIR/insecure" --format json \
  --json-output "$RUN_DIR/fixture-insecure.json" >/dev/null
"$AUDIT" --offline-dir "$LAB_DIR/hardened" --format json \
  --json-output "$RUN_DIR/fixture-hardened.json" >/dev/null
python3 - "$RUN_DIR/fixture-insecure.json" "$RUN_DIR/fixture-hardened.json" <<'PY'
import json, sys
bad, good = (json.load(open(path)) for path in sys.argv[1:3])
ok = True
if bad["findings"]["total"] < 8 or bad["findings"]["high"] < 3:
    print(f"   FAIL insecure fixture: {bad['findings']}"); ok = False
else:
    print(f"   ok   insecure fixture: {bad['findings']['total']} findings, "
          f"{bad['findings']['high']} high")
if good["findings"]["high"]:
    print(f"   FAIL hardened fixture has high findings: {good['findings']}"); ok = False
else:
    print(f"   ok   hardened fixture: {good['findings']['total']} findings, 0 high")
sys.exit(0 if ok else 1)
PY

cp "$RUN_DIR/report-api.md" "$ROOT_DIR/REPORT.md"
say "REPORT.md updated from this run"
