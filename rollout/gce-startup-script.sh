#!/usr/bin/env bash
# GCE startup script: enrol the instance at first boot.
#
#   gcloud compute instances create web-01 \
#     --metadata-from-file=startup-script=rollout/gce-startup-script.sh \
#     --metadata=headscale-url=https://headscale.example.com,ts-secret=ts-authkey-web \
#     --service-account=... --scopes=https://www.googleapis.com/auth/cloud-platform
#
# The pre-auth key is never written into the instance metadata, the image or
# the Terraform state: it is read at boot from Secret Manager with the
# instance's own service account, into a file that is deleted right after.
#
# An instance in a managed instance group should use an EPHEMERAL key
# (headscale preauthkeys create --ephemeral): instances that are recreated
# then disappear from headscale on their own instead of piling up as offline
# nodes.
set -euo pipefail

META="http://metadata.google.internal/computeMetadata/v1/instance/attributes"
meta() { curl -fsS -H "Metadata-Flavor: Google" "$META/$1" 2>/dev/null || true; }

HEADSCALE_URL="$(meta headscale-url)"
SECRET_NAME="$(meta ts-secret)"
ROLE="$(meta ts-role)"
: "${HEADSCALE_URL:?instance metadata headscale-url is required}"
: "${SECRET_NAME:?instance metadata ts-secret is required}"

WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; return 0; }
trap cleanup EXIT
KEY_FILE="$WORK/authkey"

( umask 077
  gcloud secrets versions access latest --secret="$SECRET_NAME" > "$KEY_FILE" )

# One deployment logic for every path: this script, the Ansible role and a
# manual run all call the same enroll.sh.
ENROLL_URL="${ENROLL_URL:-https://raw.githubusercontent.com/fred1433/headscale-audit/main/rollout/enroll.sh}"
if [ -f /opt/headscale-audit/rollout/enroll.sh ]; then
  ENROLL=/opt/headscale-audit/rollout/enroll.sh
else
  ENROLL="$WORK/enroll.sh"
  curl -fsSL -o "$ENROLL" "$ENROLL_URL"
fi

HEADSCALE_URL="$HEADSCALE_URL" \
AUTHKEY_FILE="$KEY_FILE" \
HOSTNAME_OVERRIDE="$(curl -fsS -H 'Metadata-Flavor: Google' \
  http://metadata.google.internal/computeMetadata/v1/instance/name)" \
ACCEPT_DNS=false \
bash "$ENROLL"

logger -t headscale-enroll "enrolment finished for role ${ROLE:-unset}"
