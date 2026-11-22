#!/usr/bin/env bash
# Puts one file on the ad hoc page's server (adhoc.sarensw.net, on tarantula).
# Its upload port answers only inside the home LAN, so this runs on a
# self-hosted Mac there. A file lands under its final name only once complete.
#
# Usage: adhoc-upload.sh <file> <path under the server, e.g. <bundle-id>/app.ipa>
# Env:   ADHOC_UPLOAD_TOKEN (secret), ADHOC_UPLOAD_URL (http://192.168.178.84:8019)
set -euo pipefail

FILE="$1"
DEST="$2"
URL="${ADHOC_UPLOAD_URL:-http://192.168.178.84:8019}"

curl -fsS --retry 3 --connect-timeout 10 \
  -H "Authorization: Bearer ${ADHOC_UPLOAD_TOKEN:?ADHOC_UPLOAD_TOKEN not set}" \
  -T "$FILE" "${URL%/}/upload/${DEST}"
