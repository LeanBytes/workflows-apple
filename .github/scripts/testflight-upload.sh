#!/usr/bin/env bash
#
# Upload every app-store leg to App Store Connect. One definition for
# distribute.yml, distribute-release.yml and distribute-alpha.yml.
#
# Env:
#   LEGS_JSON  the plan's legs. An app-store leg's .ipa or .pkg sits in
#              artifacts/<build>/<build>-build-<leg>/.
#   ASC_KEY_ID ASC_ISSUER_ID ASC_KEY_BASE64
#   ASC_KEY_ID_ALT ASC_ISSUER_ID_ALT ASC_KEY_ALT_BASE64
#              A leg with "asc-key": "alt" uploads with the *_ALT key, into that
#              team's app. Without it the leg fails: it never gets the default key.
#
# altool reads the keys from ~/.appstoreconnect/private_keys. The caller's
# Cleanup step removes them, also after a failure.

set -uo pipefail
# shellcheck source=classify-upload.sh
source "$(dirname "${BASH_SOURCE[0]}")/classify-upload.sh"

mkdir -p ~/.appstoreconnect/private_keys
[ -z "$ASC_KEY_ID" ] || (umask 077; echo "$ASC_KEY_BASE64" | base64 --decode > ~/.appstoreconnect/private_keys/"AuthKey_${ASC_KEY_ID}.p8")
[ -z "$ASC_KEY_ID_ALT" ] || (umask 077; echo "$ASC_KEY_ALT_BASE64" | base64 --decode > ~/.appstoreconnect/private_keys/"AuthKey_${ASC_KEY_ID_ALT}.p8")

# \x1f, not tab: tab is IFS-whitespace, and `read` would collapse an empty field.
LEGS=$(python3 -c '
import json, sys
for l in json.loads(sys.argv[1]):
    print("\x1f".join(str(l.get(k, "")) for k in ("leg", "platform", "channel", "distribute", "build", "asc-key")))
' "$LEGS_JSON") || exit 1

while IFS=$'\x1f' read -r leg plat chan dist kind asc; do
  [ "$chan" = "app-store" ] || continue
  [ "$dist" = "True" ] || { echo "leg $leg: distribute=false — skipping upload"; continue; }
  echo "::group::TestFlight upload — $leg"
  if [ "$asc" = "alt" ]; then KEY=$ASC_KEY_ID_ALT; ISSUER=$ASC_ISSUER_ID_ALT; else KEY=$ASC_KEY_ID; ISSUER=$ASC_ISSUER_ID; fi
  if [ -z "$KEY" ]; then
    echo "::error::No App Store Connect key for leg $leg"; echo "::endgroup::"; exit 1
  fi
  case "$plat" in ios) ext=ipa; type=ios ;; tvos) ext=ipa; type=appletvos ;; *) ext=pkg; type=macos ;; esac
  FILE=$(ls "./artifacts/$kind/$kind-build-$leg/"*."$ext" 2>/dev/null | head -1 || true)
  if [ -z "$FILE" ] || [ ! -f "$FILE" ]; then
    echo "::error::No .$ext for leg $leg"; echo "::endgroup::"; exit 1
  fi
  # errexit off around the capture: a non-zero altool exit must reach the
  # classifier below, not abort the step.
  set +e
  OUTPUT=$(xcrun altool --upload-app --type "$type" --file "$FILE" \
    --apiKey "$KEY" --apiIssuer "$ISSUER" 2>&1)
  RC=$?
  set -e
  echo "$OUTPUT"
  case "$(classify_upload "$RC" "$OUTPUT")" in
    accepted)        echo "TestFlight upload accepted for $leg"; echo "::endgroup::"; continue ;;
    already-present) echo "Build for $leg already present — treating as success."; echo "::endgroup::"; continue ;;
  esac
  echo "::error::altool failed for $leg (exit ${RC})"; echo "::endgroup::"; exit 1
done <<<"$LEGS"
