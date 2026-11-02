#!/usr/bin/env bash
#
# The GitHub side of a Direct build: its (pre-)release with the DMG + ZIP, and
# the check that GitHub serves that ZIP. One definition for both orchestrators,
# which run it after the appcast by default, and before it with
# appcast-downloads-from-github.
#
#   github-release.sh stable <tag>                 The release of a pushed tag.
#   github-release.sh attach <tag> <id>            Attach the product's DMG + ZIP to it.
#   github-release.sh beta                         Per product in the table that has
#                                                  a tag: push it, create the pre-release,
#                                                  attach its assets.
#   github-release.sh beta-tag <id>                Print that product's tag.
#   github-release.sh download-prefix <tag> <zip>  Check GitHub serves <zip>, then print
#                                                  generate_appcast's --download-url-prefix.
#                                                  Nothing else reaches stdout.
#
# Env:
#   GITHUB_REPOSITORY      owner/name (set on every runner)
#   GH_TOKEN               for gh
#   ATTACH_ASSETS          (beta) "true" attaches the DMG + ZIP
#   DOWNLOADS_FROM_GITHUB  "true" for appcast-downloads-from-github
#   CREATE_DISCUSSION, DISCUSSION_CATEGORY   (stable) the opt-in discussion
#   PRODUCTS_TSV           default /tmp/products.tsv: id, product-name, version,
#                          release-tag, \x1f-delimited
#
# Re-runs. With the release before the appcast, a failed appcast leaves the tag
# and the release behind, and re-running the failed job is the way to finish:
# `plan` compares against the -beta.N tag, so a new push builds only if it
# changes the product, and then as the next beta. So with DOWNLOADS_FROM_GITHUB
# a run keeps what exists, uploads the assets again and carries on to the
# appcast. Without it this behaves as it always did.

set -euo pipefail

PRODUCTS_TSV="${PRODUCTS_TSV:-/tmp/products.tsv}"
DOWNLOADS_FROM_GITHUB="${DOWNLOADS_FROM_GITHUB:-false}"

die() {
  echo "::error::$*" >&2
  exit 1
}

create_release() { # <tag> <notes file> <notes without one> [flags for gh release create]
  local tag=$1 notes=$2 fallback=$3
  shift 3
  if [ "$DOWNLOADS_FROM_GITHUB" = "true" ] && gh release view "$tag" --repo "$GITHUB_REPOSITORY" >/dev/null 2>&1; then
    echo "release $tag already exists — keeping it (re-run)"
    return 0
  fi
  if [ -s "$notes" ]; then
    set -- "$@" --notes-file "$notes"
  else
    set -- "$@" --notes "$fallback"
  fi
  gh release create "$tag" --repo "$GITHUB_REPOSITORY" --title "$tag" "$@"
}

cmd_attach() { # <tag> <product id>
  local dir="./artifacts/mac-direct/mac-direct-build-$2-macos-direct" assets
  shopt -s nullglob
  assets=("$dir"/*.dmg "$dir"/*.zip)
  shopt -u nullglob
  if [ ${#assets[@]} -eq 0 ]; then
    echo "No DMG/ZIP assets to attach"
    return 0
  fi
  gh release upload "$1" --repo "$GITHUB_REPOSITORY" --clobber "${assets[@]}"
}

cmd_stable() { # <tag>
  if [ "${CREATE_DISCUSSION:-}" = "true" ] && [ -n "${DISCUSSION_CATEGORY:-}" ]; then
    create_release "$1" /tmp/notes.md "Release $1" --discussion-category "$DISCUSSION_CATEGORY"
  else
    create_release "$1" /tmp/notes.md "Release $1"
  fi
}

cmd_beta() {
  git config user.name "github-actions[bot]"
  git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
  local id pname rtag
  while IFS=$'\x1f' read -r id pname _ rtag; do
    [ -n "$rtag" ] || continue
    echo "::group::publish $id → $rtag"
    if git rev-parse "refs/tags/$rtag" >/dev/null 2>&1 || git ls-remote --exit-code --tags origin "$rtag" >/dev/null 2>&1; then
      if [ "$DOWNLOADS_FROM_GITHUB" != "true" ]; then
        echo "tag $rtag already exists — skipping (idempotent re-run)"
        echo "::endgroup::"
        continue
      fi
      echo "tag $rtag already exists — keeping it (re-run)"
    else
      git tag -a "$rtag" -m "Beta $rtag"
      git push origin "$rtag"
    fi
    create_release "$rtag" "/tmp/notes-$id.md" "Beta $rtag ($pname)" --prerelease
    if [ "${ATTACH_ASSETS:-}" = "true" ]; then
      cmd_attach "$rtag" "$id"
    fi
    echo "pushed $rtag + pre-release ✅"
    echo "::endgroup::"
  done <"$PRODUCTS_TSV"
}

# legs.tsv has no tag, and a leg's label can't stand in for one: it has no <id>-
# prefix, so a prefixed product would get the wrong URL.
cmd_beta_tag() { # <product id>
  local id rtag
  while IFS=$'\x1f' read -r id _ _ rtag; do
    if [ "$id" = "$1" ] && [ -n "$rtag" ]; then
      echo "$rtag"
      return 0
    fi
  done <"$PRODUCTS_TSV"
  die "no beta tag for product '$1' in $PRODUCTS_TSV"
}

cmd_download_prefix() { # <tag> <zip>
  [ -n "$1" ] || die "no tag for the download URL"
  local want headers got url name
  # The trailing slash is load-bearing: generate_appcast resolves the ZIP's name
  # against this URL, so without it the tag silently drops out of the enclosure
  # (.../releases/download/MyApp_v1.2.0.zip) and the run still succeeds.
  local prefix="https://github.com/$GITHUB_REPOSITORY/releases/download/$1/"
  name=$(basename "$2")
  url="$prefix$name"
  want=$(wc -c <"$2" | tr -d ' ')
  # Anonymous, like Sparkle. --fail because without it a 404 is a finished
  # transfer, which --retry-all-errors doesn't retry, and an asset can lag its
  # upload. Each hop prints its headers, and the redirect says content-length: 0,
  # so only the last hop counts.
  headers=$(curl -fsSIL --retry 5 --retry-all-errors "$url") || true
  got=$(tr -d '\r' <<<"$headers" | awk '/^HTTP\//{ s = $2; n = "" } tolower($1) == "content-length:"{ n = $2 } END{ print s, n }')
  if [ "$got" != "200 $want" ]; then
    die "$url answers '$got', not '200 $want', so the appcast stays where it is. GitHub needs authentication for a private repo's assets, and it renames an asset with a space. Re-run this job once it serves the ZIP."
  fi
  echo "GitHub serves $name ($want bytes)" >&2
  echo "$prefix"
}

case "${1:-}" in
  stable) cmd_stable "$2" ;;
  attach) cmd_attach "$2" "$3" ;;
  beta) cmd_beta ;;
  beta-tag) cmd_beta_tag "$2" ;;
  download-prefix) cmd_download_prefix "$2" "$3" ;;
  *) die "usage: github-release.sh stable <tag> | attach <tag> <id> | beta | beta-tag <id> | download-prefix <tag> <zip>" ;;
esac
