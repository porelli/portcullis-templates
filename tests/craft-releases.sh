#!/usr/bin/env bash
# Bump the pinned web release of every Craft template (storytold/<app>).
# Run by .github/workflows/craft-releases.yml; Dependabot can't track
# release zips, so this does it: for each template whose compose.yml sets
# CRAFT_REPO, read the repo's latest release and, when it is newer than the
# pinned ${CRAFT_VERSION:-...}, rewrite CRAFT_VERSION and CRAFT_SHA256 and
# open one pull request per app (branch craft/<app>-<version>).
#
# The new SHA-256 must agree three ways before anything is written: the
# digest GitHub reports for <app>-web-<ver>.zip, that file's line in the
# release's SHA256SUMS.txt, and the hash of the downloaded zip. Any
# disagreement or unexpected value skips the app (and fails the run).
#
#   bash tests/craft-releases.sh            # check, push branches, open PRs
#   bash tests/craft-releases.sh --dry-run  # check and print only
#
# Needs gh (GH_TOKEN with contents + pull-requests write), git, sha256sum,
# sort -V. Release contents are untrusted: they are only hashed, never run.
set -euo pipefail
cd "$(dirname "$0")/.."

DRY=false
[ "${1:-}" = "--dry-run" ] && DRY=true

BASE="${CRAFT_BASE_BRANCH:-main}"
VER_RE='^[0-9]+\.[0-9]+\.[0-9]+$'
failed=0

log() { echo "[craft-releases] $*"; }
err() { echo "::error::[craft-releases] $*"; failed=1; }

compose_value() { # <compose> <VAR>: default of ${VAR:-default}
  sed -n "s/.*\${$2:-\([^}]*\)}.*/\1/p" "$1" | head -1
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

for compose in */compose.yml; do
  app="${compose%/compose.yml}"
  repo=$(sed -n 's/^[[:space:]]*CRAFT_REPO:[[:space:]]*\(storytold\/[a-z0-9-]*\)[[:space:]]*$/\1/p' "$compose" | head -1)
  [ -n "$repo" ] || continue
  cur=$(compose_value "$compose" CRAFT_VERSION)
  cur_sha=$(compose_value "$compose" CRAFT_SHA256)
  if ! [[ "$cur" =~ $VER_RE ]] || ! [[ "$cur_sha" =~ ^[0-9a-f]{64}$ ]]; then
    err "$app: cannot read the pinned CRAFT_VERSION / CRAFT_SHA256 in $compose"
    continue
  fi

  if ! rel=$(gh release view -R "$repo" --json tagName,assets 2>"$tmp/gh.err"); then
    err "$app: gh release view -R $repo failed: $(head -c 300 "$tmp/gh.err")"
    continue
  fi
  tag=$(jq -r '.tagName' <<<"$rel")
  ver="${tag#v}"
  if [ "$tag" != "v$ver" ] || ! [[ "$ver" =~ $VER_RE ]]; then
    err "$app: latest release tag '$tag' is not v<major>.<minor>.<patch>"
    continue
  fi
  if [ "$ver" = "$cur" ] || [ "$(printf '%s\n%s\n' "$cur" "$ver" | sort -V | tail -1)" != "$ver" ]; then
    log "$app: $cur is current (latest release $ver)"
    continue
  fi

  zip="$app-web-$ver.zip"
  digest=$(jq -r --arg n "$zip" '.assets[] | select(.name == $n) | .digest // ""' <<<"$rel")
  sha="${digest#sha256:}"
  if [ "$digest" != "sha256:$sha" ] || ! [[ "$sha" =~ ^[0-9a-f]{64}$ ]]; then
    err "$app: release $tag has no $zip asset with a sha256 digest"
    continue
  fi
  d="$tmp/$app"
  mkdir -p "$d"
  if ! gh release download "$tag" -R "$repo" -p SHA256SUMS.txt -p "$zip" -D "$d" 2>"$tmp/gh.err"; then
    err "$app: cannot download SHA256SUMS.txt / $zip of $tag: $(head -c 300 "$tmp/gh.err")"
    continue
  fi
  sums=$(awk -v n="$zip" '{ f = $2; sub(/^\*/, "", f) } f == n { print $1 }' "$d/SHA256SUMS.txt")
  got=$(sha256sum "$d/$zip" | cut -d' ' -f1)
  if [ "$sums" != "$sha" ] || [ "$got" != "$sha" ]; then
    err "$app: SHA-256 of $zip disagrees (GitHub $sha, SHA256SUMS.txt '${sums:-missing}', download $got)"
    continue
  fi

  branch="craft/$app-$ver"
  log "$app: $cur -> $ver ($sha)"
  if $DRY; then continue; fi
  if git ls-remote --exit-code --heads origin "$branch" >/dev/null 2>&1; then
    log "$app: branch $branch already exists, skipping"
    continue
  fi

  git checkout -q -B "$branch" "origin/$BASE"
  sed -i -e "s/\${CRAFT_VERSION:-$cur}/\${CRAFT_VERSION:-$ver}/" \
         -e "s/\${CRAFT_SHA256:-$cur_sha}/\${CRAFT_SHA256:-$sha}/" "$compose"
  if [ "$(compose_value "$compose" CRAFT_VERSION)" != "$ver" ] || [ "$(compose_value "$compose" CRAFT_SHA256)" != "$sha" ]; then
    err "$app: rewriting $compose failed"
    git checkout -q -- "$compose"
    git checkout -q "origin/$BASE"
    continue
  fi
  git add "$compose"
  git -c user.name="github-actions[bot]" -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
    commit -q -m "templates: bump $app web release to $ver" \
    -m "storytold/$app $tag: $zip sha256 $sha (GitHub asset digest, SHA256SUMS.txt and download agree)."
  git push -q origin "HEAD:refs/heads/$branch"
  pr_url=$(gh pr create --base "$BASE" --head "$branch" \
    --title "templates: bump $app web release to $ver" \
    --body "$(cat <<EOF
Bumps the pinned web release of \`$app\` from $cur to $ver (https://github.com/$repo/releases/tag/$tag).

- \`CRAFT_VERSION\`: $cur -> $ver
- \`CRAFT_SHA256\`: \`$sha\` (the GitHub asset digest of \`$zip\`, its line in \`SHA256SUMS.txt\` and the downloaded file agree)

Opened by the Craft releases workflow with GITHUB_TOKEN, so pull_request CI does not start on its own: the workflow dispatches **Test Apps** (\`pr=<this PR>\`, \`apps=$app\`, core ref from the base) and **Lint** on this branch. If either is missing, dispatch it by hand (or close and reopen the PR) before merging, and read the release notes for changes to the web packaging (MIME types, isolation headers, file layout).
EOF
)")
  pr_num="${pr_url##*/}"
  # workflow_dispatch is the one event GITHUB_TOKEN may start (actions: write).
  if [[ "$pr_num" =~ ^[0-9]+$ ]] \
      && gh workflow run test-apps.yml --ref "$BASE" -f pr="$pr_num" -f apps="$app" \
      && gh workflow run lint.yml --ref "$branch"; then
    log "$app: PR #$pr_num opened, Test Apps (apps=$app) + Lint dispatched"
  else
    err "$app: PR ${pr_url:-?} opened, but dispatching Test Apps / Lint failed"
  fi
  git checkout -q "origin/$BASE"
done

exit "$failed"
