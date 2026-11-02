#!/bin/sh
# One-shot init for a Craft web template (storytold/<app>, a static
# Rust/WebAssembly site): downloads the pinned release's web zip, checks its
# SHA-256 BEFORE unpacking, unpacks it next to the live copy and swaps it in
# by rename. Any failure exits non-zero, so the web server (depends_on:
# service_completed_successfully) never starts on a missing or unverified
# build. The volume is mounted at /srv/craft:
#   www/        the site nginx serves (read-only there)
#   build.txt   "<app> <version> <sha256>" of www/, written last
# Same file in every Craft template; the app comes from CRAFT_APP/CRAFT_REPO.
set -eu

log() { echo "craft-fetch: $*"; }
die() { echo "craft-fetch: ERROR: $*" >&2; exit 1; }

app=${CRAFT_APP:-}
repo=${CRAFT_REPO:-}
version=${CRAFT_VERSION:-}
sha=${CRAFT_SHA256:-}
site=${CRAFT_SITE:-/srv/craft}

# Validate every input before it reaches a URL or a path.
printf '%s' "$app" | grep -Eqx '[a-z0-9]+(-[a-z0-9]+)*' || die "CRAFT_APP '$app' is not an app name"
printf '%s' "$repo" | grep -Eqx 'storytold/[a-z0-9]+(-[a-z0-9]+)*' || die "CRAFT_REPO '$repo' is not a storytold repository"
printf '%s' "$version" | grep -Eqx '[0-9]+\.[0-9]+\.[0-9]+' || die "CRAFT_VERSION '$version' is not a release version (x.y.z)"
printf '%s' "$sha" | grep -Eqx '[0-9a-f]{64}' || die "CRAFT_SHA256 is not a lowercase SHA-256 hex digest"
[ -d "$site" ] && [ -w "$site" ] || die "$site is not a writable directory"

# A run interrupted between the two renames of the swap left only .old:
# put the last verified build back before anything else.
if [ ! -e "$site/www" ] && [ -d "$site/.old" ]; then mv "$site/.old" "$site/www"; fi

want="$app $version $sha"
if [ -f "$site/build.txt" ] && [ -f "$site/www/index.html" ] && [ "$(cat "$site/build.txt")" = "$want" ]; then
  log "$app $version already in place"
  exit 0
fi

# Leftovers of an interrupted run (all ours, never served).
rm -rf "$site"/.work.* "$site/.old"

work=$(mktemp -d "$site/.work.XXXXXX")
trap 'rm -rf "$work"' EXIT
name="$app-web-$version"
url="https://github.com/$repo/releases/download/v$version/$name.zip"

log "downloading $url"
wget -q -T 60 -O "$work/web.zip" "$url" || die "download failed: $url"

# Verify first: nothing is unpacked from an archive that doesn't match the pin.
echo "$sha  $work/web.zip" | sha256sum -c -s - || die "SHA-256 mismatch for $name.zip (expected $sha); not unpacking"
log "SHA-256 verified"

mkdir "$work/x"
unzip -q "$work/web.zip" -d "$work/x" || die "unzip failed"
rm -f "$work/web.zip"

# Exactly the expected top-level directory, with the page and no symlinks.
[ "$(ls -A "$work/x")" = "$name" ] || die "unexpected archive layout (want only $name/)"
[ -f "$work/x/$name/index.html" ] || die "$name/index.html missing"
[ -z "$(find "$work/x" -type l | head -n 1)" ] || die "archive contains symlinks"
[ -z "$(find "$work/x" ! -type f ! -type d | head -n 1)" ] || die "archive contains special files"
# Readable by nginx (non-root), writable by nobody else.
chmod -R u=rwX,go=rX "$work/x/$name"

# Swap: the old site moves aside, the new one takes its name, the marker is
# written last (a crash before it just repeats the download next start).
rm -f "$site/build.txt"
if [ -e "$site/www" ]; then mv "$site/www" "$site/.old"; fi
mv "$work/x/$name" "$site/www"
printf '%s\n' "$want" > "$site/.build.txt.tmp"
mv -f "$site/.build.txt.tmp" "$site/build.txt"
rm -rf "$site/.old"
log "$app $version installed"
