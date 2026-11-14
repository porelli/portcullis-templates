#!/usr/bin/env bash
# Test: PhotoCraft (forward-auth + group-gate; static Craft web build)
# Static checks, then a boot: photocraft-fetch downloads and verifies the pinned
# release, photocraft serves it to loopback only (Traefik's side is the sign-in
# test).
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="photocraft"
section "PhotoCraft"

APP_ID=photocraft
FETCH=photocraft-fetch

COMPOSE=$(_find_compose "$APP_ID") || { fail "compose.yml not found for $APP_ID"; exit 1; }
DIR=$(dirname "$COMPOSE")

if grep -q 'traefik.enable.*true' "$COMPOSE"; then
  pass "Traefik routing enabled"
else
  fail "Traefik routing not configured"
fi
if grep -q 'portcullis-auth@docker' "$COMPOSE" && grep -q 'portcullis-groups@docker' "$COMPOSE"; then
  pass "Forward-auth + group-gate middleware configured"
else
  fail "Missing forward-auth or group-gate middleware in compose"
fi
if grep -q 'loadbalancer.server.port.*8080' "$COMPOSE"; then
  pass "Traefik loadbalancer port is 8080"
else
  fail "Traefik loadbalancer port mismatch (expected 8080)"
fi
assert_compose_setting "$COMPOSE" CRAFT_REPO 'storytold/photocraft'
assert_compose_setting "$COMPOSE" CRAFT_VERSION '\$\{CRAFT_VERSION:-[0-9]+\.[0-9]+\.[0-9]+\}'
assert_compose_setting "$COMPOSE" CRAFT_SHA256 '\$\{CRAFT_SHA256:-[0-9a-f]{64}\}'
for f in fetch.sh nginx.conf; do
  if [ -f "$DIR/$f" ]; then pass "$f shipped"; else fail "$f missing"; fi
done
if grep -q 'include /tmp/portcullis-allow.conf;' "$DIR/nginx.conf" && grep -q 'deny all' "$COMPOSE"; then
  pass "nginx answers only the allowlist (Traefik + loopback)"
else
  fail "nginx allowlist missing"
fi
if grep -Eq 'sha256sum -c' "$DIR/fetch.sh" && \
   [ "$(grep -n 'sha256sum -c' "$DIR/fetch.sh" | cut -d: -f1)" -lt "$(grep -n '^unzip' "$DIR/fetch.sh" | cut -d: -f1)" ]; then
  pass "fetch.sh verifies the SHA-256 before unpacking"
else
  fail "fetch.sh must verify the SHA-256 before unzip"
fi

compose_up "$APP_ID"
C=portcullis-$APP_ID-1

# The init container must finish successfully (download + verify + unpack).
st=""
for _ in $(seq 1 90); do
  st=$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "portcullis-$FETCH-1" 2>/dev/null || true)
  case "$st" in exited*) break ;; esac
  sleep 2
done
if [ "$st" = "exited 0" ]; then
  pass "$FETCH downloaded, verified and unpacked the release"
else
  fail "$FETCH: $st"
  docker logs "portcullis-$FETCH-1" 2>&1 | tail -20 || true
fi

health=""
for _ in $(seq 1 60); do
  health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$C" 2>/dev/null || true)
  [ "$health" = healthy ] && break
  sleep 2
done
if [ "$health" = healthy ]; then pass "$APP_ID is healthy"; else fail "$APP_ID health: ${health:-none}"; fi

# Loopback (allowed): the page, the wasm MIME type, no listing, no dotfiles.
get() { docker exec "$C" wget -q -S -O - "http://127.0.0.1:8080$1" 2>&1 || true; }
if get / | grep -q '<title>PhotoCraft</title>'; then pass "page served"; else fail "page not served"; fi
wasm=$(docker exec "$C" sh -c 'cd /srv/craft/www && find . -name "*.wasm" | head -n 1' | sed 's|^\.||')
if [ -n "$wasm" ] && get "$wasm" | grep -qi 'Content-Type: application/wasm'; then
  pass "$wasm served as application/wasm"
else
  fail "wasm not served as application/wasm (${wasm:-no .wasm found})"
fi
# Everything the page loads through the app's route: its scripts, module
# preloads and inline imports, then every module those import, to the end of
# the static graph (tests/web_refs.py): each must answer 200, modules as
# JavaScript. A module importing a path the release zip doesn't have at that
# place (PhotoCraft's app/ -> ./snippets/) fails here, not in the browser.
if refs=$(python3 tests/web_refs.py --docker-exec "$C" http://127.0.0.1:8080/ 2>&1); then
  pass "every script, module and import the page loads answers 200 ($(grep -c '^  200 ' <<<"$refs") files)"
else
  fail "the page loads files nginx doesn't serve:"
  printf '%s\n' "$refs" | sed 's/^/    /'
fi
# The boot module fetches app/parts.txt (line 1 "photocraft-parts <n>", then
# the n part names), then each part, from inside the wasm: all must be served.
parts=$(get /app/parts.txt | sed -n '/^photocraft-parts /,$p')
n=$(printf '%s\n' "$parts" | sed -n '1s/^photocraft-parts \([0-9][0-9]*\)$/\1/p')
names=$(printf '%s\n' "$parts" | sed -n '2,$p' | grep -E '^[A-Za-z0-9._-]+$' || true)
if [ -n "$n" ] && [ "$n" -ge 1 ] && [ "$(printf '%s\n' "$names" | grep -c .)" = "$n" ]; then
  bad=""
  for p in $names; do
    docker exec "$C" wget -q -O /dev/null "http://127.0.0.1:8080/app/$p" 2>/dev/null || bad="$bad $p"
  done
  if [ -z "$bad" ]; then pass "app/parts.txt and its $n part(s) served"; else fail "app parts not served:$bad"; fi
else
  fail "app/parts.txt not served or not 'photocraft-parts <n>' + n names"
fi
# The /app/snippets/ mapping keeps the server's rules: dotfiles, listing.
if get /app/snippets/.htaccess | grep -q 'HTTP/1.1 404'; then pass "dotfiles under /app/snippets/ are 404"; else fail "dotfiles under /app/snippets/ are served"; fi
if get /app/snippets/ | grep -q 'HTTP/1.1 404'; then pass "/app/snippets/ has no listing"; else fail "/app/snippets/ answers a listing"; fi
snip=$(docker exec "$C" sh -c 'cd /srv/craft/www/snippets && find . -name "*.js" | sort | head -n 1' | sed 's|^\./||')
hdrs=$(get "/app/snippets/$snip")
if [ -n "$snip" ] && grep -q 'HTTP/1.1 200' <<<"$hdrs" && grep -qi 'X-Content-Type-Options: nosniff' <<<"$hdrs" \
   && grep -qi 'Content-Security-Policy: frame-ancestors' <<<"$hdrs" && grep -qi 'Content-Type: text/javascript' <<<"$hdrs"; then
  pass "/app/snippets/$snip served from snippets/ with the security headers"
else
  fail "/app/snippets/${snip:-?} not served as JavaScript with the security headers"
fi
if get /.htaccess | grep -q 'HTTP/1.1 404'; then pass "dotfiles are 404"; else fail "dotfiles are served"; fi
if docker exec "$C" sh -c 'test -w /srv/craft' 2>/dev/null; then fail "site volume is writable by nginx"; else pass "site volume read-only for nginx"; fi
if [ "$(docker exec "$C" id -u)" != 0 ]; then pass "nginx runs as non-root"; else fail "nginx runs as root"; fi

# Any peer but Traefik (here: the CI host) gets 403.
IP=$(app_container_ip "$APP_ID")
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://$IP:8080/" 2>/dev/null || true)
if [ "$code" = 403 ]; then pass "non-Traefik peer refused (403)"; else fail "non-Traefik peer got HTTP $code (expected 403)"; fi

compose_down "$APP_ID"
