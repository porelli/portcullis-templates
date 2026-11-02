#!/usr/bin/env bash
# Test: WordCraft (forward-auth + group-gate; static Craft web build)
# Static checks, then a boot: wordcraft-fetch downloads and verifies the pinned
# release, wordcraft serves it to loopback only (Traefik's side is the sign-in
# test).
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="wordcraft"
section "WordCraft"

APP_ID=wordcraft
FETCH=wordcraft-fetch

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
assert_compose_setting "$COMPOSE" CRAFT_REPO 'storytold/wordcraft'
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
if get / | grep -q '<title>WordCraft</title>'; then pass "page served"; else fail "page not served"; fi
wasm=$(docker exec "$C" sh -c 'cd /srv/craft/www && find . -name "*.wasm" | head -n 1' | sed 's|^\.||')
if [ -n "$wasm" ] && get "$wasm" | grep -qi 'Content-Type: application/wasm'; then
  pass "$wasm served as application/wasm"
else
  fail "wasm not served as application/wasm (${wasm:-no .wasm found})"
fi
if get /.htaccess | grep -q 'HTTP/1.1 404'; then pass "dotfiles are 404"; else fail "dotfiles are served"; fi
if docker exec "$C" sh -c 'test -w /srv/craft' 2>/dev/null; then fail "site volume is writable by nginx"; else pass "site volume read-only for nginx"; fi
if [ "$(docker exec "$C" id -u)" != 0 ]; then pass "nginx runs as non-root"; else fail "nginx runs as root"; fi

# Any peer but Traefik (here: the CI host) gets 403.
IP=$(app_container_ip "$APP_ID")
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://$IP:8080/" 2>/dev/null || true)
if [ "$code" = 403 ]; then pass "non-Traefik peer refused (403)"; else fail "non-Traefik peer got HTTP $code (expected 403)"; fi

compose_down "$APP_ID"
