#!/usr/bin/env bash
# Test: Nextcloud (native OIDC)
# Nextcloud takes a while to initialize — just verify compose config and Traefik labels.
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="nextcloud"
section "Nextcloud"

APP_ID=nextcloud

COMPOSE=$(_find_compose "$APP_ID")
if [ -n "$COMPOSE" ]; then
  pass "compose.yml found: $COMPOSE"
else
  fail "compose.yml not found for $APP_ID"
fi

# Traefik routing enabled
if grep -q 'traefik.enable.*true' "$COMPOSE"; then
  pass "Traefik routing enabled"
else
  fail "Traefik routing not configured"
fi

# Forward-auth middleware present (forward-auth + group-gate)
if grep -q 'portcullis-auth@docker' "$COMPOSE"; then
  pass "Forward-auth middleware configured"
else
  fail "Forward-auth middleware not found"
fi

# Group-gate middleware present
if grep -q 'portcullis-groups@docker' "$COMPOSE"; then
  pass "Group-gate middleware configured"
else
  fail "Group-gate middleware not found"
fi

# X-Forwarded-For trusted from Traefik only
assert_traefik_only_trust "$COMPOSE" TRUSTED_PROXIES

# Service port matches Traefik label
if grep -q 'loadbalancer.server.port.*80' "$COMPOSE"; then
  pass "Traefik loadbalancer port is 80"
else
  fail "Traefik loadbalancer port mismatch"
fi

# Public exceptions (auth.public_access; the Hub generates the router).
MANIFEST="$(dirname "$COMPOSE")/manifest.yaml"
if [ -z "$(public_routed_prefixes "$MANIFEST" listed)" ]; then
  pass "listed mode without listed shares opens nothing"
else
  fail "listed mode without listed shares opens paths"
fi
TOK=AbCdEfGh2345678
ROUTED=$(public_routed_prefixes "$MANIFEST" listed "$TOK")
if echo "$ROUTED" | grep -qx "/s/$TOK" && echo "$ROUTED" | grep -qx "/public.php/dav/files/$TOK" && ! echo "$ROUTED" | grep -qx '/s'; then
  pass "listed share expands /s/{token} and public WebDAV per token only"
else
  fail "listed share expansion wrong: $ROUTED"
fi
if echo "$ROUTED" | grep -q '^/apps/text'; then
  fail "share-wide /apps/text opened in listed mode"
else
  pass "share-wide /apps/text only in mode all"
fi
if public_routed_prefixes "$MANIFEST" all | grep -qxE '/index\.php|/ocs(/.*)?|/remote\.php(/.*)?|/apps|/core|/public\.php'; then
  fail "mode all opens a broad Nextcloud prefix"
else
  pass "mode all stays off /index.php, /ocs, /remote.php, /apps, /core"
fi
