#!/usr/bin/env bash
# Test: Immich (native OIDC + auto-register)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="immich"
section "Immich"

APP_ID=immich
SERVICE=immich-server

COMPOSE=$(_find_compose "$APP_ID")
# Static: Immich links OAuth logins to existing users by email (no setting
# to disable it); the lock job pins local users to a placeholder oauthId.
if grep -q 'immich-lock-local-users:' "$COMPOSE" && grep -q "SET \"oauthId\" = 'portcullis-local:'" "$COMPOSE"; then
  pass "local users locked against OAuth email linking"
else
  fail "immich-lock-local-users job missing"
fi

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID" "$SERVICE")
wait_for_url "http://${IP}:2283" 120 "$APP_ID"

# Server should respond with HTML or JSON
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" "http://${IP}:2283/" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 400 ]; then
  pass "/ -> HTTP $HTTP_CODE"
else
  fail "/ -> expected HTTP 2xx/3xx, got $HTTP_CODE"
fi

# Verify OIDC config is set via environment
OIDC_CONFIG=$(docker exec "portcullis-${SERVICE}-1" printenv IMMICH_CONFIG_FILE 2>/dev/null || echo "")
if [ -n "$OIDC_CONFIG" ]; then
  pass "IMMICH_CONFIG_FILE is set ($OIDC_CONFIG)"
else
  fail "IMMICH_CONFIG_FILE not set"
fi

# Runtime: the lock job ran after setup and succeeded
if LOCK_RC=$(timeout 240 docker wait "portcullis-immich-lock-local-users-1" 2>/dev/null) && [ "$LOCK_RC" = "0" ]; then
  pass "immich-lock-local-users exited 0"
else
  fail "immich-lock-local-users did not finish successfully (rc=${LOCK_RC:-none})"
  docker logs "portcullis-immich-lock-local-users-1" 2>&1 | tail -5 || true
fi

compose_down "$APP_ID"

# Public exceptions: shared links only (mode all; the Hub generates the
# router). /api as a whole must never be public.
MANIFEST="$(dirname "$(_find_compose immich)")/manifest.yaml"
ROUTED=$(public_routed_prefixes "$MANIFEST" all)
if echo "$ROUTED" | grep -qx /share && echo "$ROUTED" | grep -qx =/api/shared-links/me && ! echo "$ROUTED" | grep -qx /api; then
  pass "shared-link paths declared, /api not public"
else
  fail "immich public paths: $ROUTED"
fi
if grep -q 'enabled_by_default: false' "$MANIFEST"; then
  pass "public exceptions off by default (would drop handshake mTLS for the host)"
else
  fail "immich public exceptions must be off by default"
fi
