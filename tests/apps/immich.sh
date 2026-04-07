#!/usr/bin/env bash
# Test: Immich (native OIDC + auto-register)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="immich"
section "Immich"

APP_ID=immich
SUBDOMAIN=photos
SERVICE=immich-server

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

compose_down "$APP_ID"
