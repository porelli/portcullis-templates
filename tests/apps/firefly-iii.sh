#!/usr/bin/env bash
# Test: Firefly III (header-auth + remote_user_guard)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="firefly-iii"
section "Firefly III"

APP_ID=firefly-iii
SUBDOMAIN=finance

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID")
wait_for_url "http://${IP}:8080" 90 "$APP_ID"

# Container responds with HTTP 200 or redirect (Firefly may redirect to /login)
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" "http://${IP}:8080/" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 400 ]; then
  pass "/ -> HTTP $HTTP_CODE"
else
  fail "/ -> expected HTTP 2xx/3xx, got $HTTP_CODE"
fi

# Verify AUTHENTICATION_GUARD is set to remote_user_guard
AUTH_GUARD=$(docker exec "portcullis-${APP_ID}-1" printenv AUTHENTICATION_GUARD 2>/dev/null || echo "")
if [ "$AUTH_GUARD" = "remote_user_guard" ]; then
  pass "AUTHENTICATION_GUARD=remote_user_guard"
else
  fail "AUTHENTICATION_GUARD expected 'remote_user_guard', got '$AUTH_GUARD'"
fi

# Verify compose has forward-auth + group-gate middleware
COMPOSE=$(_find_compose "$APP_ID")
if grep -q 'portcullis-auth@docker' "$COMPOSE" && grep -q 'portcullis-groups@docker' "$COMPOSE"; then
  pass "Forward-auth + group-gate middleware configured"
else
  fail "Missing forward-auth or group-gate middleware in compose"
fi

compose_down "$APP_ID"
