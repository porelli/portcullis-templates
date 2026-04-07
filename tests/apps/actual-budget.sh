#!/usr/bin/env bash
# Test: Actual Budget (native OIDC)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="actual-budget"
section "Actual Budget"

APP_ID=actual-budget
SUBDOMAIN=budget

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID")
wait_for_url "http://${IP}:5006" 60 "$APP_ID"

# Should return HTML
BODY=$(curl -sf "http://${IP}:5006/" 2>/dev/null || echo "")
if echo "$BODY" | grep -qi "<html\|actual\|budget"; then
  pass "/ -> Actual Budget page returned"
else
  fail "/ -> Actual Budget page not found"
fi

# Verify OIDC login method is configured
LOGIN_METHOD=$(docker exec "portcullis-${APP_ID}-1" printenv ACTUAL_LOGIN_METHOD 2>/dev/null || echo "")
if [ "$LOGIN_METHOD" = "openid" ]; then
  pass "ACTUAL_LOGIN_METHOD=openid"
else
  fail "ACTUAL_LOGIN_METHOD expected 'openid', got '$LOGIN_METHOD'"
fi

compose_down "$APP_ID"
