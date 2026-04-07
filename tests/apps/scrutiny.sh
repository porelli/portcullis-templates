#!/usr/bin/env bash
# Test: Scrutiny (forward-auth + group-gate)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="scrutiny"
section "Scrutiny"

APP_ID=scrutiny
SUBDOMAIN=disks

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID")
# Scrutiny omnibus listens on port 8080
wait_for_url "http://${IP}:8080" 90 "$APP_ID"

# Scrutiny should return HTML
BODY=$(curl -sf "http://${IP}:8080/" 2>/dev/null || echo "")
if echo "$BODY" | grep -qi "scrutiny\|<html"; then
  pass "/ -> Scrutiny page returned"
else
  fail "/ -> Scrutiny page not found"
fi

# Verify compose has forward-auth + group-gate middleware
COMPOSE=$(_find_compose "$APP_ID")
if grep -q 'portcullis-auth@docker' "$COMPOSE" && grep -q 'portcullis-groups@docker' "$COMPOSE"; then
  pass "Forward-auth + group-gate middleware configured"
else
  fail "Missing forward-auth or group-gate middleware in compose"
fi

compose_down "$APP_ID"
