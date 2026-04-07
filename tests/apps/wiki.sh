#!/usr/bin/env bash
# Test: Wiki.js (forward-auth + group-gate)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="wiki"
section "Wiki.js"

APP_ID=wiki
SUBDOMAIN=wiki
SERVICE=wiki

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID" "$SERVICE")
wait_for_url "http://${IP}:3000" 90 "$APP_ID"

# Wiki.js should return HTML
BODY=$(curl -sf "http://${IP}:3000/" 2>/dev/null || echo "")
if echo "$BODY" | grep -qi "wiki\|<html"; then
  pass "/ -> Wiki.js page returned"
else
  fail "/ -> Wiki.js page not found"
fi

# Verify compose has forward-auth + group-gate middleware
COMPOSE=$(_find_compose "$APP_ID")
if grep -q 'portcullis-auth@docker' "$COMPOSE" && grep -q 'portcullis-groups@docker' "$COMPOSE"; then
  pass "Forward-auth + group-gate middleware configured"
else
  fail "Missing forward-auth or group-gate middleware in compose"
fi

compose_down "$APP_ID"
