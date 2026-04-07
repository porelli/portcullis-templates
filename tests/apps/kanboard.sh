#!/usr/bin/env bash
# Test: Kanboard (header-auth + group-gate)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="kanboard"
section "Kanboard"

APP_ID=kanboard
SUBDOMAIN=kanboard

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID")
wait_for_url "http://${IP}:80" 60 "$APP_ID"

# Kanboard should return HTML on its login page
BODY=$(curl -sf "http://${IP}:80/" 2>/dev/null || echo "")
if echo "$BODY" | grep -qi "kanboard\|login"; then
  pass "/ -> Kanboard page returned"
else
  fail "/ -> Kanboard page not found"
fi

# Verify compose has forward-auth + group-gate middleware
COMPOSE=$(_find_compose "$APP_ID")
if grep -q 'portcullis-auth@docker' "$COMPOSE" && grep -q 'portcullis-groups@docker' "$COMPOSE"; then
  pass "Forward-auth + group-gate middleware configured"
else
  fail "Missing forward-auth or group-gate middleware in compose"
fi

compose_down "$APP_ID"
