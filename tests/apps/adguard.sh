#!/usr/bin/env bash
# Test: AdGuard Home (forward-auth + group-gate)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="adguard"
section "AdGuard Home"

APP_ID=adguard
SUBDOMAIN=adguard

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID")
# AdGuard initial setup wizard listens on port 3000; after setup it moves to port 80.
# In CI with a fresh volume, port 3000 is the correct one.
wait_for_url "http://${IP}:3000" 60 "$APP_ID"

# AdGuard should return HTML (setup wizard or dashboard)
BODY=$(curl -sf "http://${IP}:3000/" 2>/dev/null || echo "")
if echo "$BODY" | grep -qi "adguard\|<html\|setup"; then
  pass "/ -> AdGuard page returned"
else
  fail "/ -> AdGuard page not found"
fi

# Verify compose has forward-auth + group-gate middleware
COMPOSE=$(_find_compose "$APP_ID")
if grep -q 'portcullis-auth@docker' "$COMPOSE" && grep -q 'portcullis-groups@docker' "$COMPOSE"; then
  pass "Forward-auth + group-gate middleware configured"
else
  fail "Missing forward-auth or group-gate middleware in compose"
fi

compose_down "$APP_ID"
