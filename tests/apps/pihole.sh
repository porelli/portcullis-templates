#!/usr/bin/env bash
# Test: Pi-hole (forward-auth + group-gate)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="pihole"
section "Pi-hole"

APP_ID=pihole
SUBDOMAIN=pihole

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID")
# Pi-hole web UI listens on port 80
wait_for_url "http://${IP}:80/admin/" 90 "$APP_ID"

# Pi-hole admin page should return HTML
BODY=$(curl -sf "http://${IP}:80/admin/" 2>/dev/null || echo "")
if echo "$BODY" | grep -qi "pi-hole\|pihole\|<html"; then
  pass "/admin/ -> Pi-hole page returned"
else
  fail "/admin/ -> Pi-hole page not found"
fi

# Verify compose has forward-auth + group-gate middleware
COMPOSE=$(_find_compose "$APP_ID")
if grep -q 'portcullis-auth@docker' "$COMPOSE" && grep -q 'portcullis-groups@docker' "$COMPOSE"; then
  pass "Forward-auth + group-gate middleware configured"
else
  fail "Missing forward-auth or group-gate middleware in compose"
fi

compose_down "$APP_ID"
