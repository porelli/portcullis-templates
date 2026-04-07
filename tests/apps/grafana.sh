#!/usr/bin/env bash
# Test: Grafana (header-auth + group-gate)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="grafana"
section "Grafana"

APP_ID=grafana
SUBDOMAIN=grafana

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID")
wait_for_url "http://${IP}:3000" 60 "$APP_ID"

# Grafana login page should return HTML
BODY=$(curl -sf "http://${IP}:3000/login" 2>/dev/null || echo "")
if echo "$BODY" | grep -qi "grafana"; then
  pass "/login -> Grafana login page returned"
else
  fail "/login -> Grafana login page not found"
fi

# Verify proxy auth is enabled in the container environment
GF_PROXY=$(docker exec "portcullis-${APP_ID}-1" printenv GF_AUTH_PROXY_ENABLED 2>/dev/null || echo "")
if [ "$GF_PROXY" = "true" ]; then
  pass "GF_AUTH_PROXY_ENABLED=true"
else
  fail "GF_AUTH_PROXY_ENABLED expected 'true', got '$GF_PROXY'"
fi

# Verify compose has forward-auth + group-gate middleware
COMPOSE=$(_find_compose "$APP_ID")
if grep -q 'portcullis-auth@docker' "$COMPOSE" && grep -q 'portcullis-groups@docker' "$COMPOSE"; then
  pass "Forward-auth + group-gate middleware configured"
else
  fail "Missing forward-auth or group-gate middleware in compose"
fi

compose_down "$APP_ID"
