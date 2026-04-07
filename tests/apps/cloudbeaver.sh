#!/usr/bin/env bash
# Test: CloudBeaver (forward-auth + group-gate)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="cloudbeaver"
section "CloudBeaver"

APP_ID=cloudbeaver
SUBDOMAIN=db

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID")
wait_for_url "http://${IP}:8978" 60 "$APP_ID"

# CloudBeaver should return HTML
BODY=$(curl -sf "http://${IP}:8978/" 2>/dev/null || echo "")
if echo "$BODY" | grep -qi "cloudbeaver\|<html"; then
  pass "/ -> CloudBeaver page returned"
else
  fail "/ -> CloudBeaver page not found"
fi

# Verify compose has forward-auth + group-gate middleware
COMPOSE=$(_find_compose "$APP_ID")
if grep -q 'portcullis-auth@docker' "$COMPOSE" && grep -q 'portcullis-groups@docker' "$COMPOSE"; then
  pass "Forward-auth + group-gate middleware configured"
else
  fail "Missing forward-auth or group-gate middleware in compose"
fi

compose_down "$APP_ID"
