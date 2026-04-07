#!/usr/bin/env bash
# Test: DokuWiki (forward-auth + group-gate)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="dokuwiki"
section "DokuWiki"

APP_ID=dokuwiki
SUBDOMAIN=dokuwiki

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID")
# DokuWiki (linuxserver image) listens on port 80, not 8080
wait_for_url "http://${IP}:80" 90 "$APP_ID"

# DokuWiki should return HTML
BODY=$(curl -sf "http://${IP}:80/" 2>/dev/null || echo "")
if echo "$BODY" | grep -qi "dokuwiki\|<html\|wiki"; then
  pass "/ -> DokuWiki page returned"
else
  fail "/ -> DokuWiki page not found"
fi

# Verify compose has forward-auth + group-gate middleware
COMPOSE=$(_find_compose "$APP_ID")
if grep -q 'portcullis-auth@docker' "$COMPOSE" && grep -q 'portcullis-groups@docker' "$COMPOSE"; then
  pass "Forward-auth + group-gate middleware configured"
else
  fail "Missing forward-auth or group-gate middleware in compose"
fi

compose_down "$APP_ID"
