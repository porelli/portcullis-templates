#!/usr/bin/env bash
# Test: Scrutiny (forward-auth + group-gate)
# Static config check only — no container startup needed.
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="scrutiny"
section "Scrutiny"

APP_ID=scrutiny

COMPOSE=$(_find_compose "$APP_ID")
if [ -n "$COMPOSE" ]; then
  pass "compose.yml found: $COMPOSE"
else
  fail "compose.yml not found for $APP_ID"
fi

# Traefik routing enabled
if grep -q 'traefik.enable.*true' "$COMPOSE"; then
  pass "Traefik routing enabled"
else
  fail "Traefik routing not configured"
fi

# Forward-auth + group-gate middleware
if grep -q 'portcullis-auth@docker' "$COMPOSE" && grep -q 'portcullis-groups@docker' "$COMPOSE"; then
  pass "Forward-auth + group-gate middleware configured"
else
  fail "Missing forward-auth or group-gate middleware in compose"
fi

# Service port matches Traefik label
if grep -q 'loadbalancer.server.port.*8080' "$COMPOSE"; then
  pass "Traefik loadbalancer port is 8080"
else
  fail "Traefik loadbalancer port mismatch (expected 8080)"
fi
