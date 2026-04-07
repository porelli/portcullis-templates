#!/usr/bin/env bash
# Test: Nextcloud (native OIDC)
# Nextcloud takes a while to initialize — just verify compose config and Traefik labels.
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="nextcloud"
section "Nextcloud"

APP_ID=nextcloud

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

# Forward-auth middleware present (forward-auth + group-gate)
if grep -q 'portcullis-auth@docker' "$COMPOSE"; then
  pass "Forward-auth middleware configured"
else
  fail "Forward-auth middleware not found"
fi

# Group-gate middleware present
if grep -q 'portcullis-groups@docker' "$COMPOSE"; then
  pass "Group-gate middleware configured"
else
  fail "Group-gate middleware not found"
fi

# Service port matches Traefik label
if grep -q 'loadbalancer.server.port.*80' "$COMPOSE"; then
  pass "Traefik loadbalancer port is 80"
else
  fail "Traefik loadbalancer port mismatch"
fi
