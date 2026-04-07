#!/usr/bin/env bash
# Test: LiteLLM (native OIDC)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="litellm"
section "LiteLLM"

APP_ID=litellm

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

# Forward-auth middleware present
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

# OIDC env vars configured
if grep -q 'GENERIC_CLIENT_ID' "$COMPOSE"; then
  pass "OIDC client config present"
else
  fail "OIDC client config not found"
fi

# Service port matches Traefik label
if grep -q 'loadbalancer.server.port.*4000' "$COMPOSE"; then
  pass "Traefik loadbalancer port is 4000"
else
  fail "Traefik loadbalancer port mismatch"
fi
