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

# Native OIDC — must NOT have forward-auth middleware (would block
# API clients using the master key / virtual keys)
if grep -qE 'portcullis-auth@docker|portcullis-groups@docker' "$COMPOSE"; then
  fail "Forward-auth middleware present on a native-OIDC app"
else
  pass "No forward-auth middleware (native OIDC only)"
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
