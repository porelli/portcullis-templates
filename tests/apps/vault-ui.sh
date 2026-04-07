#!/usr/bin/env bash
# Test: Vault UI (mTLS only, no SSO)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="vault-ui"
section "Vault UI"

APP_ID=vault-ui

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

# mTLS only — uses protected TLS tier
if grep -q 'protected@file' "$COMPOSE"; then
  pass "TLS options set to protected@file (mTLS required)"
else
  fail "Expected protected@file TLS option for mTLS-only app"
fi

# Should NOT have forward-auth middleware (mTLS handles auth)
if grep -q 'portcullis-auth@docker' "$COMPOSE"; then
  fail "Vault UI should NOT have forward-auth middleware (mTLS only)"
else
  pass "No forward-auth middleware (correct for mTLS-only app)"
fi

# Service port matches Traefik label
if grep -q 'loadbalancer.server.port.*8080' "$COMPOSE"; then
  pass "Traefik loadbalancer port is 8080"
else
  fail "Traefik loadbalancer port mismatch"
fi
