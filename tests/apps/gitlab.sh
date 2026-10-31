#!/usr/bin/env bash
# Test: GitLab (native OIDC)
# GitLab takes a long time to start — just verify compose config and Traefik labels.
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="gitlab"
section "GitLab"

APP_ID=gitlab

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

# Native OIDC — must NOT have forward-auth middleware (would break
# git-over-HTTPS, the API and CI runners)
if grep -qE 'portcullis-auth@docker|portcullis-groups@docker' "$COMPOSE"; then
  fail "Forward-auth middleware present on a native-OIDC app"
else
  pass "No forward-auth middleware (native OIDC only)"
fi

# OIDC configuration present
if grep -q 'omniauth_providers' "$COMPOSE"; then
  pass "OIDC omniauth_providers configured"
else
  fail "OIDC omniauth_providers not found in compose"
fi

# Service port matches Traefik label
if grep -q 'loadbalancer.server.port.*80' "$COMPOSE"; then
  pass "Traefik loadbalancer port is 80"
else
  fail "Traefik loadbalancer port mismatch"
fi
