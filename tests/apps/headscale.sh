#!/usr/bin/env bash
# Test: Headscale (native OIDC)
# Static config check only — no container startup needed.
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="headscale"
section "Headscale"

APP_ID=headscale

COMPOSE=$(_find_compose "$APP_ID")
if [ -n "$COMPOSE" ]; then
  pass "compose.yml found: $COMPOSE"
else
  fail "compose.yml not found for $APP_ID"
fi

# Traefik routing enabled (both headscale and headplane services)
if grep -q 'traefik.enable.*true' "$COMPOSE"; then
  pass "Traefik routing enabled"
else
  fail "Traefik routing not configured"
fi

# Two services should have Traefik labels: headscale + headplane
if grep -q 'traefik.http.routers.headscale' "$COMPOSE" && grep -q 'traefik.http.routers.headplane' "$COMPOSE"; then
  pass "Both headscale and headplane have Traefik routers"
else
  fail "Expected Traefik routers for both headscale and headplane"
fi

# Native OIDC — headscale uses OIDC via config template, headplane has OIDC env vars
if grep -q 'HEADSCALE_OIDC_CLIENT_SECRET' "$COMPOSE"; then
  pass "Headscale OIDC client secret configured"
else
  fail "Headscale OIDC client secret not found in compose"
fi

if grep -q 'HEADPLANE_OIDC__ISSUER' "$COMPOSE" && grep -q 'HEADPLANE_OIDC__CLIENT_ID' "$COMPOSE" && grep -q 'HEADPLANE_OIDC__CLIENT_SECRET' "$COMPOSE"; then
  pass "Headplane OIDC env vars configured (issuer, client_id, client_secret)"
else
  fail "Headplane OIDC env vars missing"
fi

# Service port matches Traefik label — headscale on 8080
if grep -q 'loadbalancer.server.port.*8080' "$COMPOSE"; then
  pass "Headscale Traefik loadbalancer port is 8080"
else
  fail "Headscale Traefik loadbalancer port mismatch (expected 8080)"
fi

# Headplane loadbalancer port is 3000
if grep -q 'traefik.http.services.headplane.loadbalancer.server.port.*3000' "$COMPOSE"; then
  pass "Headplane Traefik loadbalancer port is 3000"
else
  fail "Headplane Traefik loadbalancer port mismatch (expected 3000)"
fi
