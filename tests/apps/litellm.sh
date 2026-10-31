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

# Native OIDC — the host-wide (API) router must NOT have forward-auth (would
# block API clients using the master key / virtual keys)
if grep -qE 'routers\.litellm\.middlewares:.*portcullis-(auth|groups)@docker' "$COMPOSE"; then
  fail "Forward-auth middleware on the LiteLLM API router"
else
  pass "API router has no forward-auth (master key / virtual keys)"
fi

# Security: admin UI and every login path behind forward-auth + group-gate,
# so only users_litellm members can sign in via SSO.
UI_RULE=$(grep 'routers.litellm-ui.rule:' "$COMPOSE" || true)
MISSING=""
for p in /ui /sso /login /v2/login /fallback/login /onboarding; do
  echo "$UI_RULE" | grep -qF "PathPrefix(\`$p\`)" || MISSING="$MISSING $p"
done
if [ -n "$UI_RULE" ] && [ -z "$MISSING" ] \
  && grep -q 'routers.litellm-ui.middlewares:.*portcullis-auth@docker,portcullis-groups@docker' "$COMPOSE"; then
  pass "UI + login paths behind forward-auth + group-gate"
else
  fail "UI/login router missing, not gated, or missing paths:${MISSING:- (router)}"
fi

# Security: SSO users default to the least-privileged role
if grep -q 'GENERIC_ROLE_MAPPINGS_DEFAULT_ROLE: internal_user_viewer' "$COMPOSE"; then
  pass "SSO default role is internal_user_viewer"
else
  fail "SSO default role is not internal_user_viewer"
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
