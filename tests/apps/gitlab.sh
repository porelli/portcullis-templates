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

# Native OIDC — the host-wide router must NOT have forward-auth (would break
# git-over-HTTPS, the API and CI runners)
if grep -qE 'routers\.gitlab\.middlewares:.*portcullis-(auth|groups)@docker' "$COMPOSE"; then
  fail "Forward-auth middleware on the host-wide GitLab router"
else
  pass "Host-wide router has no forward-auth (API / git / runners use tokens)"
fi

# Security: interactive sign-in (/users/...) gated by forward-auth + group-gate
# so only users_gitlab members can log in or get an auto-created account
# (GitLab CE cannot restrict OIDC logins by group).
if grep -q 'routers.gitlab-login.rule:.*PathPrefix(`/users`)' "$COMPOSE" \
  && grep -q 'routers.gitlab-login.middlewares:.*portcullis-auth@docker,portcullis-groups@docker' "$COMPOSE"; then
  pass "/users/* (sign-in, OIDC, sign-up) behind forward-auth + group-gate"
else
  fail "/users/* login paths are not behind forward-auth + group-gate"
fi
MANIFEST="$(dirname "$COMPOSE")/manifest.yaml"
if grep -q '^  group_access: true' "$MANIFEST" && grep -q '^  access_group: users_gitlab' "$MANIFEST"; then
  pass "Manifest enables group_access with users_gitlab"
else
  fail "Manifest must set group_access: true and access_group: users_gitlab"
fi

# OIDC configuration present
if grep -q 'omniauth_providers' "$COMPOSE"; then
  pass "OIDC omniauth_providers configured"
else
  fail "OIDC omniauth_providers not found in compose"
fi

# Identity: keyed on preferred_username, no auto-link by email
if grep -q "uid_field: 'preferred_username'" "$COMPOSE" \
  && grep -q "gitlab_rails\['omniauth_auto_link_user'\] = false" "$COMPOSE" \
  && ! grep -q "omniauth_sync_email_from_provider" "$COMPOSE"; then
  pass "OIDC uid_field preferred_username, auto_link_user false"
else
  fail "GitLab OIDC must use uid_field preferred_username and omniauth_auto_link_user = false"
fi

# Service port matches Traefik label
if grep -q 'loadbalancer.server.port.*80' "$COMPOSE"; then
  pass "Traefik loadbalancer port is 80"
else
  fail "Traefik loadbalancer port mismatch"
fi
