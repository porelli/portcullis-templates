#!/usr/bin/env bash
# Test: Vaultwarden (native OIDC SSO)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="vaultwarden"
section "Vaultwarden"

APP_ID=vaultwarden

COMPOSE=$(_find_compose "$APP_ID" || true)

# Static: /admin has its own higher-priority router behind forward-auth
if grep -q 'routers.vaultwarden-admin.rule:.*PathPrefix(`/admin`)' "$COMPOSE" \
  && grep -q 'routers.vaultwarden-admin.middlewares:.*portcullis-auth@docker,portcullis-groups@docker' "$COMPOSE"; then
  pass "/admin router protected by forward-auth + group-gate"
else
  fail "/admin router missing or not behind forward-auth + group-gate"
fi

# Static: group-gate requires admin_vaultwarden on /admin (path_groups)
MANIFEST="$(dirname "$COMPOSE")/manifest.yaml"
if grep -qE '^  admin_paths: \["/admin"\]' "$MANIFEST" && grep -q '^  admin_group: admin_vaultwarden' "$MANIFEST"; then
  pass "auth.admin_paths [/admin] requires admin_vaultwarden"
else
  fail "auth.admin_paths [/admin] / admin_group missing in manifest"
fi

# Identity: never link an SSO login to an existing account by email
assert_compose_setting "$COMPOSE" SSO_SIGNUPS_MATCH_EMAIL false
# email-unverified scope (no email_verified) instead of email, which the
# client then must not request
if grep -qE '^    email_verified_claim: false' "$MANIFEST"; then
  pass "keycloak client: email_verified_claim: false"
else
  fail "vaultwarden keycloak client must set email_verified_claim: false"
fi
assert_compose_setting "$COMPOSE" SSO_SCOPES profile
# SSO is the only sign-in (no email + master password login)
assert_compose_setting "$COMPOSE" SSO_ONLY true
# No email invitations (claimable placeholder accounts), no non-SSO signups
assert_compose_setting "$COMPOSE" INVITATIONS_ALLOWED false
assert_compose_setting "$COMPOSE" SIGNUPS_ALLOWED false
# SSO start + callback behind forward-auth + group-gate (users_vaultwarden)
if grep -q 'routers.vaultwarden-sso.rule:.*PathPrefix(`/identity/connect/authorize`).*PathPrefix(`/identity/connect/oidc-signin`)' "$COMPOSE" \
  && grep -q 'routers.vaultwarden-sso.middlewares:.*portcullis-auth@docker,portcullis-groups@docker' "$COMPOSE"; then
  pass "SSO authorize + oidc-signin behind forward-auth + group-gate"
else
  fail "SSO login paths are not behind forward-auth + group-gate"
fi
if grep -q '^  group_access: true' "$MANIFEST" && grep -q '^  access_group: users_vaultwarden' "$MANIFEST"; then
  pass "Manifest enables group_access with users_vaultwarden"
else
  fail "Manifest must set group_access: true and access_group: users_vaultwarden"
fi

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID")
wait_for_url "http://${IP}:80" 60 "$APP_ID"

# Homepage should contain SSO-related content
BODY=$(curl -sf "http://${IP}:80/" 2>/dev/null || echo "")
if echo "$BODY" | grep -qi "bitwarden\|vaultwarden\|<html"; then
  pass "/ -> Vaultwarden page returned"
else
  fail "/ -> Vaultwarden page not found"
fi

# Verify SSO is enabled via environment
SSO_ENABLED=$(docker exec "portcullis-${APP_ID}-1" printenv SSO_ENABLED 2>/dev/null || echo "")
if [ "$SSO_ENABLED" = "true" ]; then
  pass "SSO_ENABLED=true"
else
  fail "SSO_ENABLED expected 'true', got '$SSO_ENABLED'"
fi

# SSO_ONLY at runtime: the password grant is refused before any credential
# check, with Vaultwarden's "SSO sign-in is required"
TOKEN_RESP=$(curl -s -X POST "http://${IP}:80/identity/connect/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode grant_type=password --data-urlencode username=nobody@example.invalid \
  --data-urlencode password=x --data-urlencode scope='api offline_access' \
  --data-urlencode client_id=web --data-urlencode deviceType=10 \
  --data-urlencode deviceIdentifier=00000000-0000-0000-0000-000000000000 \
  --data-urlencode deviceName=ci 2>/dev/null || echo "")
if echo "$TOKEN_RESP" | grep -qi "SSO sign-in is required"; then
  pass "password grant refused (SSO_ONLY)"
else
  fail "password grant not refused by SSO_ONLY: ${TOKEN_RESP:0:200}"
fi

compose_down "$APP_ID"
