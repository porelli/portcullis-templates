#!/usr/bin/env bash
# Test: Gitea (native OIDC through an OAuth2 source written by gitea-auth)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="gitea"
section "Gitea"

APP_ID=gitea

COMPOSE=$(_find_compose "$APP_ID" || true)
MANIFEST="$(dirname "$COMPOSE")/manifest.yaml"
AUTH_SH="$(dirname "$COMPOSE")/auth.sh"

# Static: native OIDC host-wide router without forward-auth (git over HTTPS
# and the API use personal access tokens).
if grep -qE 'routers\.gitea\.middlewares:.*portcullis-(auth|groups)@docker' "$COMPOSE"; then
  fail "forward-auth middleware on the host-wide Gitea router"
else
  pass "host-wide router has no forward-auth"
fi

# Static: no password, sign-up, passkey, OpenID or header login; nothing
# readable anonymously.
assert_compose_setting "$COMPOSE" GITEA__service__ENABLE_PASSWORD_SIGNIN_FORM false
assert_compose_setting "$COMPOSE" GITEA__service__ENABLE_BASIC_AUTHENTICATION false
assert_compose_setting "$COMPOSE" GITEA__service__ENABLE_PASSKEY_AUTHENTICATION false
assert_compose_setting "$COMPOSE" GITEA__service__DISABLE_REGISTRATION true
assert_compose_setting "$COMPOSE" GITEA__service__ALLOW_ONLY_EXTERNAL_REGISTRATION true
assert_compose_setting "$COMPOSE" GITEA__service__ENABLE_REVERSE_PROXY_AUTHENTICATION false
assert_compose_setting "$COMPOSE" GITEA__openid__ENABLE_OPENID_SIGNIN false
assert_compose_setting "$COMPOSE" GITEA__service__REQUIRE_SIGNIN_VIEW true
assert_compose_setting "$COMPOSE" GITEA__security__INSTALL_LOCK true

# Identity: username = preferred_username, never linked by name/email.
assert_compose_setting "$COMPOSE" GITEA__oauth2_client__USERNAME preferred_username
assert_compose_setting "$COMPOSE" GITEA__oauth2_client__ACCOUNT_LINKING disabled

# Group restriction and admin mapping from the instance's groups.
if grep -q "'RequiredClaimName', 'groups'" "$AUTH_SH" && grep -q "'RequiredClaimValue', :'access_group'" "$AUTH_SH" \
  && grep -q "'AdminGroup', :'admin_group'" "$AUTH_SH"; then
  pass "OAuth2 source requires the access group and maps the admin group"
else
  fail "auth.sh must set RequiredClaimName/Value (access group) and AdminGroup"
fi
if grep -q '^  group_access: true' "$MANIFEST" && grep -q '^  group_admin: true' "$MANIFEST"; then
  pass "manifest: group_access and group_admin true"
else
  fail "manifest must set group_access: true and group_admin: true"
fi

# Secret never on a command line.
if grep -qE -- '--secret' "$(dirname "$COMPOSE")/setup.sh" "$AUTH_SH" \
  || ! grep -q '\\getenv oidc_secret GITEA_OIDC_SECRET' "$AUTH_SH"; then
  fail "the OIDC secret must reach Gitea through psql \\getenv, not the CLI"
else
  pass "OIDC secret read from the environment (psql \\getenv)"
fi

compose_up "$APP_ID"

# The setup chain must finish before Gitea starts (fail closed).
for job in gitea-migrate gitea-auth; do
  if RC=$(timeout 300 docker wait "portcullis-${job}-1" 2>/dev/null) && [ "$RC" = "0" ]; then
    pass "$job exited 0"
  else
    fail "$job did not finish successfully (rc=${RC:-none})"
    docker logs "portcullis-${job}-1" 2>&1 | tail -10 || true
  fi
done

# The secret never appears in the setup logs.
SECRET="${GITEA_OIDC_SECRET:-}"
if [ -n "$SECRET" ] && docker logs portcullis-gitea-auth-1 2>&1 | grep -qF "$SECRET"; then
  fail "gitea-auth logged the OIDC client secret"
else
  pass "gitea-auth does not log the OIDC client secret"
fi

IP=$(app_container_ip "$APP_ID")
wait_for_url "http://${IP}:3000/api/healthz" 180 "$APP_ID"

# The login page redirects straight to the Portcullis source.
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' "http://${IP}:3000/user/login" || true)
if echo "$LOC" | grep -q '/user/oauth2/Portcullis'; then
  pass "/user/login -> Portcullis OAuth2 source"
else
  fail "/user/login should redirect to /user/oauth2/Portcullis (got '$LOC')"
fi

# The OAuth2 source start redirects to Keycloak with the instance's client.
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' "http://${IP}:3000/user/oauth2/Portcullis" || true)
if echo "$LOC" | grep -q "auth.${DOMAIN}/realms/portcullis/" && echo "$LOC" | grep -q "client_id=${PORTCULLIS_OIDC_CLIENT_ID:-gitea}"; then
  pass "OAuth2 start -> auth.${DOMAIN} (client ${PORTCULLIS_OIDC_CLIENT_ID:-gitea})"
else
  info "OAuth2 start redirected to '$LOC' (Keycloak discovery may be unreachable from this runner)"
fi

# Password sign-in is refused even when posted directly.
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST -d 'user_name=portcullis-breakglass&password=x' "http://${IP}:3000/user/login" || echo 000)
if [ "$CODE" = "403" ]; then
  pass "POST /user/login -> 403 (no password sign-in)"
else
  fail "POST /user/login expected 403, got $CODE"
fi

# Sign-up refused; nothing readable anonymously.
CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://${IP}:3000/explore/repos" || echo 000)
if [ "$CODE" = "303" ] || [ "$CODE" = "302" ]; then
  pass "/explore/repos anonymous -> $CODE (sign-in required)"
else
  fail "/explore/repos anonymous expected a redirect to sign-in, got $CODE"
fi
CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://${IP}:3000/api/v1/repos/search" || echo 000)
if [ "$CODE" = "401" ] || [ "$CODE" = "403" ]; then
  pass "/api/v1/repos/search anonymous -> $CODE"
else
  fail "/api/v1/repos/search anonymous expected 401/403, got $CODE"
fi

# Basic auth with a password is refused (tokens only).
CODE=$(curl -s -o /dev/null -w '%{http_code}' -u 'portcullis-breakglass:x' "http://${IP}:3000/api/v1/user" || echo 000)
if [ "$CODE" = "401" ]; then
  pass "basic auth with a password -> 401"
else
  fail "basic auth with a password expected 401, got $CODE"
fi

compose_down "$APP_ID"
