#!/usr/bin/env bash
# Test: OxiCloud (native OIDC only; authorize endpoint group-gated; setup endpoint closed before boot)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="oxicloud"
section "OxiCloud"

APP_ID=oxicloud
SERVICE=oxicloud

COMPOSE=$(_find_compose "$APP_ID") || { fail "compose.yml not found for $APP_ID"; exit 1; }
MANIFEST="$(dirname "$COMPOSE")/manifest.yaml"

# Static: the host router has no forward-auth; the authorize endpoint does
if grep -E '^[[:space:]]*traefik\.http\.routers\.oxicloud\.middlewares:' "$COMPOSE" | grep -q 'portcullis-auth@docker'; then
  fail "host router uses forward-auth (native OIDC: WebDAV/API clients would break)"
else
  pass "host router without forward-auth"
fi
if grep -E '^[[:space:]]*traefik\.http\.routers\.oxicloud-sso\.rule:' "$COMPOSE" | grep -q 'PathPrefix(`/api/auth/oidc/authorize`)' \
  && grep -E '^[[:space:]]*traefik\.http\.routers\.oxicloud-sso\.middlewares:' "$COMPOSE" | grep -q 'portcullis-auth@docker,portcullis-groups@docker'; then
  pass "authorize endpoint behind portcullis-auth + portcullis-groups"
else
  fail "oxicloud-sso router must gate /api/auth/oidc/authorize"
fi

assert_compose_setting "$COMPOSE" OXICLOUD_AUTH_METHODS oidc
assert_compose_setting "$COMPOSE" OXICLOUD_OIDC_ENABLED true
assert_compose_setting "$COMPOSE" OXICLOUD_OIDC_AUTO_LINK_EMAIL_MATCH false
assert_compose_setting "$COMPOSE" OXICLOUD_DISABLE_REGISTRATION true
assert_compose_setting "$COMPOSE" OXICLOUD_NEXTCLOUD_ENABLED false
assert_compose_setting "$COMPOSE" OXICLOUD_OIDC_ADMIN_GROUPS '\$\{PORTCULLIS_ADMIN_GROUP:-admin_oxicloud\}'
assert_compose_setting "$COMPOSE" OXICLOUD_TRUST_PROXY_CIDR '\$\{PORTCULLIS_TRAEFIK_IP:-172\.31\.250\.2\}/32'
if grep -q '^  group_access: true' "$MANIFEST" && grep -q '^  keycloak_access_role: true' "$MANIFEST"; then
  pass "manifest: group_access + keycloak_access_role"
else
  fail "manifest must set group_access: true and keycloak_access_role: true"
fi

compose_up "$APP_ID"
HOST="$PORTCULLIS_HOST_OXICLOUD"

info "Waiting for oxicloud-init..."
if INIT_RC=$(timeout 300 docker wait "portcullis-oxicloud-init-1" 2>/dev/null) && [ "$INIT_RC" = 0 ]; then
  pass "oxicloud-init exited 0"
else
  fail "oxicloud-init did not finish successfully (rc=${INIT_RC:-none})"
fi
docker logs "portcullis-oxicloud-init-1" 2>&1 | tail -3 || true

IP=$(app_container_ip "$APP_ID" "$SERVICE")
wait_for_url "http://${IP}:8086/ready" 240 "$APP_ID" || docker logs "portcullis-${SERVICE}-1" 2>&1 | tail -40

STATUS=$(curl -s "http://${IP}:8086/api/auth/status" 2>/dev/null || echo "{}")
if echo "$STATUS" | grep -q '"initialized":true'; then
  pass "instance initialized before first use: $STATUS"
else
  fail "instance not initialized (setup endpoint open?): $STATUS"
fi

# The first-run setup endpoint refuses (would create a password owner)
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
  -d '{"username":"e2e-setup","email":"e2e-setup@x.invalid","password":"e2e-setup-password"}' \
  "http://${IP}:8086/api/setup" 2>/dev/null || echo 000)
if [ "$CODE" = 403 ]; then
  pass "POST /api/setup -> 403"
else
  fail "POST /api/setup -> $CODE (expected 403)"
fi

# No password login, no sign-up
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
  -d '{"username":"e2e-setup","password":"e2e-setup-password"}' "http://${IP}:8086/api/auth/login" 2>/dev/null || echo 000)
case "$CODE" in
  401|403|404) pass "POST /api/auth/login -> $CODE (password login off)" ;;
  *) fail "POST /api/auth/login -> $CODE (expected 401/403/404)" ;;
esac
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
  -d '{"username":"e2e-reg","email":"e2e-reg@x.invalid","password":"e2e-reg-password"}' "http://${IP}:8086/api/auth/register" 2>/dev/null || echo 000)
case "$CODE" in
  403|404|501|503) pass "POST /api/auth/register -> $CODE (sign-up off)" ;;
  *) fail "POST /api/auth/register -> $CODE (expected a refusal)" ;;
esac
USERS=$(docker exec portcullis-oxicloud-db-1 psql -U oxicloud -d oxicloud -tAc "SELECT count(*) FROM auth.users" 2>&1 || true)
if [ "$USERS" = 0 ]; then
  pass "no account exists before the first SSO login"
else
  fail "unexpected accounts: $USERS"
fi

# Through Traefik, once healthy
for _ in $(seq 1 40); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "portcullis-${SERVICE}-1" 2>/dev/null)" = healthy ] && break
  sleep 3
done
if [ "$(docker inspect -f '{{.State.Health.Status}}' "portcullis-${SERVICE}-1" 2>/dev/null)" = healthy ]; then
  pass "oxicloud healthy (initialized)"
else
  fail "oxicloud not healthy"
fi
out=$(via_traefik "$HOST" /ready)
if [ "${out%% *}" = 200 ]; then
  pass "https://$HOST/ready -> 200 via Traefik (ungated)"
else
  fail "via Traefik: $out"
fi
out=$(via_traefik "$HOST" /login)
if echo "${out#* }" | grep -q '/api/auth/oidc/authorize'; then
  pass "/login redirects to the OIDC authorize endpoint"
else
  fail "/login: $out"
fi
# The authorize endpoint goes to Portcullis sign-in (oauth2-proxy), not
# straight to OxiCloud's Keycloak client.
assert_gated_path "$HOST" /api/auth/oidc/authorize
out=$(via_traefik "$HOST" /api/auth/oidc/authorize); loc=${out#* }
if echo "$loc" | grep -q 'client_id=oxicloud'; then
  fail "authorize reached OxiCloud without Portcullis sign-in: $loc"
else
  pass "authorize not answered by OxiCloud without a Portcullis session"
fi
out=$(via_traefik "$HOST" /webdav/)
case "${out%% *}" in
  401) pass "WebDAV without credentials -> 401 from OxiCloud (ungated, app passwords)" ;;
  *) fail "WebDAV: $out (expected 401)" ;;
esac

compose_down "$APP_ID"
