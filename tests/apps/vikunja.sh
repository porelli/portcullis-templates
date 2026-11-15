#!/usr/bin/env bash
# Test: Vikunja (native OIDC only: no local accounts; group via the Hub's Keycloak access role)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="vikunja"
section "Vikunja"

APP_ID=vikunja
SERVICE=vikunja

COMPOSE=$(_find_compose "$APP_ID") || { fail "compose.yml not found for $APP_ID"; exit 1; }
MANIFEST="$(dirname "$COMPOSE")/manifest.yaml"

# Static: one host-wide router without forward-auth, no path routers
if grep -E '^[[:space:]]*traefik\.http\.routers\.[^.]+\.middlewares:' "$COMPOSE" | grep -q 'portcullis-auth@docker'; then
  fail "a router uses forward-auth (native OIDC)"
else
  pass "no forward-auth on the native-OIDC router"
fi
if grep -E '^[[:space:]]*traefik\.http\.routers\.[^.]+\.rule:' "$COMPOSE" | grep -q 'Path'; then
  fail "a router uses path matchers"
else
  pass "no path-scoped routers"
fi

# Static: identity and access settings
assert_compose_setting "$COMPOSE" VIKUNJA_AUTH_LOCAL_ENABLED false
assert_compose_setting "$COMPOSE" VIKUNJA_AUTH_LDAP_ENABLED false
assert_compose_setting "$COMPOSE" VIKUNJA_SERVICE_ENABLEREGISTRATION false
assert_compose_setting "$COMPOSE" VIKUNJA_AUTH_OPENID_ENABLED true
assert_compose_setting "$COMPOSE" VIKUNJA_AUTH_OPENID_PROVIDERS_PORTCULLIS_EMAILFALLBACK false
assert_compose_setting "$COMPOSE" VIKUNJA_AUTH_OPENID_PROVIDERS_PORTCULLIS_USERNAMEFALLBACK false
assert_compose_setting "$COMPOSE" VIKUNJA_AUTH_OPENID_PROVIDERS_PORTCULLIS_CLIENTID '\$\{PORTCULLIS_OIDC_CLIENT_ID:-vikunja\}'
assert_compose_setting "$COMPOSE" VIKUNJA_SERVICE_TRUSTEDPROXIES '\$\{PORTCULLIS_TRAEFIK_SOURCE:-172\.31\.250\.2/32\}'
assert_compose_setting "$COMPOSE" VIKUNJA_OUTGOINGREQUESTS_ALLOWNONROUTABLEIPS false
assert_compose_setting "$COMPOSE" VIKUNJA_SERVICE_JWTTTL 86400
assert_compose_setting "$COMPOSE" VIKUNJA_SERVICE_ENABLELINKSHARING '\$\{VIKUNJA_LINK_SHARING:-false\}'
if grep -q '^  keycloak_access_role: true' "$MANIFEST" && grep -q '^  group_access: true' "$MANIFEST"; then
  pass "manifest: group_access + keycloak_access_role"
else
  fail "manifest must set group_access: true and keycloak_access_role: true"
fi

compose_up "$APP_ID"
HOST="$PORTCULLIS_HOST_VIKUNJA"

IP=$(app_container_ip "$APP_ID" "$SERVICE")
wait_for_url "http://${IP}:3456/api/v1/info" 180 "$APP_ID"

INFO=$(curl -sf "http://${IP}:3456/api/v1/info" 2>/dev/null || echo "{}")
LOCAL=$(echo "$INFO" | jq -r '.auth.local.enabled')
REG=$(echo "$INFO" | jq -r '.auth.local.registration_enabled')
OIDC=$(echo "$INFO" | jq -r '.auth.openid_connect.enabled')
PROVIDERS=$(echo "$INFO" | jq -r '[.auth.openid_connect.providers[]?.key] | join(",")')
LINKS=$(echo "$INFO" | jq -r '.link_sharing_enabled')
if [ "$LOCAL" = false ] && [ "$REG" = false ] && [ "$OIDC" = true ] && [ "$PROVIDERS" = portcullis ]; then
  pass "info: local login and registration off, OIDC provider portcullis only"
else
  fail "info: local=$LOCAL registration=$REG oidc=$OIDC providers=$PROVIDERS"
fi
[ "$LINKS" = false ] && pass "info: link sharing off by default" || fail "info: link_sharing_enabled=$LINKS"
AUTHURL=$(echo "$INFO" | jq -r '.auth.openid_connect.providers[0].auth_url // ""')
if echo "$AUTHURL" | grep -q "^https://auth\.$DOMAIN/realms/portcullis/protocol/openid-connect/auth"; then
  pass "provider discovered from Keycloak ($AUTHURL)"
else
  fail "provider auth_url: $AUTHURL"
fi

# The password and sign-up routes are not registered (v1 and v2).
for path in /api/v1/login /api/v1/register /api/v1/user/password/token /api/v2/login /api/v2/register; do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":"admin1234","email":"a@b.c"}' "http://${IP}:3456$path" || echo 000)
  case "$CODE" in
    404|405) pass "POST $path -> $CODE (not registered)" ;;
    *) fail "POST $path -> $CODE (expected 404/405: the route must not exist)" ;;
  esac
done

# No local account exists (CalDAV basic auth with a password only works for those).
LOCALS=$(docker exec portcullis-vikunja-db-1 psql -X -U vikunja -d vikunja -tAc \
  "SELECT count(*) FROM users WHERE issuer IS NULL OR issuer = 'local'" 2>&1)
[ "$LOCALS" = 0 ] && pass "no local accounts" || fail "local accounts: $LOCALS"

# Through Traefik (it picks the new container up within a few seconds)
for _ in $(seq 1 30); do
  out=$(via_traefik "$HOST" /api/v1/info)
  [ "${out%% *}" = 200 ] && break
  sleep 2
done
[ "${out%% *}" = 200 ] && pass "https://$HOST/api/v1/info -> 200 via Traefik" || fail "via Traefik: $out"

compose_down "$APP_ID"
