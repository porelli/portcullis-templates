#!/usr/bin/env bash
# Test: Wiki.js (native OIDC, login paths gated, configured by wiki-setup)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="wiki"
section "Wiki.js"

APP_ID=wiki
SERVICE=wiki

COMPOSE=$(_find_compose "$APP_ID") || { fail "compose.yml not found for $APP_ID"; exit 1; }
MANIFEST="$(dirname "$COMPOSE")/manifest.yaml"

# Static: no forward-auth on the whole host; /login and /finalize gated
if grep -E '^[[:space:]]*traefik\.http\.routers\.wiki\.middlewares:' "$COMPOSE" | grep -q 'portcullis-auth@docker'; then
  fail "host-wide router uses forward-auth"
else
  pass "host-wide router has no forward-auth"
fi
LOGIN_RULE=$(grep -E '^[[:space:]]*traefik\.http\.routers\.wiki-login\.rule:' "$COMPOSE" || true)
LOGIN_MW=$(grep -E '^[[:space:]]*traefik\.http\.routers\.wiki-login\.middlewares:' "$COMPOSE" || true)
if echo "$LOGIN_RULE" | grep -q 'PathPrefix(`/login`)' && echo "$LOGIN_RULE" | grep -q 'Path(`/finalize`)' \
    && echo "$LOGIN_MW" | grep -q 'portcullis-auth@docker,portcullis-groups@docker'; then
  pass "/login and /finalize behind forward-auth + group-gate"
else
  fail "wiki-login router must gate /login and /finalize"
fi
if grep -q '{{HOST_WIKI}}/login/portcullis/callback' "$MANIFEST"; then
  pass "Keycloak redirect URI is the portcullis strategy callback"
else
  fail "redirect URI must be https://{{HOST_WIKI}}/login/portcullis/callback"
fi

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID" "$SERVICE")
wait_for_url "http://${IP}:3000" 120 "$APP_ID"

info "Waiting for the wiki-setup sidecar..."
SETUP_RC=$(docker wait "portcullis-wiki-setup-1" 2>/dev/null || echo "?")
if [ "$SETUP_RC" = 0 ]; then
  pass "wiki-setup finished (exit 0)"
else
  fail "wiki-setup exited with $SETUP_RC"
  docker logs "portcullis-wiki-setup-1" 2>&1 | tail -20 || true
fi

gql() {
  curl -sf -H 'Content-Type: application/json' -d "{\"query\":\"$1\"}" "http://${IP}:3000/graphql" 2>/dev/null || echo "{}"
}

# The Portcullis OIDC strategy is active (public query)
STR=$(gql '{ authentication { activeStrategies(enabledOnly: true) { key displayName strategy { key } } } }')
if echo "$STR" | grep -q '"key":"portcullis"' && echo "$STR" | grep -q '"key":"oidc"'; then
  pass "OIDC strategy 'portcullis' active"
else
  fail "OIDC strategy 'portcullis' not active: $STR"
fi

# Anonymous visitors (Guests) can't read pages
PAGES=$(gql '{ pages { list { id } } }')
if echo "$PAGES" | grep -qi 'forbidden\|unauthorized\|not authorized'; then
  pass "anonymous page list refused"
else
  fail "anonymous page list not refused: $PAGES"
fi

# The site URL follows the instance hostname (written by the sidecar's
# wizard on a fresh install, by wiki-init on every later start)
HOST_IN_DB=$(docker exec portcullis-wiki-db-1 psql -U wiki -d wiki -tAc "SELECT value->>'v' FROM settings WHERE key = 'host'" 2>/dev/null || true)
if [ "$HOST_IN_DB" = "https://${PORTCULLIS_HOST_WIKI}" ]; then
  pass "site URL is https://${PORTCULLIS_HOST_WIKI}"
else
  fail "site URL is '$HOST_IN_DB', expected https://${PORTCULLIS_HOST_WIKI}"
fi

compose_down "$APP_ID"
