#!/usr/bin/env bash
# Test: Home Assistant (native OIDC through the pinned auth_oidc integration; no local login, onboarding closed)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="homeassistant"
section "Home Assistant"

APP_ID=homeassistant
SERVICE=homeassistant

COMPOSE=$(_find_compose "$APP_ID") || { fail "compose.yml not found for $APP_ID"; exit 1; }
DIR="$(dirname "$COMPOSE")"
CONF="$DIR/configuration.yaml"

# Static: no forward-auth on the host (Companion apps, websocket, tokens)
if grep -E '^[[:space:]]*traefik\.http\.routers\.[^.]+\.middlewares:' "$COMPOSE" | grep -q 'portcullis-auth@docker'; then
  fail "a router uses forward-auth (native OIDC)"
else
  pass "no forward-auth on the native-OIDC router"
fi
if grep -q 'network_mode' "$COMPOSE"; then
  fail "host networking would publish port 8123 past the gateway"
else
  pass "no host networking"
fi
if grep -Eq '^  auth_providers: \[\]$' "$CONF"; then
  pass "configuration.yaml: no local auth provider"
else
  fail "configuration.yaml must set auth_providers: []"
fi
if grep -Eq '^    automatic_user_linking: false$' "$CONF" && grep -Eq '^    user: !env_var HA_ACCESS_GROUP$' "$CONF" \
  && grep -Eq '^    admin: !env_var HA_ADMIN_GROUP$' "$CONF"; then
  pass "configuration.yaml: group roles, no user linking"
else
  fail "configuration.yaml: auth_oidc roles / linking not as expected"
fi
if grep -Eq '^http:' "$CONF"; then
  fail "configuration.yaml has an http: section (HA 2026.10 migrates it as a trial that reverts)"
else
  pass "no http: YAML (homeassistant-init owns .storage/http)"
fi
assert_compose_setting "$COMPOSE" HA_TRUSTED_PROXY '\$\{PORTCULLIS_TRAEFIK_IP:-172\.31\.250\.2\}'
assert_compose_setting "$COMPOSE" HA_ACCESS_GROUP '\$\{PORTCULLIS_ACCESS_GROUP:-users_homeassistant\}'
assert_compose_setting "$COMPOSE" HA_ADMIN_GROUP '\$\{PORTCULLIS_ADMIN_GROUP:-admin_homeassistant\}'
if grep -q 'configuration.yaml:/config/configuration.yaml:ro' "$COMPOSE"; then
  pass "configuration.yaml mounted read-only"
else
  fail "configuration.yaml must be mounted read-only"
fi
if grep -Eq '^AUTH_OIDC_SHA256 = "[0-9a-f]{64}"$' "$DIR/init.py" && grep -Eq '^JOSERFC_SHA256 = "[0-9a-f]{64}"$' "$DIR/init.py"; then
  pass "init.py pins auth_oidc and joserfc by SHA-256"
else
  fail "init.py must pin auth_oidc and joserfc by SHA-256"
fi

compose_up "$APP_ID"
HOST="$PORTCULLIS_HOST_HOMEASSISTANT"

info "Waiting for homeassistant-init..."
if INIT_RC=$(timeout 300 docker wait "portcullis-homeassistant-init-1" 2>/dev/null) && [ "$INIT_RC" = 0 ]; then
  pass "homeassistant-init exited 0"
else
  fail "homeassistant-init did not finish successfully (rc=${INIT_RC:-none})"
fi
docker logs "portcullis-homeassistant-init-1" 2>&1 | tail -6 || true

IP=$(app_container_ip "$APP_ID" "$SERVICE")
wait_for_url "http://${IP}:8123/manifest.json" 600 "$APP_ID" || docker logs "portcullis-${SERVICE}-1" 2>&1 | tail -60

# Through Traefik, once healthy
for _ in $(seq 1 60); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "portcullis-${SERVICE}-1" 2>/dev/null)" = healthy ] && break
  sleep 5
done
if [ "$(docker inspect -f '{{.State.Health.Status}}' "portcullis-${SERVICE}-1" 2>/dev/null)" = healthy ]; then
  pass "homeassistant healthy (OIDC only, onboarding closed)"
else
  fail "homeassistant not healthy: $(docker inspect -f '{{json .State.Health}}' "portcullis-${SERVICE}-1" 2>/dev/null | tail -c 400)"
fi
PROV=$(curl -s "http://${IP}:8123/auth/providers" 2>/dev/null || echo "")
if echo "$PROV" | grep -q '"type":"auth_oidc"' && ! echo "$PROV" | grep -q '"type":"homeassistant"' \
  && ! echo "$PROV" | grep -q '"type":"trusted_networks"'; then
  pass "auth providers: auth_oidc only ($PROV)"
else
  fail "auth providers: $PROV"
fi
CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://${IP}:8123/api/onboarding" 2>/dev/null || echo 000)
if [ "$CODE" != 200 ]; then
  pass "onboarding closed (/api/onboarding -> $CODE)"
else
  fail "onboarding view still served: $(curl -s "http://${IP}:8123/api/onboarding")"
fi
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
  -d '{"client_id":"http://x/","name":"x","username":"e2e-owner","password":"e2e-owner-password","language":"en"}' \
  "http://${IP}:8123/api/onboarding/users" 2>/dev/null || echo 000)
case "$CODE" in
  200|201) fail "POST /api/onboarding/users -> $CODE (an owner could be created)" ;;
  *) pass "POST /api/onboarding/users -> $CODE (no onboarding owner)" ;;
esac
# A login flow for Home Assistant's own provider can't be started
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
  -d "{\"client_id\":\"https://${HOST}/\",\"handler\":[\"homeassistant\",null],\"redirect_uri\":\"https://${HOST}/\"}" \
  "http://${IP}:8123/auth/login_flow" 2>/dev/null || echo 000)
case "$CODE" in
  200) fail "POST /auth/login_flow (homeassistant provider) -> 200" ;;
  *) pass "POST /auth/login_flow (homeassistant provider) -> $CODE" ;;
esac
OIDC=$(docker exec "portcullis-${SERVICE}-1" python3 -c 'import json;print(json.load(open("/config/custom_components/auth_oidc/manifest.json"))["version"])' 2>&1 || true)
if [ "$OIDC" = 1.2.1 ]; then
  pass "auth_oidc 1.2.1 installed"
else
  fail "auth_oidc version: $OIDC"
fi
HTTPCONF=$(docker exec "portcullis-${SERVICE}-1" python3 -c 'import json;d=json.load(open("/config/.storage/http"))["data"];print(d["stable"]["trusted_proxies"], d["stable"]["use_x_forwarded_for"], d["pending"])' 2>&1 || true)
if [ "$HTTPCONF" = "['${PORTCULLIS_TRAEFIK_IP:-172.31.250.2}/32'] True None" ]; then
  pass ".storage/http: X-Forwarded-For from Traefik only, nothing pending"
else
  fail ".storage/http: $HTTPCONF"
fi
if docker logs "portcullis-${SERVICE}-1" 2>&1 | grep -q 'Using pending HTTP config'; then
  fail "Home Assistant runs a pending (auto-reverting) HTTP config"
else
  pass "Home Assistant uses the stable HTTP config"
fi
# joserfc comes from the pinned wheel in /config/deps, never from a runtime pip install
JOSE=$(docker exec -e PYTHONUSERBASE=/config/deps "portcullis-${SERVICE}-1" python3 -c 'import importlib.metadata as m, joserfc; print(m.version("joserfc"), joserfc.__file__)' 2>&1 || true)
SYS=$(docker exec -e PYTHONNOUSERSITE=1 "portcullis-${SERVICE}-1" python3 -c 'import importlib.util; print(importlib.util.find_spec("joserfc"))' 2>&1 || true)
if echo "$JOSE" | grep -q '^1\.7\.7 /config/deps/' && [ "$SYS" = None ]; then
  pass "joserfc 1.7.7 from /config/deps only ($JOSE)"
else
  fail "joserfc: deps=$JOSE system=$SYS"
fi
if docker logs "portcullis-${SERVICE}-1" 2>&1 | grep -qi 'Registered OIDC provider'; then
  pass "auth_oidc registered its provider"
else
  info "no 'Registered OIDC provider' log line (log level)"
fi

out=$(via_traefik "$HOST" /manifest.json)
if [ "${out%% *}" = 200 ]; then
  pass "https://$HOST/manifest.json -> 200 via Traefik (X-Forwarded-For accepted from Traefik)"
else
  fail "via Traefik: $out"
fi
out=$(via_traefik "$HOST" /auth/oidc/redirect)
if echo "${out#* }" | grep -q "auth\.$DOMAIN/realms/portcullis/protocol/openid-connect/auth"; then
  pass "/auth/oidc/redirect goes to Keycloak"
else
  info "/auth/oidc/redirect without the state cookie: $out"
fi
# A direct peer on portcullis-proxy that isn't Traefik and sends
# X-Forwarded-For is refused by Home Assistant (trusted_proxies).
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Forwarded-For: 203.0.113.9' "http://${IP}:8123/manifest.json" 2>/dev/null || echo 000)
if [ "$CODE" = 400 ]; then
  pass "X-Forwarded-For from a non-Traefik peer -> 400"
else
  fail "X-Forwarded-For from a non-Traefik peer -> $CODE (expected 400)"
fi

compose_down "$APP_ID"
