#!/usr/bin/env bash
# Test: Wiki.js (native OIDC only, configured by wiki-setup; routed only when healthy)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="wiki"
section "Wiki.js"

APP_ID=wiki
SERVICE=wiki

COMPOSE=$(_find_compose "$APP_ID") || { fail "compose.yml not found for $APP_ID"; exit 1; }
MANIFEST="$(dirname "$COMPOSE")/manifest.yaml"

# Static: one host-wide router without forward-auth, no path-scoped router
# (nothing relies on Traefik's path matching), healthcheck = OIDC-only state
if grep -E '^[[:space:]]*traefik\.http\.routers\.wiki\.middlewares:' "$COMPOSE" | grep -q 'portcullis-auth@docker'; then
  fail "host-wide router uses forward-auth"
else
  pass "host-wide router has no forward-auth"
fi
if grep -E '^[[:space:]]*traefik\.http\.routers\.[^.]+\.rule:' "$COMPOSE" | grep -q 'Path'; then
  fail "a router uses path matchers (the wizard / password login may not depend on them)"
else
  pass "no path-scoped routers"
fi
if grep -q 'activeStrategies(enabledOnly:true)' "$COMPOSE" && grep -q '"key":"portcullis"' "$COMPOSE" && grep -qF "! echo \"\$\$out\" | grep -q '\"key\":\"local\"'" "$COMPOSE"; then
  pass "healthcheck requires OIDC on and the local login off (Traefik routes healthy containers only)"
else
  fail "healthcheck must require the portcullis strategy and no local strategy"
fi
SETUP="$(dirname "$COMPOSE")/setup.py"
if grep -q '"isEnabled": False if local' "$SETUP" && grep -q '"selfRegistration": False if local' "$SETUP" && grep -q '"autoEnrollGroups": \[\] if local' "$SETUP"; then
  pass "setup.py disables the local strategy, its registration and auto-enrolment"
else
  fail "setup.py must disable the local strategy"
fi
if grep -q '{{HOST_WIKI}}/login/portcullis/callback' "$MANIFEST"; then
  pass "Keycloak redirect URI is the portcullis strategy callback"
else
  fail "redirect URI must be https://{{HOST_WIKI}}/login/portcullis/callback"
fi

compose_up "$APP_ID"
HOST="$PORTCULLIS_HOST_WIKI"

IP=$(app_container_ip "$APP_ID" "$SERVICE")
wait_for_url "http://${IP}:3000" 120 "$APP_ID"

# Before wiki-setup has finished (fresh install = setup wizard) Traefik
# must not route the host at all.
out=$(via_traefik "$HOST" /)
if [ "${out%% *}" = 404 ]; then
  pass "wizard phase: Traefik answers 404 for $HOST"
else
  info "wizard phase already over or racing ($out)"
fi

info "Waiting for the wiki-setup sidecar..."
SETUP_RC=$(docker wait "portcullis-wiki-setup-1" 2>/dev/null || echo "?")
if [ "$SETUP_RC" = 0 ]; then
  pass "wiki-setup finished (exit 0)"
else
  fail "wiki-setup exited with $SETUP_RC"
fi
docker logs "portcullis-wiki-setup-1" 2>&1 | tail -5 || true

gql() {
  curl -sf -H 'Content-Type: application/json' -d "{\"query\":\"$1\"}" "http://${IP}:3000/graphql" 2>/dev/null || echo "{}"
}

STR=$(gql '{ authentication { activeStrategies(enabledOnly: true) { key strategy { key } } } }')
if echo "$STR" | grep -q '"key":"portcullis"' && echo "$STR" | grep -q '"key":"oidc"' && ! echo "$STR" | grep -q '"key":"local"'; then
  pass "only the OIDC strategy 'portcullis' is active (local off)"
else
  fail "strategies not OIDC-only: $STR"
fi

HOST_IN_DB=$(docker exec portcullis-wiki-db-1 psql -U wiki -d wiki -tAc "SELECT value->>'v' FROM settings WHERE key = 'host'" 2>/dev/null || true)
if [ "$HOST_IN_DB" = "https://${HOST}" ]; then
  pass "site URL is https://${HOST}"
else
  fail "site URL is '$HOST_IN_DB', expected https://${HOST}"
fi

section "Through Traefik (after setup)"
for _ in $(seq 1 60); do
  out=$(via_traefik "$HOST" /)
  case "${out%% *}" in 000|404|502|503) sleep 2 ;; *) break ;; esac
done
if [ "${out%% *}" != 404 ] && [ "${out%% *}" != 000 ]; then
  pass "healthy: Traefik routes $HOST ($out)"
else
  fail "Traefik still does not route $HOST: $out"
fi
tgql() {
  curl -sk --max-time 15 --resolve "$HOST:443:127.0.0.1" -H 'Content-Type: application/json' -d "{\"query\":\"$1\"}" "https://$HOST/graphql" 2>/dev/null || echo "{}"
}
LOGIN=$(tgql "mutation { authentication { login(username: \\\"admin@wiki.invalid\\\", password: \\\"${WIKI_ADMIN_PASSWORD}\\\", strategy: \\\"local\\\") { responseResult { succeeded } jwt } } }")
if echo "$LOGIN" | grep -q '"succeeded":false' && ! echo "$LOGIN" | grep -q '"jwt":"'; then
  pass "local admin password login refused through Traefik"
else
  fail "local password login not refused: $LOGIN"
fi
REG=$(tgql "mutation { authentication { register(email: \\\"ci@example.org\\\", password: \\\"Ci-Pass-1234567\\\", name: \\\"ci\\\") { responseResult { succeeded } } } }")
if echo "$REG" | grep -q '"succeeded":true'; then
  fail "local registration accepted through Traefik"
else
  pass "local registration refused through Traefik"
fi
PAGES=$(tgql '{ pages { list { id } } }')
if echo "$PAGES" | grep -qi 'forbidden\|unauthorized\|not authorized'; then
  pass "anonymous page list refused"
else
  fail "anonymous page list not refused: $PAGES"
fi
# No path spelling reaches the setup wizard or a password form.
for path in /login /LOGIN /login/ //login /index.php//login /finalize /finalize/ /FINALIZE; do
  code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 15 --resolve "$HOST:443:127.0.0.1" \
    -H 'Content-Type: application/json' -d '{"adminEmail":"x@example.org","adminPassword":"Ci-Pass-1234567","siteUrl":"https://x"}' \
    "https://$HOST$path" 2>/dev/null || echo 000)
  body=$(curl -sk --max-time 15 --resolve "$HOST:443:127.0.0.1" "https://$HOST$path" 2>/dev/null || true)
  if echo "$body" | grep -qi 'type="password"\|setup-wizard\|Wiki.js Setup'; then
    fail "$path serves a password form or the setup wizard"
  else
    pass "$path: no password form / wizard (POST → $code)"
  fi
done
# The wizard POST above must not have changed the admin
if docker exec portcullis-wiki-db-1 psql -U wiki -d wiki -tAc "SELECT count(*) FROM users WHERE email = 'x@example.org'" 2>/dev/null | grep -qx 0; then
  pass "no account created by the /finalize spellings"
else
  fail "a /finalize spelling created an account"
fi

compose_down "$APP_ID"
