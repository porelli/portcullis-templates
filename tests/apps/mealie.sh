#!/usr/bin/env bash
# Test: Mealie (native OIDC, group-restricted; no password login, guarded in the database)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="mealie"
section "Mealie"

APP_ID=mealie
SERVICE=mealie

COMPOSE=$(_find_compose "$APP_ID") || { fail "compose.yml not found for $APP_ID"; exit 1; }
MANIFEST="$(dirname "$COMPOSE")/manifest.yaml"

# Static: one host-wide router without forward-auth, no path routers
if grep -E '^[[:space:]]*traefik\.http\.routers\.[^.]+\.middlewares:' "$COMPOSE" | grep -q 'portcullis-auth@docker'; then
  fail "a router uses forward-auth (native OIDC)"
else
  pass "no forward-auth on the native-OIDC router"
fi
if grep -E '^[[:space:]]*traefik\.http\.routers\.[^.]+\.rule:' "$COMPOSE" | grep -q 'Path'; then
  fail "a router uses path matchers (the password API may not depend on them)"
else
  pass "no path-scoped routers"
fi

# Static: identity and access settings
assert_compose_setting "$COMPOSE" OIDC_AUTH_ENABLED true
assert_compose_setting "$COMPOSE" OIDC_USER_CLAIM preferred_username
assert_compose_setting "$COMPOSE" OIDC_NAME_CLAIM preferred_username
assert_compose_setting "$COMPOSE" OIDC_GROUPS_CLAIM groups
assert_compose_setting "$COMPOSE" OIDC_USER_GROUP '\$\{PORTCULLIS_ACCESS_GROUP:-users_mealie\}'
assert_compose_setting "$COMPOSE" OIDC_ADMIN_GROUP '\$\{PORTCULLIS_ADMIN_GROUP:-admin_mealie\}'
assert_compose_setting "$COMPOSE" ALLOW_SIGNUP false
assert_compose_setting "$COMPOSE" ALLOW_PASSWORD_LOGIN false
assert_compose_setting "$COMPOSE" LDAP_AUTH_ENABLED false
assert_compose_setting "$COMPOSE" REVERSE_PROXY_AUTH_ENABLED false
assert_compose_setting "$COMPOSE" HOST_IP '\$\{PORTCULLIS_TRAEFIK_IP:-172\.31\.250\.2\}'
if grep -q '^  group_access: true' "$MANIFEST" && grep -q '^  group_admin: true' "$MANIFEST"; then
  pass "manifest: group_access + group_admin"
else
  fail "manifest must set group_access: true and group_admin: true"
fi
GUARD="$(dirname "$COMPOSE")/guard.py"
if grep -q "NEW.auth_method := 'OIDC'" "$GUARD" && grep -q 'BEFORE INSERT OR UPDATE ON users' "$GUARD"; then
  pass "guard.py: trigger forces OIDC on every account"
else
  fail "guard.py trigger missing"
fi
if grep -q 'guard.py --check' "$COMPOSE"; then
  pass "healthcheck requires the guard (Traefik routes healthy containers only)"
else
  fail "healthcheck must run guard.py --check"
fi

compose_up "$APP_ID"
HOST="$PORTCULLIS_HOST_MEALIE"

info "Waiting for mealie-init..."
if INIT_RC=$(timeout 300 docker wait "portcullis-mealie-init-1" 2>/dev/null) && [ "$INIT_RC" = 0 ]; then
  pass "mealie-init exited 0"
else
  fail "mealie-init did not finish successfully (rc=${INIT_RC:-none})"
fi
docker logs "portcullis-mealie-init-1" 2>&1 | grep 'portcullis-guard' | tail -3 || true

IP=$(app_container_ip "$APP_ID" "$SERVICE")
wait_for_url "http://${IP}:9000/api/app/about" 180 "$APP_ID"

db() {
  docker exec portcullis-mealie-db-1 psql -U mealie -d mealie -tAc "$1" 2>&1
}

# No account has a password login; the seeded admin is retired
LOCAL=$(db "SELECT count(*) FROM users WHERE auth_method <> 'OIDC'")
if [ "$LOCAL" = 0 ]; then
  pass "no account with a password login"
else
  fail "accounts with a password login: $LOCAL"
fi
SEED=$(db "SELECT count(*) FROM users WHERE username = 'admin' OR email = 'changeme@example.com'")
if [ "$SEED" = 0 ]; then
  pass "seeded admin (admin / changeme@example.com) retired"
else
  fail "seeded admin still matchable ($SEED)"
fi

# The trigger refuses username / email changes of an account
OUT=$(db "BEGIN; UPDATE users SET username = 'e2e-takeover' WHERE id = (SELECT id FROM users LIMIT 1); ROLLBACK;")
if echo "$OUT" | grep -q 'portcullis: the username and email'; then
  pass "username change refused by the guard"
else
  fail "username change not refused: $OUT"
fi

# The trigger refuses emails that the username-in-email lookup could match
# (BEFORE triggers run ahead of NOT NULL checks, so a minimal row suffices).
OUT=$(db "BEGIN; INSERT INTO users (id, username, email) VALUES (gen_random_uuid(), 'e2e-attacker', 'e2e-victim'); ROLLBACK;")
if echo "$OUT" | grep -q 'portcullis: a Mealie account email must contain @'; then
  pass "email without @ refused by the guard"
else
  fail "email without @ not refused: $OUT"
fi
OUT=$(db "BEGIN; INSERT INTO users (id, username, email) SELECT gen_random_uuid(), email, 'e2e@x.invalid' FROM users LIMIT 1; ROLLBACK;")
if echo "$OUT" | grep -q 'portcullis: a Mealie account username or email equals'; then
  pass "username equal to another account's email refused by the guard"
else
  fail "username/email overlap not refused: $OUT"
fi

# The well-known seed credentials don't log in (password API)
for u in admin changeme@example.com; do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' --data-urlencode "username=$u" --data-urlencode "password=MyPassword" \
    "http://${IP}:9000/api/auth/token" 2>/dev/null || echo 000)
  if [ "$CODE" = 401 ]; then
    pass "POST /api/auth/token $u/MyPassword -> 401"
  else
    fail "POST /api/auth/token $u/MyPassword -> $CODE (expected 401)"
  fi
done

# OIDC is configured (startup info / app info)
INFO=$(curl -sf "http://${IP}:9000/api/app/about" 2>/dev/null || echo "{}")
if echo "$INFO" | grep -q '"enableOidc":true' && echo "$INFO" | grep -q '"oidcRedirect":true' && echo "$INFO" | grep -q '"allowPasswordLogin":false'; then
  pass "about: OIDC on, auto-redirect, password login off"
else
  fail "about: unexpected auth settings: $INFO"
fi

# Through Traefik, once healthy
for _ in $(seq 1 30); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "portcullis-${SERVICE}-1" 2>/dev/null)" = healthy ] && break
  sleep 3
done
if [ "$(docker inspect -f '{{.State.Health.Status}}' "portcullis-${SERVICE}-1" 2>/dev/null)" = healthy ]; then
  pass "mealie healthy (guard in place)"
else
  fail "mealie not healthy"
fi
out=$(via_traefik "$HOST" /api/app/about)
if [ "${out%% *}" = 200 ]; then
  pass "https://$HOST/api/app/about -> 200 via Traefik"
else
  fail "via Traefik: $out"
fi
out=$(via_traefik "$HOST" /api/auth/oauth)
if echo "${out#* }" | grep -q "auth\.$DOMAIN"; then
  pass "/api/auth/oauth redirects to Keycloak"
else
  fail "/api/auth/oauth: $out"
fi

compose_down "$APP_ID"
