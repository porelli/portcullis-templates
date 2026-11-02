#!/usr/bin/env bash
# Test: Mattermost (forward-auth + group-gate; own accounts behind it, no self sign-up, bootstrap admin)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="mattermost"
section "Mattermost"

APP_ID=mattermost
SERVICE=mattermost

COMPOSE=$(_find_compose "$APP_ID") || { fail "compose.yml not found for $APP_ID"; exit 1; }

# Static: the whole host is gated, never by path
if grep -E '^[[:space:]]*traefik\.http\.routers\.mattermost\.middlewares:' "$COMPOSE" | grep -q 'portcullis-auth@docker,portcullis-groups@docker'; then
  pass "host router behind portcullis-auth + portcullis-groups"
else
  fail "host router must use portcullis-auth@docker,portcullis-groups@docker"
fi
if grep -E '^[[:space:]]*traefik\.http\.routers\.[^.]+\.rule:' "$COMPOSE" | grep -q 'Path'; then
  fail "a router uses path matchers (the password form may not depend on them)"
else
  pass "no path-scoped routers"
fi
assert_compose_setting "$COMPOSE" MM_EMAILSETTINGS_ENABLESIGNUPWITHEMAIL false
assert_compose_setting "$COMPOSE" MM_TEAMSETTINGS_ENABLEOPENSERVER false
assert_compose_setting "$COMPOSE" MM_GITLABSETTINGS_ENABLE false
assert_compose_setting "$COMPOSE" MM_SERVICESETTINGS_ENABLEUSERACCESSTOKENS false

compose_up "$APP_ID"
HOST="$PORTCULLIS_HOST_MATTERMOST"

IP=$(app_container_ip "$APP_ID" "$SERVICE")
wait_for_url "http://${IP}:8065/api/v4/system/ping" 600 "$APP_ID" || docker logs "portcullis-${SERVICE}-1" 2>&1 | tail -40

info "Waiting for mattermost-init..."
if INIT_RC=$(timeout 600 docker wait "portcullis-mattermost-init-1" 2>/dev/null) && [ "$INIT_RC" = 0 ]; then
  pass "mattermost-init exited 0"
else
  fail "mattermost-init did not finish successfully (rc=${INIT_RC:-none})"
fi
docker logs "portcullis-mattermost-init-1" 2>&1 | tail -4 || true
if docker logs "portcullis-mattermost-init-1" 2>&1 | grep -q "$MATTERMOST_ADMIN_PASSWORD"; then
  fail "the admin password appears in mattermost-init's logs"
else
  pass "admin password not in the logs"
fi

# Self sign-up is refused (the first account included)
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
  -d '{"username":"e2esignup","email":"e2esignup@x.invalid","password":"e2e-signup-Password-1"}' \
  "http://${IP}:8065/api/v4/users" 2>/dev/null || echo 000)
case "$CODE" in
  201|200) fail "POST /api/v4/users (sign-up) -> $CODE" ;;
  *) pass "POST /api/v4/users (sign-up) -> $CODE" ;;
esac

# The bootstrap admin logs in with the generated password, and is system admin
LOGIN=$(curl -s -D - -o /tmp/mm-login.json -H 'Content-Type: application/json' \
  --data-binary @- "http://${IP}:8065/api/v4/users/login" 2>/dev/null <<EOF || true
{"login_id":"mmadmin","password":"$MATTERMOST_ADMIN_PASSWORD"}
EOF
)
if echo "$LOGIN" | head -1 | grep -q ' 200' && grep -q 'system_admin' /tmp/mm-login.json; then
  pass "mmadmin signs in with MATTERMOST_ADMIN_PASSWORD and is system admin"
else
  fail "mmadmin login: $(echo "$LOGIN" | head -1) $(head -c 200 /tmp/mm-login.json 2>/dev/null)"
fi
rm -f /tmp/mm-login.json
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
  -d '{"login_id":"mmadmin","password":"wrong-password-123"}' "http://${IP}:8065/api/v4/users/login" 2>/dev/null || echo 000)
if [ "$CODE" = 401 ]; then
  pass "wrong password -> 401"
else
  fail "wrong password -> $CODE"
fi

# Through Traefik: forward-auth on every path (web, API, websocket)
for p in / /login /api/v4/system/ping /api/v4/websocket /api/v4/users/login /hooks/x; do
  assert_gated_path "$HOST" "$p"
done

compose_down "$APP_ID"
