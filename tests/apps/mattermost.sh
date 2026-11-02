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
if grep -E '^[[:space:]]*traefik\.http\.routers\.mattermost\.middlewares:' "$COMPOSE" | grep -q 'client-headers@file,portcullis-auth@docker,portcullis-groups@docker'; then
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
assert_compose_setting "$COMPOSE" MM_SERVICESETTINGS_TRUSTEDPROXYIPHEADER X-Real-Ip

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

ADMIN="mmadmin-${MATTERMOST_ADMIN_SUFFIX:0:12}"
mm_login() {  # mm_login <login_id> <password>: prints the HTTP status, body in /tmp/mm-login.json
  printf '{"login_id":"%s","password":"%s"}' "$1" "$2" \
    | curl -s -o /tmp/mm-login.json -w '%{http_code}' -H 'Content-Type: application/json' \
      --data-binary @- "http://${IP}:8065/api/v4/users/login" 2>/dev/null || echo 000
}
# Local-mode API calls (as an operator would with mmctl --local), through the
# init image on the socket in the data volume: create e2etaker, rename the
# bootstrap admin away, give e2etaker its name.
mm_local_api() {
  docker run --rm -i --user 2000:2000 -v "portcullis_mattermost-data:/mattermost/data" \
    -e ADMIN="$1" -e TAKER_PW="$2" --entrypoint python3 \
    python:3.15.2-alpine@sha256:20a82dbc2783112ddb91d1534603f802d222a3e63e593cd002eb2ac534e70211 - <<'PY'
import http.client, json, os, socket
class C(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX); self.sock.connect("/mattermost/data/mattermost_local.socket")
def call(m, p, b=None):
    c = C("localhost"); c.request(m, p, json.dumps(b) if b is not None else None, {"Content-Type": "application/json"})
    r = c.getresponse(); d = r.read(); return r.status, (json.loads(d) if d else None)
a = os.environ["ADMIN"]
s, t = call("POST", "/api/v4/users", {"username": "e2etaker", "email": "e2etaker@mattermost.invalid", "password": os.environ["TAKER_PW"]})
s2, adm = call("GET", f"/api/v4/users/username/{a}")
# Local mode has no /patch route: PUT the whole user with the new name.
s3, _ = call("PUT", f"/api/v4/users/{adm['id']}", dict(adm, username=a + "-old"))
s4, _ = call("PUT", f"/api/v4/users/{t['id']}", dict(t, username=a))
print("create", s, "lookup", s2, "rename-admin", s3, "rename-taker", s4)
PY
}
# The mattermost image is distroless: read/remove the state file through the
# init image (same uid) with the data volume mounted.
state_file() {
  docker run --rm --user 2000:2000 -v "portcullis_mattermost-data:/d" --entrypoint "$1" \
    python:3.15.2-alpine@sha256:20a82dbc2783112ddb91d1534603f802d222a3e63e593cd002eb2ac534e70211 \
    "${@:2}" 2>/dev/null || true
}
run_init() {  # run_init <log file>: re-runs the one-shot, prints its exit code
  local rc=0
  docker start -a "portcullis-mattermost-init-1" >"$1" 2>&1 || rc=$?
  echo "$rc"
}

# The bootstrap admin logs in with the generated password and is system admin
CODE=$(mm_login "$ADMIN" "$MATTERMOST_ADMIN_PASSWORD")
if [ "$CODE" = 200 ] && grep -q 'system_admin' /tmp/mm-login.json; then
  pass "$ADMIN signs in with MATTERMOST_ADMIN_PASSWORD and is system admin"
else
  fail "$ADMIN login: HTTP $CODE $(head -c 200 /tmp/mm-login.json 2>/dev/null)"
fi
ADMIN_ID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("id",""))' /tmp/mm-login.json 2>/dev/null || true)
rm -f /tmp/mm-login.json
PINNED=$(state_file cat /d/.portcullis-bootstrap-admin.json)
if [ -n "$ADMIN_ID" ] && echo "$PINNED" | grep -q "\"id\": \"$ADMIN_ID\""; then
  pass "bootstrap admin pinned by user ID ($ADMIN_ID)"
else
  fail "pinned state does not name the bootstrap admin's ID: $PINNED"
fi
CODE=$(mm_login "$ADMIN" wrong-password-123); rm -f /tmp/mm-login.json
if [ "$CODE" = 401 ]; then
  pass "wrong password -> 401"
else
  fail "wrong password -> $CODE"
fi

# A second run grants nothing and accepts the pinned account
RC=$(run_init /dev/null)
if [ "$RC" = 0 ]; then
  pass "mattermost-init re-run with the pinned admin -> exit 0"
else
  fail "mattermost-init re-run -> exit $RC"
fi

# Takeover attempt: the bootstrap admin is renamed and another account
# takes its name. The one-shot must fail closed and grant nothing.
TAKER_PW="$(openssl rand -hex 16)"
TAKE=$(mm_local_api "$ADMIN" "$TAKER_PW" 2>&1 || true)
info "takeover setup: $TAKE"
RC=$(run_init /tmp/mm-init.log)
if [ "$RC" != 0 ] && grep -q 'not the pinned bootstrap admin' /tmp/mm-init.log; then
  pass "name taken by another account -> mattermost-init fails closed"
else
  fail "takeover not refused (rc=$RC): $(tail -3 /tmp/mm-init.log)"
fi
rm -f /tmp/mm-init.log
CODE=$(mm_login "$ADMIN" "$TAKER_PW")
if [ "$CODE" = 200 ] && ! grep -q 'system_admin' /tmp/mm-login.json; then
  pass "the account now named $ADMIN did not get system_admin"
else
  fail "renamed account: HTTP $CODE $(grep -o '"roles":"[^"]*"' /tmp/mm-login.json 2>/dev/null)"
fi
rm -f /tmp/mm-login.json

# No state file but the name exists: refused, never granted by name
state_file rm -f /d/.portcullis-bootstrap-admin.json
RC=$(run_init /tmp/mm-init.log)
if [ "$RC" != 0 ] && grep -q 'was not created by this job' /tmp/mm-init.log; then
  pass "pre-existing account with the bootstrap name and no pinned ID -> refused"
else
  fail "pre-existing name not refused (rc=$RC): $(tail -3 /tmp/mm-init.log)"
fi
rm -f /tmp/mm-init.log
CODE=$(mm_login "$ADMIN" "$TAKER_PW")
if [ "$CODE" = 200 ] && ! grep -q 'system_admin' /tmp/mm-login.json; then
  pass "still no system_admin for the account found by name"
else
  fail "account found by name: HTTP $CODE"
fi
rm -f /tmp/mm-login.json

# Through Traefik (routed once healthy): forward-auth on every path
for _ in $(seq 1 60); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "portcullis-${SERVICE}-1" 2>/dev/null)" = healthy ] && break
  sleep 3
done
if [ "$(docker inspect -f '{{.State.Health.Status}}' "portcullis-${SERVICE}-1" 2>/dev/null)" = healthy ]; then
  pass "mattermost healthy"
else
  fail "mattermost not healthy"
fi
for p in / /login /api/v4/system/ping /api/v4/websocket /api/v4/users/login /hooks/x; do
  assert_gated_path "$HOST" "$p"
done

compose_down "$APP_ID"
