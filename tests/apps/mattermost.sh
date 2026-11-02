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
assert_compose_setting "$COMPOSE" MM_PLUGINSETTINGS_ENABLEUPLOADS false
assert_compose_setting "$COMPOSE" MM_PLUGINSETTINGS_ENABLEMARKETPLACE false

compose_up "$APP_ID"
HOST="$PORTCULLIS_HOST_MATTERMOST"

IP=$(app_container_ip "$APP_ID" "$SERVICE")
# Probe sign-up as soon as Mattermost answers, racing mattermost-init: with
# no account yet, Mattermost would make the first sign-up a system admin.
# Plain and invite-id sign-ups must answer 501 signup_email_disabled
# (IsUserSignUpAllowed; an invite token is looked up first, but
# CreateUserWithToken runs the same check).
signup_probes() {  # signup_probes <label>
  local q code body
  for q in "" "?iid=e2einviteid00000000000000"; do
    body=$(curl -s -w '\n%{http_code}' -H 'Content-Type: application/json' \
      -d '{"username":"e2esignup","email":"e2esignup@x.invalid","password":"e2e-signup-Password-1"}' \
      "http://${IP}:8065/api/v4/users${q}" 2>/dev/null || echo 000)
    code=${body##*$'\n'}
    if [ "$code" = 501 ] && echo "$body" | grep -q 'signup_email_disabled'; then
      pass "$1: POST /api/v4/users${q%%=*} -> 501 signup_email_disabled"
    else
      fail "$1: POST /api/v4/users${q%%=*} -> $code $(echo "$body" | head -c 200)"
    fi
  done
}
for _ in $(seq 1 600); do
  curl -sf -o /dev/null "http://${IP}:8065/api/v4/system/ping" 2>/dev/null && break
  sleep 0.5
done
INIT_STATE=$(docker inspect -f '{{.State.Status}}' "portcullis-mattermost-init-1" 2>/dev/null || echo none)
signup_probes "first answer (mattermost-init: $INIT_STATE)"

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
signup_probes "after mattermost-init"

# The pinned plugins are installed and active (local-mode API)
PLUGINS=$(docker run --rm -i --user 2000:2000 -v "portcullis_mattermost-data:/mattermost/data" --entrypoint python3 \
  python:3.15.2-alpine@sha256:20a82dbc2783112ddb91d1534603f802d222a3e63e593cd002eb2ac534e70211 - 2>&1 <<'PY' || true
import http.client, json, socket
class C(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX); self.sock.connect("/mattermost/data/mattermost_local.socket")
def get(p):
    c = C("localhost"); c.request("GET", p); return json.loads(c.getresponse().read())
d = get("/api/v4/plugins")
print(" ".join(sorted(f"{m['id']}={m['version']}" for m in d.get("active") or [])))
ps = get("/api/v4/config")["PluginSettings"]
print(f"uploads={ps['EnableUploads']} marketplace={ps['EnableMarketplace']}")
# An upload (even through local mode, i.e. as system admin) is refused.
b = "e2eboundary"
body = (f"--{b}\r\nContent-Disposition: form-data; name=\"plugin\"; filename=\"x.tar.gz\"\r\n\r\nx\r\n--{b}--\r\n").encode()
c = C("localhost"); c.request("POST", "/api/v4/plugins", body, {"Content-Type": f"multipart/form-data; boundary={b}"})
r = c.getresponse(); print(f"upload={r.status} {json.loads(r.read() or b'{}').get('id', '')}")
PY
)
for want in freemium=2.0.0 com.github.matterpoll.matterpoll=1.9.2; do
  if echo " $(echo "$PLUGINS" | head -1) " | grep -q " $want "; then
    pass "plugin $want active"
  else
    fail "plugin $want not active: $PLUGINS"
  fi
done
if echo "$PLUGINS" | grep -q '^uploads=False marketplace=False$'; then
  pass "plugin uploads and marketplace off at runtime"
else
  fail "plugin settings at runtime: $(echo "$PLUGINS" | sed -n 2p)"
fi
if echo "$PLUGINS" | grep -q '^upload=501 app.plugin.upload_disabled.app_error$'; then
  pass "plugin upload refused even in local mode (501 upload_disabled)"
else
  fail "plugin upload: $(echo "$PLUGINS" | sed -n 3p)"
fi
if grep -Eq '"[0-9a-f]{64}"\)' "$(dirname "$COMPOSE")/plugins.py" && ! grep -q 'releases/latest' "$(dirname "$COMPOSE")/plugins.py"; then
  pass "plugins pinned by release and SHA-256"
else
  fail "plugins must be pinned by release and SHA-256"
fi

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

# Plugin signatures are required: an unsigned bundle and one signed by a
# foreign key, dropped into the file store, are refused at the next start;
# the pinned bundles (signed by mattermost-plugins' key) still load.
WORK=$(mktemp -d)
for id in e2e.unsigned e2e.foreign; do
  mkdir -p "$WORK/$id"
  printf '{"id":"%s","name":"%s","version":"0.0.1","min_server_version":"6.0.0","webapp":{"bundle_path":"main.js"}}' "$id" "$id" > "$WORK/$id/plugin.json"
  echo 'console.log(1)' > "$WORK/$id/main.js"
  tar -C "$WORK" -czf "$WORK/$id.tar.gz" "$id"
done
GNUPGHOME="$WORK/gnupg"; mkdir -m 700 "$GNUPGHOME"; export GNUPGHOME
gpg --batch --quiet --passphrase '' --pinentry-mode loopback --quick-gen-key 'e2e foreign <e2e@x.invalid>' rsa3072 sign never
gpg --batch --quiet --output "$WORK/e2e.foreign.tar.gz.sig" --detach-sign "$WORK/e2e.foreign.tar.gz"
unset GNUPGHOME
for f in e2e.unsigned.tar.gz e2e.foreign.tar.gz e2e.foreign.tar.gz.sig; do
  docker cp "$WORK/$f" "portcullis-${SERVICE}-1:/mattermost/data/plugins/$f" >/dev/null
done
rm -rf "$WORK"
docker restart "portcullis-${SERVICE}-1" >/dev/null
sleep 5
for _ in $(seq 1 120); do
  curl -sf -o /dev/null "http://${IP}:8065/api/v4/system/ping" 2>/dev/null && break
  sleep 2
done
sleep 10
AFTER=$(docker run --rm -i --user 2000:2000 -v "portcullis_mattermost-data:/mattermost/data" --entrypoint python3 \
  python:3.15.2-alpine@sha256:20a82dbc2783112ddb91d1534603f802d222a3e63e593cd002eb2ac534e70211 - 2>&1 <<'PY' || true
import http.client, json, socket
class C(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX); self.sock.connect("/mattermost/data/mattermost_local.socket")
c = C("localhost"); c.request("GET", "/api/v4/plugins"); d = json.loads(c.getresponse().read())
print(" ".join(sorted(f"{m['id']}={m['version']}" for m in (d.get("active") or []) + (d.get("inactive") or []))))
PY
)
info "plugins after restart: $AFTER"
if echo " $AFTER " | grep -q ' e2e\.'; then
  fail "an unsigned or foreign-signed bundle was installed: $AFTER"
else
  pass "unsigned and foreign-signed bundles refused"
fi
if echo " $AFTER " | grep -q ' freemium=2.0.0 ' && echo " $AFTER " | grep -q ' com.github.matterpoll.matterpoll=1.9.2 '; then
  pass "pinned, signed bundles still installed after a restart"
else
  fail "pinned bundles after restart: $AFTER"
fi
if docker logs "portcullis-${SERVICE}-1" 2>&1 | grep -q 'Failed to validate plugin signature'; then
  pass "Mattermost logged the signature refusal"
else
  info "no 'Failed to validate plugin signature' log line"
fi
if docker logs "portcullis-mattermost-plugins-1" 2>&1 | grep -q 'private key discarded'; then
  pass "mattermost-plugins signed the bundles and discarded its key"
else
  fail "mattermost-plugins: $(docker logs portcullis-mattermost-plugins-1 2>&1 | tail -3)"
fi
KEYS=$(docker run --rm -v "portcullis_mattermost-plugin-keys:/k:ro" -v "portcullis_mattermost-data:/d:ro" --entrypoint sh \
  python:3.15.2-alpine@sha256:20a82dbc2783112ddb91d1534603f802d222a3e63e593cd002eb2ac534e70211 \
  -c 'ls -A /k; grep -rlI "PRIVATE KEY" /k /d 2>/dev/null; true' 2>&1 || true)
if [ "$KEYS" = "portcullis-plugins.gpg" ]; then
  pass "only the public key is on a volume"
else
  fail "key volume / data volume content: $KEYS"
fi
# Swap attack on the signer: the file-store bundle replaced by a symlink
# (the Mattermost side can write there). mattermost-plugins must refuse
# before signing anything.
vol_py() {  # run python (stdin) as uid 2000 with the data volume at /d
  docker run --rm -i --user 2000:2000 -v "portcullis_mattermost-data:/d" --entrypoint python3 \
    python:3.15.2-alpine@sha256:20a82dbc2783112ddb91d1534603f802d222a3e63e593cd002eb2ac534e70211 - 2>&1
}
SIGS_BEFORE=$(printf 'import hashlib,glob\nfor f in sorted(glob.glob("/d/plugins/*.sig")): print(f, hashlib.sha256(open(f,"rb").read()).hexdigest())\n' | vol_py)
printf 'import os\nos.rename("/d/plugins/freemium.tar.gz", "/d/plugins/.e2e-freemium")\nos.symlink("/etc/passwd", "/d/plugins/freemium.tar.gz")\n' | vol_py
RC=0; docker start -a "portcullis-mattermost-plugins-1" >/tmp/mm-plugins.log 2>&1 || RC=$?
SIGS_AFTER=$(printf 'import hashlib,glob\nfor f in sorted(glob.glob("/d/plugins/*.sig")): print(f, hashlib.sha256(open(f,"rb").read()).hexdigest())\n' | vol_py)
if [ "$RC" != 0 ] && grep -q 'not a regular file' /tmp/mm-plugins.log && [ "$SIGS_BEFORE" = "$SIGS_AFTER" ]; then
  pass "symlinked bundle refused by mattermost-plugins, nothing signed"
else
  fail "symlink swap: rc=$RC $(tail -2 /tmp/mm-plugins.log) sigs-changed=$([ "$SIGS_BEFORE" = "$SIGS_AFTER" ] && echo no || echo yes)"
fi
printf 'import os\nos.unlink("/d/plugins/freemium.tar.gz")\nos.rename("/d/plugins/.e2e-freemium", "/d/plugins/freemium.tar.gz")\n' | vol_py
RC=0; docker start -a "portcullis-mattermost-plugins-1" >/tmp/mm-plugins.log 2>&1 || RC=$?
if [ "$RC" = 0 ]; then
  pass "mattermost-plugins re-run after restoring the bundle -> exit 0"
else
  fail "mattermost-plugins re-run: rc=$RC $(tail -2 /tmp/mm-plugins.log)"
fi
rm -f /tmp/mm-plugins.log
assert_compose_setting "$COMPOSE" MM_PLUGINSETTINGS_REQUIREPLUGINSIGNATURE true
assert_compose_setting "$COMPOSE" MM_FILESETTINGS_DRIVERNAME local

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
