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
if grep -q '^  keycloak_access_role: true' "$DIR/manifest.yaml"; then
  pass "manifest: keycloak_access_role (auth_oidc's admin role implies access)"
else
  fail "manifest must set keycloak_access_role: true"
fi
if grep -q 'configuration.yaml:/config/configuration.yaml:ro' "$COMPOSE"; then
  pass "configuration.yaml mounted read-only"
else
  fail "configuration.yaml must be mounted read-only"
fi
if grep -Eq '^AUTH_OIDC_SHA256 = "[0-9a-f]{64}"$' "$DIR/init.py"; then
  pass "init.py pins auth_oidc by SHA-256"
else
  fail "init.py must pin auth_oidc by SHA-256"
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
# auth_oidc's requirements come from the pinned image (nothing pip-installed at runtime)
REQS=$(docker exec "portcullis-${SERVICE}-1" python3 -c 'import importlib.metadata as m; print(" ".join(f"{p}={m.version(p)}" for p in ("joserfc", "aiofiles", "Jinja2")))' 2>&1 || true)
if echo "$REQS" | grep -Eq '^joserfc=[0-9.]+ aiofiles=[0-9.]+ Jinja2=[0-9.]+$'; then
  pass "auth_oidc requirements present in the image ($REQS)"
else
  fail "auth_oidc requirements: $REQS"
fi
if docker logs "portcullis-${SERVICE}-1" 2>&1 | grep -qi 'Attempting install of\|Unable to install package'; then
  fail "Home Assistant installed packages at runtime"
else
  pass "no runtime package installs"
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


# ── AI support: the built-in MCP Server integration (app_oauth) ─────────
# The hook (portcullis/mcp-hook.py) runs in the homeassistant service as the
# Hub runs it: argv verbatim, JSON on stdin. Shell tests can't sign in, so
# people's Home Assistant accounts and OAuth refresh tokens are written into
# the auth store with Home Assistant stopped (as auth_oidc + an MCP client
# would leave them), then exchanged at /auth/token like a client does.
# Home Assistant bans an address after 10 failed authentications: this
# section stays below that per start (every expected 401 is counted).
HA="portcullis-${SERVICE}-1"
MANIFEST="$DIR/manifest.yaml"
HA_IMAGE=$(sed -n 's/^    image: \(ghcr.io\/home-assistant\/home-assistant:.*\)$/\1/p' "$COMPOSE" | head -1)
TMP=$(mktemp -d)

grep -q 'portcullis/mcp-hook.py:/portcullis/mcp-hook.py:ro' "$COMPOSE" && grep -q 'portcullis/prestart.py:/portcullis/prestart.py:ro' "$COMPOSE" \
  && pass "hook and prestart mounted read-only" || fail "mcp-hook.py / prestart.py must be mounted read-only"
grep -q '^    entrypoint: \["python3", "-I", "/portcullis/prestart.py"\]$' "$COMPOSE" \
  && pass "prestart.py is the homeassistant entrypoint" || fail "homeassistant must start through prestart.py"
assert_compose_setting "$COMPOSE" HA_AI_ENABLED '\$\{PORTCULLIS_AI_ENABLED:-false\}'
if python3 - "$MANIFEST" <<'PY'
import sys, yaml
m = yaml.safe_load(open(sys.argv[1]))
c = m["ai"]["mcp"]
assert len(c) == 1, c
c = c[0]
want = {"name": "homeassistant", "kind": "builtin", "service": "homeassistant", "port": 8123, "path": "/api/mcp",
        "router": "homeassistant", "modes": ["read_write"], "aggregate": False, "upstream": "official",
        "identity": {"mode": "app_oauth", "revoke": "mcp-revoke"}}
for k, v in want.items():
    assert c.get(k) == v, (k, c.get(k))
assert "public_path" not in c
assert m["ai"]["on_change"] == "mcp-integration"
hooks = {h["name"]: h for h in m["hooks"]}
for n in ("mcp-integration", "mcp-revoke"):
    assert hooks[n]["service"] == "homeassistant" and hooks[n]["when"] == ["ai"], hooks[n]
PY
then pass "manifest: app_oauth builtin companion at /api/mcp, hooks in the homeassistant service"
else fail "manifest ai block not as the contract wants"; fi

ha_ip() { IP=$(app_container_ip "$APP_ID" "$SERVICE"); }
wait_ha() {
  for _ in $(seq 1 120); do
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$HA" 2>/dev/null)" = healthy ] && { ha_ip; return 0; }
    sleep 5
  done
  fail "homeassistant not healthy: $(docker logs "$HA" 2>&1 | tail -20)"
  ha_ip
}
# hook ROLE JSON: the exit code; stderr in $TMP/err (stdout must be unused).
hook() {
  local rc=0
  printf '%s' "$2" | docker exec -i "$HA" python3 -I /portcullis/mcp-hook.py "$1" >"$TMP/out" 2>"$TMP/err" || rc=$?
  [ ! -s "$TMP/out" ] || fail "hook $1 printed on stdout"
  echo "$rc"
}
# hook_patched ROLE PYTHON JSON: the hook with a test patch applied to its
# module (g = its live globals) — simulated API failures; the hook file is untouched.
hook_patched() {
  local rc=0
  printf '%s' "$3" | docker exec -i "$HA" python3 -I -c '
import asyncio, os, runpy, signal, sys
g = runpy.run_path("/portcullis/mcp-hook.py", run_name="hooktest")["main"].__globals__
exec(sys.argv[2])
sys.exit(g["main"](["mcp-hook.py", sys.argv[1]]))' "$1" "$2" >/dev/null 2>"$TMP/err" || rc=$?
  echo "$rc"
}
# store PYTHON: runs PYTHON (on stdin) with d = the auth store's data.
store() { docker exec -i "$HA" python3 -I -c 'import json, sys; d = json.load(open("/config/.storage/auth"))["data"]; exec(sys.stdin.read())'; }
mcp_entries() { docker exec "$HA" python3 -I -c 'import json; d = json.load(open("/config/.storage/core.config_entries"))["data"]; print(json.dumps([e.get("data") for e in d["entries"] if e.get("domain") == "mcp_server"]))'; }
hook_admin_ok() {
  store <<'PY'
u = [x for x in d["users"] if x["id"] == "706f727463756c6c6973686f6f6b7300"]
t = [x for x in d["refresh_tokens"] if x["user_id"] == "706f727463756c6c6973686f6f6b7300"]
ok = (len(u) == 1 and u[0]["system_generated"] and u[0]["local_only"] and u[0]["group_ids"] == ["system-admin"]
      and len(t) == 1 and t[0]["token_type"] == "system" and t[0]["access_token_expiration"] == 60.0)
print("ok" if ok else "bad")
PY
}
tokens_of() { store <<PY
ids = {u["id"] for u in d["users"] if u["name"] == "$1" and not u["system_generated"]}
print(len([t for t in d["refresh_tokens"] if t["user_id"] in ids]))
PY
}
active_of() { store <<PY
print([u["is_active"] for u in d["users"] if u["name"] == "$1"])
PY
}
LLATS() { store <<'PY'
print(sorted(t["client_name"] or "" for t in d["refresh_tokens"] if t["token_type"] == "long_lived_access_token"))
PY
}
# access REFRESH CLIENT_ID: an access token (secrets on curl's stdin only).
access() {
  { printf 'data = "grant_type=refresh_token&refresh_token=%s' "$1"; [ -z "$2" ] || printf '&client_id=%s' "$2"; printf '"\n'; } \
    | curl --config - -s "http://${IP}:8123/auth/token" | jq -r '.access_token // empty' 2>/dev/null || true
}
api() { # ACCESS PATH: HTTP code of GET
  printf 'header = "Authorization: Bearer %s"\n' "$1" | curl --config - -s -o /dev/null -w '%{http_code}' "http://${IP}:8123$2" || echo 000
}
mcp() { # ACCESS PATH BODY: HTTP code; answer in $TMP/mcp, headers in $TMP/mcph
  printf '%s' "$3" > "$TMP/mcpreq"
  { [ -z "$1" ] || printf 'header = "Authorization: Bearer %s"\n' "$1"; } \
    | curl --config - -s -o "$TMP/mcp" -D "$TMP/mcph" -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
      -H 'Accept: application/json, text/event-stream' --data-binary "@$TMP/mcpreq" "http://${IP}:8123$2" || echo 000
}
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"ci","version":"1"}}}'
LIST='{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
OC_ON='{"action":"on_change","enabled":true,"mode":"read_write","companion":"homeassistant"}'
OC_OFF='{"action":"on_change","enabled":false,"mode":"read_write","companion":"homeassistant"}'
REVOKE_ALL='{"action":"revoke_all","prefix":"portcullis-ai-"}'
rv() { printf '{"action":"revoke","user":"%s","ids":[]}' "$1"; }

# AI support off (the template's default): the hook admin exists, no entry.
ha_ip
[ "$(hook_admin_ok)" = ok ] && pass "prestart provisioned the hook admin (system user, one system token, 60 s access tokens)" \
  || fail "hook admin not as expected"
[ "$(mcp_entries)" = "[]" ] && pass "AI off: no MCP Server config entry" || fail "AI off: entries $(mcp_entries)"
rc=$(hook on_change "$OC_OFF"); [ "$rc" = 0 ] && pass "on_change enabled:false with AI off -> 0" || fail "on_change false (off) -> $rc: $(head -c 300 "$TMP/err")"
rc=$(hook on_change "$OC_ON"); [ "$rc" = 1 ] && grep -q 'restart' "$TMP/err" \
  && pass "on_change enabled:true in a container started with AI off -> refused" || fail "on_change true with HA_AI_ENABLED=false -> $rc"
[ "$(mcp_entries)" = "[]" ] && pass "...and nothing was added" || fail "entry added: $(mcp_entries)"
# Malformed input: refused before Home Assistant is touched.
for bad in \
  'revoke|{"action":"revoke","user":"alice","ids":["1"]}' \
  'revoke|{"action":"revoke","user":"Alice","ids":[]}' \
  'revoke|{"action":"revoke","user":"alice","ids":[],"x":1}' \
  'revoke|{"action":"revoke","user":"alice","user":"bob","ids":[]}' \
  'revoke|{"action":"revoke_all","prefix":"portcullis-"}' \
  'revoke|{"action":"on_change","enabled":false,"mode":"read_write","companion":"homeassistant"}' \
  'on_change|{"action":"on_change","enabled":"true","mode":"read_write","companion":"homeassistant"}' \
  'on_change|{"action":"on_change","enabled":true,"mode":"read_only","companion":"homeassistant"}' \
  'on_change|{"action":"on_change","enabled":true,"mode":"read_write","companion":"other"}' \
  'revoke|not json'; do
  rc=$(hook "${bad%%|*}" "${bad#*|}")
  [ "$rc" = 1 ] && pass "refused: ${bad#*|}" || fail "accepted ($rc): ${bad#*|}"
done
rc=$(hook revoke "$(rv nobody)"); [ "$rc" = 0 ] && pass "revoke for a person with no Home Assistant account -> 0" || fail "revoke nobody -> $rc: $(head -c 300 "$TMP/err")"

# People: alice, bob, dave (members), carol (administrator). MCP clients:
# Claude (client id metadata document URL) and Claude Code (loopback).
CLAUDE=https://claude.ai/oauth/mcp-oauth-client-metadata
CODE_CLIENT=http://localhost:33418/
WEB="https://${HOST}/"
MOBILE=https://home-assistant.io/android
hex() { openssl rand -hex "$1"; }
declare -A RT
FIX='{"users":['
sep=""
for spec in "alice:0:mcp=$CLAUDE,web=$WEB,llat=" "bob:0:mcp=$CODE_CLIENT,web=$WEB" "carol:1:mcp=$CLAUDE,web=$WEB" "dave:0:mcp=$CODE_CLIENT,web=$WEB,mobile=$MOBILE,llat="; do
  IFS=: read -r name admin toks <<<"$spec"
  FIX+="$sep{\"id\":\"$(hex 16)\",\"name\":\"$name\",\"admin\":$([ "$admin" = 1 ] && echo true || echo false),\"tokens\":["
  tsep=""
  IFS=, read -ra parts <<<"$toks"
  for part in "${parts[@]}"; do
    kind=${part%%=*}; client=${part#*=}
    RT[$name.$kind]=$(hex 64)
    if [ "$kind" = llat ]; then
      FIX+="$tsep{\"id\":\"$(hex 16)\",\"client_id\":null,\"client_name\":\"$name-own-token\",\"type\":\"long_lived_access_token\",\"token\":\"${RT[$name.$kind]}\",\"jwt\":\"$(hex 64)\"}"
    else
      FIX+="$tsep{\"id\":\"$(hex 16)\",\"client_id\":\"$client\",\"client_name\":null,\"type\":\"normal\",\"token\":\"${RT[$name.$kind]}\",\"jwt\":\"$(hex 64)\"}"
    fi
    tsep=","
  done
  FIX+="]}"; sep=","
done
FIX+=']}'
docker stop "$HA" >/dev/null
{ printf 'SPEC = %s\n' "$(jq -c . <<<"$FIX" | jq -Rs .)"; cat <<'PY'
import datetime, json, os, tempfile
spec = json.loads(SPEC)
p = "/config/.storage/auth"
doc = json.load(open(p))
data = doc["data"]
now = datetime.datetime.now(datetime.timezone.utc).isoformat()
for u in spec["users"]:
    data["users"].append({"id": u["id"], "group_ids": ["system-admin" if u["admin"] else "system-users"], "is_owner": False,
                          "is_active": True, "name": u["name"], "system_generated": False, "local_only": False})
    for t in u["tokens"]:
        data["refresh_tokens"].append({"id": t["id"], "user_id": u["id"], "client_id": t["client_id"], "client_name": t["client_name"],
                                       "client_icon": None, "token_type": t["type"], "created_at": now, "access_token_expiration": 1800.0,
                                       "token": t["token"], "jwt_key": t["jwt"], "last_used_at": None, "last_used_ip": None,
                                       "expire_at": None, "credential_id": None, "version": None})
fd, tmp = tempfile.mkstemp(dir=os.path.dirname(p))
with os.fdopen(fd, "w") as f:
    json.dump(doc, f)
os.chmod(tmp, 0o600)
os.replace(tmp, p)
PY
} | docker run --rm -i --volumes-from "$HA" --entrypoint python3 "$HA_IMAGE" -I - && pass "fixture: people and their OAuth tokens written" || fail "fixture write failed"

# Switch on as the Hub does: the container is recreated (HA_AI_ENABLED),
# then on_change.
export PORTCULLIS_AI_ENABLED=true
compose_up "$APP_ID"
wait_ha
[ "$(hook_admin_ok)" = ok ] && pass "a new start re-provisions the hook admin (still exactly one token)" || fail "hook admin after restart"
declare -A AT
for k in alice.mcp:$CLAUDE alice.web:$WEB alice.llat: bob.mcp:$CODE_CLIENT bob.web:$WEB carol.mcp:$CLAUDE carol.web:$WEB \
  dave.mcp:$CODE_CLIENT dave.web:$WEB dave.mobile:$MOBILE dave.llat:; do
  AT[${k%%:*}]=$(access "${RT[${k%%:*}]}" "${k#*:}")
done
n=0; for k in "${!AT[@]}"; do [ -n "${AT[$k]}" ] && [ "$(api "${AT[$k]}" /api/)" = 200 ] && n=$((n + 1)); done
[ "$n" = 11 ] && pass "all 11 fixture tokens work (/api/ -> 200)" || fail "only $n of 11 fixture tokens work"
code=$(mcp "${AT[alice.mcp]}" /api/mcp "$INIT")
[ "$code" = 404 ] && pass "before on_change: /api/mcp -> 404" || fail "before on_change: /api/mcp -> $code"

rc=$(hook on_change "$OC_ON"); [ "$rc" = 0 ] && pass "on_change enabled:true -> 0" || fail "on_change true -> $rc: $(head -c 400 "$TMP/err")"
[ "$(mcp_entries)" = '[{"all_llm_apis": false, "llm_hass_api": ["assist"], "require_admin": false}]' ] \
  && pass "one MCP Server entry: administrators-only off, Assist API only" || fail "entries: $(mcp_entries)"
for who in alice bob carol; do
  code=$(mcp "${AT[$who.mcp]}" /api/mcp "$INIT")
  if [ "$code" = 200 ] && jq -e '.result.protocolVersion and .result.serverInfo.name' "$TMP/mcp" >/dev/null 2>&1; then
    pass "$who's token: /api/mcp initialize -> 200 ($(jq -r '.result.protocolVersion + " " + .result.serverInfo.name' "$TMP/mcp"))"
  else
    fail "$who's token: /api/mcp initialize -> $code $(head -c 300 "$TMP/mcp")"
  fi
done
code=$(mcp "${AT[alice.mcp]}" /api/mcp "$LIST")
[ "$code" = 200 ] && jq -e '.result.tools | type == "array"' "$TMP/mcp" >/dev/null 2>&1 \
  && pass "alice (not an administrator): tools/list -> $(jq '.result.tools | length' "$TMP/mcp") tools ($(jq -r '[.result.tools[].name] | join(", ")' "$TMP/mcp" | head -c 200))" \
  || fail "alice tools/list -> $code $(head -c 300 "$TMP/mcp")"
code=$(mcp "" /api/mcp "$INIT")   # 401 no. 1
[ "$code" = 401 ] && grep -qi '^www-authenticate: Bearer resource_metadata=' "$TMP/mcph" \
  && pass "no token: 401 with RFC 9728 resource_metadata" || fail "no token: $code $(grep -i www-auth "$TMP/mcph")"
out=$(via_traefik "$HOST" /.well-known/oauth-authorization-server)
[ "${out%% *}" = 200 ] && pass "OAuth metadata public through Traefik" || fail "OAuth metadata via Traefik: $out"
rc=$(hook on_change "$OC_ON"); [ "$rc" = 0 ] && [ "$(mcp_entries | jq length)" = 1 ] \
  && pass "on_change enabled:true again -> 0, still one entry" || fail "on_change true (again) -> $rc: $(head -c 300 "$TMP/err")"
# Off without a restart: Home Assistant still serves /api/mcp/<api id>, so
# the hook refuses to report it off.
rc=$(hook on_change "$OC_OFF")
[ "$rc" = 1 ] && grep -q 'restart' "$TMP/err" && [ "$(mcp_entries)" = "[]" ] \
  && pass "on_change enabled:false without a restart -> 1 (/api/mcp/assist still served), entry removed" \
  || fail "on_change false without restart -> $rc: $(head -c 300 "$TMP/err")"
rc=$(hook on_change "$OC_ON"); code=$(mcp "${AT[alice.mcp]}" /api/mcp "$INIT")
[ "$rc" = 0 ] && [ "$code" = 200 ] && pass "on_change enabled:true re-adds it (alice -> 200)" || fail "re-add -> $rc / $code"

# revoke alice: every token of hers ends; the others keep theirs.
rc=$(hook revoke "$(rv alice)")
[ "$rc" = 0 ] && pass "revoke alice -> 0" || fail "revoke alice -> $rc: $(head -c 300 "$TMP/err")"
c1=$(api "${AT[alice.mcp]}" /api/); c2=$(api "${AT[alice.web]}" /api/); c3=$(api "${AT[alice.llat]}" /api/)  # 401 no. 2-4
[ "$c1 $c2 $c3" = "401 401 401" ] && [ "$(tokens_of alice)" = 0 ] \
  && pass "alice's MCP, web and long-lived tokens -> 401; none stored" || fail "alice after revoke: $c1 $c2 $c3, stored $(tokens_of alice)"
[ "$(active_of alice)" = "[True]" ] && pass "alice is active again (she can sign in if she is still a member)" || fail "alice active: $(active_of alice)"
[ "$(mcp "${AT[bob.mcp]}" /api/mcp "$INIT")" = 200 ] && [ "$(api "${AT[carol.web]}" /api/)" = 200 ] && [ "$(tokens_of bob)" = 2 ] \
  && pass "bob's and carol's tokens kept" || fail "others after alice's revoke: bob $(tokens_of bob) stored"
rc=$(hook revoke "$(rv alice)"); [ "$rc" = 0 ] && pass "revoke alice again -> 0" || fail "revoke alice again -> $rc"

# Fail closed.
LL_BEFORE=$(LLATS)
rc=$(hook_patched revoke '
orig = g["HA"].call
async def call(self, t, **kw):
    if t == "config/auth/update":
        raise g["Fail"]("simulated API failure")
    return await orig(self, t, **kw)
g["HA"].call = call' "$(rv bob)")
[ "$rc" = 1 ] && [ "$(mcp "${AT[bob.mcp]}" /api/mcp "$INIT")" = 200 ] \
  && pass "revoke while config/auth/update fails -> 1 (bob's token still works: not reported revoked)" || fail "failing revoke -> $rc"
rc=$(hook_patched revoke '
async def token(self):
    raise g["Fail"]("simulated /auth/token failure")
g["HA"].token = token' "$(rv bob)")
[ "$rc" = 1 ] && pass "revoke while the admin token exchange fails -> 1" || fail "revoke with failing token exchange -> $rc"
rc=$(hook_patched revoke '
orig = g["HA"].call
async def call(self, t, **kw):
    if t == "config/auth/update" and kw.get("is_active") is True:
        raise g["Fail"]("simulated reactivation failure")
    return await orig(self, t, **kw)
g["HA"].call = call' "$(rv bob)")
[ "$rc" = 1 ] && [ "$(active_of bob)" = "[False]" ] && [ "$(tokens_of bob)" = 0 ] \
  && pass "reactivation fails part-way -> 1, bob's tokens gone, left inactive" || fail "part-way revoke -> $rc, bob $(active_of bob) $(tokens_of bob)"
rc=$(hook_patched revoke '
orig = g["HA"].call
async def call(self, t, **kw):
    if t == "config/auth/list":
        os.kill(os.getpid(), signal.SIGTERM)
        await asyncio.sleep(30)
    return await orig(self, t, **kw)
g["HA"].call = call' "$(rv bob)")
[ "$rc" = 143 ] && pass "SIGTERM mid-run -> 143" || fail "SIGTERM mid-run -> $rc"
rc=$(hook revoke "$(rv bob)")
[ "$rc" = 0 ] && [ "$(active_of bob)" = "[True]" ] \
  && pass "the next revoke reactivates bob (the run that died remembered he was active)" || fail "retry -> $rc, bob $(active_of bob)"
[ "$(hook_admin_ok)" = ok ] && [ "$(LLATS)" = "$LL_BEFORE" ] \
  && pass "no admin credential left after the failed runs (one hook token, no new long-lived token)" \
  || fail "after failed runs: hook admin $(hook_admin_ok), long-lived tokens $(LLATS) (before $LL_BEFORE)"
rc=$(hook_patched revoke '
def boom(*a, **k):
    raise g["Fail"]("simulated /auth/revoke failure")
orig = g["revoke_all"]
async def revoke_all(ha):
    ha.s.post = boom
    await orig(ha)
g["revoke_all"] = revoke_all' "$REVOKE_ALL")
[ "$rc" = 1 ] && [ "$(api "${AT[carol.mcp]}" /api/)" = 200 ] \
  && pass "revoke_all while /auth/revoke fails -> 1 (carol's MCP token untouched)" || fail "failing revoke_all -> $rc"

# revoke_all: every OAuth client token but Home Assistant's own frontend and
# Companion apps ends; long-lived tokens stay.
rc=$(hook revoke "$REVOKE_ALL")
[ "$rc" = 0 ] && pass "revoke_all -> 0" || fail "revoke_all -> $rc: $(head -c 300 "$TMP/err")"
c1=$(api "${AT[carol.mcp]}" /api/); c2=$(api "${AT[dave.mcp]}" /api/)   # 401 no. 5-6
[ "$c1 $c2" = "401 401" ] && pass "carol's and dave's MCP client tokens -> 401" || fail "MCP tokens after revoke_all: $c1 $c2"
kept=""; for k in carol.web dave.web dave.mobile dave.llat; do kept+="$(api "${AT[$k]}" /api/) "; done
[ "$kept" = "200 200 200 200 " ] && pass "web frontend, Companion app and long-lived tokens kept" || fail "kept tokens: $kept"
[ "$(hook_admin_ok)" = ok ] && pass "the hook admin's own token survives revoke_all" || fail "hook admin after revoke_all"

# Switch off as the Hub does: recreated with AI off (prestart removes the
# entry before Home Assistant starts), then on_change enabled:false.
rc=$(hook on_change "$OC_ON"); [ "$rc" = 0 ] || fail "on_change true before the switch-off -> $rc"
unset PORTCULLIS_AI_ENABLED
compose_up "$APP_ID"
wait_ha
[ "$(mcp_entries)" = "[]" ] && pass "AI off: prestart removed the entry before Home Assistant started" || fail "after switch-off restart: $(mcp_entries)"
rc=$(hook on_change "$OC_OFF"); [ "$rc" = 0 ] && pass "on_change enabled:false after the restart -> 0" || fail "on_change false -> $rc: $(head -c 300 "$TMP/err")"
for p in /api/mcp /api/mcp/assist; do
  code=$(mcp "${AT[carol.web]}" "$p" "$INIT")
  [ "$code" = 404 ] && pass "AI off: $p -> 404 for an administrator" || fail "AI off: $p -> $code"
done
rm -rf "$TMP"

compose_down "$APP_ID"
