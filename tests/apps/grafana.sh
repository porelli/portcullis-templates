#!/usr/bin/env bash
# Test: Grafana (header-auth + group-gate)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="grafana"
section "Grafana"

APP_ID=grafana

# Public exception ON in listed mode with one listed dashboard token: the
# override the Hub would generate (tests/lib.sh quirk #12), every router of
# the host on the default policy's tier (authaware@file).
TOKEN=$(openssl rand -hex 16)
OTHER=$(openssl rand -hex 16)
MANIFEST="$(dirname "$(_find_compose "$APP_ID")")/manifest.yaml"
ROUTED=()
while read -r p; do ROUTED+=("$p"); done < <(public_routed_prefixes "$MANIFEST" listed "$TOKEN")
COMPOSE_OVERRIDE=$(mktemp)
export COMPOSE_OVERRIDE
# Core's real public guard checks paths and credentials: give it the
# policy-file entry the Hub would publish (at the version core's group-gate serves, tests/lib.sh policy_version).
write_public_policy grafana "$MANIFEST" listed
# shellcheck disable=SC2016 # ${PORTCULLIS_HOST_GRAFANA} is for compose to expand
write_public_override "$APP_ID" dashboards '${PORTCULLIS_HOST_GRAFANA:-grafana.portcullis.local}' authaware@file "$COMPOSE_OVERRIDE" "${ROUTED[@]}"

# AI support on, as the Hub writes it while the grafana-mcp companion is on
# (contracts §3.1): trust.sh then adds the companion's address.
export PORTCULLIS_AI_ENABLED=true
compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID" dashboards)
wait_for_url "http://${IP}:3000" 60 "$APP_ID"

# Grafana login page should return HTML
BODY=$(curl -sf "http://${IP}:3000/login" 2>/dev/null || echo "")
# Here-string, not echo | grep -q: grep exits at the first match and the
# echo's broken pipe would fail the test under pipefail.
if grep -qi "grafana" <<< "$BODY"; then
  pass "/login -> Grafana login page returned"
else
  fail "/login -> Grafana login page not found"
fi

# Verify proxy auth is enabled in the container environment
GF_PROXY=$(docker exec "portcullis-dashboards-1" printenv GF_AUTH_PROXY_ENABLED 2>/dev/null || echo "")
if [ "$GF_PROXY" = "true" ]; then
  pass "GF_AUTH_PROXY_ENABLED=true"
else
  fail "GF_AUTH_PROXY_ENABLED expected 'true', got '$GF_PROXY'"
fi

# Verify compose has forward-auth + group-gate middleware
COMPOSE=$(_find_compose "$APP_ID")
assert_traefik_only_trust "$COMPOSE" GF_AUTH_PROXY_WHITELIST

# The CI host is not Traefik: a spoofed identity header must not log in
assert_spoofed_identity_rejected "http://${IP}:3000/api/user" non-2xx

if grep -q 'portcullis-auth@docker' "$COMPOSE" && grep -q 'portcullis-groups@docker' "$COMPOSE"; then
  pass "Forward-auth + group-gate middleware configured"
else
  fail "Missing forward-auth or group-gate middleware in compose"
fi

# Identity is the username only; never map an email header (account
# linking). The only extra mapping is the Role setting's header delivery.
if grep -q 'GF_AUTH_PROXY_HEADER_PROPERTY: username' "$COMPOSE" \
    && [ "$(grep -c 'GF_AUTH_PROXY_HEADERS' "$COMPOSE")" = 1 ] \
    && grep -qx '      GF_AUTH_PROXY_HEADERS: Role:X-Forwarded-Attr-Grafana-Role' "$COMPOSE"; then
  pass "Grafana header login keyed on username; only Role mapped (no email)"
else
  fail "Grafana must use HEADER_PROPERTY username and GF_AUTH_PROXY_HEADERS exactly Role:X-Forwarded-Attr-Grafana-Role"
fi
# Runtime: the role header mapping and per-request sync are in the env.
GF_HEADERS=$(docker exec "portcullis-dashboards-1" printenv GF_AUTH_PROXY_HEADERS 2>/dev/null || echo "")
GF_TTL=$(docker exec "portcullis-dashboards-1" printenv GF_AUTH_PROXY_SYNC_TTL 2>/dev/null || echo "")
if [ "$GF_HEADERS" = "Role:X-Forwarded-Attr-Grafana-Role" ] && [ "$GF_TTL" = 0 ]; then
  pass "GF_AUTH_PROXY_HEADERS=Role:X-Forwarded-Attr-Grafana-Role, GF_AUTH_PROXY_SYNC_TTL=0"
else
  fail "role header mapping: GF_AUTH_PROXY_HEADERS='$GF_HEADERS' GF_AUTH_PROXY_SYNC_TTL='$GF_TTL'"
fi

section "Public exception through Traefik"
HOST="grafana.$DOMAIN"
# Traefik picks the container up from the docker provider within seconds.
for _ in $(seq 1 30); do
  out=$(via_traefik "$HOST" /)
  case "${out%% *}" in 000|404|502) sleep 1 ;; *) break ;; esac
done
if docker inspect "portcullis-dashboards-1" --format '{{json .Config.Labels}}' | grep -q 'portcullis-public-strip-grafana.headers.customrequestheaders.X-Forwarded-User'; then
  pass "public router strips X-Forwarded-User (GF_AUTH_PROXY_HEADER_NAME)"
else
  fail "public router lacks the X-Forwarded-User strip"
fi
# The Role setting's header delivery never reaches Grafana from a client on
# the public router (the Hub strips every header delivery, both spellings).
LABELS=$(docker inspect "portcullis-dashboards-1" --format '{{json .Config.Labels}}')
if grep -q 'portcullis-public-strip-grafana.headers.customrequestheaders.X-Forwarded-Attr-Grafana-Role"' <<< "$LABELS" \
    && grep -q 'portcullis-public-strip-grafana.headers.customrequestheaders.X_Forwarded_Attr_Grafana_Role"' <<< "$LABELS"; then
  pass "public router strips X-Forwarded-Attr-Grafana-Role (and its underscore form)"
else
  fail "public router lacks the X-Forwarded-Attr-Grafana-Role strip"
fi
# Listed dashboard: answered by Grafana without Keycloak.
assert_public_path "$HOST" "/public-dashboards/$TOKEN"
assert_public_path "$HOST" "/api/public/dashboards/$TOKEN"
# Unlisted dashboard, a non-public path, and a segment-boundary near miss
# stay behind forward-auth.
assert_gated_path "$HOST" "/public-dashboards/$OTHER"
assert_gated_path "$HOST" "/api/public/dashboards/$OTHER"
assert_gated_path "$HOST" "/public-dashboards/${TOKEN}x"
assert_gated_path "$HOST" "/"
assert_gated_path "$HOST" "/api/user"
# Supporting paths serve static files only.
assert_gated_path "$HOST" "/public/build/"
# Logins never ride the public router: core's public guard refuses
# requests carrying a Grafana credential (403, no redirect), with cookie /
# query names normalised the way PHP does (and case-insensitively).
for h in "Cookie: grafana_session=stolen" "Cookie: a=1; grafana%5Fsession=stolen" "Cookie: GRAFANA_SESSION=stolen" \
         "Cookie:  grafana.session=stolen" "Cookie: renderKey=stolen" "Authorization: Basic YWRtaW46YWRtaW4=" \
         "Authorization: Bearer glsa_stolen" "X-Access-Token: stolen"; do
  assert_public_refused "$HOST" "/public-dashboards/$TOKEN" -H "$h"
done
for q in "auth_token=stolen" "auth.token=stolen" "+auth_token=stolen" "auth_token%5B%5D=stolen" "auth%5Ftoken=stolen"; do
  assert_public_refused "$HOST" "/public-dashboards/$TOKEN?$q"
done

section "AI support: mcp-grafana companion (identity headers)"
TMP=$(mktemp -d)
D=portcullis-dashboards-1
M=portcullis-grafana-mcp-1
TRAEFIK_IP=${PORTCULLIS_TRAEFIK_IP:-172.31.250.2}
GF_IMAGE=$(sed -n 's/^    image: \(grafana\/grafana:[^[:space:]]*\)$/\1/p' "$COMPOSE")
MCP_IMAGE=$(sed -n 's/^    image: \(grafana\/mcp-grafana:[^[:space:]]*\)$/\1/p' "$COMPOSE")

# Static: the official image pinned, read-only by default, the caller secret
# from the environment, no shared Grafana identity, no URL override, no
# generic API tool, nothing exposed.
if [[ "$MCP_IMAGE" =~ ^grafana/mcp-grafana:[0-9]+\.[0-9]+\.[0-9]+@sha256:[0-9a-f]{64}$ ]]; then
  pass "mcp-grafana pinned tag@digest ($MCP_IMAGE)"
else
  fail "mcp-grafana must be the official image pinned tag@sha256 (got '$MCP_IMAGE')"
fi
MCP_SVC=$(awk '/^  grafana-mcp:/{f=1; next} f && /^  [a-z]/{f=0} f' "$COMPOSE")
if grep -q -- '- --disable-write=\${PORTCULLIS_AI_READONLY_GRAFANA:-true}$' <<<"$MCP_SVC" \
  && grep -q -- '- --disable-api$' <<<"$MCP_SVC" \
  && grep -q 'GRAFANA_FORWARD_HEADERS: X-Forwarded-User,X-Forwarded-Attr-Grafana-Role$' <<<"$MCP_SVC" \
  && grep -q 'MCP_GRAFANA_SERVER_TOKEN: \${MCP_GRAFANA_SERVER_TOKEN:?' <<<"$MCP_SVC" \
  && ! grep -qiE 'SERVICE_ACCOUNT|API_KEY|GRAFANA_USERNAME|GRAFANA_PASSWORD|url-override|URL_OVERRIDE|server-auth-token|EXTRA_HEADERS|traefik\.|ports:|portcullis-proxy' <<<"$MCP_SVC"; then
  pass "grafana-mcp: read-only by default, secret by env, no service account / URL override / API tool / labels / ports / proxy network"
else
  fail "grafana-mcp service settings (read-only default, --disable-api, forwarded headers, env secret, nothing shared or exposed)"
fi
if grep -qE '^hooks:' "$MANIFEST"; then
  fail "grafana declares hooks (identity_headers needs none; never on the companion)"
else
  pass "no hooks (identity_headers)"
fi

# Runtime. The Hub attaches the companion to portcullis-proxy while AI
# support is on (its override; contracts §3.2): do the same.
TRUST_NET=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$M" | tr ' ' '\n' | grep -m1 .)
DEF_NET=$(docker network ls --format '{{.Name}}' | grep -x "$(sed 's/_mcp-trust$//' <<<"$TRUST_NET")_default" || true)
docker network connect portcullis-proxy "$M"
net_ip() { docker inspect -f "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}" "$1" 2>/dev/null || true; }
MCP_IP=$(net_ip "$M" portcullis-proxy)
MCP_TRUST_IP=$(net_ip "$M" "$TRUST_NET")
GF_TRUST_IP=$(net_ip "$D" "$TRUST_NET")
GF_PROXY_IP=$(net_ip "$D" portcullis-proxy)
SUBNET=$(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' "$TRUST_NET" | awk '{print $1}')
GATEWAY=$(docker network inspect -f '{{range .IPAM.Config}}{{.Gateway}} {{end}}' "$TRUST_NET" | awk '{print $1}')
INTERNAL=$(docker network inspect -f '{{.Internal}}' "$TRUST_NET")
info "trust network $TRUST_NET ($SUBNET, gateway ${GATEWAY:-none}, internal $INTERNAL): Grafana $GF_TRUST_IP, companion $MCP_TRUST_IP"
[ "$INTERNAL" = true ] && pass "$TRUST_NET is internal" || fail "$TRUST_NET is not internal"
# trust.sh excludes the prefix's first address as the bridge gateway
# (Docker's builtin IPAM; the network is exactly {internal: true}).
FIRST=$(python3 -c 'import ipaddress,sys; print(ipaddress.ip_network(sys.argv[1])[1])' "$SUBNET")
[ -n "$GATEWAY" ] && [ "$GATEWAY" = "$FIRST" ] && pass "the trust network's gateway is its first address ($GATEWAY)" || fail "trust network gateway '$GATEWAY', first address $FIRST"
MEMBERS=$(docker network inspect -f '{{range .Containers}}{{.Name}} {{end}}' "$TRUST_NET" | tr ' ' '\n' | sed '/^$/d' | sort | tr '\n' ' ')
[ "$MEMBERS" = "$D $M " ] && pass "$TRUST_NET members: exactly dashboards and grafana-mcp" || fail "$TRUST_NET members: $MEMBERS"
DNETS=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$D" | tr ' ' '\n' | sed '/^$/d' | sort | tr '\n' ' ')
[ "$DNETS" = "$(printf '%s\n' portcullis-proxy "$TRUST_NET" | sort | tr '\n' ' ')" ] && pass "dashboards joins exactly portcullis-proxy and $TRUST_NET" || fail "dashboards networks: $DNETS"
allowlist() { docker exec "$D" sh -c 'tr "\0" "\n" < /proc/1/environ' 2>/dev/null | sed -n 's/^GF_AUTH_PROXY_WHITELIST=//p'; }
# wait_allowlist PREDICATE SECONDS: until Grafana (PID 1) runs with an
# allowlist PREDICATE accepts and answers.
wait_allowlist() {
  for _ in $(seq 1 "$2"); do
    GF_TRUST_IP=$(net_ip "$D" "$TRUST_NET")
    if "$1" "$(allowlist)" && docker exec "$D" curl -sf -o /dev/null http://127.0.0.1:3000/api/health 2>/dev/null; then return 0; fi
    sleep 1
  done
  return 1
}
# The allowlist is Traefik plus the trust subnet without its network
# address, gateway, broadcast and Grafana's own address; the companion's
# address is in it.
trust_ok() {
  python3 - "$1" "$TRAEFIK_IP" "$SUBNET" "$GATEWAY" "$GF_TRUST_IP" "$MCP_TRUST_IP" <<'PY'
import ipaddress, sys
wl, traefik, subnet, gw, own, comp = sys.argv[1:7]
parts = [p for p in wl.split(",") if p]
if not parts or parts[0] != traefik:
    sys.exit(1)
net = ipaddress.ip_network(subnet)
nets = [ipaddress.ip_network(p) for p in parts[1:]]
if not nets or any(not n.subnet_of(net) for n in nets):
    sys.exit(1)
inside = lambda a: any(ipaddress.ip_address(a) in n for n in nets)
bad = [a for a in (str(net.network_address), str(net.broadcast_address), gw, own) if a and inside(a)]
sys.exit(1 if bad or not inside(comp) else 0)
PY
}
traefik_only() { [ "$1" = "$TRAEFIK_IP" ]; }
if wait_allowlist trust_ok 90; then
  pass "Grafana trusts Traefik and $SUBNET without its network, gateway, broadcast and own address (companion $MCP_TRUST_IP in it)"
else
  fail "allowlist '$(allowlist)' (subnet $SUBNET, gateway $GATEWAY, Grafana $GF_TRUST_IP, companion $MCP_TRUST_IP)"
  docker logs "$D" 2>&1 | grep portcullis-trust | tail -5 || true
fi

# probe NETWORK URL [curl args]: a throwaway container (Grafana's image has
# curl); prints the body, then the HTTP code on the last line.
probe() {
  local net="$1" url="$2"; shift 2
  docker run --rm --network "$net" --entrypoint curl "$GF_IMAGE" -s --max-time 10 -w '\n%{http_code}' "$@" "$url" 2>/dev/null || echo 000
}
not_admin() { # label output
  local code login
  code=$(tail -n1 <<<"$2"); login=$(sed '$d' <<<"$2" | jq -r '.login // empty' 2>/dev/null || true)
  if [ "$login" = admin ] || [[ "$code" == 2* ]]; then
    fail "$1: X-Forwarded-User: admin signed in (HTTP $code, login '$login')"
  else
    pass "$1: X-Forwarded-User: admin not signed in (HTTP $code)"
  fi
}
if [ -n "$DEF_NET" ]; then
  not_admin "another container on the project's default network" \
    "$(probe "$DEF_NET" "http://${GF_PROXY_IP}:3000/api/user" -H 'X-Forwarded-User: admin')"
  not_admin "another container on the project's default network, to Grafana's trust address" \
    "$(probe "$DEF_NET" "http://${GF_TRUST_IP}:3000/api/user" -H 'X-Forwarded-User: admin')"
else
  info "no ${TRUST_NET%_mcp-trust}_default network (no service joins it): checked from portcullis-proxy and the host instead"
fi
not_admin "a container on portcullis-proxy" \
  "$(probe portcullis-proxy "http://${GF_PROXY_IP}:3000/api/user" -H 'X-Forwarded-User: admin')"
not_admin "the host (the trust network's gateway side)" \
  "$(curl -s --max-time 10 -w '\n%{http_code}' -H 'X-Forwarded-User: admin' "http://${GF_TRUST_IP}:3000/api/user" 2>/dev/null || echo 000)"
not_admin "a container in the host's network namespace (network_mode: host), to Grafana's trust address" \
  "$(probe host "http://${GF_TRUST_IP}:3000/api/user" -H 'X-Forwarded-User: admin')"
not_admin "Grafana itself, to its own trust address (a data source pointing at Grafana)" \
  "$(docker exec "$D" curl -s --max-time 10 -w '\n%{http_code}' -H 'X-Forwarded-User: admin' "http://${GF_TRUST_IP}:3000/api/user" 2>/dev/null || echo 000)"
# The companion's network namespace (its trust address) is trusted. Setup
# below goes through it; nothing but the companion may share it.
gfc() { # METHOD PATH USER [JSON]
  local data=()
  if [ -n "${4:-}" ]; then data=(-H 'Content-Type: application/json' -d "$4"); fi
  probe "container:$M" "http://${GF_TRUST_IP}:3000$2" -X "$1" -H "X-Forwarded-User: $3" ${data[@]+"${data[@]}"}
}
OUT=$(gfc GET /api/user admin)
if [ "$(sed '$d' <<<"$OUT" | jq -r .login 2>/dev/null)" = admin ]; then
  pass "from the companion's trust address: X-Forwarded-User honoured (signed in as admin)"
else
  fail "from the companion's trust address: $(head -c 300 <<<"$OUT")"
fi

# Data: a folder only admins can open, a dashboard in it, one in a folder
# everyone sees; alice and bob exist (auto sign-up, Viewer).
gfc POST /api/folders admin '{"uid":"team","title":"Team"}' >/dev/null
gfc POST /api/folders admin '{"uid":"secret-ops","title":"Secret ops"}' >/dev/null
gfc POST /api/folders/secret-ops/permissions admin '{"items":[]}' >/dev/null
gfc POST /api/dashboards/db admin '{"dashboard":{"uid":"team-dash","title":"Team dashboard"},"folderUid":"team","overwrite":true}' >/dev/null
gfc POST /api/dashboards/db admin '{"dashboard":{"uid":"secret-dash","title":"Secret dashboard"},"folderUid":"secret-ops","overwrite":true}' >/dev/null
gfc GET /api/user alice >/dev/null
gfc GET /api/user bob >/dev/null

wait_for_url "http://${MCP_IP}:8000/healthz" 60 grafana-mcp || true
# mcp IP TOKEN USER BODY [headers…]: the JSON-RPC answer; HTTP code in
# $TMP/mcpcode. The token reaches curl on stdin, never on its argv.
mcp() {
  local ip="$1" token="$2" user="$3" body="$4"; shift 4
  local hdr=()
  if [ -n "$user" ]; then hdr=(-H "X-Forwarded-User: $user"); fi
  printf '%s' "$body" > "$TMP/mcpreq"
  { [ -z "$token" ] || printf 'header = "Authorization: Bearer %s"\n' "$token"; } \
    | curl --config - -s --max-time 30 -o "$TMP/mcpout" -w '%{http_code}' -X POST "http://$ip:8000/mcp" \
      -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
      -H 'MCP-Protocol-Version: 2025-11-25' ${hdr[@]+"${hdr[@]}"} "$@" --data-binary "@$TMP/mcpreq" > "$TMP/mcpcode" || echo 000 > "$TMP/mcpcode"
  if grep -q '^data: ' "$TMP/mcpout"; then sed -n 's/^data: //p' "$TMP/mcpout"; else cat "$TMP/mcpout"; fi
}
call() { printf '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"%s","arguments":%s}}' "$1" "$2"; }
text() { jq -r '[.result.content[]?.text] | join("\n")' 2>/dev/null || true; }
TOKEN=$MCP_GRAFANA_SERVER_TOKEN
SEARCH=$(call search_dashboards '{"query":""}')

mcp "$MCP_IP" "" alice "$SEARCH" >/dev/null
[ "$(cat "$TMP/mcpcode")" = 401 ] && pass "grafana-mcp without the caller secret -> 401" || fail "grafana-mcp without the secret: HTTP $(cat "$TMP/mcpcode")"
mcp "$MCP_IP" "not-the-secret" admin "$SEARCH" >/dev/null
[ "$(cat "$TMP/mcpcode")" = 401 ] && pass "grafana-mcp with a wrong secret -> 401" || fail "grafana-mcp with a wrong secret: HTTP $(cat "$TMP/mcpcode")"

T=$(mcp "$MCP_IP" "$TOKEN" alice "$SEARCH" | text)
if grep -q 'Team dashboard' <<<"$T" && ! grep -q 'Secret dashboard' <<<"$T"; then
  pass "as alice: her dashboards only (the one in a folder she can't open is absent)"
else
  fail "search_dashboards as alice: $(head -c 400 <<<"$T")"
fi
T=$(mcp "$MCP_IP" "$TOKEN" admin "$SEARCH" | text)
grep -q 'Secret dashboard' <<<"$T" && pass "as admin: the restricted dashboard is listed (it exists)" || fail "search_dashboards as admin: $(head -c 400 <<<"$T")"
T=$(mcp "$MCP_IP" "$TOKEN" alice "$(call user_info '{}')" | text)
grep -q '"login": *"alice"\|login: alice\|"alice"' <<<"$T" && pass "user_info as alice -> alice" || fail "user_info as alice: $(head -c 300 <<<"$T")"
T=$(mcp "$MCP_IP" "$TOKEN" "" "$SEARCH")
if grep -q 'Team dashboard\|Secret dashboard' <<<"$T"; then
  fail "the secret without an identity header returned dashboards"
else
  pass "the secret without X-Forwarded-User sees nothing (no shared identity)"
fi
# The Role setting's header reaches Grafana through the companion (a
# demotion applies to AI calls too).
role_of() { gfc GET /api/org/users admin | sed '$d' | jq -r --arg u "$1" '.[] | select(.login == $u) | .role' 2>/dev/null || true; }
mcp "$MCP_IP" "$TOKEN" bob "$SEARCH" -H 'X-Forwarded-Attr-Grafana-Role: Editor' >/dev/null
R1=$(role_of bob)
mcp "$MCP_IP" "$TOKEN" bob "$SEARCH" -H 'X-Forwarded-Attr-Grafana-Role: Viewer' >/dev/null
R2=$(role_of bob)
if [ "$R1" = Editor ] && [ "$R2" = Viewer ]; then
  pass "the Role header is forwarded (bob Editor, then Viewer)"
else
  fail "Role header through grafana-mcp: bob '$R1' then '$R2' (expected Editor, Viewer)"
fi

# Protocol versions of the manifest.
for v in 2025-11-25 2025-06-18; do
  INIT=$(printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"%s","capabilities":{},"clientInfo":{"name":"ci","version":"1"}}}' "$v")
  GOT=$(mcp "$MCP_IP" "$TOKEN" alice "$INIT" -H "MCP-Protocol-Version: $v" | jq -r '.result.protocolVersion // empty' 2>/dev/null || true)
  [ "$GOT" = "$v" ] && pass "initialize $v -> $v" || fail "initialize $v -> '${GOT}'"
done

# Tool classes against the real tools: read-only (the compose companion),
# the same flags with writes on, and writes on without --disable-api (only
# to show the never patterns name real tools).
LIST='{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
mcp "$MCP_IP" "$TOKEN" alice "$LIST" > "$TMP/tools-ro.json"
probe_mcp() { # NAME extra-flags…
  local name="$1"; shift
  docker run -d --rm --name "$name" --network portcullis-proxy --read-only --tmpfs /tmp \
    --security-opt no-new-privileges:true --cap-drop ALL \
    -e GRAFANA_URL=http://dashboards-internal:3000 -e MCP_GRAFANA_SERVER_TOKEN \
    --entrypoint /app/mcp-grafana "$MCP_IMAGE" \
    -t streamable-http --address 0.0.0.0:8000 --allowed-hosts '*' --usage-stats=disabled "$@" >/dev/null
  net_ip "$name" portcullis-proxy
}
RW_IP=$(probe_mcp portcullis-t-grafana-mcp-rw --disable-write=false --disable-api)
FULL_IP=$(probe_mcp portcullis-t-grafana-mcp-full --disable-write=false)
wait_for_url "http://${RW_IP}:8000/healthz" 60 grafana-mcp-rw || true
wait_for_url "http://${FULL_IP}:8000/healthz" 60 grafana-mcp-full || true
mcp "$RW_IP" "$TOKEN" alice "$LIST" > "$TMP/tools-rw.json"
mcp "$FULL_IP" "$TOKEN" alice "$LIST" > "$TMP/tools-full.json"
docker rm -f portcullis-t-grafana-mcp-rw portcullis-t-grafana-mcp-full >/dev/null 2>&1 || true
if python3 - "$MANIFEST" "$TMP/tools-ro.json" "$TMP/tools-rw.json" "$TMP/tools-full.json" <<'PY'
import fnmatch, json, re, sys
manifest = open(sys.argv[1]).read()
pats = {k: json.loads(re.search(r"^\s+%s:\s*(\[.*\])\s*$" % k, manifest, re.M).group(1)) for k in ("writes", "confirm", "never")}
def tools(path):
    out = {}
    for t in json.load(open(path))["result"]["tools"]:
        props = (t.get("inputSchema") or {}).get("properties") or {}
        ops = [str(x).lower() for k in ("operation", "action") for x in (props.get(k, {}).get("enum") or [])]
        out[t["name"].lower()] = {"ops": ops, "ann": t.get("annotations") or {}}
    return out
ro, rw, full = (tools(p) for p in sys.argv[2:5])
match = lambda p, t: ":" not in p and fnmatch.fnmatchcase(t, p.lower())
cls = lambda k, t: any(match(p, t) for p in pats[k])
bad = []
print("  INFO %d tools read-write, %d read-only, %d with the API tool" % (len(rw), len(ro), len(full)))
for t, v in sorted(rw.items()):
    flags = [f for f, on in (("destructiveHint", v["ann"].get("destructiveHint")), ("readOnlyHint", v["ann"].get("readOnlyHint")),
                             ("hidden read-only", t not in ro)) if on]
    print("  INFO   %s%s%s" % (t, (" [" + ", ".join(flags) + "]") if flags else "", (" ops=" + ",".join(v["ops"])) if v["ops"] else ""))
for k, pool in (("writes", rw), ("confirm", rw), ("never", full)):
    for p in pats[k]:
        if not any(match(p, t) for t in pool):
            bad.append("%s pattern %r matches no real tool" % (k, p))
for t in ("grafana_api_request",):
    if t in ro or t in rw:
        bad.append("%s is listed although --disable-api is set" % t)
for t, v in rw.items():
    if cls("never", t):
        continue
    if "delete" in t and not cls("confirm", t):
        bad.append("tool %s is not in confirm" % t)
    if any("delete" in o for o in v["ops"]) and not cls("confirm", t):
        bad.append("tool %s deletes through its operation argument but is not in confirm" % t)
    if v["ann"].get("destructiveHint") and not cls("confirm", t):
        print("  INFO   %s: destructiveHint without confirm (the gate confirms it anyway)" % t)
hidden = set(rw) - set(ro)
if not hidden or not ro:
    bad.append("--disable-write hid nothing (or everything)")
for t in sorted(hidden):
    if not cls("writes", t):
        bad.append("write tool %s (hidden in read-only) is not in writes" % t)
for t in sorted(ro):
    if cls("writes", t):
        bad.append("read-only tool %s is matched by writes" % t)
for b in bad:
    print("  FAIL " + b)
sys.exit(1 if bad else 0)
PY
then
  pass "tool classes match mcp-grafana's real tools (writes = exactly what --disable-write hides, every delete confirmed, never names real tools)"
else
  fail "tool classes do not match mcp-grafana's tools (above)"
fi

# A companion restart may change its address; the subnet stays: no Grafana
# restart, and it still works.
STARTED=$(docker inspect -f '{{.State.StartedAt}}' "$D")
docker restart "$M" >/dev/null
MCP_IP=$(net_ip "$M" portcullis-proxy)
MCP_TRUST_IP=$(net_ip "$M" "$TRUST_NET")
wait_for_url "http://${MCP_IP}:8000/healthz" 60 grafana-mcp || true
T=$(mcp "$MCP_IP" "$TOKEN" alice "$SEARCH" | text)
if grep -q 'Team dashboard' <<<"$T" && [ "$(docker inspect -f '{{.State.StartedAt}}' "$D")" = "$STARTED" ]; then
  pass "after a companion restart ($MCP_TRUST_IP) grafana-mcp works as alice, Grafana not restarted"
else
  fail "after a companion restart: search as alice: $(head -c 300 <<<"$T")"
fi
# AI support off (PORTCULLIS_AI_ENABLED unset = false): Traefik only, even
# with the companion running.
unset PORTCULLIS_AI_ENABLED
compose_up "$APP_ID"
wait_for_container "$M" 30 || true
if wait_allowlist traefik_only 120; then
  pass "AI support off -> Grafana trusts Traefik only, although the companion runs"
else
  fail "AI support off: allowlist '$(allowlist)'"
fi
not_admin "AI off, from the companion's trust address" "$(gfc GET /api/user admin)"
rm -rf "$TMP"

clear_public_policy
compose_down "$APP_ID"
rm -f "$COMPOSE_OVERRIDE"

