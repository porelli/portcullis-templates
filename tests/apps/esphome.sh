#!/usr/bin/env bash
# Test: ESPHome Device Builder (forward-auth + group-gate; Traefik-only gate,
# dashboard on the instance's private network, no dashboard password).
# Hardware: none needed. Not covered in CI: mDNS-free OTA / logs to a real
# device, and flashing through a host serial port (ESPHOME_SERIAL_DEVICE).
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="esphome"
section "ESPHome"

APP_ID=esphome
COMPOSE=$(_find_compose "$APP_ID") || { fail "compose.yml not found for $APP_ID"; exit 1; }

# ── Static ──────────────────────────────────────────────────
if grep -q 'portcullis-auth@docker,portcullis-groups@docker' "$COMPOSE"; then
  pass "Forward-auth + group-gate middleware configured"
else
  fail "Missing forward-auth or group-gate middleware in compose"
fi
# Network names of a service (list or map form).
nets() {
  if [ "$(yq -r ".services[\"$1\"].networks | tag" "$COMPOSE")" = '!!map' ]; then
    yq -r ".services[\"$1\"].networks | keys | join(\",\")" "$COMPOSE"
  else
    yq -r "[.services[\"$1\"].networks[]] | join(\",\")" "$COMPOSE"
  fi
}
gate_nets=$(nets esphome-gate)
app_nets=$(nets esphome)
[ "$app_nets" = "default" ] && pass "dashboard on the default network only" || fail "dashboard networks: $app_nets (want default only)"
case "$gate_nets" in *portcullis-proxy*) pass "only the gate joins portcullis-proxy" ;; *) fail "gate networks: $gate_nets" ;; esac
if yq -r '.services.esphome.network_mode // ""' "$COMPOSE" | grep -q host; then
  fail "dashboard uses host networking"
else
  pass "no host networking"
fi
if grep -Eq 'ESPHOME_(USERNAME|PASSWORD)|USERNAME:|PASSWORD:' "$COMPOSE"; then
  fail "compose sets a dashboard credential (the gateway is the sign-in)"
else
  pass "no dashboard credential in compose"
fi
assert_compose_setting "$COMPOSE" ESPHOME_TRUSTED_DOMAINS '\$\{PORTCULLIS_HOST_ESPHOME:-esphome\.portcullis\.local\}'
assert_compose_setting "$COMPOSE" PORTCULLIS_TRAEFIK_IP '\$\{PORTCULLIS_TRAEFIK_IP:-172\.31\.250\.2\}'

# ── Runtime ─────────────────────────────────────────────────
compose_up "$APP_ID"
APP=portcullis-esphome-1
GATE=portcullis-esphome-gate-1

for _ in $(seq 1 90); do
  docker exec "$APP" curl -sf -o /dev/null http://127.0.0.1:6052/version 2>/dev/null && break
  sleep 5
done
if docker exec "$APP" curl -sf http://127.0.0.1:6052/version 2>/dev/null | grep -q '"version"'; then
  pass "Device Builder answers inside its container"
else
  fail "Device Builder does not answer /version"
  docker logs --tail 40 "$APP" 2>&1 || true
fi

# The gate answers Traefik only: the CI host (another peer) gets 403.
GATE_IP=$(docker inspect "$GATE" --format '{{with index .NetworkSettings.Networks "portcullis-proxy"}}{{.IPAddress}}{{end}}')
for _ in $(seq 1 20); do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://${GATE_IP}:6052/" 2>/dev/null || true)
  [ "$code" = 000 ] && sleep 1 || break
done
for path in / /version /ws /devices; do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://${GATE_IP}:6052${path}" 2>/dev/null || true)
  [ "$code" = 403 ] && pass "gate refuses a non-Traefik peer on $path (403)" || fail "gate answered $path to a non-Traefik peer: HTTP $code"
done

# Of this instance, only the gate is on portcullis-proxy: no other container
# there can reach the dashboard.
on_proxy=$(docker network inspect portcullis-proxy --format '{{range .Containers}}{{.Name}} {{end}}' | tr ' ' '\n' \
  | grep -E '^portcullis-esphome' | sort | tr '\n' ' ')
[ "$on_proxy" = "$GATE " ] && pass "only $GATE is on portcullis-proxy" || fail "on portcullis-proxy: $on_proxy"

# Through Traefik, unauthenticated: forward-auth sends the browser to Keycloak,
# websocket upgrade included.
# ── Gate behaviour: this template's gate.sh in throwaway containers ──
# A private network with a fixed stand-in Traefik address; an echo upstream
# shows what the app would receive.
GATE_IMG=$(yq -r '.services["esphome-gate"].image' "$COMPOSE")
GATE_SH="$(cd "$(dirname "$COMPOSE")" && pwd)/gate.sh"
gt=pc-gatetest-esphome
gt_cleanup() {
  docker rm -f "$gt-up" "$gt-gate" >/dev/null 2>&1 || true
  docker network rm "$gt" >/dev/null 2>&1 || true
}
gt_cleanup
docker network create --subnet 10.254.77.0/24 "$gt" >/dev/null
docker run -d --name "$gt-up" --network "$gt" --network-alias gt-upstream --entrypoint /bin/sh "$GATE_IMG" -c '
  printf "%s\n" "server { listen 8080; location / { default_type text/plain; return 200 \"auth=[\$http_authorization] xfat=[\$http_x_forwarded_access_token] xarat=[\$http_x_auth_request_access_token] cookie=[\$http_cookie]\n\"; } }" > /etc/nginx/conf.d/default.conf
  exec nginx -g "daemon off;"' >/dev/null
docker run -d --name "$gt-gate" --network "$gt" --ip 10.254.77.20 \
  -e PORTCULLIS_TRAEFIK_IP=10.254.77.10 -e GATE_UPSTREAM=http://gt-upstream:8080 -e GATE_LISTEN=9000 \
  -v "$GATE_SH:/portcullis/gate.sh:ro" --entrypoint /bin/sh "$GATE_IMG" /portcullis/gate.sh >/dev/null
gt_get() {  # <client ip> [wget args...]: the answer's status line(s) and body
  local ip="$1"; shift
  docker run --rm --network "$gt" --ip "$ip" --entrypoint wget "$GATE_IMG" -S -q -O- -T 10 "$@" \
    http://10.254.77.20:9000/ 2>&1 || true
}
for _ in $(seq 1 20); do
  gt_get 10.254.77.10 | grep -q 'auth=\[' && break
  sleep 1
done
FAKE=kc-secret-not-for-the-app
out=$(gt_get 10.254.77.10 --header "Authorization: Bearer $FAKE" --header "X-Forwarded-Access-Token: $FAKE" \
  --header "X-Auth-Request-Access-Token: $FAKE" \
  --header "Cookie: a=1; _oauth2_proxy=$FAKE; _oauth2_proxy_1=$FAKE; b=2; __Host-portcullis_ext=$FAKE; __Host-portcullis_ext_csrf=$FAKE; _OAUTH2_PROXY_csrf=$FAKE")
if echo "$out" | grep -qF 'auth=[] xfat=[] xarat=[] cookie=[a=1; b=2]' && ! echo "$out" | grep -qF "$FAKE"; then
  pass "gate forwards no Authorization, access-token header or forward-auth cookie (others kept)"
else
  fail "gate forwards Portcullis credentials: $(echo "$out" | tail -1)"
fi
out=$(gt_get 10.254.77.10 --header "Cookie: a=1;_oauth2_proxy=$FAKE;$(printf '\t')__Host-portcullis_ext=$FAKE; b=2")
if echo "$out" | grep -qF 'cookie=[a=1; b=2]' && ! echo "$out" | grep -qF "$FAKE"; then
  pass "gate strips forward-auth cookies after ';' without a space or with a tab"
else
  fail "gate kept a forward-auth cookie behind ';' / tab: $(echo "$out" | tail -1)"
fi
many="Cookie: a=1"
for i in 0 1 2 3 4 5 6; do many="$many; _oauth2_proxy_$i=$FAKE"; done
if gt_get 10.254.77.10 --header "$many" | grep -q 'HTTP/1.1 400'; then
  pass "gate refuses a Cookie header it can't fully strip (400)"
else
  fail "gate passed a Cookie header with seven forward-auth cookies"
fi
if gt_get 10.254.77.11 --header "X-Forwarded-For: 10.254.77.10" --header "X-Real-IP: 10.254.77.10" | grep -q 'HTTP/1.1 403'; then
  pass "gate refuses another peer even with forged X-Forwarded-For / X-Real-IP (403)"
else
  fail "gate answered a non-Traefik peer with forged forwarding headers"
fi
gt_cleanup

# The real gate, from a throwaway container on portcullis-proxy (any other
# app's container), with forged forwarding headers: 403.
TRAEFIK_IP=$(_core_env PORTCULLIS_TRAEFIK_IP); TRAEFIK_IP=${TRAEFIK_IP:-172.31.250.2}
st=$(docker run --rm --network portcullis-proxy --entrypoint wget "$GATE_IMG" -S -q -O /dev/null -T 10 \
  --header "X-Forwarded-For: $TRAEFIK_IP" --header "X-Real-IP: $TRAEFIK_IP" "http://${GATE_IP}:6052/" 2>&1 \
  | grep -o 'HTTP/1.1 [0-9]*' | tail -1 || true)
[ "$st" = "HTTP/1.1 403" ] && pass "gate refuses a portcullis-proxy neighbour with forged headers (403)" \
  || fail "gate answered a portcullis-proxy neighbour: ${st:-no answer}"

HOST="esphome.$DOMAIN"
for _ in $(seq 1 30); do
  out=$(via_traefik "$HOST" /)
  case "${out%% *}" in 000|404|502) sleep 1 ;; *) break ;; esac
done
assert_gated_path "$HOST" "/"
assert_gated_path "$HOST" "/version"
assert_gated_path "$HOST" "/ws" -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="

compose_down "$APP_ID"
