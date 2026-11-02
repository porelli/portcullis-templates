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
HOST="esphome.$DOMAIN"
for _ in $(seq 1 30); do
  out=$(via_traefik "$HOST" /)
  case "${out%% *}" in 000|404|502) sleep 1 ;; *) break ;; esac
done
assert_gated_path "$HOST" "/"
assert_gated_path "$HOST" "/version"
assert_gated_path "$HOST" "/ws" -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="

compose_down "$APP_ID"
