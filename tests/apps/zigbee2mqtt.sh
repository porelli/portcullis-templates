#!/usr/bin/env bash
# Test: Zigbee2MQTT (forward-auth + group-gate; Traefik-only gate, bundled
# password-protected Mosquitto).
# Hardware: CI has no Zigbee coordinator. Covered: the broker (no anonymous
# clients, generated users, ACL), the gate, forward-auth through Traefik,
# the idle state without a coordinator, and Zigbee2MQTT's start with this
# template's configuration up to the adapter (a network coordinator address
# nobody answers: it must fail at zigbee-herdsman, after settings validation
# and without onboarding). Not covered: a running frontend (needs a
# coordinator; the sign-in e2e marks member/admin expected_fail), pairing,
# MQTT traffic from Zigbee2MQTT itself, the host MQTT port binding.
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="zigbee2mqtt"
section "Zigbee2MQTT"

APP_ID=zigbee2mqtt
COMPOSE=$(_find_compose "$APP_ID") || { fail "compose.yml not found for $APP_ID"; exit 1; }

# ── Static ──────────────────────────────────────────────────
if grep -q 'portcullis-auth@docker,portcullis-groups@docker' "$COMPOSE"; then
  pass "Forward-auth + group-gate middleware configured"
else
  fail "Missing forward-auth or group-gate middleware in compose"
fi
nets() {
  if [ "$(yq -r ".services[\"$1\"].networks | tag" "$COMPOSE")" = '!!map' ]; then
    yq -r ".services[\"$1\"].networks | keys | join(\",\")" "$COMPOSE"
  else
    yq -r "[.services[\"$1\"].networks[]] | join(\",\")" "$COMPOSE"
  fi
}
for s in zigbee2mqtt mosquitto; do
  [ "$(nets "$s")" = default ] && pass "$s on the default network only" || fail "$s networks: $(nets "$s")"
done
case "$(nets zigbee2mqtt-gate)" in *portcullis-proxy*) pass "only the gate joins portcullis-proxy" ;; *) fail "gate not on portcullis-proxy" ;; esac
assert_compose_setting "$COMPOSE" Z2M_ONBOARD_NO_SERVER '1'
assert_compose_setting "$COMPOSE" ZIGBEE2MQTT_CONFIG_FRONTEND_URL 'https://\$\{PORTCULLIS_HOST_ZIGBEE2MQTT:-zigbee\.portcullis\.local\}'
if grep -q 'FRONTEND_AUTH_TOKEN' "$COMPOSE"; then fail "compose sets a frontend auth_token"; else pass "no frontend auth_token (the gateway is the sign-in)"; fi
MOSQ_CONF="$(dirname "$COMPOSE")/mosquitto.conf"
if grep -Eq '^allow_anonymous false$' "$MOSQ_CONF" && ! grep -Eq '^allow_anonymous true' "$MOSQ_CONF"; then
  pass "mosquitto: allow_anonymous false"
else
  fail "mosquitto must set allow_anonymous false"
fi
MANIFEST="$(dirname "$COMPOSE")/manifest.yaml"
[ "$(yq -r '.ports[] | select(.key == "Z2M_MQTT_PORT") | .bind' "$MANIFEST")" = 127.0.0.1 ] \
  && pass "MQTT host port bound to 127.0.0.1 by default" || fail "MQTT host port must default to 127.0.0.1"

# ── Runtime ─────────────────────────────────────────────────
compose_up "$APP_ID"
MQ=portcullis-mosquitto-1
Z2M=portcullis-zigbee2mqtt-1
GATE=portcullis-zigbee2mqtt-gate-1

for _ in $(seq 1 30); do
  [ "$(docker inspect -f '{{.State.Status}}' "$MQ" 2>/dev/null)" = running ] && break
  sleep 2
done
init_state=$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' portcullis-mosquitto-init-1 2>/dev/null || true)
[ "$init_state" = "exited 0" ] && pass "mosquitto-init completed" || fail "mosquitto-init: $init_state"
[ "$(docker inspect -f '{{.State.Status}}' "$MQ" 2>/dev/null)" = running ] && pass "mosquitto running" || { fail "mosquitto not running"; docker logs --tail 30 "$MQ" 2>&1 || true; }

# Password file: hashed, 0600, owned by mosquitto (1883).
if docker exec "$MQ" sh -c 'f=/mosquitto/auth/passwd; [ "$(stat -c %a:%u "$f")" = 600:1883 ] && [ "$(wc -l < "$f")" -eq 2 ] && ! grep -qvE "^(zigbee2mqtt|homeassistant):[$]([0-9]+|argon2id)[$]" "$f"'; then
  pass "password file hashed, 0600, owned by mosquitto"
else
  fail "password file not hashed / wrong mode or owner"
fi

# Client config files inside the broker container ($XDG_CONFIG_HOME/
# mosquitto_pub|mosquitto_sub, one option per line): the passwords travel by
# environment, never a command line.
docker exec -e Z2M_BROKER_PASSWORD -e Z2M_BROKER_HA_PASSWORD "$MQ" sh -c '
  umask 077
  for u in z2m ha bad; do mkdir -p /tmp/mq-$u; done
  printf -- "-h 127.0.0.1\n-u zigbee2mqtt\n-P %s\n" "$Z2M_BROKER_PASSWORD" > /tmp/mq-z2m/mosquitto_pub
  printf -- "-h 127.0.0.1\n-u homeassistant\n-P %s\n" "$Z2M_BROKER_HA_PASSWORD" > /tmp/mq-ha/mosquitto_sub
  printf -- "-h 127.0.0.1\n-u homeassistant\n-P wrong-password\n" > /tmp/mq-bad/mosquitto_pub'

# Refusals must be the broker's (not a client error).
refused() {  # <XDG dir or ""> : 0 if the broker refused the connection
  local out
  out=$(docker exec ${1:+-e XDG_CONFIG_HOME="$1"} "$MQ" mosquitto_pub -h 127.0.0.1 -t zigbee2mqtt/ci -m x 2>&1 || true)
  echo "$out" | grep -qiE 'not authori[sz]ed|bad user name or password'
}
refused "" && pass "anonymous client refused by the broker" || fail "anonymous client not refused"
refused /tmp/mq-bad && pass "wrong password refused by the broker" || fail "wrong password not refused"

# homeassistant receives what zigbee2mqtt publishes, on allowed topics only.
mq_roundtrip() {  # <topic>: 0 if a message published by zigbee2mqtt reaches homeassistant
  local topic="$1"
  docker exec "$MQ" sh -c "
    XDG_CONFIG_HOME=/tmp/mq-ha mosquitto_sub -t '$topic' -C 1 -W 8 > /tmp/got 2>/tmp/sub.err & s=\$!
    sleep 2
    XDG_CONFIG_HOME=/tmp/mq-z2m mosquitto_pub -t '$topic' -m portcullis-ci || echo 'publish failed' >&2
    wait \$s; grep -qx portcullis-ci /tmp/got"
}
if mq_roundtrip zigbee2mqtt/ci/roundtrip; then pass "zigbee2mqtt -> homeassistant on zigbee2mqtt/#"; else fail "no delivery on zigbee2mqtt/#"; docker exec "$MQ" cat /tmp/sub.err || true; fi
if mq_roundtrip homeassistant/ci/roundtrip; then pass "zigbee2mqtt -> homeassistant on homeassistant/#"; else fail "no delivery on homeassistant/#"; fi
# Meaningful only because the two deliveries above work with the same clients.
if mq_roundtrip other/ci; then fail "ACL lets other/# through"; else pass "ACL: nothing delivered outside zigbee2mqtt/# and homeassistant/#"; fi
docker exec "$MQ" rm -rf /tmp/mq-z2m /tmp/mq-ha /tmp/mq-bad /tmp/got /tmp/sub.err

# No coordinator configured: Zigbee2MQTT idles and says what to set.
sleep 3
[ "$(docker inspect -f '{{.State.Status}}' "$Z2M")" = running ] && pass "zigbee2mqtt container idles without a coordinator" || fail "zigbee2mqtt container not running"
docker logs "$Z2M" 2>&1 | grep -q 'no Zigbee coordinator configured' \
  && pass "log explains the missing coordinator" || fail "no idle message in the log"

# The broker is reachable from the bridge's container (private network).
if docker exec "$Z2M" node -e "require('net').connect(1883,'mosquitto').on('connect',()=>process.exit(0)).on('error',()=>process.exit(1));setTimeout(()=>process.exit(1),5000)"; then
  pass "zigbee2mqtt reaches mosquitto:1883"
else
  fail "zigbee2mqtt cannot reach mosquitto:1883"
fi

# Zigbee2MQTT's own start with this template's configuration, up to the
# adapter: a network coordinator nobody answers.
out=$(docker exec -e Z2M_NETWORK_COORDINATOR=tcp://127.0.0.1:9 -e Z2M_ADAPTER=zstack "$Z2M" \
  timeout 180 sh /portcullis/z2m-start.sh 2>&1 || true)
if echo "$out" | grep -q 'Failed to start zigbee-herdsman'; then
  pass "Zigbee2MQTT starts with the template's settings and stops only at the (absent) adapter"
else
  fail "Zigbee2MQTT did not reach the adapter start"
  echo "$out" | tail -30
fi
if echo "$out" | grep -qiE 'Refusing to start because configuration is not valid|onboard'; then
  fail "settings invalid or onboarding started"
else
  pass "no settings errors, no onboarding"
fi
if echo "$out" | grep -qF -f <(printf '%s\n' "${Z2M_BROKER_PASSWORD:-unset-password}"); then
  fail "the MQTT password appears in Zigbee2MQTT's output"
else
  pass "the MQTT password is not in Zigbee2MQTT's output"
fi
cfg=$(docker exec "$Z2M" cat /app/data/configuration.yaml 2>/dev/null || true)
for want in 'server: mqtt://mosquitto:1883' 'user: zigbee2mqtt' 'base_topic: zigbee2mqtt' 'port: tcp://127.0.0.1:9'; do
  echo "$cfg" | grep -qF "$want" && pass "configuration.yaml: $want" || fail "configuration.yaml lacks '$want'"
done
if echo "$cfg" | grep -q '^onboarding: true'; then fail "configuration.yaml has onboarding: true"; else pass "configuration.yaml: no onboarding"; fi
if echo "$cfg" | yq -r '.frontend.enabled' - 2>/dev/null | grep -qx true; then pass "frontend enabled"; else fail "frontend not enabled"; fi

# The gate answers Traefik only.
GATE_IP=$(docker inspect "$GATE" --format '{{with index .NetworkSettings.Networks "portcullis-proxy"}}{{.IPAddress}}{{end}}')
for _ in $(seq 1 20); do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://${GATE_IP}:8080/" 2>/dev/null || true)
  [ "$code" = 000 ] && sleep 1 || break
done
for path in / /api; do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://${GATE_IP}:8080${path}" 2>/dev/null || true)
  [ "$code" = 403 ] && pass "gate refuses a non-Traefik peer on $path (403)" || fail "gate answered $path to a non-Traefik peer: HTTP $code"
done
# Of this instance, only the gate is on portcullis-proxy (no other
# container there can reach the frontend or the broker).
on_proxy=$(docker network inspect portcullis-proxy --format '{{range .Containers}}{{.Name}} {{end}}' | tr ' ' '\n' \
  | grep -E '^portcullis-(zigbee2mqtt|mosquitto)' | sort | tr '\n' ' ')
[ "$on_proxy" = "$GATE " ] && pass "only $GATE is on portcullis-proxy" || fail "on portcullis-proxy: $on_proxy"

HOST="zigbee.$DOMAIN"
for _ in $(seq 1 30); do
  out=$(via_traefik "$HOST" /)
  case "${out%% *}" in 000|404|502) sleep 1 ;; *) break ;; esac
done
assert_gated_path "$HOST" "/"
assert_gated_path "$HOST" "/api" -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="

compose_down "$APP_ID"
