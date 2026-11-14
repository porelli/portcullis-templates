#!/usr/bin/env bash
# Test: Headscale (native OIDC)
# Static checks, then (core running) the VPN provider live: gateway, glue hooks.
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="headscale"
section "Headscale"

APP_ID=headscale

COMPOSE=$(_find_compose "$APP_ID")
if [ -n "$COMPOSE" ]; then
  pass "compose.yml found: $COMPOSE"
else
  fail "compose.yml not found for $APP_ID"
fi

# Traefik routing enabled (both headscale and headplane services)
if grep -q 'traefik.enable.*true' "$COMPOSE"; then
  pass "Traefik routing enabled"
else
  fail "Traefik routing not configured"
fi

# Two services should have Traefik labels: headscale + headplane
if grep -q 'traefik.http.routers.headscale' "$COMPOSE" && grep -q 'traefik.http.routers.headplane' "$COMPOSE"; then
  pass "Both headscale and headplane have Traefik routers"
else
  fail "Expected Traefik routers for both headscale and headplane"
fi

# Native OIDC — headscale uses OIDC via config template, headplane has OIDC env vars
if grep -q 'HEADSCALE_OIDC_CLIENT_SECRET' "$COMPOSE"; then
  pass "Headscale OIDC client secret configured"
else
  fail "Headscale OIDC client secret not found in compose"
fi

if grep -q 'HEADPLANE_OIDC__ISSUER' "$COMPOSE" && grep -q 'HEADPLANE_OIDC__CLIENT_ID' "$COMPOSE" && grep -q 'HEADPLANE_OIDC__CLIENT_SECRET' "$COMPOSE"; then
  pass "Headplane OIDC env vars configured (issuer, client_id, client_secret)"
else
  fail "Headplane OIDC env vars missing"
fi

# Service port matches Traefik label — headscale on 8080
if grep -q 'loadbalancer.server.port.*8080' "$COMPOSE"; then
  pass "Headscale Traefik loadbalancer port is 8080"
else
  fail "Headscale Traefik loadbalancer port mismatch (expected 8080)"
fi

# Headplane loadbalancer port is 3000
if grep -q 'traefik.http.services.headplane.loadbalancer.server.port.*3000' "$COMPOSE"; then
  pass "Headplane Traefik loadbalancer port is 3000"
else
  fail "Headplane Traefik loadbalancer port mismatch (expected 3000)"
fi

# Identity: unverified (user-editable) email is never synced into Headscale
HS_CONFIG="$(dirname "$COMPOSE")/config/config.yaml"
if grep -Eq '^[[:space:]]+email_verified_required:[[:space:]]*true' "$HS_CONFIG" \
  && ! grep -Eq '^[[:space:]]+allowed_users:' "$HS_CONFIG"; then
  pass "oidc.email_verified_required: true, no email-based allowed_users"
else
  fail "headscale oidc must keep email_verified_required: true and not use allowed_users"
fi

# ── Portcullis VPN provider (manifest vpn:, contract §3.3) ──────────
MANIFEST="$(dirname "$COMPOSE")/manifest.yaml"
GLUE="$(dirname "$COMPOSE")/vpn/glue.py"
PYTHON="${PYTHON:-python3}"

# The validator (schema + check_vpn) accepts the template (lint runs it
# too; Test Apps has no validator dependencies installed).
if ! "$PYTHON" -c 'import sys; sys.path.insert(0, "tests"); import validate' >/dev/null 2>&1; then
  info "validator dependencies missing (tests/requirements.txt): validate.py runs in lint"
elif "$PYTHON" tests/validate.py "$APP_ID" >/tmp/headscale-validate.log 2>&1; then
  pass "validate.py accepts the template (vpn: block included)"
else
  fail "validate.py refuses the template: $(tail -5 /tmp/headscale-validate.log)"
fi
if [ "$(yq -r '.vpn.ingress.service + " " + .vpn.identity.hook + " " + .vpn.dns.hook + " " + (.vpn.control_routers | join(","))' "$MANIFEST")" \
     = "gateway vpn-devices vpn-dns headscale" ]; then
  pass "vpn: gateway ingress, vpn-devices / vpn-dns hooks, only the headscale router stays public"
else
  fail "vpn: block differs from the reference provider shape"
fi

# The gateway is userspace: no capabilities, no devices, no TUN, read-only.
if [ "$(yq -r '.services.gateway | ((.cap_add // []) | length | tostring) + " " + ((.devices // []) | length | tostring) + " " + (.cap_drop | join(",")) + " " + (.read_only | tostring) + " " + .environment.TS_USERSPACE' "$COMPOSE")" \
     = "0 0 ALL true true" ]; then
  pass "gateway: TS_USERSPACE, cap_drop ALL, no cap_add / devices, read-only"
else
  fail "gateway must run userspace with cap_drop: [ALL], no cap_add / devices, read_only"
fi
if grep -qE '/dev/net/tun|NET_ADMIN|privileged' "$COMPOSE"; then
  fail "compose.yml mentions /dev/net/tun, NET_ADMIN or privileged"
else
  pass "no TUN device, NET_ADMIN or privileged anywhere"
fi
for svc in gateway vpn-glue; do
  img=$(yq -r ".services[\"$svc\"].image" "$COMPOSE")
  if [[ "$img" =~ ^docker\.io/[a-z0-9/_.-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$ ]]; then
    pass "$svc image pinned ($img)"
  else
    fail "$svc image must be docker.io/<repo>:<tag>@sha256:<digest> (got $img)"
  fi
done
if [ "$(yq -r '.services["vpn-glue"] | (.cap_drop | join(",")) + " " + (.read_only | tostring) + " " + ((.networks // ["default"]) | join(","))' "$COMPOSE")" = "ALL true default" ]; then
  pass "vpn-glue: cap_drop ALL, read-only, default network only"
else
  fail "vpn-glue must be cap_drop: [ALL], read_only and on the default network only"
fi
# The glue is stdlib only and never prints the API key or a pre-auth key.
if grep -qE '^(import|from) ' "$GLUE" && ! grep -E '^(import|from) ' "$GLUE" | grep -vqE '^(from __future__ import annotations|import (datetime|ipaddress|json|os|re|sys|tempfile|urllib\.error|urllib\.request)|from typing import .*)$'; then
  pass "vpn/glue.py imports the standard library only"
else
  fail "vpn/glue.py must import only the standard library"
fi

# ── Live: headscale + gateway + glue against the booted core ───────
if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -qx portcullis-traefik-1; then
  info "core is not running: skipping the live VPN checks"
  exit 0
fi

ISSUER="https://auth.$DOMAIN/realms/portcullis"
HS=portcullis-headscale-1
GL=portcullis-vpn-glue-1
NET=portcullis_default
TS_IMAGE=$(yq -r '.services.gateway.image' "$COMPOSE")
PY_IMAGE=$(yq -r '.services["vpn-glue"].image' "$COMPOSE")
STUB=headscale-test-edge
OVERRIDE=$(mktemp)
CLIENTS=()
cleanup() {
  docker rm -f "$STUB" "${CLIENTS[@]}" >/dev/null 2>&1 || true
  COMPOSE_OVERRIDE="$OVERRIDE" compose_down "$APP_ID" >/dev/null 2>&1 || true
  rm -f "$OVERRIDE"
}
trap 'cleanup; report' EXIT
devices_req() { printf '{"version":1,"trigger":"vpn","instance":"%s","op":"devices","ranges":["100.64.0.0/10"]}' "$APP_ID"; }
glue() { docker exec -i "$GL" python3 /vpn/glue.py "$@"; }
hs_api_ready() {
  docker exec "$GL" python3 -c 'import urllib.request,sys; urllib.request.urlopen("http://headscale-internal:8080/health", timeout=3)' >/dev/null 2>&1
}

printf 'services: {}\n' > "$OVERRIDE"
COMPOSE_OVERRIDE="$OVERRIDE" compose_up "$APP_ID"
for _ in $(seq 1 60); do hs_api_ready && break; sleep 2; done
if hs_api_ready; then pass "headscale is up (REST API on headscale-internal)"; else fail "headscale did not come up"; app_logs "$APP_ID" 40; exit 1; fi

# Unwired: the gateway idles until the gateway-key hook gives it a key.
if docker logs portcullis-gateway-1 2>&1 | grep -q 'not wired as a Portcullis VPN provider'; then
  pass "unwired gateway serves nothing"
else
  fail "gateway did not report the unwired state"
fi

# Without the API key the identity hook fails closed with the fix.
out=$(devices_req | glue 2>&1) && rc=0 || rc=$?
if [ "$rc" -ne 0 ] && grep -q 'set the Headscale API key setting' <<<"$out"; then
  pass "vpn-devices without the API key: exit $rc, names the setting"
else
  fail "vpn-devices without the API key must fail and name the setting (rc=$rc: $out)"
fi

HEADSCALE_API_KEY=$(docker exec "$HS" headscale apikeys create --expiration 1d | tail -1)
export HEADSCALE_API_KEY
[ -n "$HEADSCALE_API_KEY" ] || { fail "could not create a Headscale API key"; exit 1; }

# The Hub's wiring, emulated: PORTCULLIS_VPN_EDGE on the ingress service
# (the edge is a stub that prints the PROXY v2 header).
docker run -d --name "$STUB" --network "$NET" --read-only --cap-drop ALL "$PY_IMAGE" python3 -u -c '
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0", 9001)); s.listen(8)
while True:
    c, a = s.accept()
    d = b""
    while len(d) < 16:
        b = c.recv(4096)
        if not b:
            break
        d += b
    if d.startswith(b"\r\n\r\n\x00\r\nQUIT\n") and len(d) >= 28 and d[12] == 0x21 and d[13] == 0x11:
        print("PROXYv2 src=%s" % socket.inet_ntoa(d[16:20]), flush=True)
    else:
        print("no PROXY v2 header", flush=True)
    c.close()
' >/dev/null
EDGE_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$STUB")
printf 'services:\n  gateway:\n    environment:\n      PORTCULLIS_VPN_EDGE: "%s:9001"\n' "$EDGE_IP" > "$OVERRIDE"
COMPOSE_OVERRIDE="$OVERRIDE" compose_up "$APP_ID"
for _ in $(seq 1 60); do hs_api_ready && break; sleep 2; done

# gateway-key (a start hook): a single-use tagged key; the gateway registers.
HOOK_OUT=$(printf '{"version":1,"trigger":"start"}' | glue gateway-key 2>&1) && rc=0 || rc=$?
if [ "$rc" -eq 0 ]; then
  pass "gateway-key hook ran"
else
  fail "gateway-key hook failed"
fi
if [ "$(docker exec "$GL" stat -c '%a' /run/gateway/authkey 2>/dev/null)" = 600 ]; then
  pass "pre-auth key written 0600"
  PREAUTH=$(docker exec "$GL" cat /run/gateway/authkey)
else
  fail "pre-auth key missing or not 0600"
fi
GW_IP=""
for _ in $(seq 1 60); do
  GW_IP=$(devices_req | glue 2>/dev/null | jq -r '.gateway // empty' || true)
  [ -n "$GW_IP" ] && break
  sleep 3
done
if [[ "$GW_IP" =~ ^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]+\.[0-9]+$ ]]; then
  pass "gateway registered as tag:portcullis-gateway ($GW_IP)"
else
  fail "gateway did not register"; docker logs --tail 30 portcullis-gateway-1 2>&1; exit 1
fi
if docker inspect -f '{{.HostConfig.CapAdd}} {{.HostConfig.ReadonlyRootfs}}' portcullis-gateway-1 | grep -qx '\[\] true'; then
  pass "running gateway has no added capabilities and a read-only root"
else
  fail "running gateway has capabilities or a writable root"
fi

# The gateway's only credential, its pre-auth key: single-use, not
# ephemeral, tag-only (no user), at most 1 h, now used; the node carries
# exactly the gateway tag.
hs_get() {
  docker exec "$GL" python3 -c '
import json, os, sys, urllib.request
r = urllib.request.Request("http://headscale-internal:8080" + sys.argv[1], headers={"Authorization": "Bearer " + os.environ["HEADSCALE_API_KEY"]})
print(urllib.request.urlopen(r, timeout=10).read().decode())' "$1"
}
KEYS=$(hs_get /api/v1/preauthkey)
NOW=$(date -u +%s)
if jq -e --argjson now "$NOW" '
    [.preAuthKeys[] | select((.aclTags // []) | index("tag:portcullis-gateway"))] as $k
    | ($k | length) == 1 and $k[0].aclTags == ["tag:portcullis-gateway"] and $k[0].user == null
      and $k[0].reusable == false and $k[0].ephemeral == false and $k[0].used == true
      and ($k[0].expiration | sub("\\.[0-9]+"; "") | fromdateiso8601) <= $now + 3600 + 120' <<<"$KEYS" >/dev/null; then
  pass "gateway pre-auth key: one, tag-only, no user, single-use, not ephemeral, used, expiry ≤ 1 h"
else
  fail "gateway pre-auth key scope wrong: $(jq -c '[.preAuthKeys[] | del(.key)]' <<<"$KEYS")"
fi
if hs_get /api/v1/node | jq -e '[.nodes[] | select((.tags // []) | index("tag:portcullis-gateway"))] | length == 1 and .[0].tags == ["tag:portcullis-gateway"]' >/dev/null; then
  pass "one gateway node, tagged exactly tag:portcullis-gateway"
else
  fail "gateway node tags wrong"
fi
# Online: a second run mints nothing and removes the used key file.
HOOK_OUT="$HOOK_OUT$(printf '{"version":1,"trigger":"start"}' | glue gateway-key 2>&1)" || fail "second gateway-key run failed"
if [ "$(hs_get /api/v1/preauthkey | jq '[.preAuthKeys[] | select((.aclTags // []) | index("tag:portcullis-gateway"))] | length')" = 1 ] \
  && ! docker exec "$GL" test -e /run/gateway/authkey; then
  pass "gateway-key with the gateway online mints nothing and removes the key file"
else
  fail "gateway-key minted again or left the key file while the gateway is online"
fi

# The Hub's wiring as it happens on a server: the gateway runs unwired,
# then the override gains PORTCULLIS_VPN_EDGE (compose recreates it) and the
# start hooks run again; the provider's hooks then run every refresh. The
# gateway must keep running (core's e2e-vpn saw it exit about a minute
# after wiring): docker events and its whole log are kept.
printf 'services: {}\n' > "$OVERRIDE"
COMPOSE_OVERRIDE="$OVERRIDE" compose_up "$APP_ID" >/dev/null
printf '{"version":1,"trigger":"start"}' | glue gateway-key >/dev/null 2>&1 || true
sleep 20
printf 'services:\n  gateway:\n    environment:\n      PORTCULLIS_VPN_EDGE: "%s:9001"\n' "$EDGE_IP" > "$OVERRIDE"
COMPOSE_OVERRIDE="$OVERRIDE" compose_up "$APP_ID" >/dev/null
WIRED_CID=$(docker inspect -f '{{.Id}}' portcullis-gateway-1)
EVENTS=$(mktemp)
docker events --filter "container=$WIRED_CID" --format '{{.Time}} {{.Action}}' >"$EVENTS" 2>&1 &
EVENTS_PID=$!
printf '{"version":1,"trigger":"start"}' | glue gateway-key >/dev/null 2>&1 || true
for i in 1 2 3; do
  sleep 60
  devices_req | glue >/dev/null 2>&1 || info "vpn-devices failed at minute $i"
  [ "$i" = 1 ] && printf '{"version":1,"trigger":"vpn","instance":"%s","op":"dns","records":[{"name":"app-test.%s","type":"A","value":"%s"}]}' \
    "$APP_ID" "$DOMAIN" "$GW_IP" | glue >/dev/null 2>&1
done
kill "$EVENTS_PID" 2>/dev/null || true
restarts=$(docker inspect -f '{{.RestartCount}} {{.State.Status}} {{.Id}}' portcullis-gateway-1)
info "gateway after 3 min wired: restarts/state/id = $restarts (wired container $WIRED_CID)"
info "gateway events: $(tr '\n' ';' <"$EVENTS")"
if [ "${restarts%% *}" = 0 ] && [ "${restarts##* }" = "$WIRED_CID" ] && ! grep -q ' die$' "$EVENTS"; then
  pass "the wired gateway keeps running for 3 min (no exit, no restart)"
else
  fail "the wired gateway exited or restarted after wiring"
  docker logs portcullis-gateway-1 2>&1 | grep -vE 'magicsock: \[warning\]|buffer size' | grep -E 'exiting|left running state|boot:|Received error|health\(|state|failed|fatal|panic|Switching ipn state' | tail -60
fi
rm -f "$EVENTS"
# The gateway (re)starting while its login server is down longer than
# containerboot's default 60 s boot deadline (the Hub's wiring recreates
# headscale, which restarts until its OIDC discovery answers): it must wait
# (TS_BOOT_TIMEOUT), not exit.
if [ "$(yq -r '.services.gateway.environment.TS_BOOT_TIMEOUT // ""' "$COMPOSE")" = "" ]; then
  pass "gateway keeps containerboot's 60 s boot deadline (its restart cures a 421-pinned connection)"
else
  fail "gateway must not raise TS_BOOT_TIMEOUT: a gateway booted before headscale's router stays on 421 until it restarts"
fi
docker stop "$HS" >/dev/null
docker restart portcullis-gateway-1 >/dev/null
# The restarted instance's own log only (its start time, nanoseconds).
SINCE=$(docker inspect -f '{{.State.StartedAt}}' portcullis-gateway-1)
EVENTS=$(mktemp)
docker events --filter "container=$WIRED_CID" --format '{{.Time}} {{.Action}}' >"$EVENTS" 2>&1 &
EVENTS_PID=$!
sleep 75
docker start "$HS" >/dev/null
T_START=$(date +%s)
LOGGED=""
for _ in $(seq 1 80); do
  if [ "$(docker exec portcullis-gateway-1 tailscale --socket=/tmp/tailscaled.sock status --json 2>/dev/null | jq -r '.BackendState')" = Running ] \
    && docker logs --since "$SINCE" portcullis-gateway-1 2>&1 | grep -q 'Startup complete'; then LOGGED=1; break; fi
  sleep 3
done
kill "$EVENTS_PID" 2>/dev/null || true
restarts=$(grep -c ' die$' "$EVENTS" || true)
if [ -n "$LOGGED" ]; then
  pass "a gateway booted while headscale was down logs in $(( $(date +%s) - T_START )) s after headscale is back ($restarts restart(s) by its boot deadline)"
else
  fail "the gateway did not log in within 4 min of headscale coming back ($restarts restart(s))"
  docker logs --since "$SINCE" portcullis-gateway-1 2>&1 | grep -E '^boot:|^gateway:|Received error|Switching ipn state' | grep -v magicsock | tail -20
fi
rm -f "$EVENTS"
for _ in $(seq 1 60); do [ -n "$(devices_req | glue 2>/dev/null | jq -r '.gateway // empty')" ] && break; sleep 3; done

# People: alice signed in through Portcullis (provider id = issuer/sub,
# set in the store with headscale stopped), bob is a local Headscale user.
SUB=0b5a1c2e-1111-4222-8333-444455556666
docker exec "$HS" headscale users create alice >/dev/null
docker exec "$HS" headscale users create bob >/dev/null
docker stop "$HS" >/dev/null
docker run --rm -v portcullis_headscale-data:/d "$PY_IMAGE" python3 -c '
import sqlite3, sys
c = sqlite3.connect("/d/db.sqlite")
n = c.execute("update users set provider_identifier = ?, provider = ? where name = ?", (sys.argv[1], "oidc", "alice")).rowcount
c.commit()
sys.exit(0 if n == 1 else 1)' "$ISSUER/$SUB" || fail "could not mark alice as an OIDC user"
docker start "$HS" >/dev/null
for _ in $(seq 1 60); do hs_api_ready && break; sleep 2; done
HOST_HS="$PORTCULLIS_HOST_HEADSCALE"
# The clients log in through Traefik (as on a real server): wait until the
# restarted headscale is routed again.
for _ in $(seq 1 60); do
  [ "$(via_traefik "$HOST_HS" /health | cut -d' ' -f1)" = 200 ] && break
  sleep 2
done
for who in alice bob; do
  uid=$(docker exec "$HS" headscale users list -o json | jq -r --arg n "$who" '.[] | select(.name == $n) | .id')
  key=$(docker exec "$HS" headscale preauthkeys create -u "$uid" -e 1h -o json | jq -r .key)
  docker run -d --name "headscale-test-$who" --network "$NET" --cap-drop ALL --restart on-failure:5 \
    --add-host "$HOST_HS:host-gateway" -v "$PROJECT_DIR/certs/ca-bundle.crt:/etc/ssl/certs/ca-certificates.crt:ro" \
    -e TS_AUTHKEY="$key" -e TS_USERSPACE=true -e TS_STATE_DIR=/var/lib/tailscale -e TS_HOSTNAME="$who-laptop" \
    -e TS_TAILSCALED_EXTRA_ARGS=--no-logs-no-support -e "TS_EXTRA_ARGS=--login-server=https://$HOST_HS" "$TS_IMAGE" >/dev/null
  CLIENTS+=("headscale-test-$who")
done
DOC=""
for _ in $(seq 1 40); do
  DOC=$(devices_req | glue 2>/dev/null || true)
  [ "$(jq -r '[.devices[] | select(.online)] | length' <<<"$DOC" 2>/dev/null)" = 1 ] && \
    [ "$(docker exec "$HS" headscale nodes list -o json | jq '[.[] | select(.online)] | length')" -ge 3 ] && break
  sleep 3
done
if jq -e --arg gw "$GW_IP" '.version == 1 and .gateway == $gw and (keys | sort) == ["devices","gateway","version"]' <<<"$DOC" >/dev/null 2>&1; then
  pass "vpn-devices: document version 1 with the gateway"
else
  fail "vpn-devices document wrong: $DOC"
fi
ALICE_IP=$(docker exec "$HS" headscale nodes list -o json | jq -r '.[] | select(.name == "alice-laptop") | .ip_addresses[0]')
if [ -z "$ALICE_IP" ]; then
  for c in "${CLIENTS[@]}"; do info "$c: $(docker inspect -f '{{.State.Status}} restarts={{.RestartCount}}' "$c")"; docker logs --tail 15 "$c" 2>&1 | grep -vi 'magicsock\|buffer size' || true; done
fi
if jq -e --arg ip "$ALICE_IP" --arg sub "$SUB" '[.devices[] | select(.address == $ip and .owner == $sub and .name == "alice-laptop"
     and .online == true and (.id | type) == "string" and (keys | sort) == ["address","expires","id","last_seen","name","online","owner"])] | length == 1' <<<"$DOC" >/dev/null 2>&1; then
  pass "alice's node: owner = her OIDC sub (issuer prefix stripped)"
else
  fail "alice's node missing or wrong owner: $DOC"
fi
if jq -e --arg gw "$GW_IP" '(.devices | length) == 1 and ([.devices[] | select(.address == $gw or .name == "bob-laptop")] | length) == 0' <<<"$DOC" >/dev/null 2>&1; then
  pass "the local user's node and the gateway are not devices"
else
  fail "a local user's node or the gateway is listed as a device: $DOC"
fi

# Through the gateway: the edge gets PROXY v2 with alice's tunnel address.
for _ in $(seq 1 10); do
  printf 'x' | timeout 20 docker exec -i headscale-test-alice tailscale --socket=/tmp/tailscaled.sock nc "$GW_IP" 443 >/dev/null 2>&1 || true
  docker logs "$STUB" 2>&1 | grep -q "PROXYv2 src=$ALICE_IP\$" && break
  sleep 3
done
if docker logs "$STUB" 2>&1 | grep -q "PROXYv2 src=$ALICE_IP\$"; then
  pass "gateway forwards to PORTCULLIS_VPN_EDGE with PROXY v2, source = the client node ($ALICE_IP)"
else
  fail "edge stub did not get PROXY v2 from $ALICE_IP: $(docker logs "$STUB" 2>&1 | tail -3)"
  TSC=(tailscale --socket=/tmp/tailscaled.sock)
  info "alice status: $(docker exec headscale-test-alice "${TSC[@]}" status 2>&1 | head -5 | tr '\n' ';')"
  info "alice ping: $(timeout 30 docker exec headscale-test-alice "${TSC[@]}" ping -c 3 "$GW_IP" 2>&1 | tr '\n' ';')"
  info "gateway status: $(docker exec portcullis-gateway-1 "${TSC[@]}" status 2>&1 | head -5 | tr '\n' ';')"
  info "gateway serve: $(docker exec portcullis-gateway-1 "${TSC[@]}" serve status --json 2>&1 | tr -d '\n ')"
  info "gateway netcheck: $(timeout 30 docker exec portcullis-gateway-1 "${TSC[@]}" netcheck 2>&1 | tr '\n' ';' | cut -c1-600)"
  docker logs portcullis-gateway-1 2>&1 | grep -iE 'derp|x509|tls|certificate' | grep -v 'buffer size' | tail -15
fi

# vpn-dns: the records land in Headscale's extra_records_path, atomically,
# and reach the clients' MagicDNS.
REC="app-test.$DOMAIN"
if printf '{"version":1,"trigger":"vpn","instance":"%s","op":"dns","records":[{"name":"%s","type":"A","value":"%s"}]}' "$APP_ID" "$REC" "$GW_IP" | glue; then
  pass "vpn-dns hook ran"
else
  fail "vpn-dns hook failed"
fi
if docker exec "$GL" cat /dns/extra-records.json | jq -e --arg n "$REC" --arg v "$GW_IP" '. == [{"name": $n, "type": "A", "value": $v}]' >/dev/null \
  && [ -z "$(docker exec "$GL" find /dns -name '.tmp-*')" ]; then
  pass "extra-records.json holds exactly the records, no temp file left"
else
  fail "extra-records.json wrong or a temp file left behind"
fi
got=""
for _ in $(seq 1 20); do
  got=$(docker exec headscale-test-alice tailscale --socket=/tmp/tailscaled.sock debug netmap 2>/dev/null \
        | jq -r --arg n "$REC" '.DNS.ExtraRecords[]? | select(.Name == $n) | .Value' || true)
  [ "$got" = "$GW_IP" ] && break
  sleep 3
done
if [ "$got" = "$GW_IP" ]; then
  pass "Headscale reloaded the records: $REC → $GW_IP in the clients' netmap"
else
  fail "the record did not reach the clients (got '$got')"
fi
out=$(printf '{"version":1,"trigger":"vpn","op":"dns","records":[{"name":"x","type":"AAAA","value":"::1"}]}' | glue 2>&1) && rc=0 || rc=$?
if [ "$rc" -ne 0 ] && docker exec "$GL" cat /dns/extra-records.json | jq -e --arg n "$REC" '.[0].name == $n' >/dev/null; then
  pass "a bad record is refused and the file is left as it was"
else
  fail "a bad dns record must be refused without touching the file ($out)"
fi
# A rejected API key names the fix, without the key.
BAD=$(devices_req | docker exec -i -e HEADSCALE_API_KEY=hskey-api-wrong-key "$GL" python3 /vpn/glue.py 2>&1) && rc=0 || rc=$?
if [ "$rc" -ne 0 ] && grep -q 'invalid or expired' <<<"$BAD" && ! grep -q 'hskey-api-wrong-key' <<<"$BAD"; then
  pass "a rejected API key: exit $rc, names the fix, never echoes the key"
else
  fail "a rejected API key must fail naming the fix without the key (rc=$rc: $BAD)"
fi
# Never a key in hook output or in the gateway's / glue's logs.
LOGS="$(docker logs portcullis-vpn-glue-1 2>&1)$(docker logs portcullis-gateway-1 2>&1)"
leaked=""
for secret in "$HEADSCALE_API_KEY" "${PREAUTH:-}"; do
  [ -n "$secret" ] || continue
  if grep -qF "$secret" <<<"$DOC$out$HOOK_OUT$BAD$LOGS"; then leaked=1; fi
done
[ -n "${PREAUTH:-}" ] || fail "the minted pre-auth key was not captured for the leak check"
if [ -n "$leaked" ]; then fail "the API key or the pre-auth key leaked into hook output or container logs"; else pass "no API or pre-auth key in hook output or container logs"; fi
