#!/usr/bin/env bash
# Test: NetBird (native OIDC dashboard)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="netbird"
section "NetBird"

APP_ID=netbird
SERVICE=netbird-dashboard

# Static: management keys users on sub, never email
MGMT_TMPL="$(dirname "$(_find_compose "$APP_ID")")/management.json.tmpl"
if jq -e '.HttpConfig.AuthUserIDClaim == "sub"' "$MGMT_TMPL" > /dev/null 2>&1; then
  pass "management AuthUserIDClaim = sub"
else
  fail "management AuthUserIDClaim must be sub"
fi

# management-entrypoint.sh against a scratch directory (paths rewritten, no
# exec): an IPv6 TURN public IP is bracketed in the stun:/turn: URIs, and a
# later change (IPv6 -> IPv4 -> hostname) is applied in place.
ENTRY="$(dirname "$MGMT_TMPL")/management-entrypoint.sh"
SCRATCH=$(mktemp -d)
sed -e "s|/etc/netbird/|$SCRATCH/|g" -e 's|^exec /go/bin/netbird-mgmt.*|exit 0|' "$ENTRY" > "$SCRATCH/entry.sh"
cp "$MGMT_TMPL" "$SCRATCH/management.json.tmpl"
entry() {
  env -i PATH="$PATH" NETBIRD_HOST=netbird.example.org COTURN_STUN_PORT=3478 COTURN_EXTERNAL_IP="$1" \
    PORTCULLIS_DOMAIN=example.org NETBIRD_CLIENT_ID=netbird COTURN_AUTH_SECRET=s NETBIRD_OIDC_CLIENT_SECRET=s \
    sh "$SCRATCH/entry.sh" > /dev/null
}
uris() { jq -r '[.Stuns[].URI, .TURNConfig.Turns[].URI] | join(" ")' "$SCRATCH/management.json"; }
if entry 2001:db8::1 && [ "$(uris)" = "stun:[2001:db8::1]:3478 turn:[2001:db8::1]:3478" ]; then
  pass "IPv6 TURN public IP bracketed: stun:/turn:[2001:db8::1]:3478"
else
  fail "IPv6 TURN endpoint: $(uris 2>&1)"
fi
if entry 203.0.113.7 && [ "$(uris)" = "stun:203.0.113.7:3478 turn:203.0.113.7:3478" ] \
    && entry "" && [ "$(uris)" = "stun:netbird.example.org:3478 turn:netbird.example.org:3478" ] \
    && entry 2001:db8::2 && [ "$(uris)" = "stun:[2001:db8::2]:3478 turn:[2001:db8::2]:3478" ]; then
  pass "TURN endpoint changes (IPv4, hostname, IPv6) rewritten in place"
else
  fail "TURN endpoint change not applied: $(uris 2>&1)"
fi
rm -rf "$SCRATCH"

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID" "$SERVICE")
wait_for_url "http://${IP}:80" 60 "$APP_ID"

# Dashboard should return HTML
BODY=$(curl -sf "http://${IP}:80/" 2>/dev/null || echo "")
if echo "$BODY" | grep -qi "<html"; then
  pass "/ → dashboard returns HTML"
else
  fail "/ → dashboard did not return HTML"
fi

compose_down "$APP_ID"
